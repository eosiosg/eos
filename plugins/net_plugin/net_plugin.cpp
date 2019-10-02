/**
 *  @file
 *  @copyright defined in eos/LICENSE
 */
#include <eosio/chain/types.hpp>

#include <eosio/net_plugin/net_plugin.hpp>
#include <eosio/net_plugin/protocol.hpp>
#include <eosio/chain/controller.hpp>
#include <eosio/chain/exceptions.hpp>
#include <eosio/chain/block.hpp>
#include <eosio/chain/plugin_interface.hpp>
#include <eosio/producer_plugin/producer_plugin.hpp>
#include <eosio/chain/contract_types.hpp>

#include <fc/network/message_buffer.hpp>
#include <fc/network/ip.hpp>
#include <fc/io/json.hpp>
#include <fc/io/raw.hpp>
#include <fc/log/appender.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/crypto/rand.hpp>
#include <fc/exception/exception.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/host_name.hpp>
#include <boost/asio/steady_timer.hpp>

#include <boost/lexical_cast.hpp>

#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/iostreams/filter/zlib.hpp>

using namespace eosio::chain::plugin_interface::compat;

namespace fc {
   extern std::unordered_map<std::string,logger>& get_logger_map();
}

namespace eosio {
   static appbase::abstract_plugin& _net_plugin = app().register_plugin<net_plugin>();

   using std::vector;

   using boost::asio::ip::tcp;
   using boost::asio::ip::address_v4;
   using boost::asio::ip::host_name;
   using boost::multi_index_container;

   using fc::time_point;
   using fc::time_point_sec;
   using eosio::chain::transaction_id_type;

   class connection;

   class sync_manager;
   class dispatch_manager;

   using connection_ptr = std::shared_ptr<connection>;
   using connection_wptr = std::weak_ptr<connection>;

   using socket_ptr = std::shared_ptr<tcp::socket>;

   struct node_transaction_state {
      transaction_id_type id;
      time_point_sec  expires;  /// time after which this may be purged.
      uint32_t        block_num = 0; /// block transaction was included in
      std::shared_ptr<vector<char>>   serialized_txn; /// the received raw bundle
   };

   struct by_expiry;
   struct by_block_num;

   struct sha256_less {
      bool operator()( const sha256& lhs, const sha256& rhs ) const {
       return
             std::tie(lhs._hash[0], lhs._hash[1], lhs._hash[2], lhs._hash[3]) <
             std::tie(rhs._hash[0], rhs._hash[1], rhs._hash[2], rhs._hash[3]);
      }
   };

   typedef multi_index_container<
      node_transaction_state,
      indexed_by<
         ordered_unique<
            tag< by_id >,
            member < node_transaction_state,
                     transaction_id_type,
                     &node_transaction_state::id >,
            sha256_less >,
         ordered_non_unique<
            tag< by_expiry >,
            member< node_transaction_state,
                    fc::time_point_sec,
                    &node_transaction_state::expires >
            >,
         ordered_non_unique<
            tag<by_block_num>,
            member< node_transaction_state,
                    uint32_t,
                    &node_transaction_state::block_num > >
         >
      >
   node_transaction_index;

   struct p2p_peer_record{
        string peer_address;
        time_point_sec expiry;
        bool is_config;
        bool discoverable;
        bool connected;
   };
   class net_plugin_impl {
   private:
      std::vector<char> compress_pbft(const std::shared_ptr<std::vector<char>>& m)const;
      std::vector<char> decompress_pbft(const std::vector<char>& m)const;
      std::shared_ptr<std::vector<char>> encode_pbft_message(const net_message &msg, bool compress = false)const;
   public:
      net_plugin_impl();

      unique_ptr<tcp::acceptor>        acceptor;
      tcp::endpoint                    listen_endpoint;
      string                           p2p_address;
      string                           p2p_server_address;
      uint32_t                         max_client_count = 0;
      uint32_t                         max_nodes_per_host = 1;
      uint32_t                         num_clients = 0;

      vector<string>                   supplied_peers;
      map<string,p2p_peer_record>           p2p_peer_records;
      bool p2p_discoverable;
      bool request_p2p_flag=true;
      vector<chain::public_key_type>   allowed_peers; ///< peer keys allowed to connect
      std::map<chain::public_key_type,
               chain::private_key_type> private_keys; ///< overlapping with producer keys, also authenticating non-producing nodes

      enum possible_connections : char {
         None = 0,
            Producers = 1 << 0,
            Specified = 1 << 1,
            Any = 1 << 2
            };
      possible_connections             allowed_connections{None};

      connection_ptr find_connection(const string& host)const;

      std::set< connection_ptr >       connections;
      bool                             done = false;
      unique_ptr< sync_manager >       sync_master;
      unique_ptr< dispatch_manager >   dispatcher;

      unique_ptr<boost::asio::steady_timer> connector_check;
      unique_ptr<boost::asio::steady_timer> transaction_check;
      unique_ptr<boost::asio::steady_timer> keepalive_timer;
      unique_ptr<boost::asio::steady_timer> pbft_message_cache_timer;
      boost::asio::steady_timer::duration   connector_period;
      boost::asio::steady_timer::duration   txn_exp_period;
      boost::asio::steady_timer::duration   resp_expected_period;
      boost::asio::steady_timer::duration   keepalive_interval{std::chrono::seconds{32}};
      boost::asio::steady_timer::duration   pbft_message_cache_tick_interval{std::chrono::seconds{10}};
      int                           max_cleanup_time_ms = 0;

      const std::chrono::system_clock::duration peer_authentication_interval{std::chrono::seconds{1}}; ///< Peer clock may be no more than 1 second skewed from our clock, including network latency.

      bool                          network_version_match = false;
      chain_id_type                 chain_id;
      fc::sha256                    node_id;

      string                        user_agent_name;
      chain_plugin*                 chain_plug = nullptr;
      producer_plugin*              producer_plug = nullptr;
      int                           started_sessions = 0;

      node_transaction_index        local_txns;

      bool                          use_socket_read_watermark = false;

      std::unordered_map<string, time_point_sec> pbft_message_cache{};
      const int                     pbft_message_cache_TTL = 600;
      const int                     pbft_message_TTL = 60;

      channels::transaction_ack::channel_type::handle  incoming_transaction_ack_subscription;
      eosio::chain::plugin_interface::pbft::outgoing::prepare_channel::channel_type::handle pbft_outgoing_prepare_subscription;
      eosio::chain::plugin_interface::pbft::outgoing::commit_channel::channel_type::handle pbft_outgoing_commit_subscription;
      eosio::chain::plugin_interface::pbft::outgoing::view_change_channel::channel_type::handle pbft_outgoing_view_change_subscription;
      eosio::chain::plugin_interface::pbft::outgoing::new_view_channel::channel_type::handle pbft_outgoing_new_view_subscription;
      eosio::chain::plugin_interface::pbft::outgoing::checkpoint_channel::channel_type::handle pbft_outgoing_checkpoint_subscription;

      eosio::chain::plugin_interface::pbft::incoming::prepare_channel::channel_type& pbft_incoming_prepare_channel;
      eosio::chain::plugin_interface::pbft::incoming::commit_channel::channel_type& pbft_incoming_commit_channel;
      eosio::chain::plugin_interface::pbft::incoming::view_change_channel::channel_type& pbft_incoming_view_change_channel;
      eosio::chain::plugin_interface::pbft::incoming::new_view_channel::channel_type& pbft_incoming_new_view_channel;
      eosio::chain::plugin_interface::pbft::incoming::checkpoint_channel::channel_type& pbft_incoming_checkpoint_channel;

      void connect( const connection_ptr& c );
      void connect( const connection_ptr& c, const std::shared_ptr<tcp::resolver>& resolver, tcp::resolver::results_type endpoints );
      bool start_session(const connection_ptr& c);
      void start_listen_loop();
      void start_read_message(const connection_ptr& c);

      /** \brief Process the next message from the pending message buffer
       *
       * Process the next message from the pending_message_buffer.
       * message_length is the already determined length of the data
       * part of the message that will handle the message.
       * Returns true is successful. Returns false if an error was
       * encountered unpacking or processing the message.
       */
      bool process_next_message(const connection_ptr& conn, uint32_t message_length);

      void close(const connection_ptr& c);
      size_t count_open_sockets() const;

      template<typename VerifierFunc>
      void send_all( const std::shared_ptr<std::vector<char>>& send_buffer, VerifierFunc verify );

      void accepted_block(const block_state_ptr&);
      void transaction_ack(const std::pair<fc::exception_ptr, transaction_metadata_ptr>&);

      bool is_valid( const handshake_message &msg);


      void send_p2p_request(connection_ptr c);

      void handle_message(const connection_ptr& c, const handshake_message& msg);
      void handle_message(const connection_ptr& c, const chain_size_message& msg);
      void handle_message(const connection_ptr& c, const go_away_message& msg );

      /** \name Peer Timestamps
       *  Time message handling
       *  @{
       */
      /** \brief Process time_message
       *
       * Calculate offset, delay and dispersion.  Note carefully the
       * implied processing.  The first-order difference is done
       * directly in 64-bit arithmetic, then the result is converted
       * to floating double.  All further processing is in
       * floating-double arithmetic with rounding done by the hardware.
       * This is necessary in order to avoid overflow and preserve precision.
       */
      void handle_message(const connection_ptr& c, const time_message& msg);
      /** @} */
      void handle_message(const connection_ptr& c, const notice_message& msg);
      void handle_message(const connection_ptr& c, const request_message& msg);
      void handle_message(const connection_ptr& c, const sync_request_message& msg);
      void handle_message(const connection_ptr& c, const signed_block& msg) = delete; // signed_block_ptr overload used instead
      void handle_message(const connection_ptr& c, const signed_block_ptr& msg);
      void handle_message(const connection_ptr& c, const packed_transaction& msg) = delete; // packed_transaction_ptr overload used instead
      void handle_message(const connection_ptr& c, const packed_transaction_ptr& msg);
      void handle_message( connection_ptr c, const request_p2p_message &msg);
      void handle_message( connection_ptr c, const response_p2p_message &msg);

      //pbft messages
      bool maybe_add_to_pbft_cache(const string& key);
      void clean_expired_pbft_messages();
      template<typename M>
      bool is_pbft_msg_outdated(const M& msg);
      template<typename M>
      bool is_pbft_msg_valid(const M& msg);

      void bcast_pbft_msg(const net_message& msg, int ttl, const connection_ptr& c = nullptr);

      void pbft_outgoing_prepare(const pbft_prepare_ptr& prepare);
      void pbft_outgoing_commit(const pbft_commit_ptr& commit);
      void pbft_outgoing_view_change(const pbft_view_change_ptr& view_change);
      void pbft_outgoing_new_view(const pbft_new_view_ptr& new_view);
      void pbft_outgoing_checkpoint(const pbft_checkpoint_ptr& checkpoint);

      void handle_message( const connection_ptr& c, const pbft_prepare& msg);
      void handle_message( const connection_ptr& c, const pbft_commit& msg);
      void handle_message( const connection_ptr& c, const pbft_view_change& msg);
      void handle_message( const connection_ptr& c, const pbft_new_view& msg);
      void handle_message( const connection_ptr& c, const pbft_checkpoint& msg);
      void handle_message( const connection_ptr& c, const pbft_stable_checkpoint& msg);
      void handle_message( const connection_ptr& c, const checkpoint_request_message& msg);
      void handle_message( const connection_ptr& c, const compressed_pbft_message& msg);

      void start_conn_timer(boost::asio::steady_timer::duration du, std::weak_ptr<connection> from_connection);
      void start_txn_timer();
      void start_monitors();

      void expire_txns();
      void expire_local_txns();
      void connection_monitor(std::weak_ptr<connection> from_connection);

      void pbft_message_cache_ticker();
      /** \name Peer Timestamps
       *  Time message handling
       *  @{
       */
      /** \brief Peer heartbeat ticker.
       */
      void ticker();
      /** @} */
      /** \brief Determine if a peer is allowed to connect.
       *
       * Checks current connection mode and key authentication.
       *
       * \return False if the peer should not connect, true otherwise.
       */
      bool authenticate_peer(const handshake_message& msg) const;
      /** \brief Retrieve public key used to authenticate with peers.
       *
       * Finds a key to use for authentication.  If this node is a producer, use
       * the front of the producer key map.  If the node is not a producer but has
       * a configured private key, use it.  If the node is neither a producer nor has
       * a private key, returns an empty key.
       *
       * \note On a node with multiple private keys configured, the key with the first
       *       numerically smaller byte will always be used.
       */
      chain::public_key_type get_authentication_key() const;
      /** \brief Returns a signature of the digest using the corresponding private key of the signer.
       *
       * If there are no configured private keys, returns an empty signature.
       */
      chain::signature_type sign_compact(const chain::public_key_type& signer, const fc::sha256& digest) const;

      uint16_t to_protocol_version(uint16_t v);
   };

   const fc::string logger_name("net_plugin_impl");
   fc::logger logger;
   std::string peer_log_format;

#define peer_dlog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( logger.is_enabled( fc::log_level::debug ) ) \
      logger.log( FC_LOG_MESSAGE( debug, peer_log_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant()) ) ); \
  FC_MULTILINE_MACRO_END

#define peer_ilog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( logger.is_enabled( fc::log_level::info ) ) \
      logger.log( FC_LOG_MESSAGE( info, peer_log_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant()) ) ); \
  FC_MULTILINE_MACRO_END

#define peer_wlog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( logger.is_enabled( fc::log_level::warn ) ) \
      logger.log( FC_LOG_MESSAGE( warn, peer_log_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant()) ) ); \
  FC_MULTILINE_MACRO_END

#define peer_elog( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( logger.is_enabled( fc::log_level::error ) ) \
      logger.log( FC_LOG_MESSAGE( error, peer_log_format + FORMAT, __VA_ARGS__ (PEER->get_logger_variant())) ); \
  FC_MULTILINE_MACRO_END


   template<class enum_type, class=typename std::enable_if<std::is_enum<enum_type>::value>::type>
   inline enum_type& operator|=(enum_type& lhs, const enum_type& rhs)
   {
      using T = std::underlying_type_t <enum_type>;
      return lhs = static_cast<enum_type>(static_cast<T>(lhs) | static_cast<T>(rhs));
   }

   static net_plugin_impl *my_impl;

   /**
    * default value initializers
    */
   constexpr auto     def_send_buffer_size_mb = 4;
   constexpr auto     def_send_buffer_size = 1024*1024*def_send_buffer_size_mb;
   constexpr auto     def_max_write_queue_size = def_send_buffer_size*10;
   constexpr boost::asio::chrono::milliseconds def_read_delay_for_full_write_queue{100};
   constexpr auto     def_max_trx_in_progress_size = 100*1024*1024; // 100 MB
   constexpr auto     def_max_clients = 25; // 0 for unlimited clients
   constexpr auto     def_max_nodes_per_host = 1;
   constexpr auto     def_conn_retry_wait = 30;
   constexpr auto     def_txn_expire_wait = std::chrono::seconds(3);
   constexpr auto     def_resp_expected_wait = std::chrono::seconds(5);
   constexpr auto     def_sync_fetch_span = 100;

   constexpr auto     message_header_size = 4;

   /**
    *  For a while, network version was a 16 bit value equal to the second set of 16 bits
    *  of the current build's git commit id. We are now replacing that with an integer protocol
    *  identifier. Based on historical analysis of all git commit identifiers, the larges gap
    *  between ajacent commit id values is shown below.
    *  these numbers were found with the following commands on the master branch:
    *
    *  git log | grep "^commit" | awk '{print substr($2,5,4)}' | sort -u > sorted.txt
    *  rm -f gap.txt; prev=0; for a in $(cat sorted.txt); do echo $prev $((0x$a - 0x$prev)) $a >> gap.txt; prev=$a; done; sort -k2 -n gap.txt | tail
    *
    *  DO NOT EDIT net_version_base OR net_version_range!
    */
   constexpr uint16_t net_version_base = 0x04b5;
   constexpr uint16_t net_version_range = 106;
   /**
    *  If there is a change to network protocol or behavior, increment net version to identify
    *  the need for compatibility hooks
    */
   constexpr uint16_t proto_base = 0;
   constexpr uint16_t proto_explicit_sync = 1;

   constexpr uint16_t net_version = proto_explicit_sync;

   struct transaction_state {
      transaction_id_type id;
      uint32_t            block_num = 0; ///< the block number the transaction was included in
      time_point_sec      expires;
   };

   typedef multi_index_container<
      transaction_state,
      indexed_by<
         ordered_unique< tag<by_id>, member<transaction_state, transaction_id_type, &transaction_state::id >, sha256_less >,
         ordered_non_unique< tag< by_expiry >, member< transaction_state,fc::time_point_sec,&transaction_state::expires >>,
         ordered_non_unique<
            tag<by_block_num>,
            member< transaction_state,
                    uint32_t,
                    &transaction_state::block_num > >
         >

      > transaction_state_index;

   /**
    *
    */
   struct peer_block_state {
      block_id_type id;
      uint32_t      block_num;
      bool          is_known;
      bool          is_noticed;
      time_point    requested_time;
   };

   struct update_request_time {
      void operator() (struct eosio::peer_block_state &bs) {
         bs.requested_time = time_point::now();
      }
   } set_request_time;

   typedef multi_index_container<
      eosio::peer_block_state,
      indexed_by<
         ordered_unique< tag<by_id>, member<eosio::peer_block_state, block_id_type, &eosio::peer_block_state::id >, sha256_less >,
         ordered_unique< tag<by_block_num>, member<eosio::peer_block_state, uint32_t, &eosio::peer_block_state::block_num > >
         >
      > peer_block_state_index;


   struct update_known_by_peer {
      void operator() (eosio::peer_block_state& bs) {
         bs.is_known = true;
      }
   } set_is_known;


   struct update_block_num {
      uint32_t new_bnum;
      update_block_num(uint32_t bnum) : new_bnum(bnum) {}
      void operator() (node_transaction_state& nts) {
         nts.block_num = new_bnum;
      }
      void operator() (transaction_state& ts) {
         ts.block_num = new_bnum;
      }
      void operator() (peer_block_state& pbs) {
         pbs.block_num = new_bnum;
      }
   };

   /**
    * Index by start_block_num
    */
   struct sync_state {
      sync_state(uint32_t start = 0, uint32_t end = 0, uint32_t last_acted = 0)
         :start_block( start ), end_block( end ), last( last_acted ),
          start_time(time_point::now())
      {}
      uint32_t     start_block;
      uint32_t     end_block;
      uint32_t     last; ///< last sent or received
      time_point   start_time; ///< time request made or received
   };

   struct handshake_initializer {
      static void populate(handshake_message &hello);
   };

   class queued_buffer : boost::noncopyable {
   public:
      void clear_write_queue() {
         _write_queue.clear();
         _sync_write_queue.clear();
         _write_queue_size = 0;
      }

      void clear_out_queue() {
         while ( _out_queue.size() > 0 ) {
            _out_queue.pop_front();
         }
      }

      uint32_t write_queue_size() const { return _write_queue_size; }

      uint32_t out_queue_size() const { return _out_queue.size(); }

      bool is_out_queue_empty() const { return _out_queue.empty(); }

      bool ready_to_send() const {
         // if out_queue is not empty then async_write is in progress
         return ((!_sync_write_queue.empty() || !_write_queue.empty()) && _out_queue.empty());
      }

      bool add_write_queue( const std::shared_ptr<vector<char>>& buff,
                            std::function<void( boost::system::error_code, std::size_t )> callback,
                            bool to_sync_queue ) {
         if( to_sync_queue ) {
            _sync_write_queue.push_back( {buff, callback} );
         } else {
            _write_queue.push_back( {buff, callback} );
         }
         _write_queue_size += buff->size();
         if( _write_queue_size > 2 * def_max_write_queue_size ) {
            return false;
         }
         return true;
      }

      void fill_out_buffer( std::vector<boost::asio::const_buffer>& bufs ) {
         if( _sync_write_queue.size() > 0 ) { // always send msgs from sync_write_queue first
            fill_out_buffer( bufs, _sync_write_queue );
         } else { // postpone real_time write_queue if sync queue is not empty
            fill_out_buffer( bufs, _write_queue );
            EOS_ASSERT( _write_queue_size == 0, plugin_exception, "write queue size expected to be zero" );
         }
      }

      void out_callback( boost::system::error_code ec, std::size_t w ) {
         for( auto& m : _out_queue ) {
            m.callback( ec, w );
         }
      }

   private:
      struct queued_write;
      void fill_out_buffer( std::vector<boost::asio::const_buffer>& bufs,
                            deque<queued_write>& w_queue ) {
         while ( w_queue.size() > 0 ) {
            auto& m = w_queue.front();
            bufs.push_back( boost::asio::buffer( *m.buff ));
            _write_queue_size -= m.buff->size();
            _out_queue.emplace_back( m );
            w_queue.pop_front();
         }
      }

   private:
      struct queued_write {
         std::shared_ptr<vector<char>> buff;
         std::function<void( boost::system::error_code, std::size_t )> callback;
      };

      uint32_t _write_queue_size = 0;
      deque<queued_write> _write_queue;
      deque<queued_write> _sync_write_queue; // sync_write_queue will be sent first
      deque<queued_write> _out_queue;

   public:
       //used for pbft msgs sending only
       void push_to_out_queue( const queued_write& m) {
           _out_queue.emplace_back( m );
       }

   }; // queued_buffer


   class connection : public std::enable_shared_from_this<connection> {
   public:
      explicit connection( string endpoint );

      explicit connection( socket_ptr s );
      ~connection();
      void initialize();

      peer_block_state_index  blk_state;
      transaction_state_index trx_state;
      optional<sync_state>    peer_requested;  // this peer is requesting info from us
      socket_ptr              socket;

      fc::message_buffer<1024*1024>    pending_message_buffer;
      fc::optional<std::size_t>        outstanding_read_bytes;


      struct queued_pbft_message {
          std::shared_ptr<vector<char>> message;
          fc::time_point_sec deadline;
      };
      const int OUT_QUEUE_SIZE_LIMIT = 200;

      deque<queued_pbft_message>     pbft_queue;

      queued_buffer           buffer_queue;

      uint32_t                trx_in_progress_size = 0;
      fc::sha256              node_id;
      handshake_message       last_handshake_recv;
      handshake_message       last_handshake_sent;
      int16_t                 sent_handshake_count = 0;
      bool                    connecting = false;
      bool                    syncing = false;
      int                     connecting_timeout_in_seconds = 10;
      fc::time_point_sec      connecting_deadline;
      uint16_t                protocol_version  = 0;
      string                  peer_addr;
      unique_ptr<boost::asio::steady_timer> response_expected;
      unique_ptr<boost::asio::steady_timer> read_delay_timer;
      optional<request_message> pending_fetch;
      go_away_reason         no_retry = no_reason;
      block_id_type          fork_head;
      uint32_t               fork_head_num = 0;
      optional<request_message> last_req;

      connection_status get_status()const {
         connection_status stat;
         stat.peer = peer_addr;
         stat.connecting = connecting;
         stat.syncing = syncing;
         stat.last_handshake = last_handshake_recv;
         return stat;
      }

      /** \name Peer Timestamps
       *  Time message handling
       *  @{
       */
      // Members set from network data
      tstamp                         org{0};          //!< originate timestamp
      tstamp                         rec{0};          //!< receive timestamp
      tstamp                         dst{0};          //!< destination timestamp
      tstamp                         xmt{0};          //!< transmit timestamp

      // Computed data
      double                         offset{0};       //!< peer offset

      static const size_t            ts_buffer_size{32};
      char                           ts[ts_buffer_size];          //!< working buffer for making human readable timestamps
      /** @} */

      bool connected();
      bool current();
      bool pbft_ready();
      void reset();
      void close();
      void send_handshake();

      /** \name Peer Timestamps
       *  Time message handling
       */
      /**  \brief Populate and queue time_message
       */
      void send_time();
      /** \brief Populate and queue time_message immediately using incoming time_message
       */
      void send_time(const time_message& msg);
      /** \brief Read system time and convert to a 64 bit integer.
       *
       * There are only two calls on this routine in the program.  One
       * when a packet arrives from the network and the other when a
       * packet is placed on the send queue.  Calls the kernel time of
       * day routine and converts to a (at least) 64 bit integer.
       */
      tstamp get_time()
      {
         return std::chrono::system_clock::now().time_since_epoch().count();
      }
      /** @} */

      const string peer_name();

      void txn_send_pending(const vector<transaction_id_type>& ids);
      void txn_send(const vector<transaction_id_type>& txn_lis);

      void blk_send_branch();
      void blk_send(const block_id_type& blkid);
      void stop_send();

      void enqueue( const net_message &msg, bool trigger_send = true );
      void enqueue_block( const signed_block_ptr& sb, bool trigger_send = true, bool to_sync_queue = false );
      void enqueue_buffer( const std::shared_ptr<std::vector<char>>& send_buffer,
                           bool trigger_send, go_away_reason close_after_send,
                           bool to_sync_queue = false);
      void enqueue_pbft( const std::shared_ptr<std::vector<char>>& m, const time_point_sec deadline);

      bool pbft_read_to_send();

      void cancel_sync(go_away_reason);
      void flush_queues();
      bool enqueue_sync_block();
      void request_sync_blocks(uint32_t start, uint32_t end);

      void cancel_wait();
      void sync_wait();
      void fetch_wait();
      void sync_timeout(boost::system::error_code ec);
      void fetch_timeout(boost::system::error_code ec);

      void queue_write(const std::shared_ptr<vector<char>>& buff,
                       bool trigger_send,
                       std::function<void(boost::system::error_code, std::size_t)> callback,
                       bool to_sync_queue = false);
      void do_queue_write();
      void fill_out_buffer_with_pbft_queue(std::vector<boost::asio::const_buffer>& bufs);

      void send_p2p_request(bool discoverable);
      void send_p2p_response(bool discoverable,string p2p_peer_list);

      bool add_peer_block(const peer_block_state& pbs);

      fc::optional<fc::variant_object> _logger_variant;
      const fc::variant_object& get_logger_variant()  {
         if (!_logger_variant) {
            boost::system::error_code ec;
            auto rep = socket->remote_endpoint(ec);
            string ip = ec ? "<unknown>" : rep.address().to_string();
            string port = ec ? "<unknown>" : std::to_string(rep.port());

            auto lep = socket->local_endpoint(ec);
            string lip = ec ? "<unknown>" : lep.address().to_string();
            string lport = ec ? "<unknown>" : std::to_string(lep.port());

            _logger_variant.emplace(fc::mutable_variant_object()
               ("_name", peer_name())
               ("_id", node_id)
               ("_sid", ((string)node_id).substr(0, 7))
               ("_ip", ip)
               ("_port", port)
               ("_lip", lip)
               ("_lport", lport)
            );
         }
         return *_logger_variant;
      }
   };

   struct msg_handler : public fc::visitor<void> {
      net_plugin_impl &impl;
      connection_ptr c;
      msg_handler( net_plugin_impl &imp, const connection_ptr& conn) : impl(imp), c(conn) {}

      void operator()( const signed_block& msg ) const {
         EOS_ASSERT( false, plugin_config_exception, "operator()(signed_block&&) should be called" );
      }
      void operator()( signed_block& msg ) const {
         EOS_ASSERT( false, plugin_config_exception, "operator()(signed_block&&) should be called" );
      }
      void operator()( const packed_transaction& msg ) const {
         EOS_ASSERT( false, plugin_config_exception, "operator()(packed_transaction&&) should be called" );
      }
      void operator()( packed_transaction& msg ) const {
         EOS_ASSERT( false, plugin_config_exception, "operator()(packed_transaction&&) should be called" );
      }

      void operator()( signed_block&& msg ) const {
         impl.handle_message( c, std::make_shared<signed_block>( std::move( msg ) ) );
      }
      void operator()( packed_transaction&& msg ) const {
         impl.handle_message( c, std::make_shared<packed_transaction>( std::move( msg ) ) );
      }

      template <typename T>
      void operator()( T&& msg ) const
      {
         impl.handle_message( c, std::forward<T>(msg) );
      }
   };

   class sync_manager {
   private:
      enum stages {
         lib_catchup,
         head_catchup,
         in_sync
      };

      uint32_t       sync_known_lib_num;
      uint32_t       sync_last_requested_num;
      uint32_t       sync_next_expected_num;
      uint32_t       sync_req_span;
      uint32_t       last_req_scp_num;
      connection_ptr source;
      stages         state;

      chain_plugin* chain_plug = nullptr;

      constexpr static auto stage_str(stages s);

   public:
      explicit sync_manager(uint32_t span);
      void set_state(stages s);
      bool sync_required();
      void send_handshakes();
      bool is_active(const connection_ptr& conn);
      void reset_lib_num(const connection_ptr& conn);
      void request_next_chunk(const connection_ptr& conn = connection_ptr());
      void start_sync(const connection_ptr& c, uint32_t target);
      void reassign_fetch(const connection_ptr& c, go_away_reason reason);
      bool verify_catchup(const connection_ptr& c, uint32_t num, const block_id_type& id);
      void rejected_block(const connection_ptr& c, uint32_t blk_num);
      void recv_block(const connection_ptr& c, const block_id_type& blk_id, uint32_t blk_num);
      void recv_handshake(const connection_ptr& c, const handshake_message& msg);
      void recv_notice(const connection_ptr& c, const notice_message& msg);
      bool is_syncing();
      bool sync_stable_checkpoints(const connection_ptr& c, uint32_t target);
   };

   class dispatch_manager {
   public:
      std::multimap<block_id_type, connection_ptr, sha256_less> received_blocks;
      std::multimap<transaction_id_type, connection_ptr, sha256_less> received_transactions;

      void bcast_transaction(const transaction_metadata_ptr& trx);
      void rejected_transaction(const transaction_id_type& msg);
      void bcast_block(const block_state_ptr& bs);
      void rejected_block(const block_id_type& id);

      void recv_block(const connection_ptr& conn, const block_id_type& msg, uint32_t bnum);
      void expire_blocks( uint32_t bnum );
      void recv_transaction(const connection_ptr& conn, const transaction_id_type& id);
      void recv_notice(const connection_ptr& conn, const notice_message& msg, bool generated);

      void retry_fetch(const connection_ptr& conn);
   };

   //---------------------------------------------------------------------------

   connection::connection( string endpoint )
      : blk_state(),
        trx_state(),
        peer_requested(),
        socket( std::make_shared<tcp::socket>( std::ref(app().get_io_service()) )),
        node_id(),
        last_handshake_recv(),
        last_handshake_sent(),
        sent_handshake_count(0),
        connecting(false),
        syncing(false),
        protocol_version(0),
        peer_addr(endpoint),
        response_expected(),
        read_delay_timer(),
        pending_fetch(),
        no_retry(no_reason),
        fork_head(),
        fork_head_num(0),
        last_req()
   {
      wlog( "created connection to ${n}", ("n", endpoint) );
      initialize();
   }

   connection::connection( socket_ptr s )
      : blk_state(),
        trx_state(),
        peer_requested(),
        socket( s ),
        node_id(),
        last_handshake_recv(),
        last_handshake_sent(),
        sent_handshake_count(0),
        connecting(true),
        syncing(false),
        connecting_deadline(fc::time_point::now()+fc::seconds(connecting_timeout_in_seconds)),
        protocol_version(0),
        peer_addr(),
        response_expected(),
        read_delay_timer(),
        pending_fetch(),
        no_retry(no_reason),
        fork_head(),
        fork_head_num(0),
        last_req()
   {
      wlog( "accepted network connection" );
      initialize();
   }

   connection::~connection() {}

   void connection::initialize() {
      auto *rnd = node_id.data();
      rnd[0] = 0;
      response_expected.reset(new boost::asio::steady_timer(app().get_io_service()));
      read_delay_timer.reset(new boost::asio::steady_timer(app().get_io_service()));
   }

   bool connection::connected() {
      return (socket && socket->is_open() && !connecting);
   }

   bool connection::current() {
      return (connected() && !syncing);
   }

   bool connection::pbft_ready(){
       return current();
   }

   void connection::reset() {
      peer_requested.reset();
      blk_state.clear();
      trx_state.clear();
   }

   void connection::flush_queues() {
      buffer_queue.clear_write_queue();
      pbft_queue.clear();
   }

   void connection::close() {
      if(socket) {
         socket->close();
         socket.reset( new tcp::socket( std::ref(app().get_io_service())) );
      }
      else {
         wlog("no socket to close!");
      }
      flush_queues();
      connecting = false;
      connecting_deadline = fc::time_point::min();
      syncing = false;
      if( last_req ) {
         my_impl->dispatcher->retry_fetch(shared_from_this());
      }
      reset();
      sent_handshake_count = 0;
      trx_in_progress_size = 0;
      node_id = fc::sha256();
      last_handshake_recv = handshake_message();
      last_handshake_sent = handshake_message();
      my_impl->sync_master->reset_lib_num(shared_from_this());
      fc_ilog(logger, "closing ${a}, ${p}", ("a",peer_addr)("p",peer_name()));
      fc_dlog(logger, "canceling wait on ${p}", ("p",peer_name()));
      cancel_wait();
      if( read_delay_timer ) read_delay_timer->cancel();
   }

   void connection::txn_send_pending(const vector<transaction_id_type>& ids) {
      const std::set<transaction_id_type, sha256_less> known_ids(ids.cbegin(), ids.cend());
      my_impl->expire_local_txns();
      for(auto tx = my_impl->local_txns.begin(); tx != my_impl->local_txns.end(); ++tx ){
         const bool found = known_ids.find( tx->id ) != known_ids.cend();
         if( !found ) {
            queue_write( tx->serialized_txn, true, []( boost::system::error_code ec, std::size_t ) {} );
         }
      }
   }

   void connection::txn_send(const vector<transaction_id_type>& ids) {
      for(const auto& t : ids) {
         auto tx = my_impl->local_txns.get<by_id>().find(t);
         if( tx != my_impl->local_txns.end() ) {
            queue_write( tx->serialized_txn, true, []( boost::system::error_code ec, std::size_t ) {} );
         }
      }
   }

   void connection::blk_send_branch() {
      controller& cc = my_impl->chain_plug->chain();
      uint32_t head_num = cc.fork_db_head_block_num();
      notice_message note;
      note.known_blocks.mode = normal;
      note.known_blocks.pending = 0;
      fc_dlog(logger, "head_num = ${h}",("h",head_num));
      if(head_num == 0) {
         enqueue(note);
         return;
      }
      block_id_type head_id;
      block_id_type lib_id;
      block_id_type remote_head_id;
      uint32_t remote_head_num = 0;
      try {
         if (last_handshake_recv.generation >= 1) {
            remote_head_id = last_handshake_recv.head_id;
            remote_head_num = block_header::num_from_id(remote_head_id);
            fc_dlog(logger, "maybe truncating branch at  = ${h}:${id}",("h",remote_head_num)("id",remote_head_id));
         }

         lib_id = last_handshake_recv.last_irreversible_block_id;
         head_id = cc.fork_db_head_block_id();
      }
      catch (const assert_exception& ex) {
         elog( "unable to retrieve block info: ${n} for ${p}",("n",ex.to_string())("p",peer_name()));
         enqueue(note);
         return;
      }
      catch (const fc::exception& ex) {
      }
      catch (...) {
      }

      if( !peer_requested ) {
         peer_requested = sync_state( block_header::num_from_id(lib_id)+1,
                                      block_header::num_from_id(head_id),
                                      block_header::num_from_id(lib_id) );
      } else {
         uint32_t start = std::min( peer_requested->last + 1, block_header::num_from_id(lib_id)+1 );
         uint32_t end   = std::max( peer_requested->end_block, block_header::num_from_id(head_id) );
         peer_requested = sync_state( start, end, start - 1 );
      }

      if( peer_requested->start_block <= peer_requested->end_block ) {
         fc_dlog( logger, "enqueue ${s} - ${e}", ("s", peer_requested->start_block)( "e", peer_requested->end_block ) );
         enqueue_sync_block();
      } else {
         peer_requested.reset();
      }

      // still want to send transactions along during blk branch sync
      syncing = false;
   }

   void connection::blk_send(const block_id_type& blkid) {
      controller &cc = my_impl->chain_plug->chain();
      try {
         signed_block_ptr b = cc.fetch_block_by_id(blkid);
         if(b) {
            fc_dlog(logger,"found block for id at num ${n}",("n",b->block_num()));
            peer_block_state pbstate = {blkid, block_header::num_from_id(blkid), true, true, time_point()};
            add_peer_block(pbstate);
            enqueue_block( b );
         } else {
            ilog("fetch block by id returned null, id ${id} for ${p}",
                  ("id",blkid)("p",peer_name()));
         }
      }
      catch (const assert_exception &ex) {
         elog( "caught assert on fetch_block_by_id, ${ex}, id ${id} for ${p}",
               ("ex",ex.to_string())("id",blkid)("p",peer_name()));
      }
      catch (...) {
         elog( "caught other exception fetching block id ${id} for ${p}",
               ("id",blkid)("p",peer_name()));
      }
   }

   void connection::send_p2p_request(bool discoverable)
   {
         try
         {
               enqueue(net_message(request_p2p_message{discoverable}));
         }
         catch (...)
         {
               elog("send request_p2p_message message error");
         }
   }
   void connection::send_p2p_response(bool discoverable, string p2p_list)
   {
         try
         {
               enqueue(net_message(response_p2p_message{discoverable, p2p_list}));
         }
         catch (...)
         {
               elog("send response_p2p_message message error");
         }
   }

   void connection::stop_send() {
      syncing = false;
   }

   void connection::send_handshake() {
      handshake_initializer::populate(last_handshake_sent);
      last_handshake_sent.generation = ++sent_handshake_count;
      fc_dlog(logger, "Sending handshake generation ${g} to ${ep}",
              ("g",last_handshake_sent.generation)("ep", peer_name()));
      enqueue(last_handshake_sent);
   }

   void connection::send_time() {
      time_message xpkt;
      xpkt.org = rec;
      xpkt.rec = dst;
      xpkt.xmt = get_time();
      org = xpkt.xmt;
      enqueue(xpkt);
   }

   void connection::send_time(const time_message& msg) {
      time_message xpkt;
      xpkt.org = msg.xmt;
      xpkt.rec = msg.dst;
      xpkt.xmt = get_time();
      enqueue(xpkt);
   }

   void connection::queue_write(const std::shared_ptr<vector<char>>& buff,
                                bool trigger_send,
                                std::function<void(boost::system::error_code, std::size_t)> callback,
                                bool to_sync_queue) {
      if( !buffer_queue.add_write_queue( buff, callback, to_sync_queue )) {
         fc_wlog( logger, "write_queue full ${s} bytes, giving up on connection ${p}",
                  ("s", buffer_queue.write_queue_size())("p", peer_name()) );
         my_impl->close( shared_from_this() );
         return;
      }
      if( buffer_queue.is_out_queue_empty() && trigger_send) {
         do_queue_write();
      }
   }

   bool connection::pbft_read_to_send() {
       return !pbft_queue.empty() && buffer_queue.is_out_queue_empty();
   }

   void connection::do_queue_write() {
      if( !(buffer_queue.ready_to_send() || pbft_read_to_send()) )
          return;

      connection_wptr c(shared_from_this());
      if(!socket->is_open()) {
         fc_elog(logger,"socket not open to ${p}",("p",peer_name()));
         my_impl->close(c.lock());
         return;
      }
      std::vector<boost::asio::const_buffer> bufs;

      buffer_queue.fill_out_buffer( bufs );
      fill_out_buffer_with_pbft_queue( bufs );

      boost::asio::async_write(*socket, bufs, [c, socket=socket](boost::system::error_code ec, std::size_t w) {
            try {
               auto conn = c.lock();
               if(!conn)
                  return;

               conn->buffer_queue.out_callback( ec, w );

               if(ec) {
                  string pname = conn ? conn->peer_name() : "no connection name";
                  if( ec.value() != boost::asio::error::eof) {
                     elog("Error sending to peer ${p}: ${i}", ("p",pname)("i", ec.message()));
                  }
                  else {
                     ilog("connection closure detected on write to ${p}",("p",pname));
                  }
                  my_impl->close(conn);
                  return;
               }
               conn->buffer_queue.clear_out_queue();
               conn->enqueue_sync_block();
               conn->do_queue_write();
            }
            catch(const std::exception &ex) {
               auto conn = c.lock();
               string pname = conn ? conn->peer_name() : "no connection name";
               elog("Exception in do_queue_write to ${p} ${s}", ("p",pname)("s",ex.what()));
            }
            catch(const fc::exception &ex) {
               auto conn = c.lock();
               string pname = conn ? conn->peer_name() : "no connection name";
               elog("Exception in do_queue_write to ${p} ${s}", ("p",pname)("s",ex.to_string()));
            }
            catch(...) {
               auto conn = c.lock();
               string pname = conn ? conn->peer_name() : "no connection name";
               elog("Exception in do_queue_write to ${p}", ("p",pname) );
            }
         });
   }

    void connection::fill_out_buffer_with_pbft_queue(std::vector<boost::asio::const_buffer>& bufs){
        //delete timeout pbft message
        auto now = time_point::now();
        auto itr = pbft_queue.begin();
        while (itr != pbft_queue.end()) {
            if (itr->deadline <= now) {
                itr = pbft_queue.erase(itr);
            } else {
                ++itr;
            }
        }

        //drop timeout messages in mem, init send buffer only when actual send happens
        //copied from a previous version of  connection::enqueue
        connection_wptr weak_this = shared_from_this();
        go_away_reason close_after_send = no_reason;
        std::function<void(boost::system::error_code, std::size_t)> callback = [weak_this, close_after_send](boost::system::error_code ec, std::size_t ) {
            connection_ptr conn = weak_this.lock();
            if (conn) {
                if (close_after_send != no_reason) {
                    elog ("sent a go away message: ${r}, closing connection to ${p}",("r", reason_str(close_after_send))("p", conn->peer_name()));
                    my_impl->close(conn);
                    return;
                }
            } else {
                fc_wlog(logger, "connection expired before enqueued net_message called callback!");
            }
        };

        //push to out queue
        while (buffer_queue.out_queue_size() < OUT_QUEUE_SIZE_LIMIT) {
            if (pbft_queue.empty()) break;

            queued_pbft_message pbft = pbft_queue.front();
            pbft_queue.pop_front();
            auto m = pbft.message;
            if (m) {
                bufs.push_back(boost::asio::buffer(*m));
                buffer_queue.push_to_out_queue( {m, callback} );
            }
        }
    }

   void connection::cancel_sync(go_away_reason reason) {
      fc_dlog(logger,"cancel sync reason = ${m}, write queue size ${o} bytes peer ${p}",
              ("m",reason_str(reason)) ("o", buffer_queue.write_queue_size())("p", peer_name()));
      cancel_wait();
      flush_queues();
      switch (reason) {
      case validation :
      case fatal_other : {
         no_retry = reason;
         enqueue( go_away_message( reason ));
         break;
      }
      default:
         fc_dlog(logger, "sending empty request but not calling sync wait on ${p}", ("p",peer_name()));
         enqueue( ( sync_request_message ) {0,0} );
      }
   }

   bool connection::enqueue_sync_block() {
      if (!peer_requested)
         return false;
      uint32_t num = ++peer_requested->last;
      bool trigger_send = num == peer_requested->start_block;
      if(num == peer_requested->end_block) {
         peer_requested.reset();
      }
      try {
         controller& cc = my_impl->chain_plug->chain();
         signed_block_ptr sb = cc.fetch_block_by_number(num);
         if(sb) {
            enqueue_block( sb, trigger_send, true);
            return true;
         }
      } catch ( ... ) {
         wlog( "write loop exception" );
      }
      return false;
   }

   void connection::enqueue( const net_message& m, bool trigger_send ) {
      go_away_reason close_after_send = no_reason;
      if (m.contains<go_away_message>()) {
         close_after_send = m.get<go_away_message>().reason;
      }

      uint32_t payload_size = fc::raw::pack_size( m );

      char* header = reinterpret_cast<char*>(&payload_size);
      size_t header_size = sizeof(payload_size);
      size_t buffer_size = header_size + payload_size;

      auto send_buffer = std::make_shared<vector<char>>(buffer_size);
      fc::datastream<char*> ds( send_buffer->data(), buffer_size);
      ds.write( header, header_size );
      fc::raw::pack( ds, m );

      enqueue_buffer( send_buffer, trigger_send, close_after_send );
   }

   void connection::enqueue_block( const signed_block_ptr& sb, bool trigger_send, bool to_sync_queue ) {
      // this implementation is to avoid copy of signed_block to net_message
      int which = 7; // matches which of net_message for signed_block

      uint32_t which_size = fc::raw::pack_size( unsigned_int( which ));
      uint32_t payload_size = which_size + fc::raw::pack_size( *sb );

      char* header = reinterpret_cast<char*>(&payload_size);
      size_t header_size = sizeof(payload_size);
      size_t buffer_size = header_size + payload_size;

      auto send_buffer = std::make_shared<vector<char>>(buffer_size);
      fc::datastream<char*> ds( send_buffer->data(), buffer_size);
      ds.write( header, header_size );
      fc::raw::pack( ds, unsigned_int( which ));
      fc::raw::pack( ds, *sb );

      enqueue_buffer( send_buffer, trigger_send, no_reason, to_sync_queue );
   }

   void connection::enqueue_buffer( const std::shared_ptr<std::vector<char>>& send_buffer, bool trigger_send,
                                    go_away_reason close_after_send,
                                    bool to_sync_queue )
   {
      connection_wptr weak_this = shared_from_this();
      queue_write(send_buffer,trigger_send,
                  [weak_this, close_after_send](boost::system::error_code ec, std::size_t ) {
                     connection_ptr conn = weak_this.lock();
                     if (conn) {
                        if (close_after_send != no_reason) {
                           fc_elog( logger, "sent a go away message: ${r}, closing connection to ${p}",
                                    ("r", reason_str(close_after_send))("p", conn->peer_name()) );
                           my_impl->close(conn);
                           return;
                        }
                     } else {
                        fc_wlog(logger, "connection expired before enqueued net_message called callback!");
                     }
                  },
                  to_sync_queue);
   }

   void connection::enqueue_pbft(const std::shared_ptr<std::vector<char>>& m, const time_point_sec deadline)
   {
       pbft_queue.push_back(queued_pbft_message{m, deadline });
       if (buffer_queue.is_out_queue_empty()) {
           do_queue_write();
       }
   }

   void connection::cancel_wait() {
      if (response_expected)
         response_expected->cancel();
   }

   void connection::sync_wait() {
      response_expected->expires_from_now( my_impl->resp_expected_period);
      connection_wptr c(shared_from_this());
      response_expected->async_wait( [c]( boost::system::error_code ec){
            connection_ptr conn = c.lock();
            if (!conn) {
               // connection was destroyed before this lambda was delivered
               return;
            }

            conn->sync_timeout(ec);
         } );
   }

   void connection::fetch_wait() {
      response_expected->expires_from_now( my_impl->resp_expected_period);
      connection_wptr c(shared_from_this());
      response_expected->async_wait( [c]( boost::system::error_code ec){
            connection_ptr conn = c.lock();
            if (!conn) {
               // connection was destroyed before this lambda was delivered
               return;
            }

            conn->fetch_timeout(ec);
         } );
   }

   void connection::sync_timeout( boost::system::error_code ec ) {
      if( !ec ) {
         my_impl->sync_master->reassign_fetch(shared_from_this(), benign_other);
      }
      else if( ec == boost::asio::error::operation_aborted) {
      }
      else {
         elog("setting timer for sync request got error ${ec}",("ec", ec.message()));
      }
   }

   const string connection::peer_name() {
      if( !last_handshake_recv.p2p_address.empty() ) {
         return last_handshake_recv.p2p_address;
      }
      if( !peer_addr.empty() ) {
         return peer_addr;
      }
      if( socket != nullptr ) {
         boost::system::error_code ec;
         auto rep = socket->remote_endpoint(ec);
         if( !ec ) {
            return rep.address().to_string() + ':' + std::to_string( rep.port() );
         }
      }
      return "connecting client";
   }

   void connection::fetch_timeout( boost::system::error_code ec ) {
      if( !ec ) {
         if( pending_fetch.valid() && !( pending_fetch->req_trx.empty() || pending_fetch->req_blocks.empty() ) ) {
            my_impl->dispatcher->retry_fetch(shared_from_this());
         }
      }
      else if( ec == boost::asio::error::operation_aborted ) {
         if( !connected() ) {
            fc_dlog(logger, "fetch timeout was cancelled due to dead connection");
         }
      }
      else {
         elog( "setting timer for fetch request got error ${ec}", ("ec", ec.message() ) );
      }
   }

   void connection::request_sync_blocks(uint32_t start, uint32_t end) {
      sync_request_message srm = {start,end};
      enqueue( net_message(srm));
      sync_wait();
   }

   bool connection::add_peer_block(const peer_block_state& entry) {
      auto bptr = blk_state.get<by_id>().find(entry.id);
      bool added = (bptr == blk_state.end());
      if (added){
         blk_state.insert(entry);
      }
      else {
         blk_state.modify(bptr,set_is_known);
         if (entry.block_num == 0) {
            blk_state.modify(bptr,update_block_num(entry.block_num));
         }
         else {
            blk_state.modify(bptr,set_request_time);
         }
      }
      return added;
   }

   //-----------------------------------------------------------

    sync_manager::sync_manager( uint32_t req_span )
      :sync_known_lib_num( 0 )
      ,sync_last_requested_num( 0 )
      ,sync_next_expected_num( 1 )
      ,sync_req_span( req_span )
      ,source()
      ,state(in_sync)
   {
      chain_plug = app().find_plugin<chain_plugin>();
      EOS_ASSERT( chain_plug, chain::missing_chain_plugin_exception, ""  );
   }

   constexpr auto sync_manager::stage_str(stages s) {
    switch (s) {
    case in_sync : return "in sync";
    case lib_catchup: return "lib catchup";
    case head_catchup : return "head catchup";
    default : return "unkown";
    }
  }

   void sync_manager::set_state(stages newstate) {
      if (state == newstate) {
         return;
      }
      fc_dlog(logger, "old state ${os} becoming ${ns}",("os",stage_str(state))("ns",stage_str(newstate)));
      state = newstate;
   }

   bool sync_manager::is_active(const connection_ptr& c) {
      if (state == head_catchup && c) {
         bool fhset = c->fork_head != block_id_type();
         fc_dlog(logger, "fork_head_num = ${fn} fork_head set = ${s}",
                 ("fn", c->fork_head_num)("s", fhset));
            return c->fork_head != block_id_type() && c->fork_head_num < chain_plug->chain().fork_db_head_block_num();
      }
      return state != in_sync;
   }

   void sync_manager::reset_lib_num(const connection_ptr& c) {
      if(state == in_sync) {
         source.reset();
      }
      if( c->current() ) {
         if( c->last_handshake_recv.last_irreversible_block_num > sync_known_lib_num) {
            sync_known_lib_num =c->last_handshake_recv.last_irreversible_block_num;
         }
      } else if( c == source ) {
         sync_last_requested_num = 0;
         request_next_chunk();
      }
   }

   bool sync_manager::sync_required() {
      fc_dlog(logger, "last req = ${req}, last recv = ${recv} known = ${known} our head = ${head}",
              ("req",sync_last_requested_num)("recv",sync_next_expected_num)("known",sync_known_lib_num)("head",chain_plug->chain().fork_db_head_block_num()));

      return( sync_last_requested_num < sync_known_lib_num ||
              chain_plug->chain().fork_db_head_block_num() < sync_last_requested_num );
   }

   bool sync_manager::is_syncing() {
       return state != in_sync;
   }

   void sync_manager::request_next_chunk( const connection_ptr& conn ) {
      uint32_t head_block = chain_plug->chain().fork_db_head_block_num();

      if (head_block < sync_last_requested_num && source && source->current()) {
         fc_ilog(logger, "ignoring request, head is ${h} last req = ${r} source is ${p}",
                  ("h",head_block)("r",sync_last_requested_num)("p",source->peer_name()));
         return;
      }

      /* ----------
       * next chunk provider selection criteria
       * a provider is supplied and able to be used, use it.
       * otherwise select the next available from the list, round-robin style.
       */

      if (conn && conn->current() ) {
         source = conn;
      }
      else {
         if( my_impl->connections.size() == 0 ) {
            source.reset();
         } else if( my_impl->connections.size() == 1 ) {
            if (!source) {
               source = *my_impl->connections.begin();
            }
         } else {
            // init to a linear array search
            auto cptr = my_impl->connections.begin();
            auto cend = my_impl->connections.end();
            // do we remember the previous source?
            if( source ) {
               //try to find it in the list
               cptr = my_impl->connections.find( source );
               cend = cptr;
               if( cptr == my_impl->connections.end() ) {
                  //not there - must have been closed! cend is now connections.end, so just flatten the ring.
                  source.reset();
                  cptr = my_impl->connections.begin();
               } else {
                  //was found - advance the start to the next. cend is the old source.
                  if( ++cptr == my_impl->connections.end() && cend != my_impl->connections.end() ) {
                     cptr = my_impl->connections.begin();
                  }
               }
            }

            //scan the list of peers looking for another able to provide sync blocks.
            if( cptr != my_impl->connections.end() ) {
               auto cstart_it = cptr;
               do {
                  //select the first one which is current and break out.
                  if( (*cptr)->current() ) {
                     source = *cptr;
                     break;
                  }
                  if( ++cptr == my_impl->connections.end() )
                     cptr = my_impl->connections.begin();
               } while( cptr != cstart_it );
            }
            // no need to check the result, either source advanced or the whole list was checked and the old source is reused.
         }
      }

      // verify there is an available source
      if (!source || !source->current() ) {
         elog("Unable to continue syncing at this time");
         sync_known_lib_num = chain_plug->chain().last_irreversible_block_num();
         sync_last_requested_num = 0;
         set_state(in_sync); // probably not, but we can't do anything else
         return;
      }

      if( sync_last_requested_num != sync_known_lib_num ) {
         uint32_t start = sync_next_expected_num;
         uint32_t end = start + sync_req_span - 1;
         if( end > sync_known_lib_num )
            end = sync_known_lib_num;
         if( end > 0 && end >= start ) {
            fc_ilog(logger, "requesting range ${s} to ${e}, from ${n}",
                    ("n",source->peer_name())("s",start)("e",end));
            source->request_sync_blocks(start, end);
            sync_last_requested_num = end;
         }
      }
   }

   void sync_manager::send_handshakes()
   {
      for( auto &ci : my_impl->connections) {
         if( ci->current()) {
            ci->send_handshake();
         }
      }
   }

   void sync_manager::start_sync(const connection_ptr& c, uint32_t target) {
      if( target > sync_known_lib_num) {
         sync_known_lib_num = target;
      }

      uint32_t bnum = chain_plug->chain().last_irreversible_block_num();
      if (!sync_required() || target <= bnum) {
         uint32_t hnum = chain_plug->chain().fork_db_head_block_num();
         fc_dlog( logger, "We are already caught up, my irr = ${b}, head = ${h}, target = ${t}",
                  ("b",bnum)("h",hnum)("t",target));
         return;
      }

      if (state == in_sync) {
         set_state(lib_catchup);
         sync_next_expected_num = chain_plug->chain().last_irreversible_block_num() + 1;
      }

      fc_ilog(logger, "Catching up with chain, our last req is ${cc}, theirs is ${t} peer ${p}",
              ( "cc",sync_last_requested_num)("t",target)("p",c->peer_name()));

      request_next_chunk(c);
   }

   bool sync_manager::sync_stable_checkpoints(const connection_ptr& c, uint32_t target) {
       controller& cc = chain_plug->chain();
       uint32_t lscb_num = cc.last_stable_checkpoint_block_num();
       auto pbft_checkpoint_granularity = chain_plug->pbft_ctrl().pbft_db.get_checkpoint_interval();
       if (last_req_scp_num < lscb_num || last_req_scp_num == 0) last_req_scp_num = lscb_num;

       auto max_target_scp_num = last_req_scp_num + pbft_checkpoint_granularity * 10;
       auto end = std::min(max_target_scp_num, target);

       if (end - last_req_scp_num < pbft_checkpoint_granularity) {
           last_req_scp_num = lscb_num;
           return false;
       }
       checkpoint_request_message crm = {last_req_scp_num+1,end};
       c->enqueue( net_message(crm));
       fc_dlog(logger, "request sync stable checkpoints from ${s} to ${e}",
               ("s", last_req_scp_num+1)("e", end));
       last_req_scp_num = end;
       return true;
   }

   void sync_manager::reassign_fetch(const connection_ptr& c, go_away_reason reason) {
      fc_ilog(logger, "reassign_fetch, our last req is ${cc}, next expected is ${ne} peer ${p}",
              ( "cc",sync_last_requested_num)("ne",sync_next_expected_num)("p",c->peer_name()));

      if (c == source) {
         c->cancel_sync(reason);
         sync_last_requested_num = 0;
         request_next_chunk();
      }
   }

   void sync_manager::recv_handshake(const connection_ptr& c, const handshake_message& msg) {
      controller& cc = chain_plug->chain();
      uint32_t lib_num = cc.last_irreversible_block_num();
      uint32_t peer_lib = msg.last_irreversible_block_num;
      reset_lib_num(c);
      c->syncing = false;

      //--------------------------------
      // sync need checks; (lib == last irreversible block)
      //
      // 0. my head block id == peer head id means we are all caught up block wise
      // 1. my head block num < peer lib - start sync locally
      // 2. my lib > peer head num - send an last_irr_catch_up notice if not the first generation
      //
      // 3  my head block num < peer head block num - update sync state and send a catchup request
      // 4  my head block num >= peer block num send a notice catchup if this is not the first generation
      //    4.1 if peer appears to be on a different fork ( our_id_for( msg.head_num ) != msg.head_id )
      //        then request peer's blocks
      //
      //-----------------------------

      uint32_t head = cc.fork_db_head_block_num();
      block_id_type head_id = cc.fork_db_head_block_id();
      if (head_id == msg.head_id) {
         fc_dlog(logger, "sync check state 0");
         // notify peer of our pending transactions
         notice_message note;
         note.known_blocks.mode = none;
         note.known_trx.mode = catch_up;
         note.known_trx.pending = my_impl->local_txns.size();
         c->enqueue( note );
         return;
      }
      if (head < peer_lib) {
         fc_dlog(logger, "sync check state 1");
         // wait for receipt of a notice message before initiating sync
         if (c->protocol_version < proto_explicit_sync) {
            start_sync( c, peer_lib);
         }
         return;
      }
      if (lib_num > msg.head_num ) {
         fc_dlog(logger, "sync check state 2");
         if (msg.generation > 1 || c->protocol_version > proto_base) {
            notice_message note;
            note.known_trx.pending = lib_num;
            note.known_trx.mode = last_irr_catch_up;
            note.known_blocks.mode = last_irr_catch_up;
            note.known_blocks.pending = head;
            c->enqueue( note );
         }
         c->syncing = true;
         return;
      }

      if (head < msg.head_num ) {
         fc_dlog(logger, "sync check state 3");
         verify_catchup(c, msg.head_num, msg.head_id);
         return;
      }
      else {
         fc_dlog(logger, "sync check state 4");
         if (msg.generation > 1 ||  c->protocol_version > proto_base) {
            notice_message note;
            note.known_trx.mode = none;
            note.known_blocks.mode = catch_up;
            note.known_blocks.pending = head;
            note.known_blocks.ids.push_back(head_id);
            c->enqueue( note );
         }
         c->syncing = true;
         bool on_fork = true;
         try {
            on_fork = cc.get_block_id_for_num( msg.head_num ) != msg.head_id;
         } catch( ... ) {}
         if( on_fork ) {
            request_message req;
            req.req_blocks.mode = catch_up;
            req.req_trx.mode = none;
            c->enqueue( req );
         }
         return;
      }
      elog("sync check failed to resolve status");
   }

   bool sync_manager::verify_catchup(const connection_ptr& c, uint32_t num, const block_id_type& id) {
      request_message req;
      req.req_blocks.mode = catch_up;
      for (const auto& cc : my_impl->connections) {
         if (cc->fork_head == id ||
             cc->fork_head_num > num) {
            req.req_blocks.mode = none;
            break;
         }
      }
      if( req.req_blocks.mode == catch_up ) {
         ilog("got a catch_up notice while in ${s}, fork head num = ${fhn} target LIB = ${lib} next_expected = ${ne}",
               ("s",stage_str(state))("fhn",num)("lib",sync_known_lib_num)("ne", sync_next_expected_num));
         if (state == lib_catchup)
            return false;
         set_state(head_catchup);
         c->fork_head = id;
         c->fork_head_num = num;
      }
      else {
         c->fork_head = block_id_type();
         c->fork_head_num = 0;
      }
      req.req_trx.mode = none;
      c->enqueue( req );
      return true;
   }

   void sync_manager::recv_notice(const connection_ptr& c, const notice_message& msg) {
      fc_ilog(logger, "sync_manager got ${m} block notice",("m",modes_str(msg.known_blocks.mode)));
      if( msg.known_blocks.ids.size() > 1 ) {
         elog( "Invalid notice_message, known_blocks.ids.size ${s}", ("s", msg.known_blocks.ids.size()) );
         my_impl->close(c);
         return;
      }
      if (msg.known_blocks.mode == catch_up) {
         if (msg.known_blocks.ids.size() == 0) {
            elog("got a catch up with ids size = 0");
         } else {
            const block_id_type& id = msg.known_blocks.ids.back();
            controller& cc = chain_plug->chain();
            if( !cc.fetch_block_by_id( id ) ) {
               verify_catchup( c, msg.known_blocks.pending, id );
            } else {
               // we already have the block, so update peer with our view of the world
               c->send_handshake();
            }
         }
      }
      else {
         c->last_handshake_recv.last_irreversible_block_num = msg.known_trx.pending;
         reset_lib_num(c);
         start_sync(c, msg.known_trx.pending);
      }
   }

   void sync_manager::rejected_block(const connection_ptr& c, uint32_t blk_num) {
      if (state != in_sync ) {
         fc_wlog( logger, "block ${bn} not accepted from ${p}, closing connection", ("bn",blk_num)("p",c->peer_name()) );
         sync_last_requested_num = 0;
         source.reset();
         my_impl->close(c);
         set_state(in_sync);
         send_handshakes();
      }
   }
   void sync_manager::recv_block(const connection_ptr& c, const block_id_type& blk_id, uint32_t blk_num) {
      fc_dlog(logger, "got block ${bn} from ${p}",("bn",blk_num)("p",c->peer_name()));
      if (state == lib_catchup) {
         if (blk_num != sync_next_expected_num) {
            fc_wlog( logger, "expected block ${ne} but got ${bn}, from connection: ${p}",
                     ("ne",sync_next_expected_num)("bn",blk_num)("p",c->peer_name()) );
            return;
         }
         sync_next_expected_num = blk_num + 1;
      }
      if (state == head_catchup) {
         fc_dlog(logger, "sync_manager in head_catchup state");
         set_state(in_sync);
         source.reset();

         block_id_type null_id;
         for (const auto& cp : my_impl->connections) {
            if (cp->fork_head == null_id) {
               continue;
            }
            if (cp->fork_head == blk_id || cp->fork_head_num < blk_num) {
               c->fork_head = null_id;
               c->fork_head_num = 0;
            }
            else {
               set_state(head_catchup);
            }
         }

         if (state == in_sync) {
            send_handshakes();
         }
      }
      else if (state == lib_catchup) {
         if( blk_num == sync_known_lib_num ) {
            fc_dlog( logger, "All caught up with last known last irreversible block resending handshake");
            set_state(in_sync);
            send_handshakes();
         }
         else if (blk_num == sync_last_requested_num) {
            request_next_chunk();
         }
         else {
            fc_dlog(logger,"calling sync_wait on connection ${p}",("p",c->peer_name()));
            c->sync_wait();
         }
      }
   }

   //------------------------------------------------------------------------

   void dispatch_manager::bcast_block(const block_state_ptr& bs) {
      std::set<connection_ptr> skips;
      auto range = received_blocks.equal_range(bs->id);
      for (auto org = range.first; org != range.second; ++org) {
         skips.insert(org->second);
      }
      received_blocks.erase(range.first, range.second);

      block_id_type bid = bs->id;
      uint32_t bnum = bs->block_num;
      peer_block_state pbstate = {bid, bnum, false, true, time_point()};

      pbstate.is_known = true;
      for( auto& cp : my_impl->connections ) {
         if( skips.find( cp ) != skips.end() || !cp->current() ) {
            continue;
         }
         bool has_block = cp->last_handshake_recv.last_irreversible_block_num >= bnum;
         if( !has_block ) {
            fc_dlog(logger, "bcast block ${b} to ${p}", ("b", bnum)("p", cp->peer_name()));
            cp->add_peer_block( pbstate );
            cp->enqueue_block( bs->block );
         }
      }

   }

   void dispatch_manager::recv_block(const connection_ptr& c, const block_id_type& id, uint32_t bnum) {
      received_blocks.insert(std::make_pair(id, c));
      if (c &&
          c->last_req &&
          c->last_req->req_blocks.mode != none &&
          !c->last_req->req_blocks.ids.empty() &&
          c->last_req->req_blocks.ids.back() == id) {
         c->last_req.reset();
      }
      c->add_peer_block({id, bnum, false,true,time_point()});

      fc_dlog(logger, "canceling wait on ${p}", ("p",c->peer_name()));
      c->cancel_wait();
   }

   void dispatch_manager::rejected_block(const block_id_type& id) {
      fc_dlog( logger, "rejected block ${id}", ("id", id) );
      auto range = received_blocks.equal_range(id);
      received_blocks.erase(range.first, range.second);
   }

   void dispatch_manager::expire_blocks( uint32_t lib_num ) {
      for( auto i = received_blocks.begin(); i != received_blocks.end(); ) {
         const block_id_type& blk_id = i->first;
         uint32_t blk_num = block_header::num_from_id( blk_id );
         if( blk_num <= lib_num ) {
            i = received_blocks.erase( i );
         } else {
            ++i;
         }
      }
   }

   void dispatch_manager::bcast_transaction(const transaction_metadata_ptr& ptrx) {
      std::set<connection_ptr> skips;
      const auto& id = ptrx->id;

      auto range = received_transactions.equal_range(id);
      for (auto org = range.first; org != range.second; ++org) {
         skips.insert(org->second);
      }
      received_transactions.erase(range.first, range.second);

      if( my_impl->local_txns.get<by_id>().find( id ) != my_impl->local_txns.end() ) { //found
         fc_dlog(logger, "found trxid in local_trxs" );
         return;
      }

      time_point_sec trx_expiration = ptrx->packed_trx->expiration();
      const packed_transaction& trx = *ptrx->packed_trx;

      // this implementation is to avoid copy of packed_transaction to net_message
      int which = 8; // matches which of net_message for packed_transaction

      uint32_t which_size = fc::raw::pack_size( unsigned_int( which ));
      uint32_t payload_size = which_size + fc::raw::pack_size( trx );

      char* header = reinterpret_cast<char*>(&payload_size);
      size_t header_size = sizeof(payload_size);
      size_t buffer_size = header_size + payload_size;

      auto buff = std::make_shared<vector<char>>(buffer_size);
      fc::datastream<char*> ds( buff->data(), buffer_size);
      ds.write( header, header_size );
      fc::raw::pack( ds, unsigned_int( which ));
      fc::raw::pack( ds, trx );

      node_transaction_state nts = {id, trx_expiration, 0, buff};
      my_impl->local_txns.insert(std::move(nts));

      my_impl->send_all( buff, [&id, &skips, trx_expiration](const connection_ptr& c) -> bool {
         if( skips.find(c) != skips.end() || c->syncing ) {
            return false;
          }
          const auto& bs = c->trx_state.find(id);
          bool unknown = bs == c->trx_state.end();
          if( unknown ) {
             c->trx_state.insert(transaction_state({id,0,trx_expiration}));
             fc_dlog(logger, "sending trx to ${n}", ("n",c->peer_name() ) );
          }
          return unknown;
      });

   }

   void dispatch_manager::recv_transaction(const connection_ptr& c, const transaction_id_type& id) {
      received_transactions.insert(std::make_pair(id, c));
      if (c &&
          c->last_req &&
          c->last_req->req_trx.mode != none &&
          !c->last_req->req_trx.ids.empty() &&
          c->last_req->req_trx.ids.back() == id) {
         c->last_req.reset();
      }

      fc_dlog(logger, "canceling wait on ${p}", ("p",c->peer_name()));
      c->cancel_wait();
   }

   void dispatch_manager::rejected_transaction(const transaction_id_type& id) {
      fc_dlog(logger,"not sending rejected transaction ${tid}",("tid",id));
      auto range = received_transactions.equal_range(id);
      received_transactions.erase(range.first, range.second);
   }

   void dispatch_manager::recv_notice(const connection_ptr& c, const notice_message& msg, bool generated) {
      request_message req;
      req.req_trx.mode = none;
      req.req_blocks.mode = none;
      bool send_req = false;
      if (msg.known_trx.mode == normal) {
         req.req_trx.mode = normal;
         req.req_trx.pending = 0;
         send_req = false;
      }
      else if (msg.known_trx.mode != none) {
         elog("passed a notice_message with something other than a normal on none known_trx");
         return;
      }
      if (msg.known_blocks.mode == normal) {
         req.req_blocks.mode = normal;
         controller& cc = my_impl->chain_plug->chain();
         // known_blocks.ids is never > 1
         if( !msg.known_blocks.ids.empty() ) {
            const block_id_type& blkid = msg.known_blocks.ids.back();
            signed_block_ptr b;
            peer_block_state entry = {blkid,0,true,true,fc::time_point()};
            try {
               b = cc.fetch_block_by_id(blkid);
               if(b)
                  entry.block_num = b->block_num();
            } catch (const assert_exception &ex) {
               ilog( "caught assert on fetch_block_by_id, ${ex}",("ex",ex.what()));
               // keep going, client can ask another peer
            } catch (...) {
               elog( "failed to retrieve block for id");
            }
            if (!b) {
               send_req = true;
               req.req_blocks.ids.push_back( blkid );
               entry.requested_time = fc::time_point::now();
            }
            c->add_peer_block(entry);
         }
      }
      else if (msg.known_blocks.mode != none) {
         elog("passed a notice_message with something other than a normal on none known_blocks");
         return;
      }
      fc_dlog( logger, "send req = ${sr}", ("sr",send_req));
      if( send_req) {
         c->enqueue(req);
         c->fetch_wait();
         c->last_req = std::move(req);
      }
   }

   void dispatch_manager::retry_fetch(const connection_ptr& c) {
      if (!c->last_req) {
         return;
      }
      fc_wlog( logger, "failed to fetch from ${p}",("p",c->peer_name()));
      transaction_id_type tid;
      block_id_type bid;
      bool is_txn = false;
      if( c->last_req->req_trx.mode == normal && !c->last_req->req_trx.ids.empty() ) {
         is_txn = true;
         tid = c->last_req->req_trx.ids.back();
      }
      else if( c->last_req->req_blocks.mode == normal && !c->last_req->req_blocks.ids.empty() ) {
         bid = c->last_req->req_blocks.ids.back();
      }
      else {
         fc_wlog( logger,"no retry, block mpde = ${b} trx mode = ${t}",
                  ("b",modes_str(c->last_req->req_blocks.mode))("t",modes_str(c->last_req->req_trx.mode)));
         return;
      }
      for (auto& conn : my_impl->connections) {
         if (conn == c || conn->last_req) {
            continue;
         }
         bool sendit = false;
         if (is_txn) {
            auto trx = conn->trx_state.get<by_id>().find(tid);
            sendit = trx != conn->trx_state.end();
         }
         else {
            auto blk = conn->blk_state.get<by_id>().find(bid);
            sendit = blk != conn->blk_state.end() && blk->is_known;
         }
         if (sendit) {
            conn->enqueue(*c->last_req);
            conn->fetch_wait();
            conn->last_req = c->last_req;
            return;
         }
      }

      // at this point no other peer has it, re-request or do nothing?
      if( c->connected() ) {
         c->enqueue(*c->last_req);
         c->fetch_wait();
      }
   }

   //------------------------------------------------------------------------

   namespace bio = boost::iostreams;
   template<size_t Limit>
   struct read_limiter {
      using char_type = char;
      using category = bio::multichar_output_filter_tag;

      template<typename Sink>
      size_t write(Sink &sink, const char* s, size_t count)
      {
         EOS_ASSERT(_total + count <= Limit, tx_decompression_error, "Exceeded maximum decompressed transaction size");
         _total += count;
         return bio::write(sink, s, count);
      }
      size_t _total = 0;
   };

   std::vector<char> net_plugin_impl::compress_pbft(const std::shared_ptr<std::vector<char>>& m) const {
      std::vector<char> out;
      bio::filtering_ostream comp;
      comp.push(bio::zlib_compressor(bio::zlib::best_compression));
      comp.push(bio::back_inserter(out));
      bio::write(comp, m->data(), m->size());
      bio::close(comp);
      return out;
   }

   std::vector<char> net_plugin_impl::decompress_pbft(const std::vector<char>& m) const {
      try {
         std::vector<char> out;
         bio::filtering_ostream decomp;
         decomp.push(bio::zlib_decompressor());
         decomp.push(read_limiter<1*1024*1024>()); // limit to 10 megs decompressed for zip bomb protections
         decomp.push(bio::back_inserter(out));
         bio::write(decomp, m.data(), m.size());
         bio::close(decomp);
         return out;
      } catch( fc::exception& er ) {
         throw;
      } catch( ... ) {
         fc::unhandled_exception er( FC_LOG_MESSAGE( warn, "internal decompression error"), std::current_exception() );
         throw er;
      }
   }

   std::shared_ptr<std::vector<char>> net_plugin_impl::encode_pbft_message(const net_message &msg, bool compress) const {

       uint32_t payload_size = fc::raw::pack_size( msg );

       char* header = reinterpret_cast<char*>(&payload_size);
       size_t header_size = sizeof(payload_size);
       size_t buffer_size = header_size + payload_size;

       auto send_buffer = std::make_shared<vector<char>>(buffer_size);
       fc::datastream<char*> ds( send_buffer->data(), buffer_size);
       ds.write( header, header_size );
       fc::raw::pack( ds, msg );
       auto out_buffer = send_buffer;

       if (compress) {
           auto cpnv = compressed_pbft_message{ compress_pbft(send_buffer) };
           payload_size = fc::raw::pack_size( cpnv );

           header = reinterpret_cast<char*>(&payload_size);
           header_size = sizeof(payload_size);
           buffer_size = header_size + payload_size;

           auto compressed_buffer = std::make_shared<vector<char>>(buffer_size);
           fc::datastream<char*> ds( compressed_buffer->data(), buffer_size);
           ds.write( header, header_size );
           fc::raw::pack( ds, &cpnv );
           out_buffer = compressed_buffer;
       }
       return out_buffer;
   }

   void net_plugin_impl::connect(const connection_ptr& c) {
      if( c->no_retry != go_away_reason::no_reason) {
         fc_dlog( logger, "Skipping connect due to go_away reason ${r}",("r", reason_str( c->no_retry )));
         return;
      }

      auto colon = c->peer_addr.find(':');

      if (colon == std::string::npos || colon == 0) {
         elog("Invalid peer address. must be \"host:port\": ${p}", ("p",c->peer_addr));
         for ( auto itr : connections ) {
            if((*itr).peer_addr == c->peer_addr) {
               (*itr).reset();
               close(itr);
               connections.erase(itr);
               break;
            }
         }
         return;
      }

      auto host = c->peer_addr.substr( 0, colon );
      auto port = c->peer_addr.substr( colon + 1);
      idump((host)(port));
      tcp::resolver::query query( tcp::v4(), host.c_str(), port.c_str() );
      connection_wptr weak_conn = c;
      // Note: need to add support for IPv6 too

      auto resolver = std::make_shared<tcp::resolver>( std::ref(app().get_io_service()) );
      resolver->async_resolve( query,
                [weak_conn, resolver, this]( const boost::system::error_code& err, tcp::resolver::results_type endpoints ) {
                      auto c = weak_conn.lock();
                      if( !c ) return;
                      if( !err ) {
                         connect( c, resolver, endpoints );
                      } else {
                         elog( "Unable to resolve ${peer_addr}: ${error}",
                                  ("peer_addr", c->peer_name())( "error", err.message()) );
                      }
                   } );
   }

   void net_plugin_impl::connect( const connection_ptr& c, const std::shared_ptr<tcp::resolver>& resolver, tcp::resolver::results_type endpoints ) {
      if( c->no_retry != go_away_reason::no_reason) {
         string rsn = reason_str(c->no_retry);
         return;
      }
      c->connecting = true;
      c->pending_message_buffer.reset();
      c->connecting_deadline = fc::time_point::now()+fc::seconds(c->connecting_timeout_in_seconds);
      c->buffer_queue.clear_out_queue();
      connection_wptr weak_conn = c;
      boost::asio::async_connect( *c->socket, endpoints,
              [weak_conn, resolver, socket=c->socket, this]( const boost::system::error_code& err, const tcp::endpoint& endpoint ) {
            auto c = weak_conn.lock();
            if( !c ) return;
            if( !err && c->socket->is_open()) {
               if( start_session( c )) {
                  c->send_handshake();
                  send_p2p_request(c);
               }
            } else {
               elog( "connection failed to ${peer}: ${error}", ("peer", c->peer_name())( "error", err.message()) );
               c->connecting = false;
               my_impl->close( c );
            }
         } );
   }

   void net_plugin_impl::send_p2p_request(connection_ptr c)
   {
         if (p2p_discoverable && request_p2p_flag)
         {
               auto peer_record = p2p_peer_records.find(c->peer_addr);
               if (peer_record != p2p_peer_records.end())
               {
                     if (peer_record->second.is_config && !peer_record->second.connected)
                     {
                           c->send_p2p_request(p2p_discoverable);
                           peer_record->second.connected = true;
                     }
                     else
                     {
                           bool stop_flag = true;
                           for (auto record : p2p_peer_records)
                           {
                                 if (record.second.is_config && !( record.second.connected||record.second.expiry < time_point::now()))
                                 {
                                       stop_flag = false;
                                       break;
                                 }
                           }
                           if (stop_flag)
                           {
                                 request_p2p_flag = false;
                           }
                     }
               }
         }
   }

   bool net_plugin_impl::start_session(const connection_ptr& con) {
      boost::asio::ip::tcp::no_delay nodelay( true );
      boost::system::error_code ec;
      con->socket->set_option( nodelay, ec );
      if (ec) {
         elog( "connection failed to ${peer}: ${error}",
               ( "peer", con->peer_name())("error",ec.message()));
         con->connecting = false;
         close(con);
         return false;
      }
      else {
         start_read_message( con );
         ++started_sessions;
         return true;
         // for now, we can just use the application main loop.
         //     con->readloop_complete  = bf::async( [=](){ read_loop( con ); } );
         //     con->writeloop_complete = bf::async( [=](){ write_loop con ); } );
      }
   }


   void net_plugin_impl::start_listen_loop() {
      auto socket = std::make_shared<tcp::socket>( std::ref( app().get_io_service() ) );
      acceptor->async_accept( *socket, [socket,this]( boost::system::error_code ec ) {
            if( !ec ) {
               uint32_t visitors = 0;
               uint32_t from_addr = 0;
               boost::system::error_code rec;
               auto paddr = socket->remote_endpoint(rec).address();
               if (rec) {
                  fc_elog(logger,"Error getting remote endpoint: ${m}",("m", rec.message()));
               }
               else {
                  for (auto &conn : connections) {
                     if(conn->socket->is_open()) {
                        if (conn->peer_addr.empty()) {
                           visitors++;
                           boost::system::error_code ec;
                           if (paddr == conn->socket->remote_endpoint(ec).address()) {
                              from_addr++;
                           }
                        }
                     }
                  }
                  if (num_clients != visitors) {
                     fc_ilog( logger,"checking max client, visitors = ${v} num clients ${n}",("v",visitors)("n",num_clients) );
                     num_clients = visitors;
                  }
                  if( from_addr < max_nodes_per_host && (max_client_count == 0 || num_clients < max_client_count )) {
                     ++num_clients;
                     connection_ptr c = std::make_shared<connection>( socket );
                     connections.insert( c );
                     start_session( c );

                  }
                  else {
                     if (from_addr >= max_nodes_per_host) {
                        fc_elog(logger, "Number of connections (${n}) from ${ra} exceeds limit",
                                ("n", from_addr+1)("ra",paddr.to_string()));
                     }
                     else {
                        fc_elog(logger, "Error max_client_count ${m} exceeded",
                                ( "m", max_client_count) );
                     }
                     socket->close();
                  }
               }
            } else {
               fc_elog( logger, "Error accepting connection: ${m}",( "m", ec.message() ) );
               // For the listed error codes below, recall start_listen_loop()
               switch (ec.value()) {
                  case ECONNABORTED:
                  case EMFILE:
                  case ENFILE:
                  case ENOBUFS:
                  case ENOMEM:
                  case EPROTO:
                     break;
                  default:
                     return;
               }
            }
            start_listen_loop();
         });
   }

   void net_plugin_impl::start_read_message(const connection_ptr& conn) {

      try {
         if(!conn->socket) {
            return;
         }
         connection_wptr weak_conn = conn;

         std::size_t minimum_read = conn->outstanding_read_bytes ? *conn->outstanding_read_bytes : message_header_size;

         if (use_socket_read_watermark) {
            const size_t max_socket_read_watermark = 4096;
            std::size_t socket_read_watermark = std::min<std::size_t>(minimum_read, max_socket_read_watermark);
            boost::asio::socket_base::receive_low_watermark read_watermark_opt(socket_read_watermark);
            conn->socket->set_option(read_watermark_opt);
         }

         auto completion_handler = [minimum_read](boost::system::error_code ec, std::size_t bytes_transferred) -> std::size_t {
            if (ec || bytes_transferred >= minimum_read ) {
               return 0;
            } else {
               return minimum_read - bytes_transferred;
            }
         };

         if( conn->buffer_queue.write_queue_size() > def_max_write_queue_size ||
             conn->trx_in_progress_size > def_max_trx_in_progress_size )
         {
            // too much queued up, reschedule
            if( conn->buffer_queue.write_queue_size() > def_max_write_queue_size ) {
               peer_wlog( conn, "write_queue full ${s} bytes", ("s", conn->buffer_queue.write_queue_size()) );
            } else {
               peer_wlog( conn, "max trx in progress ${s} bytes", ("s", conn->trx_in_progress_size) );
            }
            if( conn->buffer_queue.write_queue_size() > 2*def_max_write_queue_size ||
                conn->trx_in_progress_size > 2*def_max_trx_in_progress_size )
            {
               fc_elog( logger, "queues over full, giving up on connection ${p}", ("p", conn->peer_name()) );
               fc_elog( logger, "  write_queue ${s} bytes", ("s", conn->buffer_queue.write_queue_size()) );
               fc_elog( logger, "  max trx in progress ${s} bytes", ("s", conn->trx_in_progress_size) );
               my_impl->close( conn );
               return;
            }
            if( !conn->read_delay_timer ) return;
            conn->read_delay_timer->expires_from_now( def_read_delay_for_full_write_queue );
            conn->read_delay_timer->async_wait( [this, weak_conn]( boost::system::error_code ec ) {
                  auto conn = weak_conn.lock();
                  if( !conn ) return;
                  if( !ec ) {
                     start_read_message( conn );
                  } else {
                     fc_elog( logger, "Read delay timer error: ${e}, closing connection: ${p}",
                              ("e", ec.message())("p",conn->peer_name()) );
                     close( conn );
                  }
            } );
            return;
         }

         boost::asio::async_read(*conn->socket,
            conn->pending_message_buffer.get_buffer_sequence_for_boost_async_read(), completion_handler, 
            [this,weak_conn,socket=conn->socket]( boost::system::error_code ec, std::size_t bytes_transferred ) {
               auto conn = weak_conn.lock();
               if (!conn || !conn->socket || !conn->socket->is_open() || !socket->is_open()) {
                  return;
               }

               conn->outstanding_read_bytes.reset();

               try {
                  if( !ec ) {
                     if (bytes_transferred > conn->pending_message_buffer.bytes_to_write()) {
                        fc_elog( logger,"async_read_some callback: bytes_transfered = ${bt}, buffer.bytes_to_write = ${btw}",
                                 ("bt",bytes_transferred)("btw",conn->pending_message_buffer.bytes_to_write()) );
                     }
                     EOS_ASSERT(bytes_transferred <= conn->pending_message_buffer.bytes_to_write(), plugin_exception, "");
                     conn->pending_message_buffer.advance_write_ptr(bytes_transferred);
                     while (conn->pending_message_buffer.bytes_to_read() > 0) {
                        uint32_t bytes_in_buffer = conn->pending_message_buffer.bytes_to_read();

                        if (bytes_in_buffer < message_header_size) {
                           conn->outstanding_read_bytes.emplace(message_header_size - bytes_in_buffer);
                           break;
                        } else {
                           uint32_t message_length;
                           auto index = conn->pending_message_buffer.read_index();
                           conn->pending_message_buffer.peek(&message_length, sizeof(message_length), index);
                           if(message_length > def_send_buffer_size*2 || message_length == 0) {
                              boost::system::error_code ec;
                              elog("incoming message length unexpected (${i}), from ${p}",
                                    ("i", message_length)("p",boost::lexical_cast<std::string>(conn->socket->remote_endpoint(ec))));
                              close(conn);
                              return;
                           }

                           auto total_message_bytes = message_length + message_header_size;

                           if (bytes_in_buffer >= total_message_bytes) {
                              conn->pending_message_buffer.advance_read_ptr(message_header_size);
                              if (!process_next_message(conn, message_length)) {
                                 return;
                              }
                           } else {
                              auto outstanding_message_bytes = total_message_bytes - bytes_in_buffer;
                              auto available_buffer_bytes = conn->pending_message_buffer.bytes_to_write();
                              if (outstanding_message_bytes > available_buffer_bytes) {
                                 conn->pending_message_buffer.add_space( outstanding_message_bytes - available_buffer_bytes );
                              }

                              conn->outstanding_read_bytes.emplace(outstanding_message_bytes);
                              break;
                           }
                        }
                     }
                     start_read_message(conn);
                  } else {
                     auto pname = conn->peer_name();
                     if (ec.value() != boost::asio::error::eof) {
                        fc_elog( logger, "Error reading message from ${p}: ${m}",("p",pname)( "m", ec.message() ) );
                     } else {
                        fc_ilog( logger, "Peer ${p} closed connection",("p",pname) );
                     }
                     close( conn );
                  }
               }
               catch(const std::exception &ex) {
                  fc_elog( logger, "Exception in handling read data from ${p}: ${s}",
                           ("p",conn->peer_name())("s",ex.what()) );
                  close( conn );
               }
               catch(const fc::exception &ex) {
                  fc_elog( logger, "Exception in handling read data from ${p}: ${s}",
                           ("p",conn->peer_name())("s",ex.to_string()) );
                  close( conn );
               }
               catch (...) {
                  fc_elog( logger, "Undefined exception handling the read data from ${p}",( "p",conn->peer_name()) );
                  close( conn );
               }
            });
      } catch (...) {
         string pname = conn ? conn->peer_name() : "no connection name";
         fc_elog( logger, "Undefined exception handling reading ${p}",("p",pname) );
         close( conn );
      }
   }

   bool net_plugin_impl::process_next_message(const connection_ptr& conn, uint32_t message_length) {
      try {
         auto ds = conn->pending_message_buffer.create_datastream();
         net_message msg;
         fc::raw::unpack( ds, msg );
         msg_handler m( *this, conn );
         if( msg.contains<signed_block>() ) {
            m( std::move( msg.get<signed_block>() ) );
         } else if( msg.contains<packed_transaction>() ) {
            m( std::move( msg.get<packed_transaction>() ) );
         } else {
            msg.visit( m );
         }
      } catch( const fc::exception& e ) {
         fc_elog( logger, "Exception in handling message from ${p}: ${s}",
                  ("p", conn->peer_name())("s", e.to_detail_string()) );
         close( conn );
         return false;
      }
      return true;
   }

   size_t net_plugin_impl::count_open_sockets() const
   {
      size_t count = 0;
      for( auto &c : connections) {
         if(c->socket->is_open())
            ++count;
      }
      return count;
   }


   template<typename VerifierFunc>
   void net_plugin_impl::send_all(const std::shared_ptr<std::vector<char>>& send_buffer, VerifierFunc verify) {
      for( auto &c : connections) {
         if( c->current() && verify( c )) {
            c->enqueue_buffer( send_buffer, true, no_reason );
         }
      }
   }

   bool net_plugin_impl::is_valid(const handshake_message& msg) {
      // Do some basic validation of an incoming handshake_message, so things
      // that really aren't handshake messages can be quickly discarded without
      // affecting state.
      bool valid = true;
      if (msg.last_irreversible_block_num > msg.head_num) {
         fc_wlog( logger, "Handshake message validation: last irreversible block (${i}) is greater than head block (${h})",
                  ("i", msg.last_irreversible_block_num)("h", msg.head_num) );
         valid = false;
      }
      if (msg.p2p_address.empty()) {
         fc_wlog( logger, "Handshake message validation: p2p_address is null string" );
         valid = false;
      }
      if (msg.os.empty()) {
         fc_wlog( logger, "Handshake message validation: os field is null string" );
         valid = false;
      }
      if ((msg.sig != chain::signature_type() || msg.token != sha256()) && (msg.token != fc::sha256::hash(msg.time))) {
         fc_wlog( logger, "Handshake message validation: token field invalid" );
         valid = false;
      }
      return valid;
   }

   void net_plugin_impl::handle_message(const connection_ptr& c, const chain_size_message& msg) {
      peer_ilog(c, "received chain_size_message");
   }


   void net_plugin_impl::handle_message( connection_ptr c, const request_p2p_message &msg){
      peer_ilog(c, "received request_p2p_message");
      string rspm;
      for(auto sd :p2p_peer_records){
            if(sd.second.discoverable){
                  rspm.append(sd.second.peer_address+"#");
            }
      }
      if(p2p_discoverable||rspm.size()>0){
            c->send_p2p_response(p2p_discoverable,rspm);
      }
   }

   void net_plugin_impl::handle_message( connection_ptr c, const response_p2p_message &msg){
      peer_ilog(c, "received response_p2p_message");
      auto peer_record=p2p_peer_records.find(c->peer_addr);
      if(peer_record!=p2p_peer_records.end()){
      peer_record->second.discoverable=msg.discoverable;
      if (peer_record->second.is_config&&msg.p2p_peer_list.length()>0){

            vector<string> p2p_peer_list;
            int start = 0;
            string delim="#";
            int idx = msg.p2p_peer_list.find(delim, start);
            string peer_list;
            while( idx != std::string::npos )
            {
                  if(max_nodes_per_host<=connections.size()||max_nodes_per_host<=p2p_peer_records.size()){
                        return;
                  }
                  peer_list=msg.p2p_peer_list.substr(start, idx-start);
                  if(peer_list.size()<3){
                        break;
                  }
                  start = idx+delim.size();
                  idx = msg.p2p_peer_list.find(delim, start);
                  if( find_connection( peer_list ))
                  continue;
                  p2p_peer_record p2prcd;
                  p2prcd.peer_address=peer_list;
                  p2prcd.discoverable=false;
                  p2prcd.is_config=true;
                  p2prcd.connected=false;
                  p2p_peer_records.insert(pair<string,p2p_peer_record>(peer_list,p2prcd));
                  connection_ptr c = std::make_shared<connection>(peer_list);
                  fc_dlog(logger,"adding new connection to the list");
                  connections.insert( c );
              }}}
   }


   void net_plugin_impl::handle_message(const connection_ptr& c, const handshake_message& msg) {
      peer_ilog(c, "received handshake_message");
      if (!is_valid(msg)) {
         peer_elog( c, "bad handshake message");
         c->enqueue( go_away_message( fatal_other ));
         return;
      }
      controller& cc = chain_plug->chain();
      uint32_t lib_num = cc.last_irreversible_block_num();
      uint32_t peer_lib = msg.last_irreversible_block_num;
      if( c->connecting ) {
         c->connecting = false;
      }
      if (msg.generation == 1) {
         if( msg.node_id == node_id) {
            fc_elog( logger, "Self connection detected. Closing connection" );
            c->enqueue( go_away_message( self ) );
            return;
         }

         if( c->peer_addr.empty() || c->last_handshake_recv.node_id == fc::sha256()) {
            fc_dlog(logger, "checking for duplicate" );
            for(const auto &check : connections) {
               if(check == c)
                  continue;
               if(check->connected() && check->peer_name() == msg.p2p_address) {
                  // It's possible that both peers could arrive here at relatively the same time, so
                  // we need to avoid the case where they would both tell a different connection to go away.
                  // Using the sum of the initial handshake times of the two connections, we will
                  // arbitrarily (but consistently between the two peers) keep one of them.
                  if (msg.time + c->last_handshake_sent.time <= check->last_handshake_sent.time + check->last_handshake_recv.time)
                     continue;

                  fc_dlog( logger, "sending go_away duplicate to ${ep}", ("ep",msg.p2p_address) );
                  go_away_message gam(duplicate);
                  gam.node_id = node_id;
                  c->enqueue(gam);
                  c->no_retry = duplicate;
                  return;
               }
            }
         }
         else {
            fc_dlog(logger, "skipping duplicate check, addr == ${pa}, id = ${ni}",("pa",c->peer_addr)("ni",c->last_handshake_recv.node_id));
         }

         if( msg.chain_id != chain_id) {
            elog( "Peer on a different chain. Closing connection");
            c->enqueue( go_away_message(go_away_reason::wrong_chain) );
            return;
         }
         c->protocol_version = to_protocol_version(msg.network_version);
         if(c->protocol_version != net_version) {
            if (network_version_match) {
               elog("Peer network version does not match expected ${nv} but got ${mnv}",
                    ("nv", net_version)("mnv", c->protocol_version));
               c->enqueue(go_away_message(wrong_version));
               return;
            } else {
               ilog("Local network version: ${nv} Remote version: ${mnv}",
                    ("nv", net_version)("mnv", c->protocol_version));
            }
         }

         if(  c->node_id != msg.node_id) {
            c->node_id = msg.node_id;
         }

         if(!authenticate_peer(msg)) {
            elog("Peer not authenticated.  Closing connection.");
            c->enqueue(go_away_message(authentication));
            return;
         }

         bool on_fork = false;
         fc_dlog(logger, "lib_num = ${ln} peer_lib = ${pl}",("ln",lib_num)("pl",peer_lib));

         if( peer_lib <= lib_num && peer_lib > 0) {
            try {
               block_id_type peer_lib_id =  cc.get_block_id_for_num( peer_lib);
               on_fork =( msg.last_irreversible_block_id != peer_lib_id);
            }
            catch( const unknown_block_exception &ex) {
               wlog( "peer last irreversible block ${pl} is unknown", ("pl", peer_lib));
               on_fork = true;
            }
            catch( ...) {
               wlog( "caught an exception getting block id for ${pl}",("pl",peer_lib));
               on_fork = true;
            }
            if( on_fork) {
               elog( "Peer chain is forked");
               c->enqueue( go_away_message( forked ));
               return;
            }
         }

         if (c->sent_handshake_count == 0) {
            c->send_handshake();
         }
      }

      c->last_handshake_recv = msg;
      c->_logger_variant.reset();
      sync_master->recv_handshake(c,msg);
   }

   void net_plugin_impl::handle_message(const connection_ptr& c, const go_away_message& msg) {
      peer_wlog(c, "received go_away_message, reason = ${r}", ("r",reason_str( msg.reason )) );
      c->no_retry = msg.reason;
      if(msg.reason == duplicate ) {
         c->node_id = msg.node_id;
      }
      c->flush_queues();
      close(c);
   }

   void net_plugin_impl::handle_message(const connection_ptr& c, const time_message& msg) {
      peer_ilog(c, "received time_message");
      /* We've already lost however many microseconds it took to dispatch
       * the message, but it can't be helped.
       */
      msg.dst = c->get_time();

      // If the transmit timestamp is zero, the peer is horribly broken.
      if(msg.xmt == 0)
         return;                 /* invalid timestamp */

      if(msg.xmt == c->xmt)
         return;                 /* duplicate packet */

      c->xmt = msg.xmt;
      c->rec = msg.rec;
      c->dst = msg.dst;

      if(msg.org == 0)
         {
            c->send_time(msg);
            return;  // We don't have enough data to perform the calculation yet.
         }

      c->offset = (double(c->rec - c->org) + double(msg.xmt - c->dst)) / 2;
      double NsecPerUsec{1000};

      if(logger.is_enabled(fc::log_level::all))
         logger.log(FC_LOG_MESSAGE(all, "Clock offset is ${o}ns (${us}us)", ("o", c->offset)("us", c->offset/NsecPerUsec)));
      c->org = 0;
      c->rec = 0;
   }

   void net_plugin_impl::handle_message(const connection_ptr& c, const notice_message& msg) {
      // peer tells us about one or more blocks or txns. When done syncing, forward on
      // notices of previously unknown blocks or txns,
      //
      peer_ilog(c, "received notice_message");
      c->connecting = false;
      request_message req;
      bool send_req = false;
      if (msg.known_trx.mode != none) {
         fc_dlog(logger,"this is a ${m} notice with ${n} transactions", ("m",modes_str(msg.known_trx.mode))("n",msg.known_trx.pending));
      }
      switch (msg.known_trx.mode) {
      case none:
         break;
      case last_irr_catch_up: {
         c->last_handshake_recv.head_num = msg.known_trx.pending;
         req.req_trx.mode = none;
         break;
      }
      case catch_up : {
         if( msg.known_trx.pending > 0) {
            // plan to get all except what we already know about.
            req.req_trx.mode = catch_up;
            send_req = true;
            size_t known_sum = local_txns.size();
            if( known_sum ) {
               for( const auto& t : local_txns.get<by_id>() ) {
                  req.req_trx.ids.push_back( t.id );
               }
            }
         }
         break;
      }
      case normal: {
         dispatcher->recv_notice(c, msg, false);
      }
      }

      if (msg.known_blocks.mode != none) {
         fc_dlog(logger,"this is a ${m} notice with ${n} blocks", ("m",modes_str(msg.known_blocks.mode))("n",msg.known_blocks.pending));
      }
      switch (msg.known_blocks.mode) {
      case none : {
         break;
      }
      case last_irr_catch_up:
      case catch_up: {
         sync_master->recv_notice(c,msg);
         break;
      }
      case normal : {
         dispatcher->recv_notice(c, msg, false);
         break;
      }
      default: {
         peer_elog(c, "bad notice_message : invalid known_blocks.mode ${m}",("m",static_cast<uint32_t>(msg.known_blocks.mode)));
      }
      }
      fc_dlog(logger, "send req = ${sr}", ("sr",send_req));
      if( send_req) {
         c->enqueue(req);
      }
   }

   void net_plugin_impl::handle_message(const connection_ptr& c, const request_message& msg) {
//      if( msg.req_blocks.ids.size() > 1 ) {
//         elog( "Invalid request_message, req_blocks.ids.size ${s}", ("s", msg.req_blocks.ids.size()) );
//         close(c);
//         return;
//      }  // we should enable requesting multiple blocks

      switch (msg.req_blocks.mode) {
      case catch_up :
         peer_ilog(c,  "received request_message:catch_up");
         c->blk_send_branch();
         break;
      case normal :
         peer_ilog(c, "received request_message:normal");
         if( !msg.req_blocks.ids.empty() ) {
            fc_dlog( logger, "received request_message, sending ${num} blocks from my node", ("num", msg.req_blocks.ids.size()));
            for (auto const &bid: msg.req_blocks.ids) {
                c->blk_send(bid);
            }
         }
         break;
      default:;
      }


      switch (msg.req_trx.mode) {
      case catch_up :
         c->txn_send_pending(msg.req_trx.ids);
         break;
      case normal :
         c->txn_send(msg.req_trx.ids);
         break;
      case none :
         if(msg.req_blocks.mode == none)
            c->stop_send();
         break;
      default:;
      }

   }

   void net_plugin_impl::handle_message(const connection_ptr& c, const sync_request_message& msg) {
      if( msg.end_block == 0) {
         c->peer_requested.reset();
         c->flush_queues();
      } else {
         c->peer_requested = sync_state( msg.start_block,msg.end_block,msg.start_block-1);
         c->enqueue_sync_block();
      }
   }

   size_t calc_trx_size( const packed_transaction_ptr& trx ) {
      // transaction is stored packed and unpacked, double packed_size and size of signed as an approximation of use
      return (trx->get_packed_transaction().size() * 2 + sizeof(trx->get_signed_transaction())) * 2 +
             trx->get_packed_context_free_data().size() * 4 +
             trx->get_signatures().size() * sizeof(signature_type);
   }

   void net_plugin_impl::handle_message( const connection_ptr& c, const checkpoint_request_message &msg) {

       if ( msg.end_block == 0 || msg.end_block < msg.start_block) return;

       fc_dlog(logger, "received checkpoint request message ${m}, from ${p}", ("m", msg)("p", c->peer_name()));

       if ( msg.end_block - msg.start_block > chain_plug->pbft_ctrl().pbft_db.get_checkpoint_interval() * 100) {
           fc_dlog(logger, "request range too large");
           return;
       }

       vector<pbft_stable_checkpoint> scp_stack;
       controller& cc = my_impl->chain_plug->chain();
       pbft_controller& pcc = my_impl->chain_plug->pbft_ctrl();

       auto end_block = std::min(msg.end_block, cc.last_stable_checkpoint_block_num());

       for (auto i = end_block; i >= msg.start_block && i > 0; --i) {
           try {
               auto bid = cc.get_block_id_for_num(i);
               auto scp = pcc.pbft_db.get_stable_checkpoint_by_id(bid);
               if (!scp.empty()) {
                   scp_stack.push_back(scp);
               }
           } catch (...) {
               break;
           }
       }

       if (!scp_stack.empty()) fc_dlog(logger, "sending ${n} stable checkpoints on my node",("n",scp_stack.size()));

       while (scp_stack.size()) {
           c->enqueue(scp_stack.back());
           scp_stack.pop_back();
       }
   }

   void net_plugin_impl::handle_message(const connection_ptr& c, const packed_transaction_ptr& trx) {
      fc_dlog(logger, "got a packed transaction, cancel wait");
      peer_ilog(c, "received packed_transaction");
      controller& cc = my_impl->chain_plug->chain();
      if( cc.get_read_mode() == eosio::db_read_mode::READ_ONLY ) {
         fc_dlog(logger, "got a txn in read-only mode - dropping");
         return;
      }
      if( sync_master->is_active(c) ) {
         fc_dlog(logger, "got a txn during sync - dropping");
         return;
      }

      auto ptrx = std::make_shared<transaction_metadata>( trx );
      const auto& tid = ptrx->id;

      if(local_txns.get<by_id>().find(tid) != local_txns.end()) {
         fc_dlog(logger, "got a duplicate transaction - dropping");
         return;
      }
      dispatcher->recv_transaction(c, tid);
      c->trx_in_progress_size += calc_trx_size( ptrx->packed_trx );
      chain_plug->accept_transaction(ptrx, [c, this, ptrx](const static_variant<fc::exception_ptr, transaction_trace_ptr>& result) {
         c->trx_in_progress_size -= calc_trx_size( ptrx->packed_trx );
         if (result.contains<fc::exception_ptr>()) {
            peer_dlog(c, "bad packed_transaction : ${m}", ("m",result.get<fc::exception_ptr>()->what()));
         } else {
            auto trace = result.get<transaction_trace_ptr>();
            if (!trace->except) {
               fc_dlog(logger, "chain accepted transaction");
               this->dispatcher->bcast_transaction(ptrx);
               return;
            }

            peer_elog(c, "bad packed_transaction : ${m}", ("m",trace->except->what()));
         }

         dispatcher->rejected_transaction(ptrx->id);
      });
   }

   void net_plugin_impl::handle_message(const connection_ptr& c, const signed_block_ptr& msg) {
      controller &cc = chain_plug->chain();
      block_id_type blk_id = msg->id();
      uint32_t blk_num = msg->block_num();
      fc_dlog(logger, "canceling wait on ${p}", ("p",c->peer_name()));
      c->cancel_wait();

      auto accept_pbft_stable_checkpoint = [&]() {
          auto &pcc = chain_plug->pbft_ctrl();
          auto scp = pcc.pbft_db.fetch_stable_checkpoint_from_blk_extn(msg);

          if (!scp.empty() && scp.block_info.block_num() > cc.last_stable_checkpoint_block_num()) {
              if (pcc.pbft_db.get_stable_checkpoint_by_id(msg->id(), false).empty()) {
                  handle_message(c, scp);
              } else {
                  pcc.pbft_db.checkpoint_local();
              }
          }
      };

      try {
         if( cc.fetch_block_by_id(blk_id)) {
            sync_master->recv_block(c, blk_id, blk_num);
            accept_pbft_stable_checkpoint();
            return;
         }
      } catch( ...) {
         // should this even be caught?
         fc_elog( logger,"Caught an unknown exception trying to recall blockID" );
      }

      dispatcher->recv_block(c, blk_id, blk_num);
      fc::microseconds age( fc::time_point::now() - msg->timestamp);
      peer_ilog(c, "received signed_block : #${n} block age in secs = ${age}",
              ("n",blk_num)("age",age.to_seconds()));

      go_away_reason reason = fatal_other;
      try {
         chain_plug->accept_block(msg); //, sync_master->is_active(c));
         accept_pbft_stable_checkpoint();
         reason = no_reason;
      } catch( const unlinkable_block_exception &ex) {
         peer_elog(c, "bad signed_block : ${m}", ("m",ex.what()));
         reason = unlinkable;
      } catch( const block_validate_exception &ex) {
         peer_elog(c, "bad signed_block : ${m}", ("m",ex.what()));
         elog( "block_validate_exception accept block #${n} syncing from ${p}",("n",blk_num)("p",c->peer_name()));
         reason = validation;
      } catch( const assert_exception &ex) {
         peer_elog(c, "bad signed_block : ${m}", ("m",ex.what()));
         elog( "unable to accept block on assert exception ${n} from ${p}",("n",ex.to_string())("p",c->peer_name()));
      } catch( const fc::exception &ex) {
         peer_elog(c, "bad signed_block : ${m}", ("m",ex.what()));
         elog( "accept_block threw a non-assert exception ${x} from ${p}",( "x",ex.to_string())("p",c->peer_name()));
         reason = no_reason;
      } catch( ...) {
         peer_elog(c, "bad signed_block : unknown exception");
         elog( "handle sync block caught something else from ${p}",("num",blk_num)("p",c->peer_name()));
      }

      update_block_num ubn(blk_num);
      if( reason == no_reason ) {
         for (const auto &recpt : msg->transactions) {
            auto id = (recpt.trx.which() == 0) ? recpt.trx.get<transaction_id_type>() : recpt.trx.get<packed_transaction>().id();
            auto ltx = local_txns.get<by_id>().find(id);
            if( ltx != local_txns.end()) {
               local_txns.modify( ltx, ubn );
            }
            auto ctx = c->trx_state.get<by_id>().find(id);
            if( ctx != c->trx_state.end()) {
               c->trx_state.modify( ctx, ubn );
            }
         }
         sync_master->recv_block(c, blk_id, blk_num);
      }
      else {
         sync_master->rejected_block(c, blk_num);
         dispatcher->rejected_block( blk_id );
      }
   }


    template<typename M>
    bool net_plugin_impl::is_pbft_msg_outdated(M const & msg) {
        if (time_point_sec(time_point::now()) > time_point_sec(msg.common.timestamp) + pbft_message_TTL) {
            fc_dlog( logger, "received an outdated pbft message ${m}", ("m", msg));
            return true;
        }
        return false;
    }

    template<typename M>
    bool net_plugin_impl::is_pbft_msg_valid(M const & msg) {
        // Do some basic validations of an incoming pbft msg, bad msgs should be quickly discarded without affecting state.
        return  !is_pbft_msg_outdated(msg)
                && !sync_master->is_syncing();
    }

    void net_plugin_impl::bcast_pbft_msg(const net_message &msg, int ttl, const connection_ptr& c) {
//        if (sync_master->is_syncing()) return;

        auto deadline = time_point_sec(time_point::now()) + ttl;

        for (auto &conn: connections) {
            if (conn != c && conn->pbft_ready()) {
                conn->enqueue_pbft(encode_pbft_message(msg), deadline);
            }
        }
    }

    void net_plugin_impl::pbft_outgoing_prepare(const pbft_prepare_ptr& msg) {
        if (maybe_add_to_pbft_cache(std::string(msg->sender_signature))) {
            bcast_pbft_msg(*msg, pbft_message_TTL);
            fc_dlog(logger, "sent prepare at height: ${n}, view: ${v} ",
                    ("n", msg->block_info.block_num())("v", msg->view));
        }
    }

    void net_plugin_impl::pbft_outgoing_commit(const pbft_commit_ptr& msg) {
        if (maybe_add_to_pbft_cache(std::string(msg->sender_signature))) {
            bcast_pbft_msg(*msg, pbft_message_TTL);
            fc_dlog(logger, "sent commit at height: ${n}, view: ${v} ",
                    ("n", msg->block_info.block_num())("v", msg->view));
        }
    }

    void net_plugin_impl::pbft_outgoing_view_change(const pbft_view_change_ptr& msg) {
        if (maybe_add_to_pbft_cache(std::string(msg->sender_signature))) {
            bcast_pbft_msg(*msg, pbft_message_TTL);
            fc_dlog(logger, "sent view change {cv: ${cv}, tv: ${tv}}",
                    ("cv", msg->current_view)("tv", msg->target_view));
        }
    }

    void net_plugin_impl::pbft_outgoing_new_view(const pbft_new_view_ptr& msg) {
        if (maybe_add_to_pbft_cache(std::string(msg->sender_signature))) {
            bcast_pbft_msg(*msg, 60 * pbft_message_TTL);
            fc_dlog( logger, "sent new view at view: ${v} ", ("v", msg->new_view));
        }

    }

    void net_plugin_impl::pbft_outgoing_checkpoint(const pbft_checkpoint_ptr& msg) {
        if (maybe_add_to_pbft_cache(std::string(msg->sender_signature))) {
            bcast_pbft_msg(*msg, pbft_message_TTL);
            fc_dlog(logger, "sent checkpoint at height: ${n} ", ("n", msg->block_info.block_num()));
        }
    }

    bool net_plugin_impl::maybe_add_to_pbft_cache(const string &key){
       auto itr = pbft_message_cache.find(key);
       if (itr == pbft_message_cache.end()) {
           //add to cache
           pbft_message_cache[key] = time_point_sec(time_point::now()) + pbft_message_cache_TTL;
           return true;
       }
       return false;
    }

    void net_plugin_impl::clean_expired_pbft_messages(){
       pbft_message_cache_ticker();

       auto itr = pbft_message_cache.begin();
       auto now = time_point::now();

       while (itr != pbft_message_cache.end()) {
           if (itr->second <= now) {
               itr = pbft_message_cache.erase(itr);
           } else
               itr++;
       }
    }

    void net_plugin_impl::handle_message( const connection_ptr& c, const pbft_prepare &msg) {
       if (is_pbft_msg_valid(msg) && maybe_add_to_pbft_cache(std::string(msg.sender_signature))) {
           auto pmm = pbft_message_metadata<pbft_prepare>(msg, chain_id);

           pmm.get_sender_key(my_impl->chain_plug->chain().get_thread_pool(), chain_id);
           pbft_controller &pcc = my_impl->chain_plug->pbft_ctrl();
		   auto sender_key = pmm.sender_key.get();

		   if (!pcc.pbft_db.is_valid_prepare(pmm.msg, sender_key)) return;

           bcast_pbft_msg(pmm.msg, pbft_message_TTL, c);
           fc_dlog(logger, "received prepare at height: ${n}, view: ${v}, from ${k}, ",
                   ("n", pmm.msg.block_info.block_num())("v", pmm.msg.view)("k", sender_key));

           pbft_incoming_prepare_channel.publish(std::make_shared<pbft_message_metadata<pbft_prepare>>(std::move(pmm)));
       }

    }

    void net_plugin_impl::handle_message( const connection_ptr& c, const pbft_commit &msg) {
       if (is_pbft_msg_valid(msg) && maybe_add_to_pbft_cache(std::string(msg.sender_signature))) {
           auto pmm = pbft_message_metadata<pbft_commit>(msg, chain_id);

		   pmm.get_sender_key(my_impl->chain_plug->chain().get_thread_pool(), chain_id);
		   pbft_controller &pcc = my_impl->chain_plug->pbft_ctrl();
		   auto sender_key = pmm.sender_key.get();

		   if (!pcc.pbft_db.is_valid_commit(pmm.msg, sender_key)) return;

           bcast_pbft_msg(pmm.msg, pbft_message_TTL, c);
           fc_dlog(logger, "received commit at height: ${n}, view: ${v}, from ${k}, ",
                   ("n", pmm.msg.block_info.block_num())("v", pmm.msg.view)("k", sender_key));

           pbft_incoming_commit_channel.publish(std::make_shared<pbft_message_metadata<pbft_commit>>(std::move(pmm)));
       }
    }

    void net_plugin_impl::handle_message( const connection_ptr& c, const pbft_view_change &msg) {
       if (is_pbft_msg_valid(msg) && maybe_add_to_pbft_cache(std::string(msg.sender_signature))) {
           auto pmm = pbft_message_metadata<pbft_view_change>(msg, chain_id);

		   pmm.get_sender_key(my_impl->chain_plug->chain().get_thread_pool(), chain_id);
		   pbft_controller &pcc = my_impl->chain_plug->pbft_ctrl();
           controller &ctrl = my_impl->chain_plug->chain();
		   auto sender_key = pmm.sender_key.get();

		   if (!pcc.pbft_db.is_valid_view_change(pmm.msg, sender_key)) return;

           auto missing_blocks = set<block_id_type>{};
           for (auto const b: pmm.msg.prepared_cert.pre_prepares) {
               if (!ctrl.fetch_block_by_id(b)) missing_blocks.emplace(b);
           }

           if (!missing_blocks.empty()) {
               fc_dlog(logger, "requesting ${num} missing blocks from view change", ("num", missing_blocks.size()));
					wlog("requesting ${num} missing blocks from view change", ("num", missing_blocks.size()));
					request_message req;
               for (auto const &b: missing_blocks) {
                   req.req_blocks.ids.push_back(b);
               }
               req.req_trx.mode = normal;
               req.req_blocks.mode = normal;
               c->enqueue(req);
           }

           bcast_pbft_msg(pmm.msg, pbft_message_TTL, c);
           fc_dlog(logger, "received view change {cv: ${cv}, tv: ${tv}} from ${v}",
                   ("cv", pmm.msg.current_view)("tv", pmm.msg.target_view)("v", sender_key));

           pbft_incoming_view_change_channel.publish(std::make_shared<pbft_message_metadata<pbft_view_change>>(std::move(pmm)));
       }
    }

    void net_plugin_impl::handle_message( const connection_ptr& c, const pbft_new_view &msg) {

       if (maybe_add_to_pbft_cache(std::string(msg.sender_signature))) {

           pbft_controller &pcc = my_impl->chain_plug->pbft_ctrl();

           if (time_point_sec(time_point::now()) > time_point_sec(msg.common.timestamp) + 60 * pbft_message_TTL
               || msg.new_view <= pcc.state_machine.get_current_view()) {
               //skip new view messages that are too old or whose target views are lower than mine.
               return;
           }

           auto pmm = pbft_message_metadata<pbft_new_view>(msg, chain_id);
		   pmm.get_sender_key(my_impl->chain_plug->chain().get_thread_pool(), chain_id);

		   auto sender_key = pmm.sender_key.get();

		   if (sender_key != pcc.pbft_db.get_new_view_primary_key(pmm.msg.new_view)) return;

           bcast_pbft_msg(pmm.msg, 60 * pbft_message_TTL, c);
           fc_dlog(logger, "received new view: ${n}, from ${v}", ("n", pmm.msg)("v", sender_key));

           pbft_incoming_new_view_channel.publish(std::make_shared<pbft_message_metadata<pbft_new_view>>(std::move(pmm)));
       }
    }

    void net_plugin_impl::handle_message( const connection_ptr& c, const compressed_pbft_message &msg) {

        auto decompressed_msg = decompress_pbft(msg.content);

        net_message message;
        fc::datastream<const char *> ds(decompressed_msg.data(), decompressed_msg.size());
        fc::raw::unpack(ds, message);

        try {
            msg_handler m(*this, c);
            message.visit( m );
        } catch(  const fc::exception& e ) {
            edump((e.to_detail_string() ));
        }
    }

    void net_plugin_impl::handle_message( const connection_ptr& c, const pbft_checkpoint &msg) {
       if (is_pbft_msg_valid(msg) && maybe_add_to_pbft_cache(std::string(msg.sender_signature))) {
           auto pmm = pbft_message_metadata<pbft_checkpoint>(msg, chain_id);

		   pmm.get_sender_key(my_impl->chain_plug->chain().get_thread_pool(), chain_id);
		   pbft_controller &pcc = my_impl->chain_plug->pbft_ctrl();
		   auto sender_key = pmm.sender_key.get();

		   if (!pcc.pbft_db.is_valid_checkpoint(pmm.msg, sender_key)) return;

           bcast_pbft_msg(pmm.msg, pbft_message_TTL, c);
           fc_dlog(logger, "received checkpoint at ${n}, from ${v}",
                   ("n", pmm.msg.block_info.block_num())("v", sender_key));

           pbft_incoming_checkpoint_channel.publish(std::make_shared<pbft_message_metadata<pbft_checkpoint>>(std::move(pmm)));
       }
    }

    void net_plugin_impl::handle_message( const connection_ptr& c, const pbft_stable_checkpoint &msg) {

       pbft_controller &pcc = my_impl->chain_plug->pbft_ctrl();

       if (!pcc.pbft_db.is_valid_stable_checkpoint(msg, true)) return;
       fc_ilog(logger, "received stable checkpoint at ${n}, from ${v}",
               ("n", msg.block_info.block_num())("v", c->peer_name()));
    }

   void net_plugin_impl::start_conn_timer(boost::asio::steady_timer::duration du, std::weak_ptr<connection> from_connection) {
      connector_check->expires_from_now( du);
      connector_check->async_wait( [this, from_connection](boost::system::error_code ec) {
            if( !ec) {
               connection_monitor(from_connection);
            }
            else {
               elog( "Error from connection check monitor: ${m}",( "m", ec.message()));
               start_conn_timer( connector_period, std::weak_ptr<connection>());
            }
         });
   }

   void net_plugin_impl::start_txn_timer() {
      transaction_check->expires_from_now( txn_exp_period);
      transaction_check->async_wait( [this](boost::system::error_code ec) {
            if( !ec) {
               expire_txns();
            }
            else {
               elog( "Error from transaction check monitor: ${m}",( "m", ec.message()));
               start_txn_timer();
            }
         });
   }

   void net_plugin_impl::pbft_message_cache_ticker() {
      pbft_message_cache_timer->expires_from_now (pbft_message_cache_tick_interval);
      pbft_message_cache_timer->async_wait ([this](boost::system::error_code ec) {

         if ( !ec ) {
            clean_expired_pbft_messages();
         } else {
            wlog ("pbft message cache ticker error: ${m}", ("m", ec.message()));
            pbft_message_cache_ticker();
         }
      });
    }

   void net_plugin_impl::ticker() {
      keepalive_timer->expires_from_now(keepalive_interval);
      keepalive_timer->async_wait([this](boost::system::error_code ec) {
            ticker();
            if (ec) {
               wlog("Peer keepalive ticked sooner than expected: ${m}", ("m", ec.message()));
            }
            for (auto &c : connections ) {
               if (c->socket->is_open()) {
                  c->send_time();
               }
            }
         });
   }

   void net_plugin_impl::start_monitors() {
      connector_check.reset(new boost::asio::steady_timer( app().get_io_service()));
      transaction_check.reset(new boost::asio::steady_timer( app().get_io_service()));
      start_conn_timer(connector_period, std::weak_ptr<connection>());
      start_txn_timer();
   }

   void net_plugin_impl::expire_txns() {
      start_txn_timer();

      auto now = time_point::now();
      auto start_size = local_txns.size();

      expire_local_txns();

      controller& cc = chain_plug->chain();
      uint32_t lib = cc.last_irreversible_block_num();
      dispatcher->expire_blocks( lib );
      for ( auto &c : connections ) {
         auto &stale_txn = c->trx_state.get<by_block_num>();
         stale_txn.erase( stale_txn.lower_bound(1), stale_txn.upper_bound(lib) );
         auto &stale_txn_e = c->trx_state.get<by_expiry>();
         stale_txn_e.erase(stale_txn_e.lower_bound(time_point_sec()), stale_txn_e.upper_bound(time_point::now()));
         auto &stale_blk = c->blk_state.get<by_block_num>();
         stale_blk.erase( stale_blk.lower_bound(1), stale_blk.upper_bound(lib) );
      }
      fc_dlog(logger, "expire_txns ${n}us size ${s} removed ${r}",
            ("n", time_point::now() - now)("s", start_size)("r", start_size - local_txns.size()) );
   }

   void net_plugin_impl::expire_local_txns() {
      auto& old = local_txns.get<by_expiry>();
      auto ex_lo = old.lower_bound( fc::time_point_sec(0) );
      auto ex_up = old.upper_bound( time_point::now() );
      old.erase( ex_lo, ex_up );

      auto& stale = local_txns.get<by_block_num>();
      controller& cc = chain_plug->chain();
      uint32_t lib = cc.last_irreversible_block_num();
      stale.erase( stale.lower_bound(1), stale.upper_bound(lib) );
   }

   void net_plugin_impl::connection_monitor(std::weak_ptr<connection> from_connection) {
      auto max_time = fc::time_point::now();
      max_time += fc::milliseconds(max_cleanup_time_ms);
      auto from = from_connection.lock();
      auto it = (from ? connections.find(from) : connections.begin());
      if (it == connections.end()) it = connections.begin();
      while (it != connections.end()) {
         if (fc::time_point::now() >= max_time) {
            start_conn_timer(std::chrono::milliseconds(1), *it); // avoid exhausting
            return;
         }
         if( !(*it)->socket->is_open() && !(*it)->connecting) {
            if( (*it)->peer_addr.length() > 0) {
               connect(*it);
            }
            else {
               it = connections.erase(it);
               continue;
            }
         }else if((*it)->connecting && (*it)->connecting_deadline < fc::time_point::now()){
             if( (*it)->peer_addr.length() > 0) {
                 close(*it);
             }
             else {
                 it = connections.erase(it);
                 continue;
             }
         }
         ++it;
      }
      start_conn_timer(connector_period, std::weak_ptr<connection>());
   }

   void net_plugin_impl::close(const connection_ptr& c) {
      if( c->peer_addr.empty() && c->socket->is_open() ) {
         if (num_clients == 0) {
            fc_wlog( logger, "num_clients already at 0");
         }
         else {
            --num_clients;
         }
      }
      c->close();
   }

   void net_plugin_impl::accepted_block(const block_state_ptr& block) {
      fc_dlog(logger,"signaled, id = ${id}",("id", block->id));
      dispatcher->bcast_block(block);
   }

   void net_plugin_impl::transaction_ack(const std::pair<fc::exception_ptr, transaction_metadata_ptr>& results) {
      const auto& id = results.second->id;
      if (results.first) {
         fc_ilog(logger,"signaled NACK, trx-id = ${id} : ${why}",("id", id)("why", results.first->to_detail_string()));
         dispatcher->rejected_transaction(id);
      } else {
         fc_ilog(logger,"signaled ACK, trx-id = ${id}",("id", id));
         dispatcher->bcast_transaction(results.second);
      }
   }

   bool net_plugin_impl::authenticate_peer(const handshake_message& msg) const {
      if(allowed_connections == None)
         return false;

      if(allowed_connections == Any)
         return true;

      if(allowed_connections & (Producers | Specified)) {
         auto allowed_it = std::find(allowed_peers.begin(), allowed_peers.end(), msg.key);
         auto private_it = private_keys.find(msg.key);
         bool found_producer_key = false;
         if(producer_plug != nullptr)
            found_producer_key = producer_plug->is_producer_key(msg.key);
         if( allowed_it == allowed_peers.end() && private_it == private_keys.end() && !found_producer_key) {
            elog( "Peer ${peer} sent a handshake with an unauthorized key: ${key}.",
                  ("peer", msg.p2p_address)("key", msg.key));
            return false;
         }
      }

      namespace sc = std::chrono;
      sc::system_clock::duration msg_time(msg.time);
      auto time = sc::system_clock::now().time_since_epoch();
      if(time - msg_time > peer_authentication_interval) {
         elog( "Peer ${peer} sent a handshake with a timestamp skewed by more than ${time}.",
               ("peer", msg.p2p_address)("time", "1 second")); // TODO Add to_variant for std::chrono::system_clock::duration
         return false;
      }

      if(msg.sig != chain::signature_type() && msg.token != sha256()) {
         sha256 hash = fc::sha256::hash(msg.time);
         if(hash != msg.token) {
            elog( "Peer ${peer} sent a handshake with an invalid token.",
                  ("peer", msg.p2p_address));
            return false;
         }
         chain::public_key_type peer_key;
         try {
            peer_key = crypto::public_key(msg.sig, msg.token, true);
         }
         catch (fc::exception& /*e*/) {
            elog( "Peer ${peer} sent a handshake with an unrecoverable key.",
                  ("peer", msg.p2p_address));
            return false;
         }
         if((allowed_connections & (Producers | Specified)) && peer_key != msg.key) {
            elog( "Peer ${peer} sent a handshake with an unauthenticated key.",
                  ("peer", msg.p2p_address));
            return false;
         }
      }
      else if(allowed_connections & (Producers | Specified)) {
         dlog( "Peer sent a handshake with blank signature and token, but this node accepts only authenticated connections.");
         return false;
      }
      return true;
   }

   chain::public_key_type net_plugin_impl::get_authentication_key() const {
      if(!private_keys.empty())
         return private_keys.begin()->first;
      /*producer_plugin* pp = app().find_plugin<producer_plugin>();
      if(pp != nullptr && pp->get_state() == abstract_plugin::started)
         return pp->first_producer_public_key();*/
      return chain::public_key_type();
   }

   chain::signature_type net_plugin_impl::sign_compact(const chain::public_key_type& signer, const fc::sha256& digest) const
   {
      auto private_key_itr = private_keys.find(signer);
      if(private_key_itr != private_keys.end())
         return private_key_itr->second.sign(digest);
      if(producer_plug != nullptr && producer_plug->get_state() == abstract_plugin::started)
         return producer_plug->sign_compact(signer, digest);
      return chain::signature_type();
   }

   void
   handshake_initializer::populate( handshake_message &hello) {
      namespace sc = std::chrono;
      hello.network_version = net_version_base + net_version;
      hello.chain_id = my_impl->chain_id;
      hello.node_id = my_impl->node_id;
      hello.key = my_impl->get_authentication_key();
      hello.time = sc::duration_cast<sc::nanoseconds>(sc::system_clock::now().time_since_epoch()).count();
      hello.token = fc::sha256::hash(hello.time);
      hello.sig = my_impl->sign_compact(hello.key, hello.token);
      // If we couldn't sign, don't send a token.
      if(hello.sig == chain::signature_type())
         hello.token = sha256();
      hello.p2p_address = my_impl->p2p_address + " - " + hello.node_id.str().substr(0,7);
#if defined( __APPLE__ )
      hello.os = "osx";
#elif defined( __linux__ )
      hello.os = "linux";
#elif defined( _MSC_VER )
      hello.os = "win32";
#else
      hello.os = "other";
#endif
      hello.agent = my_impl->user_agent_name;


      controller& cc = my_impl->chain_plug->chain();
      hello.head_id = fc::sha256();
      hello.last_irreversible_block_id = fc::sha256();
      hello.head_num = cc.fork_db_head_block_num();
      hello.last_irreversible_block_num = cc.last_irreversible_block_num();
      if( hello.last_irreversible_block_num ) {
         try {
            hello.last_irreversible_block_id = cc.get_block_id_for_num(hello.last_irreversible_block_num);
         }
         catch( const unknown_block_exception &ex) {
            ilog("caught unkown_block");
            hello.last_irreversible_block_num = 0;
         }
      }
      if( hello.head_num ) {
         try {
            hello.head_id = cc.get_block_id_for_num( hello.head_num );
         }
         catch( const unknown_block_exception &ex) {
           hello.head_num = 0;
         }
      }
   }

   net_plugin::net_plugin()
      :my( new net_plugin_impl ) {
      my_impl = my.get();
   }

   net_plugin::~net_plugin() {
   }

   void net_plugin::set_program_options( options_description& /*cli*/, options_description& cfg )
   {
      cfg.add_options()
         ( "p2p-listen-endpoint", bpo::value<string>()->default_value( "0.0.0.0:9876" ), "The actual host:port used to listen for incoming p2p connections.")
         ( "p2p-server-address", bpo::value<string>(), "An externally accessible host:port for identifying this node. Defaults to p2p-listen-endpoint.")
         ( "p2p-peer-address", bpo::value< vector<string> >()->composing(), "The public endpoint of a peer node to connect to. Use multiple p2p-peer-address options as needed to compose a network.")
         ( "p2p-max-nodes-per-host", bpo::value<int>()->default_value(def_max_nodes_per_host), "Maximum number of client nodes from any single IP address")
         ( "agent-name", bpo::value<string>()->default_value("\"EOS Test Agent\""), "The name supplied to identify this node amongst the peers.")
         ( "allowed-connection", bpo::value<vector<string>>()->multitoken()->default_value({"any"}, "any"), "Can be 'any' or 'producers' or 'specified' or 'none'. If 'specified', peer-key must be specified at least once. If only 'producers', peer-key is not required. 'producers' and 'specified' may be combined.")
         ( "peer-key", bpo::value<vector<string>>()->composing()->multitoken(), "Optional public key of peer allowed to connect.  May be used multiple times.")
         ( "peer-private-key", boost::program_options::value<vector<string>>()->composing()->multitoken(),
           "Tuple of [PublicKey, WIF private key] (may specify multiple times)")
         ( "max-clients", bpo::value<int>()->default_value(def_max_clients), "Maximum number of clients from which connections are accepted, use 0 for no limit")
         ( "connection-cleanup-period", bpo::value<int>()->default_value(def_conn_retry_wait), "number of seconds to wait before cleaning up dead connections")
         ( "max-cleanup-time-msec", bpo::value<int>()->default_value(10), "max connection cleanup time per cleanup call in millisec")
         ( "network-version-match", bpo::value<bool>()->default_value(false),
           "True to require exact match of peer network version.")
         ( "sync-fetch-span", bpo::value<uint32_t>()->default_value(def_sync_fetch_span), "number of blocks to retrieve in a chunk from any individual peer during synchronization")
         ( "use-socket-read-watermark", bpo::value<bool>()->default_value(false), "Enable expirimental socket read watermark optimization")
         ( "p2p-discoverable", bpo::value<bool>()->default_value(false),
           "True to p2p discoverable.")
         ( "peer-log-format", bpo::value<string>()->default_value( "[\"${_name}\" ${_ip}:${_port}]" ),
           "The string used to format peers when logging messages about them.  Variables are escaped with ${<variable name>}.\n"
           "Available Variables:\n"
           "   _name  \tself-reported name\n\n"
           "   _id    \tself-reported ID (64 hex characters)\n\n"
           "   _sid   \tfirst 8 characters of _peer.id\n\n"
           "   _ip    \tremote IP address of peer\n\n"
           "   _port  \tremote port number of peer\n\n"
           "   _lip   \tlocal IP address connected to peer\n\n"
           "   _lport \tlocal port number connected to peer\n\n")
        ;
   }

   template<typename T>
   T dejsonify(const string& s) {
      return fc::json::from_string(s).as<T>();
   }

   void net_plugin::plugin_initialize( const variables_map& options ) {
      ilog("Initialize net plugin");
      try {
         peer_log_format = options.at( "peer-log-format" ).as<string>();

         my->network_version_match = options.at( "network-version-match" ).as<bool>();

         my->sync_master.reset( new sync_manager( options.at( "sync-fetch-span" ).as<uint32_t>()));
         my->dispatcher.reset( new dispatch_manager );

         my->connector_period = std::chrono::seconds( options.at( "connection-cleanup-period" ).as<int>());
         my->max_cleanup_time_ms = options.at("max-cleanup-time-msec").as<int>();
         my->txn_exp_period = def_txn_expire_wait;
         my->resp_expected_period = def_resp_expected_wait;
         my->max_client_count = options.at( "max-clients" ).as<int>();
         my->max_nodes_per_host = options.at( "p2p-max-nodes-per-host" ).as<int>();
         my->num_clients = 0;
         my->started_sessions = 0;

         my->use_socket_read_watermark = options.at( "use-socket-read-watermark" ).as<bool>();

         my->p2p_discoverable=options.at( "p2p-discoverable" ).as<bool>();

         if( options.count( "p2p-listen-endpoint" ) && options.at("p2p-listen-endpoint").as<string>().length()) {
            my->p2p_address = options.at( "p2p-listen-endpoint" ).as<string>();
         }
         if( options.count( "p2p-server-address" ) ) {
            my->p2p_server_address = options.at( "p2p-server-address" ).as<string>();
         }


         if( options.count( "p2p-peer-address" )) {
            my->supplied_peers = options.at( "p2p-peer-address" ).as<vector<string> >();
         }
         if( options.count( "agent-name" )) {
            my->user_agent_name = options.at( "agent-name" ).as<string>();
         }

         if( options.count( "allowed-connection" )) {
            const std::vector<std::string> allowed_remotes = options["allowed-connection"].as<std::vector<std::string>>();
            for( const std::string& allowed_remote : allowed_remotes ) {
               if( allowed_remote == "any" )
                  my->allowed_connections |= net_plugin_impl::Any;
               else if( allowed_remote == "producers" )
                  my->allowed_connections |= net_plugin_impl::Producers;
               else if( allowed_remote == "specified" )
                  my->allowed_connections |= net_plugin_impl::Specified;
               else if( allowed_remote == "none" )
                  my->allowed_connections = net_plugin_impl::None;
            }
         }

         if( my->allowed_connections & net_plugin_impl::Specified )
            EOS_ASSERT( options.count( "peer-key" ),
                        plugin_config_exception,
                       "At least one peer-key must accompany 'allowed-connection=specified'" );

         if( options.count( "peer-key" )) {
            const std::vector<std::string> key_strings = options["peer-key"].as<std::vector<std::string>>();
            for( const std::string& key_string : key_strings ) {
               my->allowed_peers.push_back( dejsonify<chain::public_key_type>( key_string ));
            }
         }

         if( options.count( "peer-private-key" )) {
            const std::vector<std::string> key_id_to_wif_pair_strings = options["peer-private-key"].as<std::vector<std::string>>();
            for( const std::string& key_id_to_wif_pair_string : key_id_to_wif_pair_strings ) {
               auto key_id_to_wif_pair = dejsonify<std::pair<chain::public_key_type, std::string>>(
                     key_id_to_wif_pair_string );
               my->private_keys[key_id_to_wif_pair.first] = fc::crypto::private_key( key_id_to_wif_pair.second );
            }
         }

         my->chain_plug = app().find_plugin<chain_plugin>();
         EOS_ASSERT( my->chain_plug, chain::missing_chain_plugin_exception, ""  );
         my->chain_id = my->chain_plug->get_chain_id();
         fc::rand_pseudo_bytes( my->node_id.data(), my->node_id.data_size());
         ilog( "my node_id is ${id}", ("id", my->node_id));

      } FC_LOG_AND_RETHROW()
   }

   void net_plugin::plugin_startup() {
      try {
          my->producer_plug = app().find_plugin<producer_plugin>();

          auto resolver = std::make_shared<tcp::resolver>( std::ref(app().get_io_service()) );
          if( my->p2p_address.size() > 0 ) {
             auto host = my->p2p_address.substr( 0, my->p2p_address.find( ':' ));
             auto port = my->p2p_address.substr( host.size() + 1, my->p2p_address.size());
             tcp::resolver::query query( tcp::v4(), host.c_str(), port.c_str());
             // Note: need to add support for IPv6 too?

             my->listen_endpoint = *resolver->resolve( query );

             my->acceptor.reset( new tcp::acceptor( std::ref(app().get_io_service())) );

             if( !my->p2p_server_address.empty() ) {
                my->p2p_address = my->p2p_server_address;
             } else {
                if( my->listen_endpoint.address().to_v4() == address_v4::any()) {
                   boost::system::error_code ec;
                   auto host = host_name( ec );
                   if( ec.value() != boost::system::errc::success ) {

                      FC_THROW_EXCEPTION( fc::invalid_arg_exception,
                                      "Unable to retrieve host_name. ${msg}", ("msg", ec.message()));

                   }
                   auto port = my->p2p_address.substr( my->p2p_address.find( ':' ), my->p2p_address.size());
                   my->p2p_address = host + port;
                }
             }
          }

          if (my->acceptor) {
              my->acceptor->open(my->listen_endpoint.protocol());
              my->acceptor->set_option(tcp::acceptor::reuse_address(true));
              try {
                  my->acceptor->bind(my->listen_endpoint);
              } catch (const std::exception &e) {
                  elog("net_plugin::plugin_startup failed to bind to port ${port}",
                       ("port", my->listen_endpoint.port()));
                  throw e;
              }
              my->acceptor->listen();
              ilog("starting listener, max clients is ${mc}", ("mc", my->max_client_count));
              my->start_listen_loop();
          }

          chain::controller &cc = my->chain_plug->chain();
          {
              cc.accepted_block.connect(boost::bind(&net_plugin_impl::accepted_block, my.get(), _1));
          }

          my->keepalive_timer.reset(new boost::asio::steady_timer(app().get_io_service()));
          my->ticker();
          my->pbft_message_cache_timer.reset(new boost::asio::steady_timer(app().get_io_service()));
          my->pbft_message_cache_ticker();

          my->incoming_transaction_ack_subscription = app().get_channel<channels::transaction_ack>().subscribe(
                  boost::bind(&net_plugin_impl::transaction_ack, my.get(), _1));
          my->pbft_outgoing_prepare_subscription = app().get_channel<eosio::chain::plugin_interface::pbft::outgoing::prepare_channel>().subscribe(
                  boost::bind(&net_plugin_impl::pbft_outgoing_prepare, my.get(), _1));
          my->pbft_outgoing_commit_subscription = app().get_channel<eosio::chain::plugin_interface::pbft::outgoing::commit_channel>().subscribe(
                  boost::bind(&net_plugin_impl::pbft_outgoing_commit, my.get(), _1));
          my->pbft_outgoing_view_change_subscription = app().get_channel<eosio::chain::plugin_interface::pbft::outgoing::view_change_channel>().subscribe(
                  boost::bind(&net_plugin_impl::pbft_outgoing_view_change, my.get(), _1));
          my->pbft_outgoing_new_view_subscription = app().get_channel<eosio::chain::plugin_interface::pbft::outgoing::new_view_channel>().subscribe(
                  boost::bind(&net_plugin_impl::pbft_outgoing_new_view, my.get(), _1));
          my->pbft_outgoing_checkpoint_subscription = app().get_channel<eosio::chain::plugin_interface::pbft::outgoing::checkpoint_channel>().subscribe(
                  boost::bind(&net_plugin_impl::pbft_outgoing_checkpoint, my.get(), _1));

          if (cc.get_read_mode() == chain::db_read_mode::READ_ONLY) {
              my->max_nodes_per_host = 0;
              ilog("node in read-only mode setting max_nodes_per_host to 0 to prevent connections");
          }

          my->start_monitors();

          for (auto seed_node : my->supplied_peers) {
              p2p_peer_record p2prcd;
              p2prcd.peer_address = seed_node;
              p2prcd.discoverable = false;
              p2prcd.is_config = true;
              p2prcd.connected = false;
              p2prcd.expiry = time_point_sec((time_point::now()).sec_since_epoch() + 10);
              my->p2p_peer_records.insert(pair<string, p2p_peer_record>(seed_node, p2prcd));

              connect(seed_node);
          }

          if (fc::get_logger_map().find(logger_name) != fc::get_logger_map().end())
              logger = fc::get_logger_map()[logger_name];
      } catch (...) {
         // always want plugin_shutdown even on exception
         plugin_shutdown();
         throw;
      }
   }

   void net_plugin::plugin_shutdown() {
      try {
         fc_ilog( logger, "shutdown.." );
         if( my->connector_check )
            my->connector_check->cancel();
         if( my->transaction_check )
            my->transaction_check->cancel();
         if( my->keepalive_timer )
            my->keepalive_timer->cancel();

         my->done = true;
         if( my->acceptor ) {
            ilog( "close acceptor" );
            my->acceptor->cancel();
            my->acceptor->close();

            ilog( "close ${s} connections",( "s",my->connections.size()) );
            for( auto& con : my->connections ) {
               fc_dlog( logger, "close: ${p}", ("p",con->peer_name()) );
               my->close( con );
            }
            my->connections.clear();
         }
         ilog( "exit shutdown" );
      }
      FC_CAPTURE_AND_RETHROW()
   }

   size_t net_plugin::num_peers() const {
      return my->count_open_sockets();
   }

   /**
    *  Used to trigger a new connection from RPC API
    */
   string net_plugin::connect( const string& host ) {
      if( my->find_connection( host ) )
         return "already connected";

      connection_ptr c = std::make_shared<connection>(host);
      fc_dlog(logger,"adding new connection to the list");
      my->connections.insert( c );
      fc_dlog(logger,"calling active connector");
      my->connect( c );
      return "added connection";
   }

   string net_plugin::disconnect( const string& host ) {
      for( auto itr = my->connections.begin(); itr != my->connections.end(); ++itr ) {
         if( (*itr)->peer_addr == host ) {
            (*itr)->reset();
            fc_ilog( logger, "disconnecting: ${p}", ("p", (*itr)->peer_name()) );
            my->close(*itr);
            my->connections.erase(itr);
            return "connection removed";
         }
      }
      return "no known connection for host";
   }

   optional<connection_status> net_plugin::status( const string& host )const {
      auto con = my->find_connection( host );
      if( con )
         return con->get_status();
      return optional<connection_status>();
   }

   vector<connection_status> net_plugin::connections()const {
      vector<connection_status> result;
      result.reserve( my->connections.size() );
      for( const auto& c : my->connections ) {
         result.push_back( c->get_status() );
      }
      return result;
   }

   bool net_plugin::is_syncing()const {
      return my->sync_master->is_syncing();
   }

   void net_plugin::maybe_sync_stable_checkpoints() {
       controller& cc = my->chain_plug->chain();
       if (!cc.is_pbft_enabled()) return;
       //there might be a better way to sync checkpoints, yet we do not want to modify the existing handshake msg.
       uint32_t head = cc.fork_db_head_block_num();

       for (auto const &c: my->connections) {
           if (c->current()) {
               auto requested = my->sync_master->sync_stable_checkpoints(c, head);
               if (!requested) break;
           }
       }

   }


   net_plugin_impl::net_plugin_impl():
   pbft_incoming_prepare_channel(app().get_channel<eosio::chain::plugin_interface::pbft::incoming::prepare_channel>()),
   pbft_incoming_commit_channel(app().get_channel<eosio::chain::plugin_interface::pbft::incoming::commit_channel>()),
   pbft_incoming_view_change_channel(app().get_channel<eosio::chain::plugin_interface::pbft::incoming::view_change_channel>()),
   pbft_incoming_new_view_channel(app().get_channel<eosio::chain::plugin_interface::pbft::incoming::new_view_channel>()),
   pbft_incoming_checkpoint_channel(app().get_channel<eosio::chain::plugin_interface::pbft::incoming::checkpoint_channel>())
   {}

   connection_ptr net_plugin_impl::find_connection(const string& host )const {
      for( const auto& c : connections )
         if( c->peer_addr == host ) return c;
      return connection_ptr();
   }

   uint16_t net_plugin_impl::to_protocol_version(uint16_t v) {
      if (v >= net_version_base) {
         v -= net_version_base;
         return (v > net_version_range) ? 0 : v;
      }
      return 0;
   }

}
