//
// Created by deadlock on 17/10/18.
//

//#ifndef EOSIO_PBFT_HPP
//#define EOSIO_PBFT_HPP
#pragma once

#include <eosio/chain/controller.hpp>
#include <eosio/chain/fork_database.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/uuid/uuid.hpp>

namespace eosio {
    namespace chain {
        using boost::multi_index_container;
        using namespace boost::multi_index;
        using namespace std;
        using boost::uuids::uuid;


        struct block_info {
            block_id_type block_id;
            block_num_type block_num = 0;
        };

        struct pbft_prepare {
            string uuid;
            uint32_t view;
            block_num_type block_num = 0;
            block_id_type block_id;
            public_key_type public_key;
            signature_type producer_signature;

            bool operator==(const pbft_prepare &rhs) const {
                return uuid == rhs.uuid
                       && view == rhs.view
                       && block_num == rhs.block_num
                       && block_id == rhs.block_id
                       && public_key == rhs.public_key;
            }

            bool operator<(const pbft_prepare &rhs) const {
                if (block_num < rhs.block_num) {
                    return true;
                } else return block_num == rhs.block_num && view < rhs.view;
            }

            digest_type digest() const {
                digest_type::encoder enc;
                fc::raw::pack(enc, uuid);
                fc::raw::pack(enc, view);
                fc::raw::pack(enc, block_num);
                fc::raw::pack(enc, block_id);
                fc::raw::pack(enc, public_key);
                return enc.result();
            }

            bool is_signature_valid() const {
                try {
                    auto pk = crypto::public_key(producer_signature, digest(), true);
                    return public_key == pk;
                } catch (fc::exception & /*e*/) {
                    return false;
                }
            }
        };

        struct pbft_commit {
            string uuid;
            uint32_t view;
            block_num_type block_num = 0;
            block_id_type block_id;
            public_key_type public_key;
            signature_type producer_signature;

            bool operator==(const pbft_commit &rhs) const {
                return uuid == rhs.uuid
                       && view == rhs.view
                       && block_num == rhs.block_num
                       && block_id == rhs.block_id
                       && public_key == rhs.public_key;
            }

            bool operator<(const pbft_commit &rhs) const {
                if (block_num < rhs.block_num) {
                    return true;
                } else return block_num == rhs.block_num && view < rhs.view;
            }

            digest_type digest() const {
                digest_type::encoder enc;
                fc::raw::pack(enc, uuid);
                fc::raw::pack(enc, view);
                fc::raw::pack(enc, block_num);
                fc::raw::pack(enc, block_id);
                fc::raw::pack(enc, public_key);
                return enc.result();
            }

            bool is_signature_valid() const {
                try {
                    auto pk = crypto::public_key(producer_signature, digest(), true);
                    return public_key == pk;
                } catch (fc::exception & /*e*/) {
                    return false;
                }
            }
        };


        struct pbft_prepared_certificate {
            //TODO: add view??
            block_id_type block_id;
            block_num_type block_num = 0;
            vector<pbft_prepare> prepares;

            public_key_type public_key;
            signature_type producer_signature;

            bool operator==(const pbft_prepared_certificate &rhs) const {
                return block_num == rhs.block_num
                       && block_id == rhs.block_id
                       && prepares == rhs.prepares
                       && public_key == rhs.public_key;
            }


            digest_type digest() const {
                digest_type::encoder enc;
                fc::raw::pack(enc, block_id);
                fc::raw::pack(enc, block_num);
                fc::raw::pack(enc, prepares);
                fc::raw::pack(enc, public_key);
                return enc.result();
            }

            bool is_signature_valid() const {
                try {
                    auto pk = crypto::public_key(producer_signature, digest(), true);
                    return public_key == pk;
                } catch (fc::exception & /*e*/) {
                    return false;
                }
            }
        };

        struct pbft_committed_certificate {
            block_id_type block_id;
            block_num_type block_num = 0;
            vector<pbft_commit> commits;

            public_key_type public_key;
            signature_type producer_signature;

            bool operator==(const pbft_committed_certificate &rhs) const {
                return block_num == rhs.block_num
                       && block_id == rhs.block_id
                       && commits == rhs.commits
                       && public_key == rhs.public_key;
            }

            digest_type digest() const {
                digest_type::encoder enc;
                fc::raw::pack(enc, block_id);
                fc::raw::pack(enc, block_num);
                fc::raw::pack(enc, commits);
                fc::raw::pack(enc, public_key);
                return enc.result();
            }

            bool is_signature_valid() const {
                try {
                    auto pk = crypto::public_key(producer_signature, digest(), true);
                    return public_key == pk;
                } catch (fc::exception & /*e*/) {
                    return false;
                }
            }
        };

        struct pbft_view_change {
            string uuid;
            uint32_t view;
            pbft_prepared_certificate prepared;
            pbft_committed_certificate committed;
            public_key_type public_key;
            signature_type producer_signature;
            uint32_t chain_id = 0;

            bool operator==(const pbft_view_change &rhs) const {
                return view == rhs.view
                       && prepared == rhs.prepared
                       && committed == rhs.committed
                       && public_key == rhs.public_key;
            }

            bool operator<(const pbft_view_change &rhs) const {
                return view < rhs.view;
            }

            digest_type digest() const {
                digest_type::encoder enc;
                fc::raw::pack(enc, uuid);
                fc::raw::pack(enc, view);
                fc::raw::pack(enc, prepared);
                fc::raw::pack(enc, committed);
                fc::raw::pack(enc, public_key);
                return enc.result();
            }

            bool is_signature_valid() const {
                try {
                    auto pk = crypto::public_key(producer_signature, digest(), true);
                    return public_key == pk;
                } catch (fc::exception & /*e*/) {
                    return false;
                }
            }
        };

        struct pbft_view_changed_certificate {
            uint32_t view;
            vector<pbft_view_change> view_changes;

            public_key_type public_key;
            signature_type producer_signature;

            bool operator==(const pbft_view_changed_certificate &rhs) const {
                return view == rhs.view
                && view_changes == rhs.view_changes
                && public_key == rhs.public_key;
            }

            digest_type digest() const {
                digest_type::encoder enc;
                fc::raw::pack(enc, view);
                fc::raw::pack(enc, public_key);
                return enc.result();
            }

            bool is_signature_valid() const {
                try {
                    auto pk = crypto::public_key(producer_signature, digest(), true);
                    return public_key == pk;
                } catch (fc::exception & /*e*/) {
                    return false;
                }
            }
        };

        struct pbft_new_view {
            string uuid;
            uint32_t view;
            pbft_prepared_certificate prepared;
            pbft_committed_certificate committed;
            pbft_view_changed_certificate view_changed;
            public_key_type public_key;
            signature_type producer_signature;

            bool operator==(const pbft_new_view &rhs) const {
                return view == rhs.view
                && prepared == rhs.prepared
                && committed == rhs.committed
                && view_changed == rhs.view_changed
                && uuid == rhs.uuid && public_key == rhs.public_key;
            }

            bool operator<(const pbft_view_change &rhs) const {
                return view < rhs.view;
            }

            digest_type digest() const {
                digest_type::encoder enc;
                fc::raw::pack(enc, uuid);
                fc::raw::pack(enc, view);
                fc::raw::pack(enc, prepared);
                fc::raw::pack(enc, committed);
                fc::raw::pack(enc, view_changed);
                fc::raw::pack(enc, public_key);
                return enc.result();
            }

            bool is_signature_valid() const {
                try {
                    auto pk = crypto::public_key(producer_signature, digest(), true);
                    return public_key == pk;
                } catch (fc::exception & /*e*/) {
                    return false;
                }
            }
        };

        struct pbft_checkpoint {
            string uuid;
            block_num_type block_num = 0;
            block_id_type block_id;

            public_key_type public_key;
            signature_type producer_signature;

            bool operator==(const pbft_checkpoint &rhs) const {
                return uuid == rhs.uuid && block_id == rhs.block_id && public_key == rhs.public_key;
                return block_num == rhs.block_num
                && block_id == rhs.block_id
                && public_key == rhs.public_key;
            }

            bool operator<(const pbft_checkpoint &rhs) const {
                return block_num < rhs.block_num;
            }

            digest_type digest() const {
                digest_type::encoder enc;
                fc::raw::pack(enc, uuid);
                fc::raw::pack(enc, block_id);
                fc::raw::pack(enc, public_key);
                return enc.result();
            }

            bool is_signature_valid() const {
                try {
                    auto pk = crypto::public_key(producer_signature, digest(), true);
                    return public_key == pk;
                } catch (fc::exception & /*e*/) {
                    return false;
                }
            }
        };

        struct pbft_stable_checkpoint {
            block_num_type block_num = 0;
            block_id_type block_id;
            vector<pbft_checkpoint> checkpoints;

            public_key_type public_key;
            signature_type producer_signature;

            bool operator==(const pbft_stable_checkpoint &rhs) const {
                return block_id == rhs.block_id
                       && block_num == rhs.block_num
                       && checkpoints == rhs.checkpoints
                       && public_key == rhs.public_key;
            }

            bool operator<(const pbft_checkpoint &rhs) const {
                return block_num < rhs.block_num;
            }

            digest_type digest() const {
                digest_type::encoder enc;
                fc::raw::pack(enc, block_id);
                fc::raw::pack(enc, public_key);
                return enc.result();
            }

            bool is_signature_valid() const {
                try {
                    auto pk = crypto::public_key(producer_signature, digest(), true);
                    return public_key == pk;
                } catch (fc::exception & /*e*/) {
                    return false;
                }
            }
        };

        struct pbft_state {
            block_id_type block_id;
            block_num_type block_num = 0;
            vector<pbft_prepare> prepares;
            bool should_prepared = false;
            vector<pbft_commit> commits;
            bool should_committed = false;
        };

        struct pbft_view_state {
            uint32_t view;
            vector<pbft_view_change> view_changes;
            bool should_view_changed = false;
        };

        struct pbft_checkpoint_state {
            block_id_type block_id;
            block_num_type block_num = 0;
            vector<pbft_checkpoint> checkpoints;
            bool is_stable = false;
        };

        using pbft_state_ptr = std::shared_ptr<pbft_state>;
        using pbft_view_state_ptr = std::shared_ptr<pbft_view_state>;
        using pbft_checkpoint_state_ptr = std::shared_ptr<pbft_checkpoint_state>;

        struct by_block_id;
        struct by_num;
        struct by_prepare_and_num;
        struct by_commit_and_num;
        typedef multi_index_container<
                pbft_state_ptr,
                indexed_by<
                        hashed_unique<
                                tag<by_block_id>,
                                member<pbft_state, block_id_type, &pbft_state::block_id>,
                                std::hash<block_id_type>
                        >,
                        ordered_non_unique<
                                tag<by_num>,
                                composite_key<
                                        pbft_state,
                                        member<pbft_state, uint32_t, &pbft_state::block_num>
                                >,
                                composite_key_compare<less<uint32_t>>
                        >,
                        ordered_non_unique<
                                tag<by_prepare_and_num>,
                                composite_key<
                                        pbft_state,
                                        member<pbft_state, bool, &pbft_state::should_prepared>,
                                        member<pbft_state, uint32_t, &pbft_state::block_num>
                                >,
                                composite_key_compare<greater<>, greater<uint32_t>>
                        >,
                        ordered_non_unique<
                                tag<by_commit_and_num>,
                                composite_key<
                                        pbft_state,
                                        member<pbft_state, bool, &pbft_state::should_committed>,
                                        member<pbft_state, uint32_t, &pbft_state::block_num>
                                >,
                                composite_key_compare<greater<>, greater<uint32_t>>
                        >
                >
        >
                pbft_state_multi_index_type;

        struct by_view;
        struct by_count_and_view;
        typedef multi_index_container<
                pbft_view_state_ptr,
                indexed_by<
                        hashed_unique<
                                tag<by_view>,
                                member<pbft_view_state, uint32_t, &pbft_view_state::view>,
                                std::hash<uint32_t>
                        >,
                        ordered_non_unique<
                                tag<by_count_and_view>,
                                composite_key<
                                        pbft_view_state,
                                        member<pbft_view_state, bool, &pbft_view_state::should_view_changed>,
                                        member<pbft_view_state, uint32_t, &pbft_view_state::view>
                                >,
                                composite_key_compare<greater<>, greater<uint32_t>>
                        >
                >
        >
                pbft_view_state_multi_index_type;

        struct by_block_id;
        struct by_stable_and_num;
        typedef multi_index_container<
                pbft_checkpoint_state_ptr,
                indexed_by<
                        hashed_unique<
                                tag<by_block_id>,
                                member<pbft_checkpoint_state, block_id_type, &pbft_checkpoint_state::block_id>,
                                std::hash<block_id_type>
                        >,
                        ordered_non_unique<
                                tag<by_stable_and_num>,
                                composite_key<
                                        pbft_checkpoint_state,
//                                        member<pbft_checkpoint_state, bool, &pbft_checkpoint_state::is_stable>,
                                        member<pbft_checkpoint_state, uint32_t, &pbft_checkpoint_state::block_num>
                                >,
                                composite_key_compare<less<uint32_t>>
                        >
                >
        >
                pbft_checkpoint_state_multi_index_type;

        class pbft_database {
        public:
            explicit pbft_database(controller &ctrl);
            ~pbft_database();

            void close();

            bool should_prepared();

            bool should_committed();

            uint32_t should_view_change();

            bool should_new_view(const uint32_t target_view);

            bool is_new_primary(const uint32_t target_view);

            uint32_t get_proposed_new_view_num();

            void add_pbft_prepare(pbft_prepare &p);

            void add_pbft_commit(pbft_commit &c);

            void add_pbft_view_change(pbft_view_change &vc);

            void add_pbft_checkpoint(pbft_checkpoint &cp);

            vector<pbft_prepare> send_and_add_pbft_prepare(
                    const vector<pbft_prepare> &pv = vector<pbft_prepare>{},
                    uint32_t current_view = 0);

            vector<pbft_commit> send_and_add_pbft_commit(
                    const vector<pbft_commit> &cv = vector<pbft_commit>{},
                    uint32_t current_view = 0);

            vector<pbft_view_change> send_and_add_pbft_view_change(
                    const vector<pbft_view_change> &vcv = vector<pbft_view_change>{},
                    const vector<pbft_prepared_certificate> &ppc = vector<pbft_prepared_certificate>{},
                    const vector<pbft_committed_certificate> &pcc = vector<pbft_committed_certificate>{},
                    uint32_t new_view = 1);

            pbft_new_view send_pbft_new_view(
                    const vector<pbft_view_changed_certificate> &vcc = vector<pbft_view_changed_certificate>{},
                    uint32_t current_view = 1);

            vector<pbft_checkpoint> generate_and_add_pbft_checkpoint();

            bool is_valid_prepare(const pbft_prepare &p);

            bool is_valid_commit(const pbft_commit &c);

            void commit_local();

            bool pending_pbft_lib();

            void set_pbft_prepared_block_id(optional<block_id_type> bid);

            void prune_view_change_index();

            uint32_t get_committed_view();


            vector<pbft_prepared_certificate> generate_prepared_certificate();

            vector<pbft_committed_certificate> generate_committed_certificate();

            vector<pbft_view_changed_certificate> generate_view_changed_certificate();

            pbft_stable_checkpoint get_stable_checkpoint_by_id(const block_id_type &block_id);

            block_num_type cal_latest_possible_stable_checkpoint_block_num()const;

            bool should_send_pbft_msg();

            void send_pbft_checkpoint(const vector<pbft_checkpoint> &cps = vector<pbft_checkpoint>{});

            bool is_valid_checkpoint(const pbft_checkpoint &cp);

            bool is_valid_stable_checkpoint(const pbft_stable_checkpoint &cp);
            //pbft
            signal<void(const pbft_prepare &)> pbft_outgoing_prepare;
            signal<void(const pbft_prepare &)> pbft_incoming_prepare;

            signal<void(const pbft_commit &)> pbft_outgoing_commit;
            signal<void(const pbft_commit &)> pbft_incoming_commit;

            signal<void(const pbft_view_change &)> pbft_outgoing_view_change;
            signal<void(const pbft_view_change &)> pbft_incoming_view_change;

            signal<void(const pbft_new_view &)> pbft_outgoing_new_view;
            signal<void(const pbft_new_view &)> pbft_incoming_new_view;

            signal<void(const pbft_checkpoint &)> pbft_outgoing_checkpoint;
            signal<void(const pbft_checkpoint &)> pbft_incoming_checkpoint;

            bool is_valid_view_change(const pbft_view_change &certificate);

            bool is_valid_new_view(const pbft_new_view &certificate);

        private:
            controller &ctrl;
            pbft_state_multi_index_type index;
            pbft_view_state_multi_index_type view_state_index;
            pbft_checkpoint_state_multi_index_type checkpoint_index;
            fc::path pbft_db_dir;
            fc::path checkpoints_dir;

            bool is_valid_prepared_certificate(const pbft_prepared_certificate &certificate);

            bool is_valid_committed_certificate(const pbft_committed_certificate &certificate);

            public_key_type get_new_view_primary_key(const uint32_t target_view);

            vector<vector<block_info>> fetch_fork_from(const vector<block_info> block_infos);

            vector<block_info> fetch_first_fork_from(vector<block_info> &bi);

            producer_schedule_type lib_active_producers()const;

            template<typename Signal, typename Arg>
            void emit(const Signal &s, Arg &&a);

            void set(pbft_state_ptr s);

            void set(pbft_checkpoint_state_ptr s);

            void prune(const pbft_state_ptr& h);

        };

    }
} /// namespace eosio::chain

FC_REFLECT(eosio::chain::block_info, (block_id)(block_num))
FC_REFLECT(eosio::chain::pbft_prepare, (uuid)(view)(block_num)(block_id)(public_key)(producer_signature))
FC_REFLECT(eosio::chain::pbft_commit, (uuid)(view)(block_num)(block_id)(public_key)(producer_signature))
FC_REFLECT(eosio::chain::pbft_view_change, (uuid)(view)(prepared)(committed)(public_key)(producer_signature)(chain_id))
FC_REFLECT(eosio::chain::pbft_new_view, (uuid)(view)(prepared)(committed)(view_changed)(public_key)(producer_signature))
FC_REFLECT(eosio::chain::pbft_state, (block_id)(block_num)(prepares)(should_prepared)(commits)(should_committed))
FC_REFLECT(eosio::chain::pbft_prepared_certificate, (block_id)(block_num)(prepares)(public_key)(producer_signature))
FC_REFLECT(eosio::chain::pbft_committed_certificate, (block_id)(block_num)(commits)(public_key)(producer_signature))
FC_REFLECT(eosio::chain::pbft_view_changed_certificate, (view)(view_changes)(public_key)(producer_signature))
FC_REFLECT(eosio::chain::pbft_checkpoint, (uuid)(block_num)(block_id)(public_key)(producer_signature))
FC_REFLECT(eosio::chain::pbft_stable_checkpoint, (block_num)(block_id)(checkpoints)(public_key)(producer_signature))
FC_REFLECT(eosio::chain::pbft_checkpoint_state, (block_id)(block_num)(checkpoints)(is_stable))
//#endif //EOSIO_PBFT_HPP
