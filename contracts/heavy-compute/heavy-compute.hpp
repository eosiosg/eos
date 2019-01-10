#include <eosiolib/eosio.hpp>
using namespace eosio;



class heavy : public eosio::contract {
public:
    using contract::contract;
    struct sig_hash_key {
        checksum256 hash;
        public_key pk;
        signature sig;
    };


    /// @abi action
    void hi(sig_hash_key k);

    void do_compute(sig_hash_key sh);
};
EOSIO_ABI( heavy, (hi) )


