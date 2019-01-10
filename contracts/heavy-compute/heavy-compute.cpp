#include "heavy-compute.hpp"
#include <eosiolib/eosio.hpp>
#include <eosiolib/crypto.h>

using namespace eosio;



/// @abi action
void heavy::hi(sig_hash_key k) {
    int LOOP = 10;
    for (int i = 0; i < LOOP; i++) {
        do_compute(k);
    }
}

//int recover_key( const checksum256* digest, const char* sig, size_t siglen, char* pub, size_t publen );
void heavy::do_compute(sig_hash_key sh) {
    read_action_data((char *) &sh, sizeof(sh));
    public_key pk;
    recover_key(&sh.hash, (const char *) &sh.sig, sizeof(sh.sig), pk.data, sizeof(pk));
    for (uint32_t i = 0; i < sizeof(pk); i++)
        if (pk.data[i] != sh.pk.data[i])
            eosio_assert(false, "public key does not match");

}

