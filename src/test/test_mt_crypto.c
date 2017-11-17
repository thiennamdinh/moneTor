#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "../mt.h"
#include "../mt_crypto.h"
#include "test_mt_main.h"

/**
 * terminal command: gcc test/test_crypto_lib.c -o test/test_crypto_lib crypto_lib.c -lssl -lcrypto && ./test/test_crypto_lib
 */

void test_mt_crypto(){

    // test strings
    char* str_1 = "This is a test message that is longer than the size of a single hash";
    char* str_2 = "This is another message different from the first but has same length";

    int msg_1_size = strlen(str_1);
    int msg_2_size = strlen(str_2);

    byte* msg_1 = (byte*)str_1;
    byte* msg_2 = (byte*)str_2;

    // recurring parameters
    byte pp[MT_SZ_PP];

    byte pk1[MT_SZ_PK];
    byte sk1[MT_SZ_SK];

    byte pk2[MT_SZ_PK];
    byte sk2[MT_SZ_SK];

    // if these are buggy then it should be obvious later
    mt_crypt_setup(&pp);
    mt_crypt_keygen(&pp, &pk1, &sk1);
    mt_crypt_keygen(&pp, &pk2, &sk2);

    //----------------------------- test random ------------------------------//

    int rand_size = 1000;
    byte rand1[rand_size];
    byte rand2[rand_size];

    mt_crypt_rand_bytes(rand_size, rand1);
    mt_crypt_rand_bytes(rand_size, rand2);

    // check that random numbers are different from eachother
    assert(memcpy(rand1, rand2, rand_size) != 0);

    //------------------------------- test hash ------------------------------//

    // expected hash outputs of msg_1 based on third party implementations
    char* expected_hex = "44465f39bfa6bfac40cdf928e0e79354a411e498f955794e0c70dc314eefbd44";
    byte expected_bytes[MT_SZ_HASH];

    for(int i = 0; i < MT_SZ_HASH; i++)
	sscanf(expected_hex + (i*2), "%2hhx", &expected_bytes[i]);

    byte hash_out[MT_SZ_HASH];
    mt_crypt_hash(msg_1, msg_1_size, &hash_out);

    assert(memcmp(expected_bytes, hash_out, MT_SZ_HASH) == MT_SUCCESS);

    //------------------------------- test sig -------------------------------//

    byte sig_1_pk1[MT_SZ_SIG];
    byte sig_2_pk1[MT_SZ_SIG];
    byte sig_1_pk2[MT_SZ_SIG];
    byte sig_2_pk2[MT_SZ_SIG];

    mt_sig_sign(msg_1, msg_1_size, &sk1, &sig_1_pk1);
    mt_sig_sign(msg_2, msg_2_size, &sk1, &sig_2_pk1);
    mt_sig_sign(msg_1, msg_1_size, &sk2, &sig_1_pk2);
    mt_sig_sign(msg_2, msg_2_size, &sk2, &sig_2_pk2);

    // check that correct signatures verify
    assert(mt_sig_verify(msg_1, msg_1_size, &pk1, &sig_1_pk1) == MT_SUCCESS);
    assert(mt_sig_verify(msg_2, msg_2_size, &pk1, &sig_2_pk1) == MT_SUCCESS);
    assert(mt_sig_verify(msg_1, msg_1_size, &pk2, &sig_1_pk2) == MT_SUCCESS);
    assert(mt_sig_verify(msg_2, msg_2_size, &pk2, &sig_2_pk2) == MT_SUCCESS);

    // check that incorrect signatures do not verify
    assert(mt_sig_verify(msg_1, msg_1_size, &pk1, &sig_2_pk1) == MT_ERROR);
    assert(mt_sig_verify(msg_1, msg_1_size, &pk1, &sig_1_pk2) == MT_ERROR);
    assert(mt_sig_verify(msg_1, msg_1_size, &pk1, &sig_2_pk2) == MT_ERROR);
    assert(mt_sig_verify(msg_1, msg_1_size, &pk2, &sig_1_pk1) == MT_ERROR);
    assert(mt_sig_verify(msg_1, msg_1_size, &pk2, &sig_2_pk1) == MT_ERROR);
    assert(mt_sig_verify(msg_1, msg_1_size, &pk2, &sig_2_pk2) == MT_ERROR);
    assert(mt_sig_verify(msg_2, msg_2_size, &pk1, &sig_1_pk1) == MT_ERROR);
    assert(mt_sig_verify(msg_2, msg_2_size, &pk1, &sig_1_pk2) == MT_ERROR);
    assert(mt_sig_verify(msg_2, msg_2_size, &pk1, &sig_2_pk2) == MT_ERROR);
    assert(mt_sig_verify(msg_2, msg_2_size, &pk2, &sig_1_pk1) == MT_ERROR);
    assert(mt_sig_verify(msg_2, msg_2_size, &pk2, &sig_2_pk1) == MT_ERROR);
    assert(mt_sig_verify(msg_2, msg_2_size, &pk2, &sig_1_pk2) == MT_ERROR);

    //------------------------------- test commit ----------------------------//

    byte rand_com_1[MT_SZ_HASH];
    byte rand_com_2[MT_SZ_HASH];

    byte com_1_1[MT_SZ_COM];
    byte com_2_1[MT_SZ_COM];
    byte com_1_2[MT_SZ_COM];
    byte com_2_2[MT_SZ_COM];

    mt_crypt_rand_bytes(MT_SZ_HASH, rand_com_1);
    mt_crypt_rand_bytes(MT_SZ_HASH, rand_com_2);

    mt_com_commit(msg_1, msg_1_size, &rand_com_1, &com_1_1);
    mt_com_commit(msg_2, msg_2_size, &rand_com_1, &com_2_1);
    mt_com_commit(msg_1, msg_1_size, &rand_com_2, &com_1_2);
    mt_com_commit(msg_2, msg_2_size, &rand_com_2, &com_2_2);

    // check that correct commitments verify
    assert(mt_com_decommit(msg_1, msg_1_size, &rand_com_1, &com_1_1) == MT_SUCCESS);
    assert(mt_com_decommit(msg_2, msg_2_size, &rand_com_1, &com_2_1) == MT_SUCCESS);
    assert(mt_com_decommit(msg_1, msg_1_size, &rand_com_2, &com_1_2) == MT_SUCCESS);
    assert(mt_com_decommit(msg_2, msg_2_size, &rand_com_2, &com_2_2) == MT_SUCCESS);

    // check that incorrect commitments do not verify
    assert(mt_com_decommit(msg_1, msg_1_size, &rand_com_1, &com_1_2) == MT_ERROR);
    assert(mt_com_decommit(msg_1, msg_1_size, &rand_com_1, &com_2_1) == MT_ERROR);
    assert(mt_com_decommit(msg_1, msg_1_size, &rand_com_1, &com_2_2) == MT_ERROR);
    assert(mt_com_decommit(msg_2, msg_2_size, &rand_com_1, &com_1_1) == MT_ERROR);
    assert(mt_com_decommit(msg_2, msg_2_size, &rand_com_1, &com_1_2) == MT_ERROR);
    assert(mt_com_decommit(msg_2, msg_2_size, &rand_com_1, &com_2_2) == MT_ERROR);
    assert(mt_com_decommit(msg_1, msg_1_size, &rand_com_2, &com_1_1) == MT_ERROR);
    assert(mt_com_decommit(msg_1, msg_1_size, &rand_com_2, &com_2_1) == MT_ERROR);
    assert(mt_com_decommit(msg_1, msg_1_size, &rand_com_2, &com_2_2) == MT_ERROR);
    assert(mt_com_decommit(msg_2, msg_2_size, &rand_com_2, &com_1_1) == MT_ERROR);
    assert(mt_com_decommit(msg_2, msg_2_size, &rand_com_2, &com_1_2) == MT_ERROR);
    assert(mt_com_decommit(msg_2, msg_2_size, &rand_com_2, &com_2_1) == MT_ERROR);

    //------------------------------- test bsig ------------------------------//

    //TODO: not sure if we can have bsig only apply to the hash
    byte blinded[MT_SZ_BL];
    byte unblinder[MT_SZ_UBLR];
    byte blind_sig[MT_SZ_SIG];
    byte unblinded_sig[MT_SZ_SIG];

    mt_bsig_blind(msg_1, msg_1_size, &pk1, &blinded, &unblinder);
    mt_sig_sign(blinded, MT_SZ_BL, &sk2, &blind_sig);
    mt_bsig_unblind(&pk1, &blind_sig, &unblinder, &unblinded_sig);


    // check that the original message is not same as the blinded message
    assert(memcmp(msg_1, blinded, MT_SZ_HASH) != 0);

    // check that the blind sig verifies
    assert(mt_bsig_verify(msg_1, msg_1_size, &pk2, &unblinded_sig) == MT_SUCCESS);

    //------------------------------- test zpk -------------------------------//

    byte proof_1[MT_SZ_ZKP];
    byte proof_2[MT_SZ_ZKP];
    byte proof_3[MT_SZ_ZKP];

    mt_zkp_prove(&pp, msg_1, msg_1_size, &proof_1);
    mt_zkp_prove(&pp, msg_2, msg_2_size, &proof_2);
    mt_crypt_rand_bytes(MT_SZ_ZKP, proof_3);

    // check that correct proofs are correct
    assert(mt_zkp_verify(&pp, &proof_1) == MT_SUCCESS);
    assert(mt_zkp_verify(&pp, &proof_2) == MT_SUCCESS);

    // check that correct proofs are not identical
    assert(memcmp(proof_1, proof_2, MT_SZ_ZKP) != 0);

    // check that incorrect proofs are incorrect
    assert(mt_zkp_verify(&pp, &proof_3) == MT_ERROR);
}
