#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "../crypto_lib.h"

/**
 * terminal command: gcc test/test_crypto_lib.c -o test/test_crypto_lib crypto_lib.c -lssl -lcrypto && ./test/test_crypto_lib
 */

void test_crypto_lib(){

    // test strings
    char* str_1 = "This is a test message that is longer than the size of a single hash";
    char* str_2 = "This is another message different from the first but has same length";

    int msg_1_size = strlen(str_1);
    int msg_2_size = strlen(str_2);

    byte* msg_1 = (byte*)str_1;
    byte* msg_2 = (byte*)str_2;

    // recurring parameters
    byte pp[SIZE_PP];

    byte pk1[SIZE_PK];
    byte sk1[SIZE_SK];

    byte pk2[SIZE_PK];
    byte sk2[SIZE_SK];

    // if these are buggy then it should be obvious later
    paycrypt_setup(&pp);
    paycrypt_keygen(&pp, &pk1, &sk1);
    paycrypt_keygen(&pp, &pk2, &sk2);

    //----------------------------- test random ------------------------------//

    int rand_size = 1000;
    byte rand1[rand_size];
    byte rand2[rand_size];

    paycrypt_rand_bytes(rand_size, rand1);
    paycrypt_rand_bytes(rand_size, rand2);

    // check that random numbers are different from eachother
    assert(memcpy(rand1, rand2, rand_size) != 0);

    //------------------------------- test hash ------------------------------//

    // expected hash outputs of msg_1 based on third party implementations
    char* expected_hex = "44465f39bfa6bfac40cdf928e0e79354a411e498f955794e0c70dc314eefbd44";
    byte expected_bytes[SIZE_HASH];

    for(int i = 0; i < SIZE_HASH; i++)
	sscanf(expected_hex + (i*2), "%2hhx", &expected_bytes[i]);

    byte hash_out[SIZE_HASH];
    paycrypt_hash(msg_1, msg_1_size, &hash_out);

    assert(memcmp(expected_bytes, hash_out, SIZE_HASH) == MT_SUCCESS);

    //------------------------------- test sig -------------------------------//

    byte sig_1_pk1[SIZE_SIG];
    byte sig_2_pk1[SIZE_SIG];
    byte sig_1_pk2[SIZE_SIG];
    byte sig_2_pk2[SIZE_SIG];

    sig_sign(msg_1, msg_1_size, &sk1, &sig_1_pk1);
    sig_sign(msg_2, msg_2_size, &sk1, &sig_2_pk1);
    sig_sign(msg_1, msg_1_size, &sk2, &sig_1_pk2);
    sig_sign(msg_2, msg_2_size, &sk2, &sig_2_pk2);

    // check that correct signatures verify
    assert(sig_verify(msg_1, msg_1_size, &pk1, &sig_1_pk1) == MT_SUCCESS);
    assert(sig_verify(msg_2, msg_2_size, &pk1, &sig_2_pk1) == MT_SUCCESS);
    assert(sig_verify(msg_1, msg_1_size, &pk2, &sig_1_pk2) == MT_SUCCESS);
    assert(sig_verify(msg_2, msg_2_size, &pk2, &sig_2_pk2) == MT_SUCCESS);

    // check that incorrect signatures do not verify
    assert(sig_verify(msg_1, msg_1_size, &pk1, &sig_2_pk1) == MT_ERROR);
    assert(sig_verify(msg_1, msg_1_size, &pk1, &sig_1_pk2) == MT_ERROR);
    assert(sig_verify(msg_1, msg_1_size, &pk1, &sig_2_pk2) == MT_ERROR);
    assert(sig_verify(msg_1, msg_1_size, &pk2, &sig_1_pk1) == MT_ERROR);
    assert(sig_verify(msg_1, msg_1_size, &pk2, &sig_2_pk1) == MT_ERROR);
    assert(sig_verify(msg_1, msg_1_size, &pk2, &sig_2_pk2) == MT_ERROR);
    assert(sig_verify(msg_2, msg_2_size, &pk1, &sig_1_pk1) == MT_ERROR);
    assert(sig_verify(msg_2, msg_2_size, &pk1, &sig_1_pk2) == MT_ERROR);
    assert(sig_verify(msg_2, msg_2_size, &pk1, &sig_2_pk2) == MT_ERROR);
    assert(sig_verify(msg_2, msg_2_size, &pk2, &sig_1_pk1) == MT_ERROR);
    assert(sig_verify(msg_2, msg_2_size, &pk2, &sig_2_pk1) == MT_ERROR);
    assert(sig_verify(msg_2, msg_2_size, &pk2, &sig_1_pk2) == MT_ERROR);

    //------------------------------- test commit ----------------------------//

    byte rand_com_1[SIZE_HASH];
    byte rand_com_2[SIZE_HASH];

    byte com_1_1[SIZE_COM];
    byte com_2_1[SIZE_COM];
    byte com_1_2[SIZE_COM];
    byte com_2_2[SIZE_COM];

    paycrypt_rand_bytes(SIZE_HASH, rand_com_1);
    paycrypt_rand_bytes(SIZE_HASH, rand_com_2);

    com_commit(msg_1, msg_1_size, &rand_com_1, &com_1_1);
    com_commit(msg_2, msg_2_size, &rand_com_1, &com_2_1);
    com_commit(msg_1, msg_1_size, &rand_com_2, &com_1_2);
    com_commit(msg_2, msg_2_size, &rand_com_2, &com_2_2);

    // check that correct commitments verify
    assert(com_decommit(msg_1, msg_1_size, &rand_com_1, &com_1_1) == MT_SUCCESS);
    assert(com_decommit(msg_2, msg_2_size, &rand_com_1, &com_2_1) == MT_SUCCESS);
    assert(com_decommit(msg_1, msg_1_size, &rand_com_2, &com_1_2) == MT_SUCCESS);
    assert(com_decommit(msg_2, msg_2_size, &rand_com_2, &com_2_2) == MT_SUCCESS);

    // check that incorrect commitments do not verify
    assert(com_decommit(msg_1, msg_1_size, &rand_com_1, &com_1_2) == MT_ERROR);
    assert(com_decommit(msg_1, msg_1_size, &rand_com_1, &com_2_1) == MT_ERROR);
    assert(com_decommit(msg_1, msg_1_size, &rand_com_1, &com_2_2) == MT_ERROR);
    assert(com_decommit(msg_2, msg_2_size, &rand_com_1, &com_1_1) == MT_ERROR);
    assert(com_decommit(msg_2, msg_2_size, &rand_com_1, &com_1_2) == MT_ERROR);
    assert(com_decommit(msg_2, msg_2_size, &rand_com_1, &com_2_2) == MT_ERROR);
    assert(com_decommit(msg_1, msg_1_size, &rand_com_2, &com_1_1) == MT_ERROR);
    assert(com_decommit(msg_1, msg_1_size, &rand_com_2, &com_2_1) == MT_ERROR);
    assert(com_decommit(msg_1, msg_1_size, &rand_com_2, &com_2_2) == MT_ERROR);
    assert(com_decommit(msg_2, msg_2_size, &rand_com_2, &com_1_1) == MT_ERROR);
    assert(com_decommit(msg_2, msg_2_size, &rand_com_2, &com_1_2) == MT_ERROR);
    assert(com_decommit(msg_2, msg_2_size, &rand_com_2, &com_2_1) == MT_ERROR);

    //------------------------------- test bsig ------------------------------//

    //TODO: not sure if we can have bsig only apply to the hash
    byte msg_1_hash[SIZE_HASH];
    byte blinded[SIZE_BL];
    byte unblinder[SIZE_UBLR];
    byte blind_sig[SIZE_SIG];
    byte unblinded_sig[SIZE_SIG];

    bsig_blind(msg_1, msg_1_size, &pk1, &blinded, &unblinder);
    sig_sign(blinded, SIZE_BL, &sk2, &blind_sig);
    bsig_unblind(&pk1, &blind_sig, &unblinder, &unblinded_sig);


    // check that the original message is not same as the blinded message
    assert(memcmp(msg_1, blinded, SIZE_HASH) != 0);

    // check that the blind sig verifies
    assert(bsig_verify(msg_1, msg_1_size, &pk2, &unblinded_sig) == MT_SUCCESS);

    //------------------------------- test zpk -------------------------------//

    byte proof_1[SIZE_ZKP];
    byte proof_2[SIZE_ZKP];
    byte proof_3[SIZE_ZKP];

    zkp_prove(&pp, msg_1, msg_1_size, &proof_1);
    zkp_prove(&pp, msg_2, msg_2_size, &proof_2);
    paycrypt_rand_bytes(SIZE_ZKP, proof_3);

    // check that correct proofs are correct
    assert(zkp_verify(&pp, &proof_1) == MT_SUCCESS);
    assert(zkp_verify(&pp, &proof_2) == MT_SUCCESS);

    // check that correct proofs are not identical
    assert(memcmp(proof_1, proof_2, SIZE_ZKP) != 0);

    // check that incorrect proofs are incorrect
    assert(zkp_verify(&pp, &proof_3) == MT_ERROR);
}

int main(){
    test_crypto_lib();
    return 0;
}
