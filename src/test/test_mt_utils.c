#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "../mt_crypto.h"
#include "../mt_tokens.h"
#include "../mt_utils.h"
#include "test_mt_main.h"

//gcc test/test_payment_utils.c token_lib.c payment_utils.c crypto_lib.c -o test/test_payment_utils `pk-config --cflags --libs glib-2.0` -lssl -lcrypto

void test_mt_utils(){

    byte pp[SIZE_PP];
    byte pk[SIZE_PK];
    byte sk[SIZE_SK];

    paycrypt_setup(&pp);
    paycrypt_keygen(&pp, &pk, &sk);

    //----------------------------- Test PK to Address ---------------------------//

    byte pk_copy[SIZE_PK];
    byte pk_diff[SIZE_PK];
    byte sk_diff[SIZE_SK];

    memcpy(pk_copy, pk, SIZE_PK);
    paycrypt_keygen(&pp, &pk_diff, &sk_diff);

    byte addr[SIZE_ADDR];
    byte addr_copy[SIZE_ADDR];
    byte addr_diff[SIZE_ADDR];

    pk_to_addr(&pk, &addr);
    pk_to_addr(&pk_copy, &addr_copy);
    pk_to_addr(&pk_diff, &addr_diff);

    assert(memcmp(addr, addr_copy, SIZE_ADDR) == 0);
    assert(memcmp(addr, addr_diff, SIZE_ADDR) != 0);

    //----------------------------- Test Address to Hex --------------------------//

    byte addr_str[SIZE_ADDR] = "20 bytes ++)(*_*)///";
    char expected_hex[SIZE_ADDR * 2 + 3] = "0x3230206279746573202B2B29282A5F2A292F2F2F\0";
    char hex_out[SIZE_ADDR * 2 + 3];

    addr_to_hex(&addr_str, &hex_out);

    assert(memcmp(expected_hex, hex_out, strlen(hex_out)) == 0);

    //----------------------------- Test Hash Chains -----------------------------//

    int hc_size = 1000;
    byte head[SIZE_HASH];
    byte hc[hc_size][SIZE_HASH];

    paycrypt_rand_bytes(SIZE_HASH, head);
    hash_create_chain(hc_size, &head, &hc);

    // make sure correct hashes are correct
    assert(hash_verify_chain(&(hc[0]), &(hc[0]), 0) == MT_SUCCESS);
    assert(hash_verify_chain(&(hc[0]), &(hc[hc_size / 2]), hc_size / 2) == MT_SUCCESS);
    assert(hash_verify_chain(&(hc[0]), &(hc[hc_size - 1]), hc_size - 1) == MT_SUCCESS);

    // make sure incorrect hashes are incorrect
    assert(hash_verify_chain(&(hc[0]), &(hc[hc_size - 1]), 0) == MT_ERROR);
    assert(hash_verify_chain(&(hc[0]), &(hc[hc_size / 2]), hc_size / 3 - 1) == MT_ERROR);
    assert(hash_verify_chain(&(hc[0]), &(hc[0]), hc_size) == MT_ERROR);

    //----------------------------- Test Commit Wallet ---------------------------//

    //----------------------------- Test Verify Refund ---------------------------//

}
