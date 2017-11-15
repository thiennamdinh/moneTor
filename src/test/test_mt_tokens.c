#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "../mt.h"
#include "../mt_crypto.h"
#include "../mt_tokens.h"
#include "test_mt_main.h"

typedef unsigned char byte;

/**
 * Take a void pointer and overwrite the given number of bytes with random numbers
 *
 * terminal command (until we have a make file)
 * gcc test_token_lib.c token_lib.c payment_utils.c crypto_lib.c -o test_token_lib
 * `pkg-config --cflags --libs glib-2.0` && ./test_token_lib
 */
void write_random_bytes(void* data, int size){
    byte* str = (byte*)data;
    for(int i = 0; i < size; i++){
	str[i] = (byte)rand();
    }
}

void test_mt_tokens(){

    byte pp[SIZE_PP];
    byte pk[SIZE_PK];
    byte sk[SIZE_SK];
    paycrypt_setup(&pp);
    paycrypt_keygen(&pp, &pk, &sk);

    // declare each type of token
    mac_aut_mint tk1_mac_aut_mint;
    mac_any_trans tk1_mac_any_trans;
    chn_end_escrow tk1_chn_end_escrow;
    chn_int_escrow tk1_chn_int_escrow;
    chn_int_reqclose tk1_chn_int_reqclose;
    chn_end_close tk1_chn_end_close;
    chn_int_close tk1_chn_int_close;
    chn_end_cashout tk1_chn_end_cashout;
    chn_int_cashout tk1_chn_int_cashout;

    // fill the tokens with random info so we don't get any trivial blank tokens
    write_random_bytes(&tk1_mac_aut_mint, sizeof(mac_aut_mint));
    write_random_bytes(&tk1_mac_any_trans, sizeof(mac_any_trans));
    write_random_bytes(&tk1_chn_end_escrow, sizeof(chn_end_escrow));
    write_random_bytes(&tk1_chn_int_escrow, sizeof(chn_int_escrow));
    write_random_bytes(&tk1_chn_int_reqclose, sizeof(chn_int_reqclose));
    write_random_bytes(&tk1_chn_end_close, sizeof(chn_end_close));
    write_random_bytes(&tk1_chn_int_close, sizeof(chn_int_close));
    write_random_bytes(&tk1_chn_end_cashout, sizeof(chn_end_cashout));
    write_random_bytes(&tk1_chn_int_cashout, sizeof(chn_int_cashout));

    // string pointers that will point to the network sendable strings
    cell_t* cell_mac_aut_mint;
    cell_t* cell_mac_any_trans;
    cell_t* cell_chn_end_escrow;
    cell_t* cell_chn_int_escrow;
    cell_t* cell_chn_int_reqclose;
    cell_t* cell_chn_end_close;
    cell_t* cell_chn_int_close;
    cell_t* cell_chn_end_cashout;
    cell_t* cell_chn_int_cashout;

    // pack the original tokens into the strings
    pack_mac_aut_mint(tk1_mac_aut_mint, &pk, &sk, &cell_mac_aut_mint);
    pack_mac_any_trans(tk1_mac_any_trans, &pk, &sk, &cell_mac_any_trans);
    pack_chn_end_escrow(tk1_chn_end_escrow, &pk, &sk, &cell_chn_end_escrow);
    pack_chn_int_escrow(tk1_chn_int_escrow, &pk, &sk, &cell_chn_int_escrow);
    pack_chn_int_reqclose(tk1_chn_int_reqclose, &pk, &sk, &cell_chn_int_reqclose);
    pack_chn_end_close(tk1_chn_end_close, &pk, &sk, &cell_chn_end_close);
    pack_chn_int_close(tk1_chn_int_close, &pk, &sk, &cell_chn_int_close);
    pack_chn_end_cashout(tk1_chn_end_cashout, &pk, &sk, &cell_chn_end_cashout);
    pack_chn_int_cashout(tk1_chn_int_cashout, &pk, &sk, &cell_chn_int_cashout);

    // declare each type of token
    mac_aut_mint tk2_mac_aut_mint;
    mac_any_trans tk2_mac_any_trans;
    chn_end_escrow tk2_chn_end_escrow;
    chn_int_escrow tk2_chn_int_escrow;
    chn_int_reqclose tk2_chn_int_reqclose;
    chn_end_close tk2_chn_end_close;
    chn_int_close tk2_chn_int_close;
    chn_end_cashout tk2_chn_end_cashout;
    chn_int_cashout tk2_chn_int_cashout;

    // extract new tokens from the strings
    unpack_mac_aut_mint(cell_mac_aut_mint, &tk2_mac_aut_mint, &pk);
    unpack_mac_any_trans(cell_mac_any_trans, &tk2_mac_any_trans, &pk);
    unpack_chn_end_escrow(cell_chn_end_escrow, &tk2_chn_end_escrow, &pk);
    unpack_chn_int_escrow(cell_chn_int_escrow, &tk2_chn_int_escrow, &pk);
    unpack_chn_int_reqclose(cell_chn_int_reqclose, &tk2_chn_int_reqclose, &pk);
    unpack_chn_end_close(cell_chn_end_close, &tk2_chn_end_close, &pk);
    unpack_chn_int_close(cell_chn_int_close, &tk2_chn_int_close, &pk);
    unpack_chn_end_cashout(cell_chn_end_cashout, &tk2_chn_end_cashout, &pk);
    unpack_chn_int_cashout(cell_chn_int_cashout, &tk2_chn_int_cashout, &pk);

    // assert that the original tokens are identical to the new torkns
    assert(memcmp(&tk1_mac_aut_mint, &tk2_mac_aut_mint, sizeof(mac_aut_mint)) == 0);
    assert(memcmp(&tk1_mac_any_trans, &tk2_mac_any_trans, sizeof(mac_any_trans)) == 0);
    assert(memcmp(&tk1_chn_end_escrow, &tk2_chn_end_escrow, sizeof(chn_end_escrow)) == 0);
    assert(memcmp(&tk1_chn_int_escrow, &tk2_chn_int_escrow, sizeof(chn_int_escrow)) == 0);
    assert(memcmp(&tk1_chn_int_reqclose, &tk2_chn_int_reqclose, sizeof(chn_int_reqclose)) == 0);
    assert(memcmp(&tk1_chn_end_close, &tk2_chn_end_close, sizeof(chn_end_close)) == 0);
    assert(memcmp(&tk1_chn_int_close, &tk2_chn_int_close, sizeof(chn_int_close)) == 0);
    assert(memcmp(&tk1_chn_end_cashout, &tk2_chn_end_cashout, sizeof(chn_end_cashout)) == 0);
    assert(memcmp(&tk1_chn_int_cashout, &tk2_chn_int_cashout, sizeof(chn_int_cashout)) == 0);
}
