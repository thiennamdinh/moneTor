#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "../crypto_lib.h"
#include "../token_lib.h"

typedef unsigned char byte;

/**
 * Take a void pointer and overwrite the given number of bytes with random numbers
 *
 * terminal command (until we have a make file)
 * gcc ledger.c token_lib.c payment_utils.c crypto_lib.c -o test_token_lib
 * `pkg-config --cflags --libs glib-2.0` && ./test_token_lib
 */
void write_random_bytes(void* data, int size){
    byte* str = (byte*)data;
    for(int i = 0; i < size; i++){
	str[i] = (byte)rand();
    }
}

void test_token_lib(){

    // declare each type of token
    chn_end_chantok tk1_chn_end_chantok;
    chn_int_chantok tk1_chn_int_chantok;
    nan_any_chantok tk1_nan_any_chantok;
    chn_end_revoke tk1_chn_end_revoke;
    chn_end_refund tk1_chn_end_refund;
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
    write_random_bytes(&tk1_chn_end_chantok, sizeof(chn_end_chantok));
    write_random_bytes(&tk1_chn_int_chantok, sizeof(chn_int_chantok));
    write_random_bytes(&tk1_nan_any_chantok, sizeof(nan_any_chantok));
    write_random_bytes(&tk1_chn_end_revoke, sizeof(chn_end_revoke));
    write_random_bytes(&tk1_chn_end_refund, sizeof(chn_end_refund));
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
    byte* str_chn_end_chantok;
    byte* str_chn_int_chantok;
    byte* str_nan_any_chantok;
    byte* str_chn_end_revoke;
    byte* str_chn_end_refund;
    byte* str_mac_aut_mint;
    byte* str_mac_any_trans;
    byte* str_chn_end_escrow;
    byte* str_chn_int_escrow;
    byte* str_chn_int_reqclose;
    byte* str_chn_end_close;
    byte* str_chn_int_close;
    byte* str_chn_end_cashout;
    byte* str_chn_int_cashout;

    // pack the original tokens into the strings
    pack_chn_end_chantok(tk1_chn_end_chantok, &str_chn_end_chantok);
    pack_chn_int_chantok(tk1_chn_int_chantok, &str_chn_int_chantok);
    pack_nan_any_chantok(tk1_nan_any_chantok, &str_nan_any_chantok);
    pack_chn_end_revoke(tk1_chn_end_revoke, &str_chn_end_revoke);
    pack_chn_end_refund(tk1_chn_end_refund, &str_chn_end_refund);
    pack_mac_aut_mint(tk1_mac_aut_mint, &str_mac_aut_mint);
    pack_mac_any_trans(tk1_mac_any_trans, &str_mac_any_trans);
    pack_chn_end_escrow(tk1_chn_end_escrow, &str_chn_end_escrow);
    pack_chn_int_escrow(tk1_chn_int_escrow, &str_chn_int_escrow);
    pack_chn_int_reqclose(tk1_chn_int_reqclose, &str_chn_int_reqclose);
    pack_chn_end_close(tk1_chn_end_close, &str_chn_end_close);
    pack_chn_int_close(tk1_chn_int_close, &str_chn_int_close);
    pack_chn_end_cashout(tk1_chn_end_cashout, &str_chn_end_cashout);
    pack_chn_int_cashout(tk1_chn_int_cashout, &str_chn_int_cashout);

    // extract new tokens from the strings
    chn_end_chantok tk2_chn_end_chantok = unpack_chn_end_chantok(str_chn_end_chantok);
    chn_int_chantok tk2_chn_int_chantok = unpack_chn_int_chantok(str_chn_int_chantok);
    nan_any_chantok tk2_nan_any_chantok = unpack_nan_any_chantok(str_nan_any_chantok);
    chn_end_revoke tk2_chn_end_revoke = unpack_chn_end_revoke(str_chn_end_revoke);
    chn_end_refund tk2_chn_end_refund = unpack_chn_end_refund(str_chn_end_refund);
    mac_aut_mint tk2_mac_aut_mint = unpack_mac_aut_mint(str_mac_aut_mint);
    mac_any_trans tk2_mac_any_trans = unpack_mac_any_trans(str_mac_any_trans);
    chn_end_escrow tk2_chn_end_escrow = unpack_chn_end_escrow(str_chn_end_escrow);
    chn_int_escrow tk2_chn_int_escrow = unpack_chn_int_escrow(str_chn_int_escrow);
    chn_int_reqclose tk2_chn_int_reqclose = unpack_chn_int_reqclose(str_chn_int_reqclose);
    chn_end_close tk2_chn_end_close = unpack_chn_end_close(str_chn_end_close);
    chn_int_close tk2_chn_int_close = unpack_chn_int_close(str_chn_int_close);
    chn_end_cashout tk2_chn_end_cashout = unpack_chn_end_cashout(str_chn_end_cashout);
    chn_int_cashout tk2_chn_int_cashout = unpack_chn_int_cashout(str_chn_int_cashout);

    // assert that the strings we correctly embedded with the token type
    assert(token_type(str_chn_end_chantok) == TTYPE_CHN_END_CHANTOK);
    assert(token_type(str_chn_int_chantok) == TTYPE_CHN_INT_CHANTOK);
    assert(token_type(str_nan_any_chantok) == TTYPE_NAN_ANY_CHANTOK);
    assert(token_type(str_chn_end_revoke) == TTYPE_CHN_END_REVOKE);
    assert(token_type(str_chn_end_refund) == TTYPE_CHN_END_REFUND);
    assert(token_type(str_mac_aut_mint) == TTYPE_MAC_AUT_MINT);
    assert(token_type(str_mac_any_trans) == TTYPE_MAC_ANY_TRANS);
    assert(token_type(str_chn_end_escrow) == TTYPE_CHN_END_ESCROW);
    assert(token_type(str_chn_int_escrow) == TTYPE_CHN_INT_ESCROW);
    assert(token_type(str_chn_int_reqclose) == TTYPE_CHN_INT_REQCLOSE);
    assert(token_type(str_chn_end_close) == TTYPE_CHN_END_CLOSE);
    assert(token_type(str_chn_int_close) == TTYPE_CHN_INT_CLOSE);
    assert(token_type(str_chn_end_cashout) == TTYPE_CHN_END_CASHOUT);
    assert(token_type(str_chn_int_cashout) == TTYPE_CHN_INT_CASHOUT);

    // assert that the original tokens are identical to the new torkns
    assert(memcmp(&tk1_chn_end_chantok, &tk2_chn_end_chantok, sizeof(chn_end_chantok)) == 0);
    assert(memcmp(&tk1_chn_int_chantok, &tk2_chn_int_chantok, sizeof(chn_int_chantok)) == 0);
    assert(memcmp(&tk1_nan_any_chantok, &tk2_nan_any_chantok, sizeof(nan_any_chantok)) == 0);
    assert(memcmp(&tk1_chn_end_revoke, &tk2_chn_end_revoke, sizeof(chn_end_revoke)) == 0);
    assert(memcmp(&tk1_chn_end_refund, &tk2_chn_end_refund, sizeof(chn_end_refund)) == 0);
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

int main(){
    test_token_lib();
    return 0;
}
