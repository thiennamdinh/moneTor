#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "../mt_crypto.h"
#include "../mt_tokens.h"
#include "../mt_utils.h"
#include "../mt_ledger.h"
#include "test_mt_main.h"

void test_mt_ledger(){

    //----------------------------------- Setup ---------------------------------//

    // pretend everything is in cents
    int fee = 5;
    double tax = 0.1;
    int close_window = 10;
    byte pp[SIZE_PP];

    paycrypt_setup(&pp);

    // set up roger
    byte roger_pk[SIZE_PK];
    byte roger_sk[SIZE_SK];
    byte roger_addr[SIZE_ADDR];
    paycrypt_keygen(&pp, &roger_pk, &roger_sk);
    pk_to_addr(&roger_pk, &roger_addr);

    ledger_setup(&pp, fee, tax, close_window, &roger_pk);

    // set up end user
    byte end_pk_1[SIZE_PK];
    byte end_sk_1[SIZE_SK];
    byte end_addr_1[SIZE_ADDR];
    paycrypt_keygen(&pp, &end_pk_1, &end_sk_1);
    pk_to_addr(&end_pk_1, &end_addr_1);

    // set up intermediary
    byte int_pk_1[SIZE_PK];
    byte int_sk_1[SIZE_SK];
    byte int_addr_1[SIZE_ADDR];
    paycrypt_keygen(&pp, &int_pk_1, &int_sk_1);
    pk_to_addr(&int_pk_1, &int_addr_1);

    // set up channel
    byte chn_addr[SIZE_ADDR];
    paycrypt_rand_bytes(SIZE_ADDR, chn_addr);

    // hash chain for nanopayments
    int n = 1000;
    byte head[SIZE_HASH];
    byte hc[n][SIZE_HASH];
    paycrypt_rand_bytes(SIZE_HASH, head);
    hash_create_chain(n, &head, &hc);
    int k = 58;

    char roger_hex[SIZE_ADDR * 2 + 3] ;
    char end_hex[SIZE_ADDR * 2 + 3] ;
    char int_hex[SIZE_ADDR * 2 + 3] ;

    addr_to_hex(&roger_addr, &roger_hex);
    addr_to_hex(&end_addr_1, &end_hex);
    addr_to_hex(&int_addr_1, &int_hex);

    //printf("rog addr %s\n", roger_hex);
    //printf("end addr %s\n", end_hex);
    //printf("int addr %s\n", int_hex);

    //---------------------------------- Mint -----------------------------------//

    // mint first token
    int mint_val_1 = 1000 * 100;
    mac_aut_mint mint_1 = {.value = mint_val_1};
    byte* mint_str_1;
    pack_mac_aut_mint(mint_1, &roger_pk, &roger_sk, &mint_str_1);
    assert(post(mint_str_1) == MT_SUCCESS);

    // mint second otken
    int mint_val_2 = 1500 * 100;
    mac_aut_mint mint_2 = {.value = mint_val_2};
    byte* mint_str_2;
    pack_mac_aut_mint(mint_2, &roger_pk, &roger_sk, &mint_str_2);
    assert(post(mint_str_2) == MT_SUCCESS);

    //------------------------------ Transfer -----------------------------------//

    int end_val = 100 * 100;
    int int_val = 1000 * 100;

    // transfer to end user
    mac_any_trans end_trans = {.val_from = end_val + fee, .val_to = end_val};
    memcpy(end_trans.from, roger_addr, SIZE_ADDR);
    memcpy(end_trans.to, end_addr_1, SIZE_ADDR);
    byte* end_trans_str;
    pack_mac_any_trans(end_trans, &roger_pk, &roger_sk, &end_trans_str);
    assert(post(end_trans_str) == MT_SUCCESS);

    // transfer to intermediary
    mac_any_trans int_trans = {.val_from = int_val + fee, .val_to = int_val};
    memcpy(int_trans.from, roger_addr, SIZE_ADDR);
    memcpy(int_trans.to, int_addr_1, SIZE_ADDR);
    byte* int_trans_str;
    pack_mac_any_trans(int_trans, &roger_pk, &roger_sk, &int_trans_str);
    assert(post(int_trans_str) == MT_SUCCESS);

    //------------------------------- Post Escrow -------------------------------//

    int end_esc_val = 90 * 100;
    int int_esc_val = 900 * 100;

    // end user escrow
    chn_end_escrow end_esc = {.val_from = end_esc_val + fee, .val_to =   end_esc_val};
    memcpy(end_esc.from, end_addr_1, SIZE_ADDR);
    memcpy(end_esc.chn, chn_addr, SIZE_ADDR);
    // ignore channel token

    // send to ledger
    byte* end_esc_str;
    pack_chn_end_escrow(end_esc, &end_pk_1, &end_sk_1, &end_esc_str);
    assert(post(end_esc_str) == MT_SUCCESS);

    // intermediary escrow
    chn_int_escrow int_esc = {.val_from = int_esc_val + fee, .val_to =   int_esc_val};
    memcpy(int_esc.from, int_addr_1, SIZE_ADDR);
    memcpy(int_esc.chn, chn_addr, SIZE_ADDR);
    // ignore channel token

    // send to ledger
    byte* int_esc_str;
    pack_chn_int_escrow(int_esc, &int_pk_1, &int_sk_1, &int_esc_str);
    assert(post(int_esc_str) == MT_SUCCESS);

    //------------------------ Intermediary Request Close -----------------------//

    chn_int_reqclose reqclose;
    memcpy(reqclose.chn, chn_addr, SIZE_ADDR);
    byte* reqclose_str;
    pack_chn_int_reqclose(reqclose, &int_pk_1, &int_sk_1, &reqclose_str);
    assert(post(reqclose_str) == MT_SUCCESS);

    //------------------------------ End User Close -----------------------------//

    chn_end_close end_close = {.last_pay_num = k};
    memcpy(end_close.chn, chn_addr, SIZE_ADDR);
    memcpy(end_close.last_hash, hc[k], SIZE_HASH);
    byte* end_close_str;
    pack_chn_end_close(end_close, &end_pk_1, &end_sk_1, &end_close_str);
    assert(post(end_close_str) == MT_SUCCESS);

    //---------------------------- Intermediary Close ---------------------------//

    chn_int_close int_close = {.close_code = CODE_ACCEPT, .last_pay_num = k};
    memcpy(int_close.chn, chn_addr, SIZE_ADDR);
    memcpy(int_close.last_hash, hc[k], SIZE_HASH);
    byte* int_close_str;
    pack_chn_int_close(int_close, &int_pk_1, &int_sk_1, &int_close_str);
    assert(post(int_close_str) == MT_SUCCESS);

    //-------------------------------- Cash Out ---------------------------------//

    int end_cashout_val = 50 * 100;
    int int_cashout_val = 50 * 100;

    // end user cash out
    chn_end_cashout end_cashout = {.val_from = end_cashout_val + fee, .val_to = end_cashout_val};
    memcpy(end_cashout.chn, chn_addr, SIZE_ADDR);
    byte* end_cashout_str;
    pack_chn_end_cashout(end_cashout, &end_pk_1, &end_sk_1, &end_cashout_str);
    assert(post(end_cashout_str) == MT_SUCCESS);

    // intermediary cash out
    chn_int_cashout int_cashout;
    int_cashout.val_from = int_cashout_val + fee + (int_cashout_val * tax);
    int_cashout.val_to = int_cashout_val;
    memcpy(int_cashout.chn, chn_addr, SIZE_ADDR);
    byte* int_cashout_str;
    pack_chn_int_cashout(int_cashout, &int_pk_1, &int_sk_1, &int_cashout_str);
    assert(post(int_cashout_str) == MT_SUCCESS);

    //---------------------------------- Query ----------------------------------//

    byte pk_discard[SIZE_PK];

    // query roger
    mac_led_query roger_query;
    byte* roger_query_str;
    byte* roger_str_out;
    mac_led_data roger_out;
    memcpy(&roger_query.addr, roger_addr, SIZE_ADDR);
    pack_mac_led_query(roger_query, &roger_pk, &roger_sk, &roger_query_str);
    assert(query(roger_query_str, &roger_str_out) == MT_SUCCESS);
    unpack_mac_led_data(roger_str_out, &roger_out, &pk_discard);

    // query end user
    mac_led_query end_query;
    byte* end_query_str;
    byte* end_str_out;
    mac_led_data end_out;
    memcpy(&end_query.addr, end_addr_1, SIZE_ADDR);
    pack_mac_led_query(end_query, &roger_pk, &roger_sk, &end_query_str);
    assert(query(end_query_str, &end_str_out) == MT_SUCCESS);
    unpack_mac_led_data(end_str_out, &end_out, &pk_discard);

    // query intermediary
    mac_led_query int_query;
    byte* int_query_str;
    byte* int_str_out;
    mac_led_data int_out;
    memcpy(&int_query.addr, int_addr_1, SIZE_ADDR);
    pack_mac_led_query(int_query, &roger_pk, &roger_sk, &int_query_str);
    assert(query(int_query_str, &int_str_out) == MT_SUCCESS);
    unpack_mac_led_data(int_str_out, &int_out, &pk_discard);

    // query channel
    chn_led_query chn_query;
    byte* chn_query_str;
    byte* chn_str_out;
    chn_led_data chn_out;
    memcpy(&chn_query.addr, chn_addr, SIZE_ADDR);
    pack_chn_led_query(chn_query, &roger_pk, &roger_sk, &chn_query_str);
    assert(query(chn_query_str, &chn_str_out) == MT_SUCCESS);
    unpack_chn_led_data(chn_str_out, &chn_out, &pk_discard);

    printf("roger %d\n", roger_out.balance);
    printf("end %d\n", end_out.balance);
    printf("int %d\n", int_out.balance);
    printf("channel end  %d\n", chn_out.end_balance);
    printf("channel int  %d\n", chn_out.int_balance);
}
