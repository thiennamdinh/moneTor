/**
   This module defines all high-level tokens used by the moneTor payment system
   (using structs). It also contains macro definitions to interpret token types
   and pack/unpack functions to convert between the semantically-meaningful c
   structs and the compressed byte arrays.

   The intent is that other moneTor modules will use these definitions to more
   clearly and consistently perform local operations on the various tokens
   without having to worry about how they appear on the network.
 */

//TODO: move signed_msg to utils

#ifndef mt_token_h
#define mt_token_h

#include <glib.h>
#include "mt_crypto.h" // only needed for the defined byte array sizes

#define MT_SUCCESS 0
#define MT_ERROR -1

#define SIZE_ADDR 20

typedef unsigned char byte;

//----------------------------- Token Types ---------------------------------//

/**
 * High-level token structures housing the information necessary to operate the
 * moneTor payment scheme. Most have 1:1 correlations with symbols in the formal
 * protocol algorithm documentation. The following conventions are maintained:
 *
 * prefix 1: token type
 *     mic - pertains to micropayments only
 *     nan - pertains to nanopayments only
 *     chn - pertains to both nano and micropayments
 *     mac - macropayments (normal transfers on the ledger)
 *
 * prefix 2: party
 *     end - end user (Tor client or relay)
 *     cli - Tor client
 *     rel - Tor relay
 *     int - intermediary
 *     any - any party (either end user or intermediary)
 *     aut - Tor authority
 *     led - ledger
 */

/**
 * Locally maintained tokens that are never sent directly over the network
 */
typedef enum {

    LTYPE_CHN_INT_STATE,       // intermediary micropayment state
    LTYPE_CHN_END_SECRET,      // end user micropayment secrets
    LTYPE_MIC_END_WALLET,      // end user wallet
    LTYPE_NAN_INT_STATE,       // end user nanopayment state
    LTYPE_NAN_END_STATE,       // intermediary nanopayment state
    LTYPE_NAN_END_SECRET,      // end user nanopayment secrets

    LTYPE_CHN_END_CHNTOK,     // end user micropayment channel token
    LTYPE_CHN_INT_CHNTOK,     // intermediary micropayment channel token
    LTYPE_NAN_ANY_CHNTOK,     // nanopayment channel token
    LTYPE_CHN_END_REVOKE,      // end user revocation of a wallet/nano channel
    LTYPE_CHN_END_REFUND,      // end user nanopayment refund token
} ltype;

/**
 * Tokens that need to be sent across the network at one point or another
 */
typedef enum {

    // channel establish protocol messages
    NTYPE_CHN_END_ESTAB1,
    NTYPE_CHN_INT_ESTAB2,
    NTYPE_CHN_END_ESTAB3,
    NTYPE_CHN_INT_ESTAB4,

    // micropayment pay protocol messages
    NTYPE_MIC_CLI_PAY1,
    NTYPE_MIC_REL_PAY2,
    NTYPE_MIC_CLI_PAY3,
    NTYPE_MIC_INT_PAY4,
    NTYPE_MIC_CLI_PAY5,
    NTYPE_MIC_REV_PAY6,
    NTYPE_MIC_INT_PAY7,
    NTYPE_MIC_INT_PAY8,

    // nanopayment setup protocol messages
    NTYPE_NAN_CLI_SETUP1,
    NTYPE_NAN_INT_SETUP2,
    NTYPE_NAN_CLI_SETUP3,
    NTYPE_NAN_INT_SETUP4,
    NTYPE_NAN_CLI_SETUP5,
    NTYPE_NAN_INT_SETUP6,

    // nanopayment establish protocol messages
    NTYPE_NAN_CLI_ESTAB1,
    NTYPE_NAN_REL_ESTAB2,
    NTYPE_NAN_INT_ESTAB3,
    NTYPE_NAN_REL_ESTAB4,
    NTYPE_NAN_INT_ESTAB5,

    // nanopayment close protocol messages
    NTYPE_NAN_END_CLOSE1,
    NTYPE_NAN_INT_CLOSE2,
    NTYPE_NAN_END_CLOSE3,
    NTYPE_NAN_INT_CLOSE4,
    NTYPE_NAN_END_CLOSE5,
    NTYPE_NAN_INT_CLOSE6,
    NTYPE_NAN_END_CLOSE7,
    NTYPE_NAN_INT_CLOSE8,

    // tokens for posting to the ledger
    NTYPE_MAC_AUT_MINT,        // message by tor authority to mint coins
    NTYPE_MAC_ANY_TRANS,       // macropayment transaction
    NTYPE_CHN_END_ESCROW,      // end user escrow transaction
    NTYPE_CHN_INT_ESCROW,      // intermediary escrow transaction
    NTYPE_CHN_INT_REQCLOSE,    // intermediary msg to request a user closure
    NTYPE_CHN_END_CLOSE,       // end user microchannel closure message
    NTYPE_CHN_INT_CLOSE,       // intermediary microchannel closure message
    NTYPE_CHN_END_CASHOUT,     // cash out of closed channel
    NTYPE_CHN_INT_CASHOUT,     // cash out of closed channel

    // tokens for querying the ledger
    NTYPE_MAC_LED_DATA,        // macropayment ledger data mapped to an address
    NTYPE_CHN_LED_DATA,        // channel ledger data mapped to an address
    NTYPE_MAC_LED_QUERY,       // request to query macropayment data
    NTYPE_CHN_LED_QUERY,       // request to query channel data
} ntype;

// special codes used by various parts of the protocol
typedef enum {
    CODE_REFUND,
    CODE_ACCEPT,
    CODE_REVOKE,
    CODE_REQCLOSE,
    CODE_ESTABLISH
} code;

// possible states for micropayment channels on the ledger
typedef enum {
    CSTATE_EMPTY,                  // channel has not yet been initialized
    CSTATE_INIT,                   // channel initialized by the end user
    CSTATE_OPEN,                   // channel is open (payments can be sent)
    CSTATE_INT_REQCLOSED,          // channel closure request sent by intermediary
    CSTATE_END_CLOSED,             // channel closed by end user
    CSTATE_INT_CLOSED,             // channel closed by both parties
    CSTATE_RESOLVED,               // final channel balances are set
} cstate;

//----------------------------- Token Structs -------------------------------//

typedef struct {
    byte rev[SIZE_PK];
    byte sig[SIZE_SIG];
} chn_end_revoke;

typedef struct {
    // public keys -> revocation tokens
    GHashTable* state;
} chn_int_state;

typedef struct {
    int num_payments;
    byte last_hash[SIZE_HASH];
} nan_end_state;

typedef struct {
    // nanochannel tokens -> nanopayment states
    GHashTable* state;
} nan_int_state;

typedef struct {
    int balance;
    byte wpk[SIZE_PK];
    byte wsk[SIZE_SK];
    byte rand[SIZE_HASH];
    chn_end_revoke revocation;
} mic_end_wallet;

typedef struct {
    int balance;
    byte commitment[SIZE_COM];
    byte esc_pk[SIZE_PK];
    byte wpk[SIZE_PK];
    byte wsk[SIZE_SK];
    byte rand[SIZE_HASH];
} chn_end_secret;

typedef struct {
    byte wpk[SIZE_PK];
    byte wsk[SIZE_SK];
    byte hash_head[SIZE_HASH];
} nan_end_secret;

typedef struct {
    int balance;
    byte esc_pk[SIZE_PK];
    byte commitment[SIZE_COM];
} chn_end_chntok;

typedef struct {
    int balance;
    byte esc_pk[SIZE_PK];
} chn_int_chntok;

typedef struct {
    int val_from;
    int val_to;
    int num_payments;
    byte hash_tail[SIZE_HASH];
} nan_any_chntok;

typedef struct {
    code refund_code;
    byte wpk[SIZE_PK];
    int balance;

    // blank if refund for micropayment
    nan_any_chntok channel_token;

    // partial blind sig on everything but the code
    byte sig[SIZE_SIG];
    byte unblinder[SIZE_UBLR];
} chn_end_refund;

typedef struct {
    int value;
} mac_aut_mint;

typedef struct {
    int val_from;
    int val_to;
    byte from[SIZE_ADDR];
    byte to[SIZE_ADDR];
} mac_any_trans;

typedef struct {
    int val_from;
    int val_to;
    byte from[SIZE_ADDR];
    byte chn[SIZE_ADDR];
    chn_end_chntok chn_token;
} chn_end_escrow;

typedef struct {
    int val_from;
    int val_to;
    byte from[SIZE_ADDR];
    byte chn[SIZE_ADDR];
    chn_int_chntok chn_token;
} chn_int_escrow;

typedef struct {
    byte chn[SIZE_ADDR];
} chn_int_reqclose;

typedef struct {
    byte chn[SIZE_ADDR];
    chn_end_refund refund_token;

    // blank for micropayment closes
    int last_pay_num;
    byte last_hash[SIZE_HASH];
} chn_end_close;

typedef struct {
    code close_code;
    byte chn[SIZE_ADDR];
    chn_end_revoke revocation;

    // blank for micropayment closes
    int last_pay_num;
    byte last_hash[SIZE_HASH];
} chn_int_close;

typedef struct {
    int val_from;
    int val_to;
    byte chn[SIZE_ADDR];
} chn_end_cashout;

typedef struct {
    int val_from;
    int val_to;
    byte chn[SIZE_ADDR];
} chn_int_cashout;

typedef struct {
    int balance;
} mac_led_data;

typedef struct{
    cstate state;

    byte end_addr[SIZE_ADDR];
    byte int_addr[SIZE_ADDR];

    int end_balance;
    int int_balance;

    chn_end_chntok end_chn_token;
    chn_int_chntok int_chn_token;

    chn_end_close end_close_token;
    chn_int_close int_close_token;

    int close_epoch;
} chn_led_data;

typedef struct {
    byte addr[SIZE_ADDR];
} mac_led_query;

typedef struct {
    byte addr[SIZE_ADDR];
} chn_led_query;

typedef struct {

} chn_end_estab1;

typedef struct {

} chn_int_estab2;

typedef struct {

} chn_end_estab3;

typedef struct {

} chn_int_estab4;

typedef struct {

} mic_cli_pay1;

typedef struct {

} mic_rel_pay2;

typedef struct {

} mic_cli_pay3;

typedef struct {

} mic_int_pay4;

typedef struct {

} mic_cli_pay5;

typedef struct {

} mic_rev_pay6;

typedef struct {

} mic_int_pay7;

typedef struct {

} mic_int_pay8;

typedef struct {

} nan_cli_setup1;

typedef struct {

} nan_int_setup2;

typedef struct {

} nan_cli_setup3;

typedef struct {

} nan_int_setup4;

typedef struct {

} nan_cli_setup5;

typedef struct {

} nan_int_setup6;

typedef struct {

} nan_cli_estab1;

typedef struct {

} nan_rel_estab2;

typedef struct {

} nan_int_estab3;

typedef struct {

} nan_rel_estab4;

typedef struct {

} nan_int_estab5;

typedef struct {

} nan_end_close1;

typedef struct {

} nan_int_close2;

typedef struct {

} nan_end_close3;

typedef struct {

} nan_int_close4;

typedef struct {

} nan_end_close5;

typedef struct {

} nan_int_close6;

typedef struct {

} nan_end_close7;

typedef struct {

} nan_int_close8;

//-------------------------- Pack/Unpack Functions --------------------------//

// extract the token type from the packed message
ntype token_type(byte* str);
int pack_token(ntype type, void* ptr, int size, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int unpack_token(ntype type, byte* str, int struct_size, void* struct_out, byte(*pk_out)[SIZE_PK]);

// convert semantically meaningful structs to sendable byte strings & sizes

int pack_mac_aut_mint(mac_aut_mint token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_mac_any_trans(mac_any_trans token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_chn_end_escrow(chn_end_escrow token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_chn_int_escrow(chn_int_escrow token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_chn_int_reqclose(chn_int_reqclose token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_chn_end_close(chn_end_close token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_chn_int_close(chn_int_close token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_chn_end_cashout(chn_end_cashout token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_chn_int_cashout(chn_int_cashout token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);

int pack_mac_led_data(mac_led_data token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_chn_led_data(chn_led_data token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_mac_led_query(mac_led_query token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_chn_led_query(chn_led_query token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);

int pack_chn_end_estab1(chn_end_estab1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_chn_int_estab2(chn_int_estab2 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_chn_end_estab3(chn_end_estab3 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_chn_int_estab4(chn_int_estab4 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);

int pack_mic_cli_pay1(mic_cli_pay1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_mic_rel_pay2(mic_rel_pay2 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_mic_cli_pay3(mic_cli_pay3 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_mic_int_pay4(mic_int_pay4 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_mic_cli_pay5(mic_cli_pay5 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_mic_rev_pay6(mic_rev_pay6 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_mic_int_pay7(mic_int_pay7 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_mic_int_pay8(mic_int_pay8 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);

int pack_nan_cli_setup1(nan_cli_setup1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_int_setup2(nan_int_setup2 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_cli_setup3(nan_cli_setup3 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_int_setup4(nan_int_setup4 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_cli_setup5(nan_cli_setup5 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_int_setup6(nan_int_setup6 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);

int pack_nan_cli_estab1(nan_cli_estab1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_rel_estab2(nan_rel_estab2 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_int_estab3(nan_int_estab3 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_rel_estab4(nan_rel_estab4 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_int_estab5(nan_int_estab5 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);

int pack_nan_end_close1(nan_end_close1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_int_close2(nan_int_close2 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_end_close3(nan_end_close3 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_int_close4(nan_int_close4 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_end_close5(nan_end_close5 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_int_close6(nan_int_close6 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_end_close7(nan_end_close7 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);
int pack_nan_int_close8(nan_int_close8 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out);

// convert sendable byte strings to semantically meaningful structs

int unpack_mac_aut_mint(byte* str, mac_aut_mint* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_mac_any_trans(byte* str, mac_any_trans* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_end_escrow(byte* str, chn_end_escrow* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_int_escrow(byte* str, chn_int_escrow* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_int_reqclose(byte* str, chn_int_reqclose* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_end_close(byte* str, chn_end_close* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_int_close(byte* str, chn_int_close* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_end_cashout(byte* str, chn_end_cashout* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_int_cashout(byte* str, chn_int_cashout* struct_out, byte(*pk_out)[SIZE_PK]);

int unpack_mac_led_data(byte* str, mac_led_data* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_led_data(byte* str, chn_led_data* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_mac_led_query(byte* str, mac_led_query* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_led_query(byte* str, chn_led_query* struct_out, byte(*pk_out)[SIZE_PK]);

int unpack_chn_end_estab1(byte* str, chn_end_estab1* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_int_estab2(byte* str, chn_int_estab2* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_end_estab3(byte* str, chn_end_estab3* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_int_estab4(byte* str, chn_int_estab4* struct_out, byte(*pk_out)[SIZE_PK]);

int unpack_mic_cli_pay1(byte* str, mic_cli_pay1* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_mic_rel_pay2(byte* str, mic_rel_pay2* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_mic_cli_pay3(byte* str, mic_cli_pay3* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_mic_int_pay4(byte* str, mic_int_pay4* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_mic_cli_pay5(byte* str, mic_cli_pay5* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_mic_rev_pay6(byte* str, mic_rev_pay6* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_mic_int_pay7(byte* str, mic_int_pay7* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_mic_int_pay8(byte* str, mic_int_pay8* struct_out, byte(*pk_out)[SIZE_PK]);

int unpack_nan_cli_setup1(byte* str, nan_cli_setup1* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_setup2(byte* str, nan_int_setup2* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_cli_setup3(byte* str, nan_cli_setup3* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_setup4(byte* str, nan_int_setup4* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_cli_setup5(byte* str, nan_cli_setup5* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_setup6(byte* str, nan_int_setup6* struct_out, byte(*pk_out)[SIZE_PK]);

int unpack_nan_cli_estab1(byte* str, nan_cli_estab1* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_rel_estab2(byte* str, nan_rel_estab2* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_estab3(byte* str, nan_int_estab3* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_rel_estab4(byte* str, nan_rel_estab4* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_estab5(byte* str, nan_int_estab5* struct_out, byte(*pk_out)[SIZE_PK]);

int unpack_nan_end_close1(byte* str, nan_end_close1* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_close2(byte* str, nan_int_close2* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_end_close3(byte* str, nan_end_close3* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_close4(byte* str, nan_int_close4* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_end_close5(byte* str, nan_end_close5* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_close6(byte* str, nan_int_close6* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_end_close7(byte* str, nan_end_close7* struct_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_close8(byte* str, nan_int_close8* struct_out, byte(*pk_out)[SIZE_PK]);


#endif
