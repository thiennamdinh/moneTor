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

#ifndef token_lib_h
#define token_lib_h

#include <glib.h>
#include "crypto_lib.h" // only needed for the defined byte array sizes

#define SIZE_ADDR 20

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
 *     int - intermediary
 *     any - any party (either end user or intermediary)
 *     aut - Tor authority
 *     led - ledger
 */

typedef enum {
    // tokens that are maintained locally by a single party
    TTYPE_CHN_INT_STATE,       // intermediary micropayment state
    TTYPE_CHN_END_SECRET,      // end user micropayment secrets
    TTYPE_MIC_END_WALLET,      // end user wallet
    TTYPE_NAN_INT_STATE,       // end user nanopayment state
    TTYPE_NAN_END_STATE,       // intermediary nanopayment state
    TTYPE_NAN_END_SECRET,      // end user nanopayment secrets

    // tokens that get sent to other  parties within the channel protocols
    TTYPE_CHN_END_CHANTOK,     // end user micropayment channel token
    TTYPE_CHN_INT_CHANTOK,     // intermediary micropayment channel token
    TTYPE_NAN_ANY_CHANTOK,     // nanopayment channel token
    TTYPE_CHN_END_REVOKE,      // end user revocation of a wallet/nano channel
    TTYPE_CHN_END_REFUND,      // end user nanopayment refund token

    // tokens for posting to the ledger
    TTYPE_MAC_AUT_MINT,        // message by tor authority to mint coins
    TTYPE_MAC_ANY_TRANS,       // macropayment transaction
    TTYPE_CHN_END_ESCROW,      // end user escrow transaction
    TTYPE_CHN_INT_ESCROW,      // intermediary escrow transaction
    TTYPE_CHN_INT_REQCLOSE,    // intermediary msg to request a user closure
    TTYPE_CHN_END_CLOSE,       // end user microchannel closure message
    TTYPE_CHN_INT_CLOSE,       // intermediary microchannel closure message
    TTYPE_CHN_END_CASHOUT,     // cash out of closed channel
    TTYPE_CHN_INT_CASHOUT,     // cash out of closed channel

    // tokens for querying the ledger
    TTYPE_MAC_LED_DATA,        // macropayment ledger data mapped to an address
    TTYPE_CHN_LED_DATA,        // channel ledger data mapped to an address
    TTYPE_MAC_LED_QUERY,       // request to query macropayment data
    TTYPE_CHN_LED_QUERY,       // request to query channel data
} ttype;

// special codes used to identify types of signed tokens
typedef enum {
    CODE_REFUND,
    CODE_ACCEPT,
    CODE_REVOKE,
    CODE_REQCLOSE,
} code;

// possible states for micropayment channels
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
} chn_end_chantok;

typedef struct {
    int balance;
    byte esc_pk[SIZE_PK];
} chn_int_chantok;

typedef struct {
    int val_from;
    int val_to;
    int num_payments;
    byte hash_tail[SIZE_HASH];
} nan_any_chantok;

typedef struct {
    code code;
    byte wpk[SIZE_PK];
    int balance;

    // blank if refund for micropayment
    nan_any_chantok channel_token;

    // partial blind sig on everything but the code
    byte sig[SIZE_SIG];
    byte unblinder[SIZE_UBLR];
} chn_end_refund;

typedef struct {
    int value;
} mac_aut_mint;

typedef struct {
    int val_to;
    int val_from;
    byte from[SIZE_ADDR];
    byte to[SIZE_ADDR];
} mac_any_trans;

typedef struct {
    int val_to;
    int val_from;
    byte from[SIZE_ADDR];
    byte chan[SIZE_ADDR];
    chn_end_chantok chn_token;
} chn_end_escrow;

typedef struct {
    int val_to;
    int val_from;
    byte from[SIZE_ADDR];
    byte chan[SIZE_ADDR];
    chn_int_chantok chn_token;
} chn_int_escrow;

typedef struct {
    byte chan[SIZE_ADDR];
    byte sig[SIZE_SIG];
} chn_int_reqclose;

typedef struct {
    byte chan[SIZE_ADDR];
    chn_end_refund refund_token;

    int last_pay_num;
    byte last_hash[SIZE_HASH];
} chn_end_close;

typedef struct {
    int code;
    byte chan[SIZE_ADDR];
    chn_end_revoke revocation;

    int last_pay_num;
    byte last_hash[SIZE_HASH];
} chn_int_close;

typedef struct {
    int val_from;
    int val_to;
    byte chan[SIZE_ADDR];
    byte from[SIZE_ADDR];
    byte to[SIZE_ADDR];
} chn_end_cashout;

typedef struct {
    int val_from;
    int val_to;
    byte chan[SIZE_ADDR];
    byte from[SIZE_ADDR];
    byte to[SIZE_ADDR];
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

    chn_end_chantok end_chn_token;
    chn_int_chantok int_chn_token;

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

//-------------------------- Pack/Unpack Functions --------------------------//

// extract the token type from the packed message
ttype token_type(byte* str);

// convert semantically meaningful structs to sendable byte strings & sizes

int pack_chn_end_chantok(chn_end_chantok token, byte** str_out);
int pack_chn_int_chantok(chn_int_chantok token, byte** str_out);
int pack_nan_any_chantok(nan_any_chantok token, byte** str_out);
int pack_chn_end_revoke(chn_end_revoke token, byte** str_out);
int pack_chn_end_refund(chn_end_refund token, byte** str_out);

int pack_mac_aut_mint(mac_aut_mint token, byte** str_out);
int pack_mac_any_trans(mac_any_trans token, byte** str_out);
int pack_chn_end_escrow(chn_end_escrow token, byte** str_out);
int pack_chn_int_escrow(chn_int_escrow token, byte** str_out);
int pack_chn_int_reqclose(chn_int_reqclose token, byte** str_out);
int pack_chn_end_close(chn_end_close token, byte** str_out);
int pack_chn_int_close(chn_int_close token, byte** str_out);
int pack_chn_end_cashout(chn_end_cashout token, byte** str_out);
int pack_chn_int_cashout(chn_int_cashout token, byte** str_out);

int pack_mac_led_data(mac_led_data token, byte** str_out);
int pack_chn_led_data(chn_led_data token, byte** str_out);

// convert sendable byte strings to semantically meaningful structs

chn_end_chantok unpack_chn_end_chantok(byte* str);
chn_int_chantok unpack_chn_int_chantok(byte* str);
nan_any_chantok unpack_nan_any_chantok(byte* str);
chn_end_revoke unpack_chn_end_revoke(byte* str);
chn_end_refund unpack_chn_end_refund(byte* str);

mac_aut_mint unpack_mac_aut_mint(byte* str);
mac_any_trans unpack_mac_any_trans(byte* str);
chn_end_escrow unpack_chn_end_escrow(byte* str);
chn_int_escrow unpack_chn_int_escrow(byte* str);
chn_int_reqclose unpack_chn_int_reqclose(byte* str);
chn_end_close unpack_chn_end_close(byte* str);
chn_int_close unpack_chn_int_close(byte* str);
chn_end_cashout unpack_chn_end_cashout(byte* str);
chn_int_cashout unpack_chn_int_cashout(byte* str);

mac_led_data unpack_mac_led_data(byte* str);
chn_led_data unpack_chn_led_data(byte* str);
mac_led_query unpack_mac_led_query(byte* str);
chn_led_query unpack_chn_led_query(byte* str);

#endif
