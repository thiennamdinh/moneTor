//TODO: move signed_msg to utils

#ifndef mt_h
#define mt_h

#include <stdint.h>
#include <glib.h>

//TODO replace all struct names with _t suffix

//------------------------------- Definitions -------------------------------//

#define MT_SUCCESS 0
#define MT_ERROR -1

typedef unsigned char byte;

typedef enum {
    CODE_VERIFIED,
    CODE_REFUND,
    CODE_ACCEPT,
    CODE_REVOKE,
    CODE_REQCLOSE,
    CODE_ESTABLISH
} code;

//-------------------- Cryptographic String Sizes (bytes) -------------------//

#define SIZE_HASH 32
#define SIZE_PK 162
#define SIZE_SK 612
#define SIZE_SIG 128
#define SIZE_COM 128

#define SIZE_BL 128
#define SIZE_UBLR 128
#define SIZE_UBLD 128

#define SIZE_PP 128
#define SIZE_ZKP 128

#define SIZE_ADDR 20

//------------------ Cryptographic Simulate Delays (microsec) ---------------//

#define DELAY_COM_COMMIT 0
#define DELAY_COM_DECOMMIT 0
#define DELAY_BSIG_BLIND 0
#define DELAY_BSIG_UNBLIND 0
#define DELAY_BSIG_VERIFY 0
#define DELAY_ZKP_PROVE 1000000
#define DELAY_ZKP_VERIFY 0

//---------------------------- Tor-Facing API -------------------------------//

typedef struct {
    int spam;
} circuit_t;

typedef struct {
    int spam;
} edge_connection_t;

typedef struct {
    int spam;
} crypt_path_t;

typedef struct{
    int spam;
} circid_t;

//TODO From tor (or.h); get rid of as soon as we import Tor classes
#define CELL_PAYLOAD_SIZE 509
typedef struct cell_t {
  circid_t circ_id; /**< Circuit which received the cell. */
  uint8_t command; /**< Type of the cell: one of CELL_PADDING, CELL_CREATE,
                    * CELL_DESTROY, etc */
  uint8_t payload[CELL_PAYLOAD_SIZE]; /**< Cell body. */
} cell_t;

#define MT_PAYLOAD_SIZE 497

typedef struct{
    circuit_t* circ;
    edge_connection_t* conn;
    crypt_path_t* layer;
} mt_ctx;

typedef int (*mt_pay_cb)(circuit_t*);
typedef int (*mt_send_cb)(cell_t*, int, mt_ctx*);

//---------------------------- Controller States ----------------------------//

typedef enum {
    CSTATE_SOMETHING,
} cstate;

typedef enum {
    RSTATE_SOMETHING,
} rstate;

typedef enum {
    ISTATE_SOMETHING,
} istate;

// possible states for micropayment channels on the ledger
typedef enum {
    LSTATE_EMPTY,                  // channel has not yet been initialized
    LSTATE_INIT,                   // channel initialized by the end user
    LSTATE_OPEN,                   // channel is open (payments can be sent)
    LSTATE_INT_REQCLOSED,          // channel closure request sent by intermediary
    LSTATE_END_CLOSED,             // channel closed by end user
    LSTATE_INT_CLOSED,             // channel closed by both parties
    LSTATE_RESOLVED,               // final channel balances are set
} lstate;

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
    LTYPE_CHN_END_REVOKE,      // end user revocation of a wallet/nano channel

    LTYPE_CHN_INT_STATE,       // intermediary micropayment state
    LTYPE_CHN_END_SECRET,      // end user micropayment secrets
    LTYPE_MIC_END_WALLET,      // end user wallet
    LTYPE_NAN_INT_STATE,       // end user nanopayment state
    LTYPE_NAN_END_STATE,       // intermediary nanopayment state
    LTYPE_NAN_END_SECRET,      // end user nanopayment secrets

    LTYPE_CHN_END_CHNTOK,      // end user micropayment channel token
    LTYPE_CHN_INT_CHNTOK,      // intermediary micropayment channel token
    LTYPE_NAN_ANY_CHNTOK,      // nanopayment channel token
    LTYPE_CHN_END_REFUND,      // end user nanopayment refund token

    LTYPE_CHN_END_DATA,        // info to maintain channel for end user
    LTYPE_CHN_INT_DATA,        // info to maintain channel for intermediary

} ltype;

/**
 * Tokens that need to be sent across the network at one point or another
 */
typedef enum {

    // channel establish protocol messages
    NTYPE_CHN_END_ESTAB1,      // to intermediary
    NTYPE_CHN_INT_ESTAB2,      // to end user
    NTYPE_CHN_END_ESTAB3,      // to intermediary
    NTYPE_CHN_INT_ESTAB4,      // to end user

    // micropayment pay protocol messages
    NTYPE_MIC_CLI_PAY1,	       // to relay
    NTYPE_MIC_REL_PAY2,	       // to client
    NTYPE_MIC_CLI_PAY3,	       // to intermediary
    NTYPE_MIC_INT_PAY4,	       // to client
    NTYPE_MIC_CLI_PAY5,	       // to relay
    NTYPE_MIC_REV_PAY6,	       // to intermediary
    NTYPE_MIC_INT_PAY7,	       // to client
    NTYPE_MIC_INT_PAY8,	       // to relay

    // nanopayment setup protocol messages
    NTYPE_NAN_CLI_SETUP1,      // to intermediary
    NTYPE_NAN_INT_SETUP2,      // to client
    NTYPE_NAN_CLI_SETUP3,      // to intermediary
    NTYPE_NAN_INT_SETUP4,      // to client
    NTYPE_NAN_CLI_SETUP5,      // to intermediary
    NTYPE_NAN_INT_SETUP6,      // to client

    // nanopayment establish protocol messages
    NTYPE_NAN_CLI_ESTAB1,      // to relay
    NTYPE_NAN_REL_ESTAB2,      // to intermediary
    NTYPE_NAN_INT_ESTAB3,      // to relay
    NTYPE_NAN_REL_ESTAB4,      // to intermediary
    NTYPE_NAN_INT_ESTAB5,      // to relay

    // nanopayment pay protocol messages
    NTYPE_NAN_CLI_PAY1,	       // to relay

    // nanopayment close protocol messages
    NTYPE_NAN_END_CLOSE1,      // to intermediary
    NTYPE_NAN_INT_CLOSE2,      // to end user
    NTYPE_NAN_END_CLOSE3,      // to intermediary
    NTYPE_NAN_INT_CLOSE4,      // to end user
    NTYPE_NAN_END_CLOSE5,      // to intermediary
    NTYPE_NAN_INT_CLOSE6,      // to end user
    NTYPE_NAN_END_CLOSE7,      // to intermediary
    NTYPE_NAN_INT_CLOSE8,      // to end user

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

//----------------------------- Local Tokens --------------------------------//

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
    chn_end_revoke revoke;
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
    byte esk_pk[SIZE_PK];
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

    // blank except for conditional refund
    byte conditional[SIZE_PK];

    // blank if refund for micropayment
    nan_any_chntok channel_token;

    // partial blind sig on everything but the code
    byte sig[SIZE_SIG];
    byte unblinder[SIZE_UBLR];
} chn_end_refund;

typedef struct {
    byte pk[SIZE_PK];
    byte sk[SIZE_SK];
    int balance;
} mac_end_data;

typedef struct {
    lstate state;
    byte pk[SIZE_PK];
    byte sk[SIZE_SK];
    int balance;

    mic_end_wallet wallet;
    chn_end_secret chn_secret;
    chn_end_chntok chn_token;

    nan_any_chntok nan_token;
    nan_end_state nan_state;
    nan_end_secret nan_secret;
    chn_end_refund refund;
} chn_end_data;

typedef struct {
    istate state;
    byte pk[SIZE_PK];
    byte sk[SIZE_SK];
    int balance;

    chn_int_state chn_state;
    nan_int_state nan_state;
    chn_int_chntok chn_token;
} chn_int_data;

//----------------------------- Network Tokens --------------------------//

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
    chn_end_revoke revoke;

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
    lstate state;

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
    byte zkp[SIZE_ZKP];
} chn_end_estab1;

typedef struct {
    code verified;
} chn_int_estab2;

typedef struct {
    byte wcom[SIZE_COM];
} chn_end_estab3;

typedef struct {
    byte sig[SIZE_SIG];
} chn_int_estab4;

typedef struct {
    int value;
} mic_cli_pay1;

typedef struct {
    byte wcom[SIZE_COM];
    byte zkp[SIZE_ZKP];
} mic_rel_pay2;

typedef struct {
    byte cli_valcom[SIZE_COM];
    byte rel_valcom[SIZE_COM];
    byte cli_wcom[SIZE_COM];
    byte rel_wcom[SIZE_COM];
    byte cli_zkp[SIZE_ZKP];
    byte rel_zkp[SIZE_ZKP];
} mic_cli_pay3;

typedef struct {
    chn_end_refund cli_refund;
    chn_end_refund rel_refund;
} mic_int_pay4;

typedef struct {
    chn_end_revoke cli_revoke;
    chn_end_refund rel_refund;
} mic_cli_pay5;

typedef struct {
    chn_end_revoke cli_revoke;
    chn_end_revoke rel_revoke;
} mic_rev_pay6;

typedef struct {
    byte wsig[SIZE_SIG];
} mic_int_pay7;

typedef struct {
    byte wsig[SIZE_SIG];
} mic_int_pay8;

typedef struct {
    byte wpk[SIZE_PK];
    byte nwpk[SIZE_PK];
    byte wcom[SIZE_COM];
    byte zkp[SIZE_ZKP];
    nan_any_chntok chntok;
} nan_cli_setup1;

typedef struct {
    code verified;
} nan_int_setup2;

typedef struct {
    byte nwcom[SIZE_COM];
} nan_cli_setup3;

typedef struct {
    byte sig[SIZE_SIG];
} nan_int_setup4;

typedef struct {
    chn_end_revoke revoke;
} nan_cli_setup5;

typedef struct {
    code established;
} nan_int_setup6;

typedef struct {
    nan_any_chntok chntok;
} nan_cli_estab1;

typedef struct {
    byte rel_wpk[SIZE_PK];
    byte rel_nwpk[SIZE_PK];
    byte nwcom[SIZE_COM];
    byte zkp[SIZE_ZKP];
    nan_any_chntok chntok;
} nan_rel_estab2;

typedef struct {
    code verified;
} nan_int_estab3;

typedef struct {
    byte nwcom[SIZE_COM];
} nan_rel_estab4;

typedef struct {
    byte sig[SIZE_SIG];
} nan_int_estab5;

typedef struct {
    byte preimage[SIZE_HASH];
} nan_cli_pay1;

typedef struct {
    byte wpk[SIZE_PK];
    byte wcom[SIZE_COM];
    byte zkp[SIZE_ZKP];
    nan_any_chntok chntok;
    int total_value;
    int num_payments;
    byte preimage[SIZE_HASH];
} nan_end_close1;

typedef struct {
    code verified;
} nan_int_close2;

typedef struct {
    byte refund_com[SIZE_COM];
} nan_end_close3;

typedef struct {
    byte sig[SIZE_SIG];
} nan_int_close4;

typedef struct {
    byte nwpk[SIZE_PK];
    chn_end_revoke revoke;
} nan_end_close5;

typedef struct {
    code verified;
} nan_int_close6;

typedef struct {
    byte wcom[SIZE_COM];
} nan_end_close7;

typedef struct {
    byte sig[SIZE_SIG];
} nan_int_close8;

#endif
