//TODO: move signed_msg to utils

#ifndef mt_h
#define mt_h

#include <stdint.h>
#include <glib.h>

//TODO: clang-format

//------------------------------- Definitions -------------------------------//

typedef unsigned char byte;

// local return codes indicating return value success
#define MT_SUCCESS 0
#define MT_ERROR -1

// network codes used for assorted purposes
typedef enum {
    MT_CODE_VERIFIED,
    MT_CODE_REFUND,
    MT_CODE_ACCEPT,
    MT_CODE_REVOKE,
    MT_CODE_REQCLOSE,
    MT_CODE_ESTABLISH,
    MT_CODE_SUCCESS,
    MT_CODE_FAILED,
} mt_code_t;

//-------------------- Cryptographic String Sizes (bytes) -------------------//

#define MT_SZ_HASH 32
#define MT_SZ_PK 162
#define MT_SZ_SK 612
#define MT_SZ_SIG 128
#define MT_SZ_COM 128

#define MT_SZ_BL 128
#define MT_SZ_UBLR 128
#define MT_SZ_UBLD 128

#define MT_SZ_PP 128
#define MT_SZ_ZKP 128

#define MT_SZ_ADDR 20

//---------------------------- Tor-Facing API -------------------------------//

// TODO: remove the Tor-based structs; these are only here so the test compile
//       we obviously do not need them after integration with Tor

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

typedef enum {
    MT_PARTY_CLI,
    MT_PARTY_REL,
    MT_PARTY_INT,
} mt_party_t;

typedef struct {
    int id;
    mt_party_t party;
} mt_desc_t;

typedef int (*mt_set_prem)(mt_desc_t);
typedef int (*mt_open_conn(/*some notion of a unique idenity (ED5519 idenity??*/);
typedef int (*mt_send_cells)(mt_desc_t, cell_t*, int);
typedef int (*mt_close_conn)(mt_desc_t);

//---------------------------- Controller States ----------------------------//

typedef enum {
    MT_CSTATE_SOMETHING,
} mt_cstate_t;

typedef enum {
    MT_RSTATE_SOMETHING,
} mt_rstate_t;

typedef enum {
    MT_ISTATE_SOMETHING,
} mt_istate_t;

// possible states for micropayment channels on the ledger
typedef enum {
    MT_LSTATE_EMPTY,                  // channel has not yet been initialized
    MT_LSTATE_INIT,                   // channel initialized by the end user
    MT_LSTATE_OPEN,                   // channel is open (payments can be sent)
    MT_LSTATE_INT_REQCLOSED,          // channel closure request sent by intermediary
    MT_LSTATE_END_CLOSED,             // channel closed by end user
    MT_LSTATE_INT_CLOSED,             // channel closed by both parties
    MT_LSTATE_RESOLVED,               // final channel balances are set
} mt_lstate_t;

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
    MT_LTYPE_CHN_END_REVOKE,      // end user revocation of a wallet/nano channel

    MT_LTYPE_CHN_INT_STATE,       // intermediary micropayment state
    MT_LTYPE_CHN_END_SECRET,      // end user micropayment secrets
    MT_LTYPE_MIC_END_WALLET,      // end user wallet
    MT_LTYPE_NAN_INT_STATE,       // end user nanopayment state
    MT_LTYPE_NAN_END_STATE,       // intermediary nanopayment state
    MT_LTYPE_NAN_END_SECRET,      // end user nanopayment secrets

    MT_LTYPE_CHN_END_CHNTOK,      // end user micropayment channel token
    MT_LTYPE_CHN_INT_CHNTOK,      // intermediary micropayment channel token
    MT_LTYPE_NAN_ANY_CHNTOK,      // nanopayment channel token
    MT_LTYPE_CHN_END_REFUND,      // end user nanopayment refund token

    MT_LTYPE_CHN_END_DATA,        // info to maintain channel for end user
    MT_LTYPE_CHN_INT_DATA,        // info to maintain channel for intermediary

} mt_ltype_t;

/**
 * Tokens that need to be sent across the network at one point or another
 */
typedef enum {

    // channel establish protocol messages
    MT_NTYPE_CHN_END_ESTAB1,      // to intermediary
    MT_NTYPE_CHN_INT_ESTAB2,      // to end user
    MT_NTYPE_CHN_END_ESTAB3,      // to intermediary
    MT_NTYPE_CHN_INT_ESTAB4,      // to end user

    // micropayment pay protocol messages
    MT_NTYPE_MIC_CLI_PAY1,	       // to relay
    MT_NTYPE_MIC_REL_PAY2,	       // to client
    MT_NTYPE_MIC_CLI_PAY3,	       // to intermediary
    MT_NTYPE_MIC_INT_PAY4,	       // to client
    MT_NTYPE_MIC_CLI_PAY5,	       // to relay
    MT_NTYPE_MIC_REV_PAY6,	       // to intermediary
    MT_NTYPE_MIC_INT_PAY7,	       // to client
    MT_NTYPE_MIC_INT_PAY8,	       // to relay

    // nanopayment setup protocol messages
    MT_NTYPE_NAN_CLI_SETUP1,      // to intermediary
    MT_NTYPE_NAN_INT_SETUP2,      // to client
    MT_NTYPE_NAN_CLI_SETUP3,      // to intermediary
    MT_NTYPE_NAN_INT_SETUP4,      // to client
    MT_NTYPE_NAN_CLI_SETUP5,      // to intermediary
    MT_NTYPE_NAN_INT_SETUP6,      // to client

    // direct payment establish protocol messages
    MT_NTYPE_NAN_CLI_DIRECT1,     // to intermediary
    MT_NTYPE_NAN_INT_DIRECT2,     // to client

    // nanopayment establish protocol messages
    MT_NTYPE_NAN_CLI_ESTAB1,      // to relay
    MT_NTYPE_NAN_REL_ESTAB2,      // to intermediary
    MT_NTYPE_NAN_INT_ESTAB3,      // to relay
    MT_NTYPE_NAN_REL_ESTAB4,      // to intermediary
    MT_NTYPE_NAN_INT_ESTAB5,      // to relay

    // nanopayment pay protocol messages
    MT_NTYPE_NAN_CLI_PAY1,	  // to relay or intermediary

    // nanopayment close protocol messages
    MT_NTYPE_NAN_END_CLOSE1,      // to intermediary
    MT_NTYPE_NAN_INT_CLOSE2,      // to end user
    MT_NTYPE_NAN_END_CLOSE3,      // to intermediary
    MT_NTYPE_NAN_INT_CLOSE4,      // to end user
    MT_NTYPE_NAN_END_CLOSE5,      // to intermediary
    MT_NTYPE_NAN_INT_CLOSE6,      // to end user
    MT_NTYPE_NAN_END_CLOSE7,      // to intermediary
    MT_NTYPE_NAN_INT_CLOSE8,      // to end user

    // tokens for posting to the ledger
    MT_NTYPE_MAC_AUT_MINT,        // message by tor authority to mint coins
    MT_NTYPE_MAC_ANY_TRANS,       // macropayment transaction
    MT_NTYPE_CHN_END_ESCROW,      // end user escrow transaction
    MT_NTYPE_CHN_INT_ESCROW,      // intermediary escrow transaction
    MT_NTYPE_CHN_INT_REQCLOSE,    // intermediary msg to request a user closure
    MT_NTYPE_CHN_END_CLOSE,       // end user microchannel closure message
    MT_NTYPE_CHN_INT_CLOSE,       // intermediary microchannel closure message
    MT_NTYPE_CHN_END_CASHOUT,     // cash out of closed channel
    MT_NTYPE_CHN_INT_CASHOUT,     // cash out of closed channel

    // tokens for querying the ledger
    MT_NTYPE_MAC_LED_DATA,        // macropayment ledger data mapped to an address
    MT_NTYPE_CHN_LED_DATA,        // channel ledger data mapped to an address
    MT_NTYPE_MAC_LED_QUERY,       // request to query macropayment data
    MT_NTYPE_CHN_LED_QUERY,       // request to query channel data
} mt_ntype_t;

//----------------------------- Local Tokens --------------------------------//

typedef struct {
    byte rev[MT_SZ_PK];
    byte sig[MT_SZ_SIG];
} chn_end_revoke_t;

typedef struct {
    // public keys -> revocation tokens
    GHashTable* state;
} chn_int_state_t;

typedef struct {
    int num_payments;
    byte last_hash[MT_SZ_HASH];
} nan_end_state_t;

typedef struct {
    // nanochannel tokens -> nanopayment states
    GHashTable* state;
} nan_int_state_t;

typedef struct {
    int balance;
    byte wpk[MT_SZ_PK];
    byte wsk[MT_SZ_SK];
    byte rand[MT_SZ_HASH];
    chn_end_revoke_t revoke;
} mic_end_wallet_t;

typedef struct {
    int balance;
    byte commitment[MT_SZ_COM];
    byte esc_pk[MT_SZ_PK];
    byte wpk[MT_SZ_PK];
    byte wsk[MT_SZ_SK];
    byte rand[MT_SZ_HASH];
} chn_end_secret_t;

typedef struct {
    byte wpk[MT_SZ_PK];
    byte wsk[MT_SZ_SK];
    byte hash_head[MT_SZ_HASH];
} nan_end_secret_t;

typedef struct {
    int balance;
    byte esc_pk[MT_SZ_PK];
    byte commitment[MT_SZ_COM];
} chn_end_chntok_t;

typedef struct {
    int balance;
    byte esk_pk[MT_SZ_PK];
} chn_int_chntok_t;

typedef struct {
    int val_from;
    int val_to;
    int num_payments;
    byte hash_tail[MT_SZ_HASH];
} nan_any_chntok_t;

typedef struct {
    mt_code_t refund_code;
    byte wpk[MT_SZ_PK];
    int balance;

    // blank except for conditional refund
    byte conditional[MT_SZ_PK];

    // blank if refund for micropayment
    nan_any_chntok_t channel_token;

    // partial blind sig on everything but the code
    byte sig[MT_SZ_SIG];
    byte unblinder[MT_SZ_UBLR];
} chn_end_refund_t;

typedef struct {
    byte pk[MT_SZ_PK];
    byte sk[MT_SZ_SK];
    int balance;
} mac_end_data_t;

typedef struct {
    mt_lstate_t state;
    byte pk[MT_SZ_PK];
    byte sk[MT_SZ_SK];
    int balance;

    mic_end_wallet_t wallet;
    chn_end_secret_t chn_secret;
    chn_end_chntok_t chn_token;

    nan_any_chntok_t nan_token;
    nan_end_state_t nan_state;
    nan_end_secret_t nan_secret;
    chn_end_refund_t refund;
} chn_end_data_t;

typedef struct {
    mt_istate_t state;
    byte pk[MT_SZ_PK];
    byte sk[MT_SZ_SK];
    int balance;

    chn_int_state_t chn_state;
    nan_int_state_t nan_state;
    chn_int_chntok_t chn_token;
} chn_int_data_t;

//----------------------------- Network Tokens --------------------------//

typedef struct {
    byte nonce[MT_SZ_HASH];
    int value;
} mac_aut_mint_t;

typedef struct {
    byte nonce[MT_SZ_HASH];
    int val_from;
    int val_to;
    byte from[MT_SZ_ADDR];
    byte to[MT_SZ_ADDR];
} mac_any_trans_t;

typedef struct {
    int val_from;
    int val_to;
    byte from[MT_SZ_ADDR];
    byte chn[MT_SZ_ADDR];
    chn_end_chntok_t chn_token;
} chn_end_escrow_t;

typedef struct {
    int val_from;
    int val_to;
    byte from[MT_SZ_ADDR];
    byte chn[MT_SZ_ADDR];
    chn_int_chntok_t chn_token;
} chn_int_escrow_t;

typedef struct {
    byte chn[MT_SZ_ADDR];
} chn_int_reqclose_t;

typedef struct {
    byte chn[MT_SZ_ADDR];
    chn_end_refund_t refund_token;

    // blank for micropayment closes
    int last_pay_num;
    byte last_hash[MT_SZ_HASH];
} chn_end_close_t;

typedef struct {
    mt_code_t close_code;
    byte chn[MT_SZ_ADDR];
    chn_end_revoke_t revoke;

    // blank for micropayment closes
    int last_pay_num;
    byte last_hash[MT_SZ_HASH];
} chn_int_close_t;

typedef struct {
    int val_from;
    int val_to;
    byte chn[MT_SZ_ADDR];
} chn_end_cashout_t;

typedef struct {
    int val_from;
    int val_to;
    byte chn[MT_SZ_ADDR];
} chn_int_cashout_t;

typedef struct {
    int balance;
} mac_led_data_t;

typedef struct {
    mt_lstate_t state;

    byte end_addr[MT_SZ_ADDR];
    byte int_addr[MT_SZ_ADDR];

    int end_balance;
    int int_balance;

    chn_end_chntok_t end_chn_token;
    chn_int_chntok_t int_chn_token;

    chn_end_close_t end_close_token;
    chn_int_close_t int_close_token;

    int close_epoch;
} chn_led_data_t;

typedef struct {
    byte addr[MT_SZ_ADDR];
} mac_led_query_t;

typedef struct {
    byte addr[MT_SZ_ADDR];
} chn_led_query_t;

typedef struct {
    byte zkp[MT_SZ_ZKP];
} chn_end_estab1_t;

typedef struct {
    mt_code_t verified;
} chn_int_estab2_t;

typedef struct {
    byte wcom[MT_SZ_COM];
} chn_end_estab3_t;

typedef struct {
    mt_code_t success;
    byte sig[MT_SZ_SIG];
} chn_int_estab4_t;

typedef struct {
    int value;
} mic_cli_pay1_t;

typedef struct {
    byte wcom[MT_SZ_COM];
    byte zkp[MT_SZ_ZKP];
} mic_rel_pay2_t;

typedef struct {
    byte cli_valcom[MT_SZ_COM];
    byte rel_valcom[MT_SZ_COM];
    byte cli_wcom[MT_SZ_COM];
    byte rel_wcom[MT_SZ_COM];
    byte cli_zkp[MT_SZ_ZKP];
    byte rel_zkp[MT_SZ_ZKP];
} mic_cli_pay3_t;

typedef struct {
    chn_end_refund_t cli_refund;
    chn_end_refund_t rel_refund;
} mic_int_pay4_t;

typedef struct {
    chn_end_revoke_t cli_revoke;
    chn_end_refund_t rel_refund;
} mic_cli_pay5_t;

typedef struct {
    chn_end_revoke_t cli_revoke;
    chn_end_revoke_t rel_revoke;
} mic_rev_pay6_t;

typedef struct {
    mt_code_t success;
    byte wsig[MT_SZ_SIG];
} mic_int_pay7_t;

typedef struct {
    mt_code_t success;
    byte wsig[MT_SZ_SIG];
} mic_int_pay8_t;

typedef struct {
    byte wpk[MT_SZ_PK];
    byte nwpk[MT_SZ_PK];
    byte wcom[MT_SZ_COM];
    byte zkp[MT_SZ_ZKP];
    nan_any_chntok_t chntok;
} nan_cli_setup1_t;

typedef struct {
    mt_code_t verified;
} nan_int_setup2_t;

typedef struct {
    byte nwcom[MT_SZ_COM];
} nan_cli_setup3_t;

typedef struct {
    byte sig[MT_SZ_SIG];
} nan_int_setup4_t;

typedef struct {
    chn_end_revoke_t revoke;
} nan_cli_setup5_t;

typedef struct {
    mt_code_t success;
} nan_int_setup6_t;

typedef struct {
    nan_any_chntok_t chntok;
} nan_cli_direct1_t;

typedef struct {
    mt_code_t success;
} nan_int_direct2_t;

typedef struct {
    nan_any_chntok_t chntok;
} nan_cli_estab1_t;

typedef struct {
    byte rel_wpk[MT_SZ_PK];
    byte rel_nwpk[MT_SZ_PK];
    byte nwcom[MT_SZ_COM];
    byte zkp[MT_SZ_ZKP];
    nan_any_chntok_t chntok;
} nan_rel_estab2_t;

typedef struct {
    mt_code_t verified;
} nan_int_estab3_t;

typedef struct {
    byte nwcom[MT_SZ_COM];
} nan_rel_estab4_t;

typedef struct {
    mt_code_t success;
    byte sig[MT_SZ_SIG];
} nan_int_estab5_t;

typedef struct {
    byte preimage[MT_SZ_HASH];
} nan_cli_pay1_t;

typedef struct {
    byte wpk[MT_SZ_PK];
    byte wcom[MT_SZ_COM];
    byte zkp[MT_SZ_ZKP];
    nan_any_chntok_t chntok;
    int total_value;
    int num_payments;
    byte preimage[MT_SZ_HASH];
} nan_end_close1_t;

typedef struct {
    mt_code_t verified;
} nan_int_close2_t;

typedef struct {
    byte refund_com[MT_SZ_COM];
} nan_end_close3_t;

typedef struct {
    byte sig[MT_SZ_SIG];
} nan_int_close4_t;

typedef struct {
    byte nwpk[MT_SZ_PK];
    chn_end_revoke_t revoke;
} nan_end_close5_t;

typedef struct {
    mt_code_t verified;
} nan_int_close6_t;

typedef struct {
    byte wcom[MT_SZ_COM];
} nan_end_close7_t;

typedef struct {
    mt_code_t success;
    byte sig[MT_SZ_SIG];
} nan_int_close8_t;

#endif
