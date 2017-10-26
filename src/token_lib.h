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

//----------------------------- Token Types ---------------------------------//
// These tokens should have a (hopefully straightforward) 1:1 mapping with
// mathematical symbols found in the algorithm documentation.
//---------------------------------------------------------------------------//

// tokens that are maintained locally by a single party
#define TYPE_mic_int_state 1;    // intermediary micropayment state
#define TYPE_mic_end_wallet 2;   // end user wallet
#define TYPE_mic_end_secret 3;   // end user micropayment secrets
#define TYPE_nan_int_state 4;    // end user nanopayment state
#define TYPE_nan_end_state 5;    // intermediary nanopayment state
#define TYPE_nan_end_secret 6;   // end user nanopayment secrets

// tokens that get sent to other parties within the channel protocols
#define TYPE_mic_end_chan 7;     // end user micropayment channel token
#define TYPE_mic_int_chan 8;     // intermediary micropayment channel token
#define TYPE_mic_end_refund 9;   // end user micropayment refund token
#define TYPE_nan_all_chan 10;    // nanopayment channel token
#define TYPE_nan_end_refund 11;  // end user nanopayment refund token

// tokens that get posted to the ledger
#define TYPE_mac_aut_mint 12;    // message by tor authority to mint coins
#define TYPE_mac_all_trans 13;   // macropayment transaction
#define TYPE_mac_end_escrow 14;  // end user escrow transaction
#define TYPE_mac_int_escrow 15;  // intermediary escrow transaction
#define TYPE_mac_all_cashout 16; // cash out of closed channel
#define TYPE_mic_int_close 17;   // intermediary msg to force end user close
#define TYPE_mic_end_close 18;   // end user microchannel closure message
#define TYPE_mic_int_refute 19;  // intermediary microchannel closure message
#define TYPE_nan_end_refute 20;   // end user nanochannel closure message
#define TYPE_nan_int_close 21;   // intermediary nanochannel closure message

//----------------------------- Miscellaneous -------------------------------//

// special cryptographic string sizes
#define SIZE_ADDR 32
#define SIZE_REV 32   //TODO: fill in correct size for rev

// closure messages
enum closure_msg {
    refund,                      // end user initiates channel closure
    accept,                      // intermediary accepts channel closure
    refute,                      // intermediary refutes end user's closure
    force                        // intermediary forces the end user to close
};

//----------------------------- Token Structs -------------------------------//

// Since most tokens need to be signed by the sender, this wrapper removes the
// public key and signature from the underlying token so that it can be verified
// immediately.
typedef struct {
    int type;
    int msg_size;

    byte* msg;
    byte pk[SIZE_KEY];
    byte sig[SIZE_SIG];
} signed_msg;

typedef struct {
    GHashTable* state;   // public key (byte*) -> state (byte*)
} mic_int_state;

typedef struct {
    int num_payments;
    byte last_hash[SIZE_HASH];
} nan_end_state;

typedef struct {
    GHashTable* state;   // nanochannel token (byte*) -> state (byte*)
} nan_int_state;

typedef struct {
    int balance;
    byte wallet_pk[SIZE_KEY];
    byte wallet_sk[SIZE_KEY];
    byte rand[SIZE_HASH];
    byte revocation[SIZE_REV];
    byte rev_sig[SIZE_SIG];
} mic_end_wallet;

typedef struct {
    int balance;
    byte commitment[SIZE_COM];
    byte escrow_pk[SIZE_KEY];
    byte wallet_pk[SIZE_KEY];
    byte wallet_sk[SIZE_KEY];
    byte rand[SIZE_HASH];
} mic_end_secret;

typedef struct {
    byte wallet_pk[SIZE_KEY];
    byte wallet_sk[SIZE_KEY];
    byte hash_head[SIZE_HASH];
} nan_end_secret;

typedef struct {
    byte escrow_pk[SIZE_KEY];
    byte commitment[SIZE_COM];
} mic_end_chan;

typedef struct {
    byte escrow_pk[SIZE_KEY];
} mic_int_chan;

typedef struct {
    int payer_val;
    int payee_val;
    int num_payments;
    byte hash_tail[SIZE_HASH];
} nan_all_chan;

typedef struct {
    int closure_msg;
    byte wallet_pk[SIZE_KEY];
    int balance;

    byte sig[SIZE_SIG];
    byte unblinder[SIZE_UBLR];

} mic_end_refund;

typedef struct {
    int closure_msg;
    nan_all_chan channel_token;
    byte nan_wallet_pk[SIZE_KEY];
    int balance;

    // partial blind sig on prior four attributes (closure_msg is transparently signed)
    byte sig[SIZE_SIG];
    byte unblinder[SIZE_UBLR];
} nan_end_refund;

typedef struct {
    int value;
} mac_aut_mint;

typedef struct {
    int payee_val;
    int payer_val;
    byte from[SIZE_ADDR];
    byte to[SIZE_ADDR];
} mac_all_trans;

typedef struct {
    int payee_val;
    int payer_val;
    byte from[SIZE_ADDR];
    byte chan[SIZE_ADDR];
    mic_end_chan channel_token;
} mac_end_escrow;

typedef struct {
    int payee_val;
    int payer_val;
    byte from[SIZE_ADDR];
    byte chan[SIZE_ADDR];
    mic_int_chan channel_token;
} mac_int_escrow;

typedef struct {
    byte chan[SIZE_ADDR];
} mic_int_close;

typedef struct {
    mic_end_refund refund_token;
    byte chan[SIZE_ADDR];
} mic_end_close;

typedef struct {
    int closure_msg;
    byte revocation[SIZE_REV];
    byte rev_sig[SIZE_SIG];

    byte chan[SIZE_ADDR];
} mic_int_refute;

typedef struct {
    nan_end_refund refund_token;
    int last_pay_num;
    byte last_hash[SIZE_HASH];
    byte chan[SIZE_ADDR];
} nan_end_refute;

typedef struct {
    int closure_msg;
    int last_pay_num;
    byte last_hash[SIZE_HASH];
    byte chan[SIZE_ADDR];
} nan_int_close;

typedef struct {
    int payer_val;
    int payee_val;
    byte chan[SIZE_ADDR];
    byte from[SIZE_ADDR];
    byte to[SIZE_ADDR];
} mac_all_cashout;


//-------------------------- Pack/Unpack Functions --------------------------//

// Converts the specified token structs to byte arrays that are capable of being
// sent across a network. The return value points to dynamically allocated
// memory and should be freed by the calling procedure.
byte* pack_signed_msg(signed_msg token);
byte* pack_mic_end_chan(mic_end_chan token);
byte* pack_mic_int_chan(mic_int_chan token);
byte* pack_mic_end_refund(mic_end_refund token);
byte* pack_nan_all_chan(nan_all_chan token);
byte* pack_nan_end_refund(nan_end_refund token);
byte* pack_mac_all_trans(mac_all_trans token);
byte* pack_mac_end_escrow(mac_end_escrow token);
byte* pack_mac_int_escrow(mac_int_escrow token);
byte* pack_mac_all_cashout(mac_all_cashout token);
byte* pack_mic_int_close(mic_int_refute token);
byte* pack_mic_end_close(mic_end_close token);
byte* pack_mic_int_refute(mic_int_refute token);
byte* pack_nan_end_refute(nan_end_refute token);
byte* pack_nan_int_close(nan_int_close token);

// Converts a byte array into the specified token struct.
signed_msg unpack_signed_msg(byte* str);
mic_end_chan unpack_mic_end_chan(byte* str);
mic_int_chan unpack_mic_int_chan(byte* str);
mic_end_refund unpack_mic_end_refund(byte* str);
nan_all_chan unpack_nan_all_chan(byte* str);
nan_end_refund unpack_nan_end_refund(byte* str);
mac_all_trans unpack_mac_all_trans(byte* str);
mac_end_escrow unpack_mac_end_escrow(byte* str);
mac_int_escrow unpack_mac_int_escrow(byte* str);
mac_all_cashout unpack_mac_all_cashout(byte* str);
mic_int_close unpack_mic_int_close(byte* str);
mic_end_close unpack_mic_end_close(byte* str);
mic_int_refute unpack_mic_int_refute(byte* str);
nan_end_refute unpack_nan_end_refute(byte* str);
nan_int_close unpack_nan_int_refute(byte* str);

#endif
