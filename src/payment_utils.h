#ifndef crypto_utils_h
#define crypto_utils_h

#include "crypto_lib.h"
#include "token_lib.h"

/**
 * Since most tokens need to be signed by the sender, this wrapper removes the
 * public key and signature from the underlying token so that it can be verified
 * immediately
 */
typedef struct {
    byte* msg;
    int msg_size;

    byte pk[SIZE_ADDR];
    byte sig[SIZE_SIG];
} signed_msg;

int pack_signed_msg(signed_msg token, byte* str_out);
signed_msg unpack_signed_msg(byte* str);

void pk_to_addr(byte (*pk)[SIZE_KEY], byte (*addr_out)[SIZE_ADDR]);

void hash_create_chain(byte (*head)[SIZE_HASH], byte** hc_out);
int hash_verify_chain(byte (*preimage)[SIZE_HASH], byte** hc, int k);

void commit_wallet(byte (*pp)[SIZE_PP], byte (*pk_payee)[SIZE_KEY], byte *wallet, int pay_val,
		   byte (*com_out)[SIZE_COM]);

int chn_refund_verify(chn_end_close token);

#endif
