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
    int size;

    byte pk[SIZE_PK];
    byte sig[SIZE_SIG];
} signed_msg;

int pack_signed_msg(signed_msg token, byte** str_out);
int unpack_signed_msg(byte* str, signed_msg* struct_out);

int pk_to_addr(byte (*pk)[SIZE_PK], byte (*addr_out)[SIZE_ADDR]);
int addr_to_hex(byte (*addr)[SIZE_ADDR], char (*hex_out)[SIZE_ADDR * 2 + 3]);

int hash_create_chain(int size, byte (*head)[SIZE_HASH], byte (*hc_out)[][SIZE_HASH]);
int hash_verify_chain(byte (*tail)[SIZE_HASH], byte (*preimage)[SIZE_HASH], int k);

int commit_wallet(byte (*pp)[SIZE_PP], byte (*pk_payee)[SIZE_PK], byte *wallet, int pay_val,
		   byte (*com_out)[SIZE_COM]);

int chn_refund_verify(chn_end_close token);

#endif
