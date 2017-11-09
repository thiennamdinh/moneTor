#ifndef mt_utils_h
#define mt_utils_h

#include "mt_crypto.h"
#include "mt_tokens.h"

int create_signed_msg(byte* msg, int size, byte (*pk)[SIZE_PK], byte (*sk)[SIZE_SK], byte** str_out);

int pk_to_addr(byte (*pk)[SIZE_PK], byte (*addr_out)[SIZE_ADDR]);
int addr_to_hex(byte (*addr)[SIZE_ADDR], char (*hex_out)[SIZE_ADDR * 2 + 3]);

int hash_create_chain(int size, byte (*head)[SIZE_HASH], byte (*hc_out)[][SIZE_HASH]);
int hash_verify_chain(byte (*tail)[SIZE_HASH], byte (*preimage)[SIZE_HASH], int k);

int commit_wallet(byte (*pp)[SIZE_PP], byte (*pk_payee)[SIZE_PK], mic_end_wallet wallet, int pay_val,
		   byte (*com_out)[SIZE_COM]);

int chn_refund_verify(chn_end_close token);

#endif
