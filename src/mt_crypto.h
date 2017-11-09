/**
   \file mt_crypto.h

   This module serves as a cryptographic library for all payment-related moneTor
   operations. Some calls (such as hashing) will perform real operations while
   others (such as zero knowledge proofs) are simply modeled as a time delay.
*/

#ifndef mt_crypto_h
#define mt_crypto_h

typedef unsigned char byte;

#define MT_SUCCESS 0
#define MT_ERROR -1

//-------------------- Cryptographic String Sizes (bytes) -------------------//

#define SIZE_HASH 32
#define SIZE_PK 273
#define SIZE_SK 893
#define SIZE_SIG 128
#define SIZE_COM 128

#define SIZE_BL 128
#define SIZE_UBLR 128
#define SIZE_UBLD 128

#define SIZE_PP 128
#define SIZE_ZKP 128

//------------------ Cryptographic Simulate Delays (microsec) ---------------//

#define DELAY_COM_COMMIT 0
#define DELAY_COM_DECOMMIT 0
#define DELAY_BSIG_BLIND 0
#define DELAY_BSIG_UNBLIND 0
#define DELAY_BSIG_VERIFY 0
#define DELAY_ZKP_PROVE 1000000
#define DELAY_ZKP_VERIFY 0

//----------------------- Cryptographic Op Library --------------------------//

// common
int paycrypt_setup(byte (*pp_out)[SIZE_PP]);
int paycrypt_keygen(byte (*pp)[SIZE_PP], byte (*pk_out)[SIZE_PK], byte (*sk_out)[SIZE_SK]);
int paycrypt_rand_bytes(int size, byte* rand_out);
int paycrypt_hash(byte* msg, int msg_size, byte (*hash_out)[SIZE_HASH]);

// signature scheme
int sig_sign(byte* msg, int msg_size, byte (*sk)[SIZE_SK], byte (*sig_out)[SIZE_SIG]);
int sig_verify(byte* msg, int msg_size, byte (*pk)[SIZE_PK], byte (*sig)[SIZE_SIG]);

// commitment scheme
int com_commit(byte* msg, int msg_size, byte (*rand)[SIZE_HASH], byte (*com_out)[SIZE_COM]);
int com_decommit(byte* msg, int msg_size, byte (*rand)[SIZE_HASH], byte (*com)[SIZE_COM]);

// blind signature scheme
int bsig_blind(byte* msg, int msg_size, byte (*pk)[SIZE_PK], byte (*blinded_out)[SIZE_BL],
		byte(*unblinder_out)[SIZE_UBLR]);
int bsig_unblind(byte (*pk)[SIZE_PK], byte (*blinded_sig)[SIZE_SIG], byte (*unblinder)[SIZE_UBLR],
		  byte (*unblinded_sig_out)[SIZE_SIG]);
int bsig_verify(byte* msg, int msg_size, byte (*pk)[SIZE_PK], byte (*unblinded_sig)[SIZE_SIG]);

// zero-knowledge proof of wallet validity
int zkp_prove(byte (*pp)[SIZE_PP], byte* inputs, int input_size, byte (*zkp_out)[SIZE_ZKP]);
int zkp_verify(byte (*pp)[SIZE_PP], byte (*proof)[SIZE_ZKP]);

#endif
