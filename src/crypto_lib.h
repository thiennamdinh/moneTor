/**
   \file moneTor_crypto_lib.h

   This module serves as a cryptographic library for all payment-related moneTor
   operations. Some calls (such as hashing) will perform real operations while
   others (such as zero knowledge proofs) are simply modeled as a time delay.
*/

#ifndef crypto_lib_h
#define crypto_lib_h

typedef unsigned char byte;

//----------------------- Cryptographic String Sizes ------------------------//

//TODO: fill in correct sizes

#define SIZE_HASH 32
#define SIZE_KEY 32
#define SIZE_SIG 32
#define SIZE_COM 32

// these might all just be SIZE_HASH ...
#define SIZE_BL 32
#define SIZE_UBLR 32
#define SIZE_UBLD 32

#define SIZE_PP 32
#define SIZE_ZKP 32

//----------------------- Cryptographic Op Library --------------------------//

// common
void setup(byte (*pp_out)[SIZE_PP]);
void keygen(byte (*pp)[SIZE_PP], byte (*pk_out)[SIZE_KEY], byte (*sk_out)[SIZE_KEY]);
void random_bytes(int size, byte* rand_out);

// hash scheme
void hash(byte* msg, int msg_size, byte (*hash_out)[SIZE_HASH]);

// signature scheme
void sig_sign(byte* msg, int msg_size, byte (*sk)[SIZE_KEY], byte (*sig_out)[SIZE_SIG]);
int sig_verify(byte* msg, int msg_size, byte (*pk)[SIZE_KEY], byte (*sig)[SIZE_SIG]);

// commitment scheme
void com_commit(byte* inputs, int input_size, byte (*rand)[SIZE_HASH], byte (*com_out)[SIZE_COM]);
int com_decommit(byte* msg, int msg_size, byte (*rand)[SIZE_HASH], byte (*com)[SIZE_COM]);

// blind signature scheme
void bsig_blind(byte (*msg)[SIZE_HASH], byte (*pk)[SIZE_KEY], byte (*blinded_out)[SIZE_BL],
		byte(*unblinder_out)[SIZE_UBLR]);
void bsig_unblind(byte (*pk)[SIZE_KEY], byte (*blinded_sig)[SIZE_SIG], byte (*unblinder)[SIZE_UBLR],
		  byte (*unblinded)[SIZE_UBLD]);
int bsig_verify(byte (*msg)[SIZE_HASH], byte (*pk)[SIZE_KEY], byte (*sig)[SIZE_SIG],
		byte (*unblinder)[SIZE_UBLR]);

// zero-knowledge proof of wallet validity
void zkp_wal_prove(byte (*pp)[SIZE_PP], byte* inputs, int input_size, byte (*zkp_out)[SIZE_ZKP]);
int zkp_wal_verify(byte (*pp)[SIZE_PP], byte (*proof)[SIZE_ZKP]);

#endif
