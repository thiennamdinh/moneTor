/**
 * \file mt_crypto.c
 *
 * This module provides a simplified interface for cryptographic operations
 * required from by the moneTor payment scheme. Since the original design of
 * moneTor does the include a fully functional cryptographic suite, the
 * high-level operations all redirect to this module. The intent is that code in
 * this module can eventually be redirected to real cryptographic libraries with
 * minimal change to the otherwise functional moneTor code body.
 *
 * A breakdown of cryptographic topics in this module are as follows. The
 * implemention is a combination of real openssl calls and approximations that
 * are sufficient for simulation purposes. In the case of simulated
 * cryptography, cpu delays are added and messages are appropriately padded to
 * size.
 *
 * - KeyGen (RSA): Openssl; fully functional. Keys are imported and exported as
 *   PEM formatted c-strings
 * - Hash Function: Openssl; fully functional
 * - Random Function: Openssl; fully functional
 * - Message Signing: Openssl; fully functional
 *
 * - Commitment: Simulation; messages are committed using a naive one-step
 *   hashing scheme that is incompatible with the final system requirements
 * - Blind Signatures: Simulation; messages are signed by not really blinded
 * - Zero-Knowledge Proofs: Simulation; no effort whatsoever to implement
 *   outside of the delay
 */

#include <string.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "mt_crypto.h"

// global parameters for key generation
int num_bits = 1024;
char* exp_str = "65537";

// random byte string used to simulate a "blinder" for bsig operations
byte* bsig_fake_blinder = (byte*)"1234567812345678123456781234567812345678";

/**
 * Call system nanosleep() to delay the thread for given the microseconds
 */
void micro_sleep(int microsecs){
    struct timespec delay;
    delay.tv_sec = microsecs / 1000000;
    delay.tv_nsec = 0;
    nanosleep(&delay, NULL);
}

/**
 * Called at system setup to obtain public parameters
 */
int paycrypt_setup(byte (*pp_out)[SIZE_PP]){
    return paycrypt_rand_bytes(SIZE_PP, *pp_out);
}

/**
 * Generate a public and private keypair outputted as RSA PEM c-strings. For
 * simulation purposes, keys are simply RSA keys. In the final implementation,
 * it may be necessary for the keys to carry extra information for ZKP scheme
 */
int paycrypt_keygen(byte (*pp)[SIZE_PP], byte (*pk_out)[SIZE_PK], byte  (*sk_out)[SIZE_SK]){

    // generate the rsa struct
    BIGNUM *exponent = BN_new();
    BN_dec2bn(&exponent, exp_str);
    RSA* rsa = RSA_new();
    if(RSA_generate_key_ex(rsa, num_bits, exponent, NULL) != 1)
	return MT_ERROR;

    // write public key
    BIO* bio_pk = BIO_new(BIO_s_mem());
    if(PEM_write_bio_RSA_PUBKEY(bio_pk, rsa) != 1)
	return MT_ERROR;

    int size_pk = BIO_pending(bio_pk);
    if(size_pk > SIZE_SK + 1)
	return MT_ERROR;

    BIO_read(bio_pk, *pk_out, size_pk);
    (*pk_out)[size_pk] = '\0';

    // write private key
    BIO* bio_sk = BIO_new(BIO_s_mem());
    if(PEM_write_bio_RSAPrivateKey(bio_sk, rsa, NULL, NULL, 0, NULL, NULL) != 1)
	return MT_ERROR;

    int size_sk = BIO_pending(bio_sk);
    if(size_pk > SIZE_SK + 1)
	return MT_ERROR;

    BIO_read(bio_sk, *sk_out, size_sk);
    (*sk_out)[size_sk] = '\0';

    RSA_free(rsa);
    BIO_free(bio_pk);
    BIO_free(bio_sk);

    return MT_SUCCESS;
}

/**
 * Write the specified number of random bytes to the provided buffer
 */
int paycrypt_rand_bytes(int size, byte* rand_out){
    if(RAND_bytes(rand_out, size) != 1){
	if(RAND_pseudo_bytes(rand_out, size) != 1){
	    return MT_ERROR;
	}
    }
    return MT_SUCCESS;
}

/**
 * Hash the provided message and write to the buffer
 */
int paycrypt_hash(byte* msg, int msg_size, byte (*hash_out)[SIZE_HASH]){
    SHA256_CTX context;

    if(SHA256_Init(&context) != 1)
	return MT_ERROR;

    if(SHA256_Update(&context, (unsigned char*)msg, msg_size) != 1)
	return MT_ERROR;

    if(SHA256_Final(*hash_out, &context) != 1)
	return MT_ERROR;

    return MT_SUCCESS;
}

/**
 * Accept a message of arbitrary length, compute the digest, and output a signature
 */
int sig_sign(byte* msg, int msg_size, byte (*sk)[SIZE_SK], byte (*sig_out)[SIZE_SIG]){
    BIO* bio = BIO_new_mem_buf(sk, strlen((char*)*sk));
    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

    if(bio == NULL || rsa == NULL)
	return MT_ERROR;

    byte digest[SIZE_HASH];
    if(paycrypt_hash(msg, msg_size, &digest) != 0)
	return MT_ERROR;

    uint sig_len;
    if(RSA_sign(NID_sha256, digest, SIZE_HASH, *sig_out, &sig_len, rsa) != 1)
	return MT_ERROR;

    if(sig_len != SIZE_SIG)
	return MT_ERROR;

    RSA_free(rsa);
    BIO_free(bio);
    return MT_SUCCESS;
}

/**
 * Accept a message of arbitrary length, compute the digest, and verify the
 * provided signature
 */
int sig_verify(byte* msg, int msg_size, byte (*pk)[SIZE_PK], byte  (*sig)[SIZE_SIG]){
    BIO* bio = BIO_new_mem_buf(pk, strlen((char*)*pk));
    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

    if(bio == NULL || rsa == NULL)
	return MT_ERROR;

    byte digest[SIZE_HASH];
    if(paycrypt_hash(msg, msg_size, &digest) != MT_SUCCESS)
	return MT_ERROR;

    // signature did not verify
    if(RSA_verify(NID_sha256, digest, SIZE_HASH, *sig, SIZE_SIG, rsa) != 1)
	return MT_ERROR;

    RSA_free(rsa);
    BIO_free(bio);
    return MT_SUCCESS;
}

/**
 * Accept a message of arbitrary length along with some random bytes and compute a
 * commitment. In this simulated environment, the commitment is simply a hash of
 * the message concatenated with the random bytes
 */
int com_commit(byte* msgs, int msg_size, byte (*rand)[SIZE_HASH], byte (*com_out)[SIZE_COM]){
    byte* concated = malloc(msg_size + SIZE_HASH);
    memcpy(concated, msgs, msg_size);
    memcpy(concated + msg_size, *rand, SIZE_HASH);

    byte digest[SIZE_HASH];
    if(paycrypt_hash(concated, msg_size + SIZE_HASH, &digest) != MT_SUCCESS)
	return MT_ERROR;

    // commitment in the final scheme may be larger than hash; pad the difference
    memcpy(*com_out, digest, SIZE_HASH);
    if(paycrypt_rand_bytes(SIZE_COM - SIZE_HASH, (*com_out) + SIZE_HASH) !=  MT_SUCCESS)
	return MT_ERROR;

    micro_sleep(DELAY_COM_COMMIT);
    return MT_SUCCESS;
}

/**
 * Verify the commitment provided for a message of arbitrary length
 */
int com_decommit(byte* msg, int msg_size, byte (*rand)[SIZE_HASH], byte  (*com)[SIZE_COM]){
    byte com_ver[SIZE_COM];
    if(com_commit(msg, msg_size, rand, &com_ver) != MT_SUCCESS)
	return MT_ERROR;
    if(memcmp(com, com_ver, SIZE_HASH) != 0)
	return MT_ERROR;

    micro_sleep(DELAY_COM_DECOMMIT);
    return MT_SUCCESS;
}

/**
 * Accept a message of arbitrary length and "blind" it so that it can be signed
 * anonymously. In this simulated version, the blinding is simply an operation
 * with the globally visible bsig_fake_blinder string. The unblinder does
 * nothing and is simply filled with random bytes
 */
int bsig_blind(byte *msg, int msg_size, byte (*pk)[SIZE_PK], byte (*blinded_out)[SIZE_BL],
		byte(*unblinder_out)[SIZE_UBLR]){

    byte digest[SIZE_HASH];
    if(paycrypt_hash(msg, msg_size, &digest) != MT_SUCCESS)
	return MT_ERROR;

    for(int i = 0; i < SIZE_BL; i++)
	(*blinded_out)[i] = bsig_fake_blinder[i % SIZE_HASH] ^ digest[i % SIZE_HASH];

    if(paycrypt_rand_bytes(SIZE_UBLR, *unblinder_out) != MT_SUCCESS)
	return MT_ERROR;

    micro_sleep(DELAY_BSIG_BLIND);
    return MT_SUCCESS;
}

/**
 * Accept a signature on a blinded message and unblind it so it can be verified
 * later. Since we do not having a real blinding scheme, this simply copies over
 * the "blinded" signature to the "unblinded" buffer.
 */
int bsig_unblind(byte (*pk)[SIZE_PK], byte (*blinded_sig)[SIZE_SIG], byte (*unblinder)[SIZE_UBLR],
		  byte (*unblinded_sig_out)[SIZE_SIG]){
    memcpy(*unblinded_sig_out, *blinded_sig, SIZE_SIG);
    micro_sleep(DELAY_BSIG_UNBLIND);
    return MT_SUCCESS;
}

/**
 * Verify an unblinded signature on the original message. This is easy for the
 * simulated version since the message simply needs to be put through the fake
 * blinding process to verify with the signature.
 */
int bsig_verify(byte* msg, int msg_size, byte (*pk)[SIZE_PK], byte (*unblinded_sig)[SIZE_SIG]){

    byte* blinded = malloc(SIZE_BL);

    byte digest[SIZE_HASH];
    if(paycrypt_hash(msg, msg_size, &digest) != MT_SUCCESS)
	return MT_ERROR;

    for(int i = 0; i < SIZE_BL; i++)
	blinded[i] = bsig_fake_blinder[i % SIZE_HASH] ^ digest[i % SIZE_HASH];

    if(sig_verify(blinded, SIZE_BL, pk, unblinded_sig) != MT_SUCCESS)
	return MT_ERROR;

    micro_sleep(DELAY_BSIG_VERIFY);
    return MT_SUCCESS;
}

/**
 * Accept some inputs and compute a zero-knowledge proof on some statements
 * about the input. We do not even attempt to implement this in the simulated
 * scheme. Only the bare minimum computations are done so that proofs are not
 * accidently rejected or confused with other proofs in the simulation.
 */
int zkp_prove(byte (*pp)[SIZE_PP], byte* inputs, int input_size, byte (*zkp_out)[SIZE_ZKP]){
    // override output with pp xor'd with some constant string

    byte digest[SIZE_HASH];
    if(paycrypt_hash(inputs, input_size, &digest) != MT_SUCCESS)
	return MT_ERROR;

    memcpy(*zkp_out, *pp, SIZE_HASH / 2);
    memcpy((*zkp_out) + SIZE_HASH / 2, digest, SIZE_HASH / 2);

    if(paycrypt_rand_bytes(SIZE_ZKP - SIZE_HASH, (*zkp_out) + SIZE_HASH) !=  MT_SUCCESS)
	return MT_ERROR;

    micro_sleep(DELAY_ZKP_PROVE);
    return MT_SUCCESS;
}

/**
 * Accept some zero-knowledge proof and verify its correctness. In the simulated
 * version, we do a simple sanity check to make sure that the proof was at least
 * likely to be generated on purpose in some other part of the simulation.
 */
int zkp_verify(byte (*pp)[SIZE_PP], byte (*proof)[SIZE_ZKP]){
    // override output with pp xor'd with some constant string
    if(memcmp(proof, pp, SIZE_HASH / 2) != 0)
	return MT_ERROR;

    micro_sleep(DELAY_ZKP_VERIFY);
    return MT_SUCCESS;
}
