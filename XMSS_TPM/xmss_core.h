#ifndef XMSS_CORE_H
#define XMSS_CORE_H

#include "params.h"

/**
 * Given a set of parameters, this function returns the size of the secret key.
 * This is implementation specific, as varying choices in tree traversal will
 * result in varying requirements for state storage.
 *
 * This function handles both XMSS and XMSSMT parameter sets.
 */
unsigned long long xmss_xmssmt_core_sk_bytes(const xmss_params *params);

/**
 * Given a set of parameters, this function returns the the bds NEXT size of the 
 * bottom layer
 */
unsigned long long xmss_xmssmt_core_bds_next_bytes(const xmss_params *params);


/* Recover the BDS state for a whole XMSS(^MT) tree */
int core_recover_bds_data(xmss_params *params, unsigned char *sk, unsigned int *layers,
                            unsigned int nr_of_hmaced_bds_layers);

/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) index || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED], omitting algorithm OID.
 */
int xmss_core_keypair(xmss_params *params,
                      unsigned char *pk, unsigned char *sk);

/**
 * Signs a message. Returns an array containing the signature followed by the
 * message and an updated secret key.
 */
int xmss_core_sign(xmss_params *params,
                   unsigned char *sk,
                   unsigned char *sm, unsigned long long *smlen,
                   const unsigned char *m, unsigned long long mlen);

/**
 * Verifies a given message signature pair under a given public key.
 * Note that this assumes a pk without an OID, i.e. [root || PUB_SEED]
 */
int xmss_core_sign_open(const xmss_params *params,
                        unsigned char *m, unsigned long long *mlen,
                        const unsigned char *sm, unsigned long long smlen,
                        const unsigned char *pk);

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [(ceil(h/8) bit) index || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] omitting algorithm OID.
 */
int xmssmt_core_keypair(xmss_params *params,
                        unsigned char *pk, unsigned char *sk);

/*
 * Derives a XMSSMT key pair for a given parameter set.
 * Seed must be 3*n long.
 * Format sk: [(ceil(h/8) bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algorithm OID.
 */
int xmssmt_core_seed_keypair(const xmss_params *params,
                             unsigned char *pk, unsigned char *sk,
                             unsigned char *seed);

/**
 * Signs a message. Returns an array containing the signature followed by the
 * message and an updated secret key.
 */
int xmssmt_core_sign(xmss_params *params,
                     unsigned char *sk,
                     unsigned char *sm, unsigned long long *smlen,
                     const unsigned char *m, unsigned long long mlen);

/**
 * Verifies a given message signature pair under a given public key.
 * Note that this assumes a pk without an OID, i.e. [root || PUB_SEED]
 */
int xmssmt_core_sign_open(const xmss_params *params,
                          unsigned char *m, unsigned long long *mlen,
                          const unsigned char *sm, unsigned long long smlen,
                          const unsigned char *pk);

void bds_reserve(xmss_params *params, unsigned char *sk);

void bds_reserve_mt(xmss_params *params, unsigned char *sk);

#endif
