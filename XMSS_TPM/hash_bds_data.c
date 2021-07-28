#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "params.h"
#include "hash.h"
#include "zeroize.h"
#include "utils.h"
#include "hash_bds_data.h"

#define IPAD 0x36
#define OPAD 0x5c

/**
 * NOTE: This code is inspired and copied from the LMS reference code (RFC 8554) 
 */

/*
 * This generates the derived value that we'll use as a key the authenticate
 * the aux data.  We pass the ctx (rather than using a local one) so we have
 * one less thing to zeroize
 *
 * We use a derived key (rather than using the seed directly) because the
 * outer hash within the HMAC don't use the diversification factors that every
 * other hash within this packet does; hence for HMAC, we use a key that
 * is independent of every other hash used
 */
static void compute_seed_derive( const xmss_params *params, unsigned char *result, 
                                    const unsigned char *seed) {
    core_hash(params, result, seed, params->n);
}

static void xor_key( unsigned char *key, unsigned xor_val, unsigned len_key) {
    unsigned i;
    for (i = 0; i<len_key; i++) {
        key[i] ^= xor_val;
    }
}

static void compute_hmac( const xmss_params *params,
                          unsigned char *dest,
                          unsigned size_hash,
                          unsigned char *key,
                          const unsigned char *data, size_t len_data) {
    int block_len = block_size(params);

    /* Step 1: first phase of the HMAC */
    unsigned char pad_key[block_len];
    memset(pad_key, 0, block_len);
    memcpy(pad_key, key, size_hash);
    // K ^ IPAD
    xor_key(pad_key, IPAD, block_len);
    // H(K^IPAD)
    core_hash(params, dest, pad_key, block_len);
    // H(K^IPAD) || m
    unsigned char *hash_tmp = malloc(size_hash+len_data);
    memcpy(hash_tmp, dest, size_hash);
    memcpy(hash_tmp+size_hash, data, len_data);
    // H(H(K^IPAD)||m)
    core_hash(params, dest, hash_tmp, size_hash+len_data);
    free(hash_tmp);

    /* Step 2: second phase of the HMAC */
    // K ^ OPAD
    xor_key(pad_key, IPAD^OPAD, size_hash );
    // K^OPAD || H(H(K^IPAD)||m)
    hash_tmp = malloc(block_len+size_hash);
    memcpy(hash_tmp, pad_key, block_len);
    memcpy(hash_tmp+block_len, dest, size_hash);
    // H(K^OPAD || H(H(K^IPAD)||m))
    core_hash(params, dest, hash_tmp, block_len+size_hash);
    free(hash_tmp);
}

/*
 * This is called when we're done computing the aux data; this generates the
 * authentication code that goes with each level
 */
void hmac_bds_data( const xmss_params *params, const unsigned char *seed,
                    unsigned char *data, unsigned long long datalen,
                    unsigned char *out) {

    /* Generate the key we'll use to authenticate the data */
    unsigned int hmac_seed_len = params->n;
    unsigned char hmac_seed[ hmac_seed_len ];
    // Compute the seed from the seed
    compute_seed_derive( params, hmac_seed, seed );

    compute_hmac( params, out, params->n, hmac_seed,
                    data, datalen );

    hss_zeroize( hmac_seed, params->n );
}

void hmac_all_bds_data(const xmss_params *params, unsigned char *sk, unsigned char *sk_seed,
                        unsigned char *hmac_out, int update_bds_hmac, int update_wots_hmac) {
    /* HMAC the BDS data layers */
    unsigned int bds_holder_len = params->bds_next_bytes + 8;
    unsigned int added_to_hmac = 0;
    unsigned char *bds_holder = NULL;
    uint64_t max_idx = 0;
    uint64_t idx_tree;
    unsigned char *max_idx_bytes = malloc(8);
    if (update_bds_hmac) {
        bds_holder = malloc(bds_holder_len);
        for (unsigned int i = 0; i < params->d; i++) {
            memcpy(bds_holder, sk+(i*params->bds_next_bytes), params->bds_next_bytes);
            if (i == 0)
                max_idx = params->reserve_count;
            else {
                idx_tree = (params->reserve_count >> (params->tree_height * (i+1)));
                max_idx = (idx_tree+1) * (1ULL << (params->tree_height * (i+1)));
            } 
            ull_to_bytes(max_idx_bytes, 8, max_idx);
            memcpy(bds_holder+params->bds_next_bytes, max_idx_bytes, 8);
            hmac_bds_data(params, sk_seed, bds_holder, bds_holder_len, hmac_out);
            hmac_out += params->n;
            added_to_hmac += params->n;
        }
        free(bds_holder);
    }
    // We still need to advance hmac_out pointer
    else {
        hmac_out += params->d * params->n;
    }

    /* If we have more than 1 tree layer */
    if (params->d > 1) {
        /* HMAC the BDS NEXT data */
        unsigned int bds_NEXT_layer_addr = params->d * params->bds_next_bytes;
        bds_holder_len = ((params->d - 1) * params->bds_next_bytes) + 8;
        unsigned char *bds_holder = malloc(bds_holder_len);
        max_idx = params->reserve_count;
        ull_to_bytes(max_idx_bytes, 8, max_idx);
        for (unsigned int i = 0; i < params->d-1; i++) {
            memcpy(bds_holder+(i*params->bds_next_bytes), sk+bds_NEXT_layer_addr+i*params->bds_next_bytes, params->bds_next_bytes);
        }
        memcpy(bds_holder+(params->d-1)*params->bds_next_bytes, max_idx_bytes, 8);
        hmac_bds_data(params, sk_seed, bds_holder, bds_holder_len, hmac_out);
        hmac_out += params->n;
        added_to_hmac += params->n;
        free(bds_holder);

        /* HMAC the WOTS sigs */
        if (update_wots_hmac) {
            unsigned int wots_sigs_addr = (2*params->d - 1) * params->bds_next_bytes;
            bds_holder_len = params->wots_sig_bytes + 8;
            bds_holder = malloc(bds_holder_len);
            for (unsigned int i = 0; i < params->d-1; i++) {
                memcpy(bds_holder, sk+wots_sigs_addr+i*params->wots_sig_bytes, params->wots_sig_bytes);
                idx_tree = (params->reserve_count >> (params->tree_height * (i+1)));
                max_idx = (idx_tree+1) * (1ULL << (params->tree_height * (i+1)));
                ull_to_bytes(max_idx_bytes, 8, max_idx);
                memcpy(bds_holder+params->wots_sig_bytes, max_idx_bytes, 8);
                hmac_bds_data(params, sk_seed, bds_holder, bds_holder_len, hmac_out);
                hmac_out += params->n;
                added_to_hmac += params->n;
            }
            free(bds_holder);
        }
        else {
            hmac_out += (params->d-1) * params->n;
        }
    }

    /* HMAC the BDS next data */
    if (params->autoreserve > 0) {
        unsigned int bds_next_idx_addr = params->sk_bytes-(params->index_bytes + 4*params->n) + params->index_bytes;
        unsigned int total_bds_next_size = params->index_bytes + params->bds_next_bytes;
        hmac_bds_data(params, sk_seed, sk+bds_next_idx_addr, total_bds_next_size, hmac_out);
    }

    free(max_idx_bytes);
}


void set_corrupted_layers(unsigned int *layers, unsigned int nr_of_hmaced_bds_layers, int layer) {
    // If we need to recover BDS data of all layers
    if (layer == -1) {
        for (unsigned int i = 0; i < nr_of_hmaced_bds_layers; i++) {
            layers[i] = 1;
        }
    }
    // Set that we need to recover a specific layer
    else {
        layers[layer] = 1;
    }
}

int is_layer_corrupt(xmss_params *params,
                    unsigned int *corrupted_layers,
                    int bds_structure, unsigned int current_layer) {
    unsigned int corrupted_idx;

    if (bds_structure == data_layer) {
        corrupted_idx = current_layer;
        if (corrupted_layers[corrupted_idx]) {
                printf("BDS data is corrupted at layer %d\n", current_layer);
                return 1;
            }
    }
    else if (params->d == 1) {
        if (bds_structure == WOTS_sigs) { // WOTS sigs is corrupted
            corrupted_idx = params->d + current_layer;
            if (corrupted_layers[corrupted_idx]) {
                printf("WOTS sigs is corrupted at layer %d\n", current_layer);
                return 1;
            }
        }
        else if (bds_structure == RESERVED) { // BDS RESERVED is corrupted
            corrupted_idx = params->d + (params->d-1);
            if (corrupted_layers[corrupted_idx]) {
                printf("BDS RESERVED is corrupted\n");
                return 1;
            }
        }
    }
    else if (params->d > 1) {
        if (bds_structure == NEXT_layer) { // BDS NEXT layers is corrupted
            corrupted_idx = params->d;
            if (corrupted_layers[corrupted_idx]) {
                printf("BDS NEXT is corrupted\n");
                return 1;
            }
        }
        else if (bds_structure == WOTS_sigs) { // WOTS sigs is corrupted
            corrupted_idx = params->d + 1 + current_layer;
            if (corrupted_layers[corrupted_idx]) {
                printf("WOTS sigs is corrupted at layer %d\n", current_layer);
                return 1;
            }
        }
        else if (bds_structure == RESERVED) { // BDS RESERVED is corrupted
            corrupted_idx = params->d + 1 + (params->d-1);
            if (corrupted_layers[corrupted_idx]) {
                printf("BDS RESERVED is corrupted\n");
                return 1;
            }
        }
    }

    return 0;
}