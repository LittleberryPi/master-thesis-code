#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "xmss_reserve.h"
#include "tpm_functions.h"
#include "utils.h"
#include "xmss_core.h"

// For TPM library
#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ekutils.h>

#ifdef XMSSMT
    #define BDS_RESERVE bds_reserve_mt
#else
    #define BDS_RESERVE bds_reserve
#endif

#define NVINDEX_OID 0x01000004
#define NVINDEX_HBSS_INDEX 0x01000005
#define NVINDEX_SEED_PRF 0x01000006
#define NVINDEX_ROOT_PKSEED 0x01000007
#define NVINDEX_COUNTER_DIFF 0x01000008
#define NVPWD	"pwd"
#define NVCOUNTER_SIZE 8

/**
 * NOTE: This code is inspired and copied from the LMS reference code (RFC 8554) 
 */

/*
 * Initialize the reservation count to the given value
 */
void xmss_set_reserve_count(xmss_params *params, uint64_t count) {
    params->reserve_count = count;
}

/*
 * Set the autoreserve count
 */
int xmss_set_autoreserve(xmss_params *params, unsigned sigs_to_autoreserve) {
    if (!params) {
        return 1;
    }

    /* Note: we do not check if the working key is in a usable state */
    /* There are a couple of odd-ball scenarios (e.g. when they've */
    /* manually allocated the key, but haven't loaded it yet) that we */
    /* don't have a good reason to disallow */

    params->autoreserve = sigs_to_autoreserve;
    return 0;
}

/*
 * For the fast version (xmss_core_fast.c)
 * This is called when we generate a signature; it checks if we need
 * to write out a new private key (and advance the reservation); if it
 * decides it needs to write out a new private key, it also decides how
 * far it needs to advance it
 */
int xmss_advance_count(xmss_params *params, uint64_t idx_leaf) {
    /* The check whether idx_leaf is the last leaf already happened in xmss_core(_fast).c */

    uint64_t new_count = idx_leaf + 1;
    int sigs_reserved = 0;

    // if we're 1 index before the reserve count, this is needed for the bds reserve computation
    if (idx_leaf == params->reserve_count - 1) { 
        sigs_reserved = -1;
    }
    // if we're at the last leaf index
    else if (new_count > ((1ULL << params->full_height) - 1)) {
        sigs_reserved = -2;
    }
    // else, the next count will be over the reserve count and is less than total no. leaves
    else if (new_count > params->reserve_count && new_count < (1ULL << params->full_height)) { 
        /* We need to advance the reservation */
        // printf("We need to advance the reservation, new_count=%ld, reserve_count=%ld\n", new_count, params->reserve_count);

        /* Check if we have enough space to do the entire autoreservation */
        if (((1ULL << params->full_height) - 1) - new_count > params->autoreserve) {
            new_count += params->autoreserve;
            sigs_reserved = params->autoreserve;
        } else {
            /* If we don't have enough space, reserve what we can */
            sigs_reserved = ((1ULL << params->full_height) - 1) - new_count;
            new_count = ((1ULL << params->full_height) - 1);
        }

        /*
        * Update sk and write to NV memory
        */
        /* Increment the index in the secret key. */        
        #ifdef DEFAULT_STORAGE
            unsigned char hbss_nv_index[params->index_bytes];
            ull_to_bytes(hbss_nv_index, params->index_bytes, new_count);
            FILE *keypair_file = fopen("keypair", "r+b");
            if (keypair_file == NULL) {
                fprintf(stderr, "Could not open keypair file.\n");
                return -1;
            }
            fseek(keypair_file, XMSS_OID_LEN + params->pk_bytes + XMSS_OID_LEN, SEEK_SET);
            fwrite(hbss_nv_index, 1, params->index_bytes, keypair_file);
            fclose(keypair_file);
        #endif // DEFAULT_STORAGE
        #ifdef TPM_STORAGE
            TPM_RC rc = 0;
            TPM_RC rc1 = 0;
            TSS_CONTEXT	*tssContext = NULL;
            TPMI_SH_AUTH_SESSION sessionHandle = TPM_RS_PW;

            rc = TSS_Create(&tssContext);

            /* Always increment the index when updating, because in normal mode
            the index is incremented by 1 and in modulo increment mode hss_advance_count()
            keeps track of when to update 1 */
            if (rc == 0) {
                rc = nvIncrement(tssContext, sessionHandle, NVINDEX_HBSS_INDEX);
            }

            rc1 = TSS_Delete(tssContext);
            if (rc != 0 || rc1 != 0) {
                const char *msg;
                const char *submsg;
                const char *num;
                TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
                printf("%s%s%s\n", msg, submsg, num);
                return -1;
            }
        #endif // TPM_STORAGE

        params->reserve_count = new_count;
    }

    return sigs_reserved;
}


/*
 * For fast version (xmss_core_fast.c)
 * This will make sure that (at least) N signatures are reserved; that is, we
 * won't need to actually call the update function for the next N signatures
 * generated
 *
 * This can be useful if the update_private_key function is expensive.
 *
 * Note that if, N (or more) signatures are already reserved, this won't do
 * anything.
 */
int xmss_reserve_signature(xmss_params *params, unsigned sigs_to_reserve,
                            uint64_t idx_leaf, 
                            __attribute__((unused)) unsigned char *sk) {
    int sigs_reserved = 0;

    if (sigs_to_reserve > ((1ULL << params->full_height) - 1)) {
        return 1; /* Very funny */
    }

    uint64_t new_reserve_count;  /* This is what the new reservation */
                     /* setting would be (if we accept the reservation) */
    if (idx_leaf > ((1ULL << params->full_height) - 1) - sigs_to_reserve) {
        /* Not that many sigantures left */
        /* Reserve as many as we can */
        sigs_reserved = ((1ULL << params->full_height) - 1) - idx_leaf;
        new_reserve_count = ((1ULL << params->full_height) - 1);
    } else {
        new_reserve_count = idx_leaf + sigs_to_reserve;
        sigs_reserved = sigs_to_reserve;
    }

    if (new_reserve_count <= params->reserve_count) {
        /* We already have (at least) that many reserved; do nothing */
        return 0;
    }

    /* Attempt to update the count in the private key */
    #ifdef DEFAULT_STORAGE
        /* Increment the index in the secret key in NV memory. 
        Do this using a copy of sk (sk_nv), because sk is still needed in this
        form (old index) during siging*/
        unsigned char hbss_nv_index[params->index_bytes];
        ull_to_bytes(hbss_nv_index, params->index_bytes, new_reserve_count);
        FILE *keypair_file = fopen("keypair", "r+b");
        if (keypair_file == NULL) {
            fprintf(stderr, "Could not open keypair file.\n");
            return -1;
        }
        fseek(keypair_file, XMSS_OID_LEN + params->pk_bytes + XMSS_OID_LEN, SEEK_SET);
        fwrite(hbss_nv_index, 1, params->index_bytes, keypair_file);
        fclose(keypair_file);
    #endif // DEFAULT_STORAGE
    #ifdef TPM_STORAGE
        TPM_RC rc = 0;
        TPM_RC rc1 = 0;
        TSS_CONTEXT	*tssContext = NULL;
        TPMI_SH_AUTH_SESSION sessionHandle = TPM_RS_PW;

        rc = TSS_Create(&tssContext);

        /* Always increment the index when updating, because in normal mode
        the index is incremented by 1 and in modulo increment mode hss_advance_count()
        keeps track of when to update 1 */
        if (rc == 0) {
            rc = nvIncrement(tssContext, sessionHandle, NVINDEX_HBSS_INDEX);
        }

        rc1 = TSS_Delete(tssContext);
        if (rc != 0 || rc1 != 0) {
            const char *msg;
            const char *submsg;
            const char *num;
            TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
            printf("%s%s%s\n", msg, submsg, num);
            return 1;
        }
    #endif // TPM_STORAGE

    params->reserve_count = new_reserve_count;

    /* Update the bds_next data in NV memory */
    BDS_RESERVE(params, sk);

    return sigs_reserved;
}
