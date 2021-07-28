#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../params.h"
#include "../xmss.h"
#include "../hash_bds_data.h"

// Self included
#include "../tpm_functions.h"
#include "../xmss_reserve.h"

// For TPM library
#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ekutils.h>

#ifdef XMSSMT
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_KEYPAIR xmssmt_keypair
#else
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_KEYPAIR xmss_keypair
#endif

// For TPM
#define NVINDEX_OID 0x01000004
#define NVINDEX_HBSS_INDEX 0x01000005
#define NVINDEX_SEED_PRF 0x01000006
#define NVINDEX_ROOT_PKSEED 0x01000007
#define NVINDEX_COUNTER_DIFF 0x01000008
#define NVPWD	"pwd"
#define NVCOUNTER_SIZE 8

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Expected parameter string (e.g. 'XMSS-SHA2_10_256')"
                        " and autoreserve number.\n"
                        "The keypair is written to stdout.\n");
        return -1;
    }

    xmss_params params;
    uint32_t oid = 0;
    int parse_oid_result = 0;

    XMSS_STR_TO_OID(&oid, argv[1]);
    parse_oid_result = XMSS_PARSE_OID(&params, oid);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing oid.\n");
        return parse_oid_result;
    }

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char *sk;
    unsigned char *hmac_out = NULL;

    unsigned int sk_data_size = params.index_bytes + 4*params.n;
    unsigned int sk_seed_addr = XMSS_OID_LEN + params.index_bytes;
    unsigned int bds_addr = XMSS_OID_LEN + sk_data_size;
    unsigned int bds_size = params.sk_bytes - sk_data_size;
    unsigned int total_bds_size = bds_size + params.index_bytes;
    unsigned int total_bds_next_size = params.index_bytes + params.bds_next_bytes;
    unsigned int autoreserve = atoi(argv[2]);
    unsigned int nr_of_hmaced_bds_layers = 0;

    /* If we're in fast mode, we want to store BDS next data, so sk is larger */
    if (XMSS_OID_LEN + params.sk_bytes > bds_addr) { // We're in fast mode
        if (autoreserve > 0) { // we reserve and need BDS INDEX | BDS NEXT | BDS NEXT INDEX
            sk = malloc(XMSS_OID_LEN + params.sk_bytes + params.index_bytes + total_bds_size);
            // main trees + NEXT trees if exists + WOTS sigs if exists + next tree
            nr_of_hmaced_bds_layers = params.d + (params.d > 1 ? 1 : 0) + (params.d-1) + 1;
        }
        else { // we don´t reserve but need BDS INDEX
            sk = malloc(XMSS_OID_LEN + params.sk_bytes + params.index_bytes);
            // main trees + NEXT trees if exists + WOTS sigs if exists
            nr_of_hmaced_bds_layers = params.d + (params.d > 1 ? 1 : 0) + (params.d-1);
        }
        hmac_out = malloc(nr_of_hmaced_bds_layers * params.n);
    }
    else {
        sk = malloc(XMSS_OID_LEN + params.sk_bytes + params.index_bytes);
    }
    xmss_set_reserve_count(&params, 0);
    xmss_set_autoreserve(&params, autoreserve);

    XMSS_KEYPAIR(pk, sk, oid, &params);

    #ifdef DEFAULT_STORAGE
        FILE *keypair_file = fopen("keypair", "w+");
        if (XMSS_OID_LEN + params.sk_bytes > bds_addr) { // We're in fast mode
            fwrite(pk, XMSS_OID_LEN + params.pk_bytes, 1, keypair_file);
            if (autoreserve > 0) // we reserve and need BDS INDEX | BDS NEXT | BDS NEXT INDEX
                fwrite(sk, XMSS_OID_LEN + params.sk_bytes + params.index_bytes + total_bds_next_size, 1, keypair_file);
            else // we don´t reserve but need BDS INDEX
                fwrite(sk, XMSS_OID_LEN + params.sk_bytes + params.index_bytes, 1, keypair_file);
        }
        else {
            fwrite(pk, XMSS_OID_LEN + params.pk_bytes, 1, keypair_file);
            fwrite(sk, XMSS_OID_LEN + params.sk_bytes, 1, keypair_file);
        }
        fclose(keypair_file);
    #endif //DEFAULT_STORAGE

    #ifdef TPM_STORAGE
        TPM_RC rc = 0;
        TPM_RC rc1 = 0;
        TSS_CONTEXT	*tssContext = NULL;
        Startup_In 		in;
        TPMI_SH_AUTH_SESSION sessionHandle = TPM_RS_PW;
        unsigned char *readBuffer = NULL;

        /* Initialize TPM, regardless whether it is already initialized.
        * Ignore the error when the TPM is already initialized. */
        /* Start a TSS context */
        rc = TSS_Create(&tssContext);
        if (rc == 0) {
            TSS_SetProperty(tssContext, TPM_TRANSMIT_LOCALITY, NULL);
        }
        /* Call TSS to execute the command */
        if (rc == 0) {
            in.startupType = TPM_SU_CLEAR;
            rc = TSS_Execute(tssContext,
                    NULL, 
                    (COMMAND_PARAMETERS *)&in,
                    NULL,
                    TPM_CC_Startup,
                    TPM_RH_NULL, NULL, 0);
        }
        if (rc != 0) {
            rc = 0;
        }


        /* Store the oid in TPM NVRAM ordinary index.
        Probe to see if the index already exists. */
        if (rc == 0) {
            if (tpmVerbose) printf("TPM_INFO: Read the NV index at %08x\n", NVINDEX_OID);
            rc = nvReadPublic(tssContext, NVINDEX_OID);
            /* on failure, define the index */
            if (rc != 0) {
                if (tpmVerbose) printf("TPM_INFO: Create the NV index at %08x\n", NVINDEX_OID);
                rc = defineSpace(tssContext, XMSS_OID_LEN, TPMA_NVA_ORDINARY, NVINDEX_OID);
            }
        }
        /* Write to the NV memory index */
        if (rc == 0) {
            if (tpmVerbose) printf("TPM_INFO: Write to index %08x and written bit\n", NVINDEX_OID);
            unsigned char data[XMSS_OID_LEN];
            memcpy(data, sk, XMSS_OID_LEN);
            rc = nvWrite(tssContext, sessionHandle, data, XMSS_OID_LEN, NVINDEX_OID);
        }


        /* Define the HBSS index in an NV counter index.
        Probe to see if the index already exists.
        Increment the index so the written flag is set.
        Then, read the index value and store it in an NV ordinary index.*/
        if (rc == 0) {
            if (tpmVerbose) printf("TPM_INFO: Read the NV index at %08x\n", NVINDEX_HBSS_INDEX);
            rc = nvReadPublic(tssContext, NVINDEX_HBSS_INDEX);
            /* on failure, define the index */
            if (rc != 0) {
                /* Define the NV counter index for the HBSS index */
                if (tpmVerbose) printf("TPM_INFO: Create the NV index at %08x\n", NVINDEX_HBSS_INDEX);
                rc = defineSpace(tssContext, NVCOUNTER_SIZE, TPMA_NVA_COUNTER, NVINDEX_HBSS_INDEX);
                /* Increment the NV counter */
                if (rc == 0) {
                    rc = nvIncrement(tssContext, sessionHandle, NVINDEX_HBSS_INDEX);
                }

                /* Read the HBSS index from the NV counter index. */
                if (rc == 0) {
                    if (tpmVerbose) printf("TPM_INFO: Read index %08x\n", NVINDEX_HBSS_INDEX);
                    readBuffer = malloc(NVCOUNTER_SIZE);
                    rc = nvRead(tssContext, sessionHandle, readBuffer, NVINDEX_HBSS_INDEX, NVCOUNTER_SIZE);
                }
                
                /* Store the counter value in a new NV ordinary index, because the TPM 
                defines a counter with the max counter value the TPM has ever known. Probe
                to see if the index already exists. */
                if (rc == 0) {
                    if (tpmVerbose) printf("TPM_INFO: Read the NV index at %08x\n", NVINDEX_COUNTER_DIFF);
                    rc = nvReadPublic(tssContext, NVINDEX_COUNTER_DIFF);
                    /* on failure, define the index */
                    if (rc != 0) {
                        if (tpmVerbose) printf("TPM_INFO: Create the NV index at %08x\n", NVINDEX_COUNTER_DIFF);
                        rc = defineSpace(tssContext, NVCOUNTER_SIZE, TPMA_NVA_ORDINARY, NVINDEX_COUNTER_DIFF);
                    }
                }
                /* Write to the NV memory index */
                if (rc == 0) {
                    if (tpmVerbose) printf("TPM_INFO: Write to index %08x and written bit\n", NVINDEX_COUNTER_DIFF);
                    rc = nvWrite(tssContext, sessionHandle, readBuffer, NVCOUNTER_SIZE, NVINDEX_COUNTER_DIFF);
                }
            }
        }


        /* Store the seed and prf in TPM NVRAM ordinary index.
        Probe to see if the index already exists. */
        if (rc == 0) {
            if (tpmVerbose) printf("TPM_INFO: Read the NV index at %08x\n", NVINDEX_SEED_PRF);
            rc = nvReadPublic(tssContext, NVINDEX_SEED_PRF);
            /* on failure, define the index */
            if (rc != 0) {
                if (tpmVerbose) printf("TPM_INFO: Create the NV index at %08x\n", NVINDEX_SEED_PRF);
                rc = defineSpace(tssContext, 2 * params.n, TPMA_NVA_ORDINARY, NVINDEX_SEED_PRF);
            }
        }
        /* Write to the NV memory index */
        if (rc == 0) {
            if (tpmVerbose) printf("TPM_INFO: Write to index %08x and written bit\n", NVINDEX_SEED_PRF);
            unsigned char data[2 * params.n];
            memcpy(data, sk + XMSS_OID_LEN + params.index_bytes, 2 * params.n);
            rc = nvWrite(tssContext, sessionHandle, data, 2 * params.n, NVINDEX_SEED_PRF);
        }


        /* Store the root node and pub seed in TPM NVRAM ordinary index.
        Probe to see if the index already exists. */
        if (rc == 0) {
            if (tpmVerbose) printf("TPM_INFO: Read the NV index at %08x\n", NVINDEX_ROOT_PKSEED);
            rc = nvReadPublic(tssContext, NVINDEX_ROOT_PKSEED);
            /* on failure, define the index */
            if (rc != 0) {
                if (tpmVerbose) printf("TPM_INFO: Create the NV index at %08x\n", NVINDEX_ROOT_PKSEED);
                rc = defineSpace(tssContext, 2 * params.n, TPMA_NVA_ORDINARY, NVINDEX_ROOT_PKSEED);
            }
        }
        /* Write to the NV memory index */
        if (rc == 0) {
            if (tpmVerbose) printf("TPM_INFO: Write to index %08x and written bit\n", NVINDEX_ROOT_PKSEED);
            unsigned char data[2 * params.n];
            memcpy(data, sk + XMSS_OID_LEN + params.index_bytes + 2 * params.n, 2 * params.n);
            rc = nvWrite(tssContext, sessionHandle, data, 2 * params.n, NVINDEX_ROOT_PKSEED);
        }

        /* Delete TSS context */
        rc1 = TSS_Delete(tssContext);
        if (rc != 0 || rc1 != 0) {
            const char *msg;
            const char *submsg;
            const char *num;
            TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
            printf("%s%s%s\n", msg, submsg, num);
            return 0;
        }

        /* Write the BDS data to a file (only in fast mode) */
        if (XMSS_OID_LEN + params.sk_bytes > bds_addr) {
            FILE *f_bds = fopen( "bds.data", "w+" );
            if (autoreserve > 0) // write bds_next data too
                fwrite(sk + bds_addr, total_bds_size + total_bds_next_size, 1, f_bds);
            else // only write bds data
                fwrite(sk + bds_addr, total_bds_size, 1, f_bds);
            fclose(f_bds);
        }

        /* Write the public key to a file */
        FILE *f = fopen("public.key", "w+");
        fwrite(pk, XMSS_OID_LEN + params.pk_bytes, 1, f);
        fclose(f);
    #endif //TPM_STORAGE

    // If we have BDS data, compute and store the HMAC'ed BDS data
    if (XMSS_OID_LEN + params.sk_bytes > bds_addr) {
        hmac_all_bds_data(&params, sk + bds_addr, sk + sk_seed_addr, hmac_out, 1, 1);
        FILE *fhmac = fopen("hmac.data", "w+");
        fwrite(hmac_out, nr_of_hmaced_bds_layers * params.n, 1, fhmac);
        fclose(fhmac);
    }

    free(sk);

    return 0;
}
