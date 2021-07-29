#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>

#include "../params.h"
#include "../xmss.h"
#include "../utils.h"

// Self included
#include "../tpm_functions.h"
#include "../xmss_reserve.h"
#include "../hash_bds_data.h"

// For TPM library
#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ekutils.h>

#ifdef XMSSMT
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_RECOVER_BDS_DATA xmssmt_recover_bds_data
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_SIGN xmss_sign
    #define XMSS_RECOVER_BDS_DATA xmss_recover_bds_data
#endif

// For TPM
#define NVINDEX_OID 0x01000004
#define NVINDEX_HBSS_INDEX 0x01000005
#define NVINDEX_SEED_PRF 0x01000006
#define NVINDEX_ROOT_PKSEED 0x01000007
#define NVINDEX_COUNTER_DIFF 0x01000008
#define NVPWD	"pwd"
#define NVCOUNTER_SIZE 8

/*
 * Convert an unsigned char array of 8 to an uint64_t
*/
uint64_t char_array_to_int(unsigned char* buffer){
    uint64_t new_int = (uint64_t)buffer[0] << 56 |
        (uint64_t)buffer[1] << 48 |
        (uint64_t)buffer[2] << 40 |
        (uint64_t)buffer[3] << 32 |
        (uint64_t)buffer[4] << 24 |
        (uint64_t)buffer[5] << 16 |
        (uint64_t)buffer[6] << 8  |
        (uint64_t)buffer[7];
    return new_int;
}


int main(int argc, char **argv) {
    struct timespec t_begin, t_end;
    if (argc < 4) {
        fprintf(stderr, "Expected keypair and message filenames\n"
                        "The keypair is updated with the changed state, "
                        "and the message + signature is output via stdout.\n");
        return -1;
    }

    unsigned int autoreserve = atoi(argv[1]);

    /************************************
     * Read in the data from files      *
     ************************************/
    #ifdef TPM_STORAGE
        TPM_RC rc = 0;
        TPM_RC rc1 = 0;
        TSS_CONTEXT	*tssContext = NULL;
        Startup_In 		in;
        TPMI_SH_AUTH_SESSION sessionHandle = TPM_RS_PW;
    #endif // TPM_STORAGE

    FILE *keypair_file;
    FILE *m_file;
    FILE *fhmac;

    xmss_params params;
    uint32_t oid_pk = 0;
    uint32_t oid_sk = 0;
    uint8_t buffer[XMSS_OID_LEN];
    int parse_oid_result;

    unsigned long long mlen;

    keypair_file = fopen(argv[2], "r+b");
    if (keypair_file == NULL) {
        fprintf(stderr, "Could not open keypair file.\n");
        return -1;
    }

    /* Read the OID from the public key, as we need its length to seek past it */
    fread(&buffer, 1, XMSS_OID_LEN, keypair_file);
    /* The XMSS_OID_LEN bytes in buffer are a big-endian uint32. */
    oid_pk = (uint32_t)bytes_to_ull(buffer, XMSS_OID_LEN);
    parse_oid_result = XMSS_PARSE_OID(&params, oid_pk);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing public key oid.\n");
        fclose(keypair_file);
        return parse_oid_result;
    }

    /* Initialize the index in sk where the BDS data would begin */
    unsigned int sk_data_size = params.index_bytes + 4*params.n;
    unsigned int sk_seed_addr = XMSS_OID_LEN + params.index_bytes;
    unsigned int bds_addr = XMSS_OID_LEN + sk_data_size;
    unsigned int bds_reserved_idx_addr = XMSS_OID_LEN + params.sk_bytes + params.index_bytes;
    unsigned int bds_reserved_data_addr = XMSS_OID_LEN + params.sk_bytes + params.index_bytes + params.index_bytes;
    unsigned int bds_NEXT_layer_addr = bds_addr + (params.d*params.bds_state_bytes);
    unsigned int bds_NEXT_layer_size = (params.d-1)*params.bds_state_bytes;
    unsigned int bds_size = params.sk_bytes - sk_data_size;
    unsigned int total_bds_size = bds_size + params.index_bytes;
    unsigned int total_bds_reserved_size = params.index_bytes + params.bds_state_bytes;
    unsigned int nr_of_hmaced_bds_layers = 0;
    unsigned int bds_data_corrupted = 0;
    
    /* fseek past the public key */
    #ifdef DEFAULT_STORAGE
        fseek(keypair_file, params.pk_bytes, SEEK_CUR);
        /* This is the OID we're actually going to use. Likely the same, but still. */
        fread(&buffer, 1, XMSS_OID_LEN, keypair_file);
    #endif //DEFAULT_STORAGE
    #ifdef TPM_STORAGE
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

        /* Read the parameter set from TPM NV memory */
        rc = nvRead(tssContext, sessionHandle, buffer, NVINDEX_OID, XMSS_OID_LEN);
    #endif //TPM_STORAGE
    oid_sk = (uint32_t)bytes_to_ull(buffer, XMSS_OID_LEN);
    parse_oid_result = XMSS_PARSE_OID(&params, oid_sk);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing secret key oid.\n");
        fclose(keypair_file);
        return parse_oid_result;
    }

    unsigned char *sk;
    unsigned char *hmac = NULL;
    if (XMSS_OID_LEN + params.sk_bytes > bds_addr) { // We're in fast mode
        if (autoreserve > 0) { // use bds_reserved
            sk = malloc(XMSS_OID_LEN + params.sk_bytes + params.index_bytes + total_bds_size);
            // main trees + NEXT trees if exists + WOTS sigs if exists + next tree
            nr_of_hmaced_bds_layers = params.d + (params.d > 1 ? 1 : 0) + (params.d-1) + 1;
        }
        else { // only use bds
            sk = malloc(XMSS_OID_LEN + params.sk_bytes + params.index_bytes);
            // main trees + NEXT trees + WOTS sigs
            nr_of_hmaced_bds_layers = params.d + (params.d > 1 ? 1 : 0)  + (params.d-1);
        }
        hmac = malloc(nr_of_hmaced_bds_layers * params.n);
    }
    else {
        sk = malloc(XMSS_OID_LEN + params.sk_bytes + params.index_bytes);
    }


    /* Read in the XMSS secret key
       XMSS sk format = OID | INDEX | SEED+PRF | ROOT | PUBSEED
       XMSS fast sk format = OID | INDEX | SEED+PRF | ROOT | PUBSEED | BDS_DATA | BDS IDX (| BDS_NEXT IDX | BDS_NEXT DATA) */
    #ifdef DEFAULT_STORAGE
        /* fseek back to start of sk. */
        fseek(keypair_file, -((long int)XMSS_OID_LEN), SEEK_CUR);
        fread(sk, 1, XMSS_OID_LEN + params.sk_bytes, keypair_file); // read in sk data

        if (XMSS_OID_LEN + params.sk_bytes > bds_addr) { // if we're in fast mode
            // read in bds index
            unsigned int size_read = fread(sk + XMSS_OID_LEN + params.sk_bytes, 1, params.index_bytes, keypair_file);
            // Verify whether file is deleted/shrinked
            if (size_read < params.index_bytes) {
                bds_data_corrupted = 1;
            }
            else if (autoreserve > 0) { // read in bds_reserved too
                size_read = fread(sk + bds_reserved_idx_addr, 1, total_bds_reserved_size, keypair_file);
                // Verify whether file is deleted/shrinked
                if (size_read < total_bds_reserved_size) {
                    bds_data_corrupted = 1;
                }
            }
        }
    #endif //DEFAULT_STORAGE
    #ifdef TPM_STORAGE
        /* Set the OID */
        memcpy(sk, buffer, XMSS_OID_LEN);

        /* Set the index */
        /* First, read the HBSS index from TPM NV memory */
        unsigned char *readBuffer = NULL;
        readBuffer = malloc(NVCOUNTER_SIZE);
        rc = nvRead(tssContext, sessionHandle, readBuffer, NVINDEX_HBSS_INDEX, NVCOUNTER_SIZE);
        uint64_t tpm_counter = char_array_to_int(readBuffer);
        free(readBuffer);
        /* Read the counter difference from TPM NV memory */
        readBuffer = malloc(NVCOUNTER_SIZE);
        rc = nvRead(tssContext, sessionHandle, readBuffer, NVINDEX_COUNTER_DIFF, NVCOUNTER_SIZE);
        uint64_t counter_difference = char_array_to_int(readBuffer);
        free(readBuffer);
        unsigned char actual_hbss_index[params.index_bytes];
        uint64_t actual_hbss_index_int64 = tpm_counter - counter_difference;
        if (autoreserve > 0) {
            actual_hbss_index_int64 = actual_hbss_index_int64 * (autoreserve+1);
        }
        /* From actual_hbss_index_int64 to char array of size params.index_bytes */
        for (unsigned int i = 0; i < params.index_bytes; i++) {
            int shift_value = i * 8;
            actual_hbss_index[params.index_bytes - 1 - i] = actual_hbss_index_int64 >> shift_value;
        }
        memcpy(sk + XMSS_OID_LEN, actual_hbss_index, params.index_bytes);


        /* Read in the seed and prf from TPM NV memory */
        readBuffer = malloc(2 * params.n);
        rc = nvRead(tssContext, sessionHandle, readBuffer, NVINDEX_SEED_PRF, 2 * params.n);
        memcpy(sk + XMSS_OID_LEN + params.index_bytes, readBuffer, 2 * params.n);
        free(readBuffer);

        /* Read in the root and pubseed from TPM NV memory */
        readBuffer = malloc(2 * params.n);
        rc = nvRead(tssContext, sessionHandle, readBuffer, NVINDEX_ROOT_PKSEED, 2 * params.n);
        memcpy(sk + XMSS_OID_LEN + params.index_bytes + 2 * params.n, readBuffer, 2 * params.n);
        free(readBuffer);

        /* If we're in fast mode, read in the BDS data */
        if (XMSS_OID_LEN + params.sk_bytes > bds_addr) {
            // Read in BDS data
            FILE *f_bds = fopen("bds.data", "rb");
            if (!f_bds) {
                bds_data_corrupted = 1;
            }
            else {
                unsigned int size_read = fread(sk + bds_addr, 1, total_bds_size, f_bds);
                // Verify whether file is deleted/shrinked
                if (size_read < total_bds_size) {
                    bds_data_corrupted = 1;
                }
                // Read in bds_reserved data
                else if (autoreserve > 0) {
                    size_read = fread(sk + bds_reserved_idx_addr, 1, total_bds_reserved_size, f_bds);
                    if (size_read < total_bds_reserved_size) {
                        bds_data_corrupted = 1;
                    }
                }
                fclose(f_bds);
            }
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
    #endif //TPM_STORAGE
    fclose(keypair_file);

    /************************************
     * Set some variables               *
     ************************************/
    // If we are in fast mode and we reserve, set the rest of bds_reserved to be similar to bds
    if (XMSS_OID_LEN + params.sk_bytes > bds_addr && autoreserve > 0) {
        unsigned int bds_reserved_data_layer1_addr = bds_reserved_data_addr + params.bds_state_bytes;
        unsigned int bds_data_layer1_addr = bds_addr + params.bds_state_bytes;
        unsigned int bds_no_layer0_size = bds_size - params.bds_state_bytes;
        memcpy(sk + bds_reserved_data_layer1_addr, sk + bds_data_layer1_addr, bds_no_layer0_size);
    }

    /* Set the reserve count in params by reading index from sk */
    uint64_t reserve_count = 0;
    for (unsigned int i = 0; i < params.index_bytes; i++) {
        int shift = i * 8;
        reserve_count |= (uint64_t)sk[XMSS_OID_LEN + params.index_bytes - 1 - i] << shift;
    }
    xmss_set_reserve_count(&params, reserve_count);

    /* Set the autoreserve number in params */
    xmss_set_autoreserve(&params, autoreserve);

    /************************************
     * Verify BDS data                  *
     ************************************/
    /* If we have BDS data, read in HMAC'ed BDS data and verify HMAC */
    if (XMSS_OID_LEN + params.sk_bytes > bds_addr) {
        int data_recovered = 0;
        unsigned int *corrupted_layers = calloc(nr_of_hmaced_bds_layers, sizeof(unsigned int));
        /* Recover the BDS data if it is deleted/shrinked */
        if (bds_data_corrupted) {
            printf("BDS data is deleted/shrinked\n");
            set_corrupted_layers(corrupted_layers, nr_of_hmaced_bds_layers, -1);
            XMSS_RECOVER_BDS_DATA(sk, &params, corrupted_layers, nr_of_hmaced_bds_layers);
            data_recovered = 1;
        }
        else {
            fhmac = fopen("hmac.data", "r+b");
            // Ŕecover if file doesn't exist
            if (!fhmac) {
                printf("HMAC'ed BDS data is removed\n");
                set_corrupted_layers(corrupted_layers, nr_of_hmaced_bds_layers, -1);
                XMSS_RECOVER_BDS_DATA(sk, &params, corrupted_layers, nr_of_hmaced_bds_layers);
                data_recovered = 1;

                fhmac = fopen("hmac.data", "w+");
            }
            else {
                fread(hmac, nr_of_hmaced_bds_layers * params.n, 1, fhmac);
                /* Check if BDS data corresponds to HMAC */
                unsigned char *hmac_data = malloc(nr_of_hmaced_bds_layers * params.n);
                memcpy(hmac_data, hmac, nr_of_hmaced_bds_layers * params.n);
                hmac_all_bds_data(&params, sk + bds_addr, sk + sk_seed_addr, hmac_data, 1, 1);
                for (unsigned int i = 0; i < nr_of_hmaced_bds_layers; i++) {
                    if (0 != memcmp( hmac + i * params.n, hmac_data + i * params.n, params.n)) {
                        printf("BDS data hmac %d is not as expected\n", i);
                        set_corrupted_layers(corrupted_layers, nr_of_hmaced_bds_layers, i);
                        data_recovered = 1;
                    }
                }
                if (data_recovered) {
                    XMSS_RECOVER_BDS_DATA(sk, &params, corrupted_layers, nr_of_hmaced_bds_layers);
                }
                free(hmac_data);
            }
            fclose(fhmac);
        }
        free(corrupted_layers);
            

        /* If the data is recovered, we need to correct the BDS data in NV memory */
        if (data_recovered) {
            #ifdef DEFAULT_STORAGE
                FILE *keypair_file = fopen("keypair", "r+b");
                fseek(keypair_file, XMSS_OID_LEN + params.pk_bytes + bds_addr, SEEK_SET);
                fwrite(sk + bds_addr, 1, total_bds_size + total_bds_reserved_size, keypair_file);
                fclose(keypair_file);
            #endif //TPM_STORAGE
            #ifdef TPM_STORAGE
                FILE *f_bds = fopen( "bds.data", "w+" );
                fwrite(sk + bds_addr, 1, total_bds_size + total_bds_reserved_size, f_bds);
                fclose(f_bds);
            #endif //TPM_STORAGE
        }
    }

    /*****************************************
     * Reserve autoreserve nr of signatures  *
     *****************************************/
    if (autoreserve > 0) {
        /* Reserve autoreserve number of keys */
        xmss_reserve_signature(&params, autoreserve+1, reserve_count, sk);

        if (XMSS_OID_LEN + params.sk_bytes > bds_addr) { // if we're in fast mode
            /* bds_reserved in nv memory = bds_reserved in memory and 
            bds in nv memory = bds_reserved in nv memory */
            unsigned char sk_nv[total_bds_size + total_bds_size];
            // bds + bds_reserved in sk_nv = bds + bds_reserved in sk
            memcpy(sk_nv, sk + bds_addr, total_bds_size + total_bds_size); 
            // bds in sk_nv = bds_reserved in sk
            memcpy(sk_nv, sk + bds_reserved_data_addr, bds_size); 
            // update bds idx
            ull_to_bytes(sk + XMSS_OID_LEN + params.sk_bytes, params.index_bytes, params.reserve_count); 

            #ifdef DEFAULT_STORAGE
                FILE *keypair_file = fopen("keypair", "r+b");
                fseek(keypair_file, XMSS_OID_LEN + params.pk_bytes + bds_addr, SEEK_SET);
                fwrite(sk_nv, 1, total_bds_size + total_bds_reserved_size, keypair_file);
                fclose(keypair_file);
            #endif //TPM_STORAGE
            #ifdef TPM_STORAGE
                FILE *f_bds = fopen( "bds.data", "r+b" );
                fwrite(sk_nv, 1, total_bds_size + total_bds_reserved_size, f_bds);
                fclose(f_bds);
            #endif //TPM_STORAGE

            hmac_all_bds_data(&params, sk_nv, sk + sk_seed_addr, hmac, 1, 1);
        }
    }


    /************************************
     * Sign the messages                *
     ************************************/
    for (int file_nr = 3; file_nr < argc; file_nr++) {
        // printf( "Signing %s\n", argv[file_nr] );
        m_file = fopen(argv[file_nr], "rb");
        if (m_file == NULL) {
            fprintf(stderr, "Could not open message file.\n");
            return -1;
        }

        /* Find out the message length. */
        fseek(m_file, 0, SEEK_END);
        mlen = ftell(m_file);

        unsigned char *m = malloc(mlen);
        unsigned char *sm = malloc(params.sig_bytes + mlen);
        unsigned long long smlen;
        fseek(m_file, 0, SEEK_SET);
        fread(m, 1, mlen, m_file);

        int sigs_reserved = XMSS_SIGN(sk, &params, sm, &smlen, m, mlen);
        
        /**************************************
         * If we ran out of keys: delete data *
         **************************************/
        if (sigs_reserved == -2) {
            printf("ran out of keys\n");
            #ifdef DEFAULT_STORAGE
                unsigned int keypair_sk_size;
                if (autoreserve > 0) {
                    keypair_sk_size = XMSS_OID_LEN + params.sk_bytes + params.index_bytes;
                }
                else {
                    keypair_sk_size = XMSS_OID_LEN + params.sk_bytes + params.index_bytes + total_bds_reserved_size;
                }
                unsigned char zero_nv[keypair_sk_size];
                memset(zero_nv, 0, keypair_sk_size);
                FILE *keypair_file = fopen("keypair", "r+b");
                // fseek past the public key
                fseek(keypair_file, XMSS_OID_LEN + params.pk_bytes, SEEK_SET);
                fwrite(zero_nv, 1, keypair_sk_size, keypair_file);
                fclose(keypair_file);
            #endif // DEFAULT_STORAGE
            #ifdef TPM_STORAGE
                rc = TSS_Create(&tssContext);
                if (rc == 0) {
                    TSS_SetProperty(tssContext, TPM_TRANSMIT_LOCALITY, NULL);
                }

                /* Delete the NV indices */
                nvUndefineSpace(tssContext, NVINDEX_OID);
                nvUndefineSpace(tssContext, NVINDEX_HBSS_INDEX);
                nvUndefineSpace(tssContext, NVINDEX_SEED_PRF);
                nvUndefineSpace(tssContext, NVINDEX_ROOT_PKSEED);
                nvUndefineSpace(tssContext, NVINDEX_COUNTER_DIFF);
                
                rc = TSS_Delete(tssContext);
                if (rc != 0 || rc1 != 0) {
                    const char *msg;
                    const char *submsg;
                    const char *num;
                    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
                    printf("%s%s%s\n", msg, submsg, num);
                    return 1;
                }

                /* Delete the BDS data */
                unsigned int bds_file_size;
                if (autoreserve > 0) {
                    bds_file_size = total_bds_size;
                }
                else {
                    bds_file_size = total_bds_size + total_bds_reserved_size;
                }
                unsigned char zero_nv[bds_file_size];
                memset(zero_nv, 0, bds_file_size);
                FILE *f_bds = fopen( "bds.data", "w+" );
                fwrite(zero_nv, 1, bds_file_size, f_bds);
                fclose(f_bds);
            #endif // TPM_STORAGE

            return 0;
        }

        /************************************
         * Update the BDS data              *
         ************************************/
        // Write bds data to nv memory and if autoreserve>0 also bds_reserved (only in fast mode)
        if (XMSS_OID_LEN + params.sk_bytes > bds_addr) {
            if (autoreserve == 0) { // always only update bds in nv memory because we have no bds_reserved
                #ifdef DEFAULT_STORAGE
                    FILE *keypair_file = fopen("keypair", "r+b");
                    fseek(keypair_file, XMSS_OID_LEN + params.pk_bytes + bds_addr, SEEK_SET);
                    fwrite(sk + bds_addr, 1, total_bds_size, keypair_file);
                    fclose(keypair_file);
                #endif //TPM_STORAGE
                #ifdef TPM_STORAGE
                    FILE *f_bds = fopen( "bds.data", "w+" );
                    fwrite(sk + bds_addr, 1, total_bds_size, f_bds);
                    fclose(f_bds);
                #endif //TPM_STORAGE

                hmac_all_bds_data(&params, sk + bds_addr, sk + sk_seed_addr, hmac, 1, 1);
            }
            else { // we also have to deal with bds_reserved
                if (sigs_reserved > 0) { // bds in nv memory = bds_reserved in ram
                    // Put BDS next in sk, but BDS NEXT layers are already in sk so keep those
                    unsigned char sk_nv[total_bds_size + total_bds_size];
                    // copy sk bds + bds next to sk_nv
                    memcpy(sk_nv, sk + bds_addr, total_bds_size + total_bds_size); 
                    // fully bds in sk_nv = fully bds_reserved in sk
                    memcpy(sk_nv, sk + bds_reserved_data_addr, bds_size); 
                    // copy NEXT layers in sk to sk_nv
                    memcpy(sk_nv + (bds_NEXT_layer_addr - bds_addr), sk + bds_NEXT_layer_addr, bds_NEXT_layer_size);
                    // update bds idx
                    ull_to_bytes(sk_nv + bds_size, params.index_bytes, params.reserve_count); 
                    
                    #ifdef DEFAULT_STORAGE
                        FILE *keypair_file = fopen("keypair", "r+b");
                        fseek(keypair_file, XMSS_OID_LEN + params.pk_bytes + bds_addr, SEEK_SET);
                        fwrite(sk_nv, 1, total_bds_size + total_bds_reserved_size, keypair_file);
                        fclose(keypair_file);
                    #endif //TPM_STORAGE
                    #ifdef TPM_STORAGE
                        FILE *f_bds = fopen( "bds.data", "w+" );
                        fwrite(sk_nv, 1, total_bds_size + total_bds_reserved_size, f_bds);
                        fclose(f_bds);
                    #endif //TPM_STORAGE

                    hmac_all_bds_data(&params, sk_nv, sk + sk_seed_addr, hmac, 1, 1);
                }
                else {
                    // Update BDS NEXT layers and BDS next                    
                    #ifdef DEFAULT_STORAGE
                        FILE *keypair_file = fopen("keypair", "r+b");
                        if (params.d > 1) {
                            // update bds NEXT layers
                            fseek(keypair_file, XMSS_OID_LEN + params.pk_bytes + bds_NEXT_layer_addr, SEEK_SET);
                            fwrite(sk + bds_NEXT_layer_addr, 1, (params.d-1)*params.bds_state_bytes, keypair_file);
                        }
                        // update BDS next
                        fseek(keypair_file, XMSS_OID_LEN + params.pk_bytes + bds_reserved_idx_addr, SEEK_SET);
                        fwrite(sk + bds_reserved_idx_addr, 1, total_bds_reserved_size, keypair_file);
                        fclose(keypair_file);
                    #endif //TPM_STORAGE
                    #ifdef TPM_STORAGE
                        FILE *f_bds = fopen( "bds.data", "r+b" );
                        if (params.d > 1) {
                            // update bds NEXT layers
                            fseek(f_bds, bds_NEXT_layer_addr - bds_addr, SEEK_SET);
                            fwrite(sk + bds_NEXT_layer_addr, 1, (params.d-1)*params.bds_state_bytes, f_bds);
                        }
                        // update BDS next
                        fseek(f_bds, total_bds_size, SEEK_SET);
                        fwrite(sk + bds_reserved_idx_addr, 1, total_bds_reserved_size, f_bds);
                        fclose(f_bds);
                    #endif //TPM_STORAGE

                    hmac_all_bds_data(&params, sk + bds_addr, sk + sk_seed_addr, hmac, 0, 0);
                }
            }
        }

        // If we have BDS data, write the HMAC'ed BDS data
        if (XMSS_OID_LEN + params.sk_bytes > bds_addr) {
            fhmac = fopen("hmac.data", "w+");
            fwrite(hmac, nr_of_hmaced_bds_layers * params.n, 1, fhmac);
            fclose(fhmac);
        }

        /************************************
         * Write the signature to a file    *
         ************************************/
        size_t sig_file_name_len = strlen(argv[file_nr]) + sizeof( ".sig" ) + 1;
        char *sig_file_name = malloc( sig_file_name_len );
        sprintf( sig_file_name, "%s.sig", argv[file_nr] );
        FILE *f_sig = fopen( sig_file_name, "w+" );
        if (!f_sig) {
            /* Unable to open file */
            printf("unable to open file\n");
            return 0;
        }
        fwrite(sm, 1, smlen, f_sig);

        fclose(m_file);
        fclose(f_sig);

        free(m);
        free(sm);
    }
    free(sk);

    return 0;
}
