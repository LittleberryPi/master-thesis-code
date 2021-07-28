#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../params.h"
#include "../xmss.h"
#include "../utils.h"

#ifdef XMSSMT
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_SIGN_OPEN xmssmt_sign_open
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_SIGN_OPEN xmss_sign_open
#endif

int main(int argc, char **argv) {
    struct timespec t_begin, t_end;
    if (argc != 3) {
        fprintf(stderr, "Expected keypair and signature + message filenames "
                        "as two parameters.\n"
                        "Keypair file needs only to contain the public key.\n"
                        "The return code 0 indicates verification success.\n");
        return -1;
    }

    FILE *keypair_file;
    FILE *sm_file;

    xmss_params params;
    uint32_t oid = 0;
    uint8_t buffer[XMSS_OID_LEN];
    int parse_oid_result;

    unsigned long long smlen;
    int ret;

    keypair_file = fopen(argv[1], "rb");
    if (keypair_file == NULL) {
        fprintf(stderr, "Could not open keypair file.\n");
        return -1;
    }

    fread(&buffer, 1, XMSS_OID_LEN, keypair_file);
    oid = (uint32_t)bytes_to_ull(buffer, XMSS_OID_LEN);
    parse_oid_result = XMSS_PARSE_OID(&params, oid);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing oid.\n");
        fclose(keypair_file);
        fclose(sm_file);
        return parse_oid_result;
    }

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char *sm;
    unsigned char *m;
    unsigned long long mlen;

    fseek(keypair_file, 0, SEEK_SET);
    fread(pk, 1, XMSS_OID_LEN + params.pk_bytes, keypair_file);

    for (int file_nr = 2; file_nr < argc; file_nr++) {
        size_t sig_file_name_len = strlen(argv[file_nr]) + sizeof( ".sig" ) + 2;
        char *sig_file_name = malloc(sig_file_name_len);
        sprintf( sig_file_name, "%s.sig", argv[2], file_nr );
        sm_file = fopen(sig_file_name, "rb");
        if (sm_file == NULL) {
            fprintf(stderr, "Could not open signature + message file.\n");
            fclose(keypair_file);
            return -1;
        }

        /* Find out the message length. */
        fseek(sm_file, 0, SEEK_END);
        smlen = ftell(sm_file);

        sm = malloc(smlen);
        m = malloc(smlen);

        fseek(sm_file, 0, SEEK_SET);
        fread(sm, 1, smlen, sm_file);

        ret = XMSS_SIGN_OPEN(m, &mlen, sm, smlen, pk);

        if (ret) {
            printf("Verification failed!\n");
            return 1;
        }
        else {
            printf("Verification succeeded!\n");
        }

        fclose(sm_file);

        free(m);
        free(sm);
    }

    fclose(keypair_file);

    return ret;
}
