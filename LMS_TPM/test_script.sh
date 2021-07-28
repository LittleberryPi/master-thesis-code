#!/bin/bash

trap 'exit' ERR

# # DEFAULT_STORAGE
# echo "--- Key gen ---"
# ./tpm_demo_default genkey keypair
# echo "--- Sig gen ---"
# ./tpm_demo_default sign keypair 7 100_bytes.txt
# echo "--- Sig verify ---"
# ./tpm_demo_default verify keypair 100_bytes.txt

# # TPM_STORAGE
# echo "--- Key gen ---"
# ./tpm_demo_tpm genkey keypair
# echo "--- Sig gen ---"
# ./tpm_demo_tpm sign keypair 7 100_bytes.txt
# echo "--- Sig verify ---"
# ./tpm_demo_tpm verify keypair 100_bytes.txt

# # Recovery
# echo "--- Key gen ---"
# ./tpm_demo_tpm genkey keypair
# echo "--- Aux recovery ---"
# ./tpm_demo_tpm recover_aux keypair 7
# echo "--- Sig gen ---"
# ./tpm_demo_tpm sign keypair 7 100_bytes.txt
# echo "--- Sig verify ---"
# ./tpm_demo_tpm verify keypair 100_bytes.txt