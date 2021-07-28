#!/bin/bash

trap 'exit' ERR

# Keypair generation for DEFAULT_STORAGE
echo "----XMSS fast multi-tree keygen----"
ui/xmssmt_keypair_fast_default XMSSMT-SHA2_20/4_256 7
echo "----XMSS fast multi-tree sig gen----"
ui/xmssmt_sign_fast_default 7 keypair 100_bytes.txt 100_bytes.txt
echo "----XMSSMT fast sig verify----"
ui/xmssmt_open_fast_default keypair 100_bytes.txt

# Keypair generation for TPM_STORAGE
echo "----XMSS fast multi-tree keygen----"
ui/xmssmt_keypair_fast_tpm XMSSMT-SHA2_20/4_256 7
echo "----XMSS fast multi-tree sig gen----"
ui/xmssmt_sign_fast_tpm 7 public.key 100_bytes.txt 100_bytes.txt
echo "----XMSSMT fast sig verify----"
ui/xmssmt_open_fast_tpm public.key 100_bytes.txt