# Secure state handling of LMS
This repository is an extension of the [LMS reference code](https://github.com/cisco/hash-sigs). The code is extended by linking it to a TPM and adding an auxiliary data recovery option. In order to communicate with the TPM, code from the [IBM TSS 1.6.0 library](https://sourceforge.net/projects/ibmtpm20tss/) was used. The library is not included in this repository and should be downloaded separately. In order to use the Makefile, one has to modify the paths to the IBM TSS library. An example of how to code can be run is seen in test_script.sh.

# Original README
This code attempts to be a usable implementation of the LMS Hash Based
Signature Scheme from RFC 8554.

See read.me for documentation how to use it.

This is the ACVP branch - designed to be (optionally) compatible with the
public ACVP server
