#if !defined( TPM_FUNCTIONS_H_ )
#define TPM_FUNCTIONS_H_

// For TPM library
#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ekutils.h>

extern int tpmVerbose;

/* Get a random number from the TPM */
TPM_RC get_random(unsigned char *random_buffer, unsigned long long nr_bytes);

/* TPM function to read NV index */
TPM_RC nvReadPublic(TSS_CONTEXT *tssContext, int nvIndex);

/* TPM function to start a session */
TPM_RC startSession(TSS_CONTEXT *tssContext,
			   TPMI_SH_AUTH_SESSION *sessionHandle,
			   TPMI_DH_OBJECT tpmKey,		/* salt key */
			   TPMI_DH_ENTITY bind);		/* bind object */


/* TPM function to flush a session */
TPM_RC flush(TSS_CONTEXT *tssContext,
		    TPMI_DH_CONTEXT flushHandle);

/* TPM function to define space */
TPM_RC defineSpace(TSS_CONTEXT *tssContext, size_t spaceSize, int nvType, 
                          int nvIndex);

/* TPM function to undefine an NV index */
TPM_RC nvUndefineSpace(TSS_CONTEXT *tssContext, int nvIndex);

/* TPM function to write to an NV memory index */
TPM_RC nvWrite(TSS_CONTEXT *tssContext, TPMI_SH_AUTH_SESSION sessionHandle,
		  	  unsigned char *data, size_t len_data, int nvIndex);

/* TPM function to read from a TPM NV memory index */
TPM_RC nvRead(TSS_CONTEXT *tssContext, TPMI_SH_AUTH_SESSION sessionHandle,
                    unsigned char *readBuffer, int nvIndex, int nvIndexLength);

/* TPM function to increment the index of a NV memory counter */
TPM_RC nvIncrement(TSS_CONTEXT *tssContext, TPMI_SH_AUTH_SESSION sessionHandle,
                          int nvIndex);
#endif /* TPM_FUNCTIONS_H */