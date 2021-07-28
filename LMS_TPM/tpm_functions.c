#include <string.h>
#include "tpm_functions.h"
// For TPM library
#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ekutils.h>

#define NVPWD	"pwd"

int tpmVerbose = 0;

/**
 * NOTE: This code is inspired and copied from the IBM TSS 1.6.0 library 
 */

/*
 * Get a random number from the TPM
*/
unsigned char * get_random(uint32_t nr_bytes) {
    TPM_RC			rc = 0;
    TSS_CONTEXT			*tssContext = NULL;
    GetRandom_In 		in;
    GetRandom_Out 		out;
    uint32_t			bytesRequested = nr_bytes;
    uint32_t 			bytesCopied;
    unsigned char 		*randomBuffer = NULL;
    int				noZeros = FALSE;
    TPMI_SH_AUTH_SESSION    	sessionHandle = TPM_RH_NULL;
    unsigned int		sessionAttributes = 0;

    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    rc = TSS_Malloc(&randomBuffer, bytesRequested + 1);	/* freed @1 */

    /* Start TSS context */
    if (rc == 0) {
	       rc = TSS_Create(&tssContext);
    }

    for (bytesCopied = 0 ; (rc == 0) && (bytesCopied < bytesRequested) ; ) {
    	/* Request whatever is left */
    	if (rc == 0) {
    	    in.bytesRequested = bytesRequested - bytesCopied;
    	}
    	/* call TSS to execute the command */
    	if (rc == 0) {
    	    rc = TSS_Execute(tssContext,
    			     (RESPONSE_PARAMETERS *)&out,
    			     (COMMAND_PARAMETERS *)&in,
    			     NULL,
    			     TPM_CC_GetRandom,
    			     sessionHandle, NULL, sessionAttributes,
    			     TPM_RH_NULL, NULL, 0);
    	}
    	if (rc == 0) {
    	    size_t br;
    	    if (tpmVerbose) TSS_PrintAll("randomBytes in pass",
    				      out.randomBytes.t.buffer, out.randomBytes.t.size);
    	    /* copy as many bytes as were received or until bytes requested */
    	    for (br = 0 ; (br < out.randomBytes.t.size) && (bytesCopied < bytesRequested) ; br++) {

    		if (!noZeros || (out.randomBytes.t.buffer[br] != 0)) {
    		    randomBuffer[bytesCopied] = out.randomBytes.t.buffer[br];
    		    bytesCopied++;
    		}
    	    }
    	}
    	if (rc == 0) {
    	    if (noZeros) {
    		randomBuffer[bytesCopied] = 0x00;
    	    }
    	}
    }

    // Delete TSS context
    TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}

    /* Print randomly generated value in human readable format */
    // if (rc == 0) {
	//     TSS_PrintAll("randomBytes", randomBuffer, bytesRequested);
	// }

    return randomBuffer;
}


/*
*   TPM function to read NV index
*/
TPM_RC nvReadPublic(TSS_CONTEXT *tssContext, int nvIndex)
{
    TPM_RC			        rc = 0;
    NV_ReadPublic_In 		in;
    NV_ReadPublic_Out		out;

    if (rc == 0) {
		in.nvIndex = nvIndex;
		rc = TSS_Execute(tssContext,
				 (RESPONSE_PARAMETERS *)&out,
				 (COMMAND_PARAMETERS *)&in,
				 NULL,
				 TPM_CC_NV_ReadPublic,
				 TPM_RH_NULL, NULL, 0);
    }
    return rc;
}

/*
*   TPM function to start a session
*/
TPM_RC startSession(TSS_CONTEXT *tssContext,
			   TPMI_SH_AUTH_SESSION *sessionHandle,
			   TPMI_DH_OBJECT tpmKey,		/* salt key */
			   TPMI_DH_ENTITY bind)			/* bind object */
{
    TPM_RC			        rc = 0;
    StartAuthSession_In 	startAuthSessionIn;
    StartAuthSession_Out 	startAuthSessionOut;
    StartAuthSession_Extra	startAuthSessionExtra;

    /*	Start an authorization session */
    if (rc == 0) {
		startAuthSessionIn.tpmKey = tpmKey;		/* salt key */
		startAuthSessionIn.bind = bind;			/* bind object */
		startAuthSessionIn.sessionType = TPM_SE_HMAC;	/* HMAC session */
		startAuthSessionIn.authHash = TPM_ALG_SHA512;	/* HMAC SHA-256 */
		startAuthSessionIn.symmetric.algorithm = TPM_ALG_AES;	/* parameter encryption */
		startAuthSessionIn.symmetric.keyBits.aes = 128;
		startAuthSessionIn.symmetric.mode.aes = TPM_ALG_CFB;
		startAuthSessionExtra.bindPassword = NVPWD;	/* bind password */
		rc = TSS_Execute(tssContext,
				 (RESPONSE_PARAMETERS *)&startAuthSessionOut,
				 (COMMAND_PARAMETERS *)&startAuthSessionIn,
				 (EXTRA_PARAMETERS *)&startAuthSessionExtra,
				 TPM_CC_StartAuthSession,
				 TPM_RH_NULL, NULL, 0);
		*sessionHandle = startAuthSessionOut.sessionHandle;
    }
    return rc;
}

/*
*   TPM function to flush a session
*/
TPM_RC flush(TSS_CONTEXT *tssContext, TPMI_DH_CONTEXT flushHandle)
{
    TPM_RC			rc = 0;
    FlushContext_In 		in;

    if (rc == 0) {
		in.flushHandle = flushHandle;
		rc = TSS_Execute(tssContext,
				 NULL,
				 (COMMAND_PARAMETERS *)&in,
				 NULL,
				 TPM_CC_FlushContext,
				 TPM_RH_NULL, NULL, 0);
    }
    return rc;
}

/*
*   TPM function to define space
*/
TPM_RC defineSpace(TSS_CONTEXT *tssContext, size_t spaceSize, int nvType, 
                          int nvIndex)
{
    TPM_RC					rc = 0;
    NV_DefineSpace_In 		in;

	if (rc == 0) {
	    in.authHandle = TPM_RH_OWNER;
	    in.publicInfo.nvPublic.authPolicy.t.size = 0;	/* default empty policy */
	    in.publicInfo.nvPublic.nvIndex = nvIndex;	/* the handle of the data area */
	    in.publicInfo.nvPublic.nameAlg = TPM_ALG_SHA256;/* hash algorithm used to compute the name */
	    in.publicInfo.nvPublic.attributes.val = TPMA_NVA_OWNERWRITE | TPMA_NVA_OWNERREAD |
	                        TPMA_NVA_AUTHWRITE | TPMA_NVA_AUTHREAD |
	                        nvType;
	    in.publicInfo.nvPublic.dataSize = spaceSize;
	    rc = TSS_TPM2B_StringCopy(&in.auth.b, NVPWD, sizeof(in.auth.t.buffer));
	}

	if (rc == 0) {
	    rc = TSS_Execute(tssContext,
	             NULL,
	             (COMMAND_PARAMETERS *)&in,
	             NULL,
	             TPM_CC_NV_DefineSpace,
	             /* Empty owner auth */
	             TPM_RS_PW, NULL, 0,
	             TPM_RH_NULL, NULL, 0);

	}
    return rc;
}

/*
*   TPM function to write to an NV memory index
*/
TPM_RC nvWrite(TSS_CONTEXT *tssContext, TPMI_SH_AUTH_SESSION sessionHandle,
		  	  unsigned char *data, size_t len_data, int nvIndex)
{
    TPM_RC				rc = 0;
    NV_Write_In			nvWriteIn;

    /* NV write */
    if (rc == 0) {
		nvWriteIn.authHandle = nvIndex;	/* use index authorization */
		nvWriteIn.nvIndex = nvIndex;		/* NV index to write */
		nvWriteIn.data.t.size = len_data;       /* data length in bytes */
        memcpy(nvWriteIn.data.t.buffer, data, len_data);
		nvWriteIn.offset = 0;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
		rc = TSS_Execute(tssContext,
				 NULL,
				 (COMMAND_PARAMETERS *)&nvWriteIn,
				 NULL,
				 TPM_CC_NV_Write,
				 sessionHandle, NVPWD, 0,
				 TPM_RH_NULL, NULL, 0);
    }
    return rc;
}

/* 
*   Read from a TPM NV memory index
*/
TPM_RC nvRead(TSS_CONTEXT *tssContext, TPMI_SH_AUTH_SESSION sessionHandle,
                    unsigned char *readBuffer, int nvIndex, int nvIndexLength,
					uint16_t offset)
{
	TPM_RC				rc = 0;
	NV_Read_In 			in;
    NV_Read_Out			out;
	uint32_t 			nvBufferMax;
	// unsigned char 		*readBuffer = NULL;
	int					done = FALSE;
	uint16_t bytesRead = 0;
	uint16_t readLength = nvIndexLength;
	// readBuffer = malloc(readLength);		/* freed @1 */
	if (readBuffer == NULL) {
		printf("Cannot malloc %u bytes for read buffer\n", readLength);
	}
	rc = readNvBufferMax(tssContext, &nvBufferMax);
	in.nvIndex = nvIndex;
	in.authHandle = nvIndex;
	in.offset = offset;

	/* call TSS to execute the command */
    while ((rc == 0) && !done) {
		if (rc == 0) {
		    /* read a chunk */
		    in.offset = offset + bytesRead;
		    if ((uint32_t)(readLength - bytesRead) < nvBufferMax) {
				in.size = readLength - bytesRead;	/* last chunk */
		    }
		    else {
				in.size = nvBufferMax;		/* next chunk */
		    }
		}
		if (rc == 0) {
		    if (tpmVerbose) printf("TPM_INFO: nv reading %u bytes of index %x\n", in.size, nvIndex);
		    rc = TSS_Execute(tssContext,
				     (RESPONSE_PARAMETERS *)&out,
				     (COMMAND_PARAMETERS *)&in,
				     NULL,
				     TPM_CC_NV_Read,
				     sessionHandle, NVPWD, 0,
				     TPM_RH_NULL, NULL, 0);
		}
		/* copy the results to the read buffer */
		if ((rc == 0) && (readBuffer != NULL)) {	/* check to handle 0 size read */
		    memcpy(readBuffer + bytesRead, out.data.b.buffer, out.data.b.size);
		}
		if (rc == 0) {
		    bytesRead += out.data.b.size;
		    if (bytesRead == readLength) {
			done = TRUE;
		    }
		}
    }

	if (rc == 0) {
		if (tpmVerbose) printf("TPM_INFO: nvread success\n");
		// TSS_PrintAll("nvread: data", readBuffer, readLength);
	}
	// free(readBuffer);
    // return readBuffer;
	return rc;
}


/*
 * TPM function to increment the index of a NV memory counter
*/
TPM_RC nvIncrement(TSS_CONTEXT *tssContext, TPMI_SH_AUTH_SESSION sessionHandle,
                        int nvIndex) {
    TPM_RC			    rc = 0;
    NV_Increment_In 	in;
    in.authHandle = nvIndex;
	in.nvIndex = nvIndex;

    rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_NV_Increment,
			 sessionHandle, NVPWD, 0,
			 TPM_RH_NULL, NULL, 0);
    
    return rc;
}


/*
 * TPM function to undefine an NV index
*/
TPM_RC nvUndefineSpace(TSS_CONTEXT *tssContext, int nvIndex) {
	TPM_RC			    rc = 0;
	NV_UndefineSpace_In 	in;
	in.authHandle = TPM_RH_OWNER;
	in.nvIndex = nvIndex;
	
	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_NV_UndefineSpace,
			 TPM_RS_PW, NULL, 0,
			//  sessionHandle0, parentPassword, sessionAttributes0,
			 TPM_RH_NULL, NULL, 0);

	return rc;
}