/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h>         // for PRIx32, int32_t
#include <stdlib.h>           // for NULL, calloc

#include "esys_int.h"         // for ESYS_CONTEXT, RSRC_NODE_T, _ESYS_STATE_...
#include "esys_iutil.h"       // for iesys_compute_session_value, esys_GetRe...
#include "esys_types.h"       // for IESYS_RESOURCE
#include "tss2_common.h"      // for TSS2_RC, TSS2_RC_SUCCESS, TSS2_BASE_RC_...
#include "tss2_esys.h"        // for ESYS_CONTEXT, ESYS_TR, Esys_Rewrap, Esy...
#include "tss2_sys.h"         // for Tss2_Sys_ExecuteAsync, TSS2L_SYS_AUTH_C...
#include "tss2_tpm2_types.h"  // for TPM2B_ENCRYPTED_SECRET, TPM2B_PRIVATE

#define LOGMODULE esys
#include "util/log.h"         // for return_state_if_error, LOG_DEBUG, LOG_E...

/** One-Call function for TPM2_Rewrap
 *
 * This function invokes the TPM2_Rewrap command in a one-call
 * variant. This means the function will block until the TPM response is
 * available. All input parameters are const. The memory for non-simple output
 * parameters is allocated by the function implementation.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in]  oldParent Parent of object.
 * @param[in]  newParent New parent of the object.
 * @param[in]  shandle1 Session handle for authorization of oldParent
 * @param[in]  shandle2 Second session handle.
 * @param[in]  shandle3 Third session handle.
 * @param[in]  inDuplicate An object encrypted using symmetric key derived from
 *             inSymSeed.
 * @param[in]  name The Name of the object being rewrapped.
 * @param[in]  inSymSeed The seed for the symmetric key and HMAC key.
 * @param[out] outDuplicate An object encrypted using symmetric key derived
 *             from outSymSeed.
 *             (callee-allocated)
 * @param[out] outSymSeed Seed for a symmetric key protected by newParent
 *             asymmetric key.
 *             (callee-allocated)
 * @retval TSS2_RC_SUCCESS if the function call was a success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if the esysContext or required input
 *         pointers or required output handle references are NULL.
 * @retval TSS2_ESYS_RC_BAD_CONTEXT: if esysContext corruption is detected.
 * @retval TSS2_ESYS_RC_MEMORY: if the ESAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_ESYS_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_RESPONSE: if the TPM's response does not
 *          at least contain the tag, response length, and response code.
 * @retval TSS2_ESYS_RC_MALFORMED_RESPONSE: if the TPM's response is corrupted.
 * @retval TSS2_ESYS_RC_RSP_AUTH_FAILED: if the response HMAC from the TPM
           did not verify.
 * @retval TSS2_ESYS_RC_MULTIPLE_DECRYPT_SESSIONS: if more than one session has
 *         the 'decrypt' attribute bit set.
 * @retval TSS2_ESYS_RC_MULTIPLE_ENCRYPT_SESSIONS: if more than one session has
 *         the 'encrypt' attribute bit set.
 * @retval TSS2_ESYS_RC_BAD_TR: if any of the ESYS_TR objects are unknown
 *         to the ESYS_CONTEXT or are of the wrong type or if required
 *         ESYS_TR objects are ESYS_TR_NONE.
 * @retval TSS2_RCs produced by lower layers of the software stack may be
 *         returned to the caller unaltered unless handled internally.
 */
TSS2_RC
Esys_Rewrap(
    ESYS_CONTEXT *esysContext,
    ESYS_TR oldParent,
    ESYS_TR newParent,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PRIVATE *inDuplicate,
    const TPM2B_NAME *name,
    const TPM2B_ENCRYPTED_SECRET *inSymSeed,
    TPM2B_PRIVATE **outDuplicate,
    TPM2B_ENCRYPTED_SECRET **outSymSeed)
{
    TSS2_RC r;

    r = Esys_Rewrap_Async(esysContext, oldParent, newParent, shandle1, shandle2,
                          shandle3, inDuplicate, name, inSymSeed);
    return_if_error(r, "Error in async function");

    /* Set the timeout to indefinite for now, since we want _Finish to block */
    int32_t timeouttmp = esysContext->timeout;
    esysContext->timeout = -1;
    /*
     * Now we call the finish function, until return code is not equal to
     * from TSS2_BASE_RC_TRY_AGAIN.
     * Note that the finish function may return TSS2_RC_TRY_AGAIN, even if we
     * have set the timeout to -1. This occurs for example if the TPM requests
     * a retransmission of the command via TPM2_RC_YIELDED.
     */
    do {
        r = Esys_Rewrap_Finish(esysContext, outDuplicate, outSymSeed);
        /* This is just debug information about the reattempt to finish the
           command */
        if (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN)
            LOG_DEBUG("A layer below returned TRY_AGAIN: %" PRIx32
                      " => resubmitting command", r);
    } while (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN);

    /* Restore the timeout value to the original value */
    esysContext->timeout = timeouttmp;
    return_if_error(r, "Esys Finish");

    return TSS2_RC_SUCCESS;
}

/** Asynchronous function for TPM2_Rewrap
 *
 * This function invokes the TPM2_Rewrap command in a asynchronous
 * variant. This means the function will return as soon as the command has been
 * sent downwards the stack to the TPM. All input parameters are const.
 * In order to retrieve the TPM's response call Esys_Rewrap_Finish.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[in]  oldParent Parent of object.
 * @param[in]  newParent New parent of the object.
 * @param[in]  shandle1 Session handle for authorization of oldParent
 * @param[in]  shandle2 Second session handle.
 * @param[in]  shandle3 Third session handle.
 * @param[in]  inDuplicate An object encrypted using symmetric key derived from
 *             inSymSeed.
 * @param[in]  name The Name of the object being rewrapped.
 * @param[in]  inSymSeed The seed for the symmetric key and HMAC key.
 * @retval ESYS_RC_SUCCESS if the function call was a success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if the esysContext or required input
 *         pointers or required output handle references are NULL.
 * @retval TSS2_ESYS_RC_BAD_CONTEXT: if esysContext corruption is detected.
 * @retval TSS2_ESYS_RC_MEMORY: if the ESAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_RCs produced by lower layers of the software stack may be
           returned to the caller unaltered unless handled internally.
 * @retval TSS2_ESYS_RC_MULTIPLE_DECRYPT_SESSIONS: if more than one session has
 *         the 'decrypt' attribute bit set.
 * @retval TSS2_ESYS_RC_MULTIPLE_ENCRYPT_SESSIONS: if more than one session has
 *         the 'encrypt' attribute bit set.
 * @retval TSS2_ESYS_RC_BAD_TR: if any of the ESYS_TR objects are unknown
 *         to the ESYS_CONTEXT or are of the wrong type or if required
 *         ESYS_TR objects are ESYS_TR_NONE.
 */
TSS2_RC
Esys_Rewrap_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR oldParent,
    ESYS_TR newParent,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PRIVATE *inDuplicate,
    const TPM2B_NAME *name,
    const TPM2B_ENCRYPTED_SECRET *inSymSeed)
{
    TSS2_RC r;
    LOG_TRACE("context=%p, oldParent=%"PRIx32 ", newParent=%"PRIx32 ","
              "inDuplicate=%p, name=%p, inSymSeed=%p",
              esysContext, oldParent, newParent, inDuplicate, name,
              inSymSeed);
    TSS2L_SYS_AUTH_COMMAND auths;
    RSRC_NODE_T *oldParentNode;
    RSRC_NODE_T *newParentNode;

    /* Check context, sequence correctness and set state to error for now */
    if (esysContext == NULL) {
        LOG_ERROR("esyscontext is NULL.");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }
    r = iesys_check_sequence_async(esysContext);
    if (r != TSS2_RC_SUCCESS)
        return r;
    esysContext->state = _ESYS_STATE_INTERNALERROR;

    /* Check input parameters */
    r = check_session_feasibility(shandle1, shandle2, shandle3, 1);
    return_state_if_error(r, _ESYS_STATE_INIT, "Check session usage");

    /* Retrieve the metadata objects for provided handles */
    r = esys_GetResourceObject(esysContext, oldParent, &oldParentNode);
    return_state_if_error(r, _ESYS_STATE_INIT, "oldParent unknown.");
    r = esys_GetResourceObject(esysContext, newParent, &newParentNode);
    return_state_if_error(r, _ESYS_STATE_INIT, "newParent unknown.");

    /* Initial invocation of SAPI to prepare the command buffer with parameters */
    r = Tss2_Sys_Rewrap_Prepare(esysContext->sys,
                                (oldParentNode == NULL) ? TPM2_RH_NULL
                                 : oldParentNode->rsrc.handle,
                                (newParentNode == NULL) ? TPM2_RH_NULL
                                 : newParentNode->rsrc.handle, inDuplicate, name,
                                inSymSeed);
    return_state_if_error(r, _ESYS_STATE_INIT, "SAPI Prepare returned error.");

    /* Calculate the cpHash Values */
    r = init_session_tab(esysContext, shandle1, shandle2, shandle3);
    return_state_if_error(r, _ESYS_STATE_INIT, "Initialize session resources");
    if (oldParentNode != NULL)
        iesys_compute_session_value(esysContext->session_tab[0],
                &oldParentNode->rsrc.name, &oldParentNode->auth);
    else
        iesys_compute_session_value(esysContext->session_tab[0], NULL, NULL);

    iesys_compute_session_value(esysContext->session_tab[1], NULL, NULL);
    iesys_compute_session_value(esysContext->session_tab[2], NULL, NULL);

    /* Generate the auth values and set them in the SAPI command buffer */
    r = iesys_gen_auths(esysContext, oldParentNode, newParentNode, NULL, &auths);
    return_state_if_error(r, _ESYS_STATE_INIT,
                          "Error in computation of auth values");

    esysContext->authsCount = auths.count;
    if (auths.count > 0) {
        r = Tss2_Sys_SetCmdAuths(esysContext->sys, &auths);
        return_state_if_error(r, _ESYS_STATE_INIT, "SAPI error on SetCmdAuths");
    }

    /* Trigger execution and finish the async invocation */
    r = Tss2_Sys_ExecuteAsync(esysContext->sys);
    return_state_if_error(r, _ESYS_STATE_INTERNALERROR,
                          "Finish (Execute Async)");

    esysContext->state = _ESYS_STATE_SENT;

    return r;
}

/** Asynchronous finish function for TPM2_Rewrap
 *
 * This function returns the results of a TPM2_Rewrap command
 * invoked via Esys_Rewrap_Finish. All non-simple output parameters
 * are allocated by the function's implementation. NULL can be passed for every
 * output parameter if the value is not required.
 *
 * @param[in,out] esysContext The ESYS_CONTEXT.
 * @param[out] outDuplicate An object encrypted using symmetric key derived
 *             from outSymSeed.
 *             (callee-allocated)
 * @param[out] outSymSeed Seed for a symmetric key protected by newParent
 *             asymmetric key.
 *             (callee-allocated)
 * @retval TSS2_RC_SUCCESS on success
 * @retval ESYS_RC_SUCCESS if the function call was a success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE if the esysContext or required input
 *         pointers or required output handle references are NULL.
 * @retval TSS2_ESYS_RC_BAD_CONTEXT: if esysContext corruption is detected.
 * @retval TSS2_ESYS_RC_MEMORY: if the ESAPI cannot allocate enough memory for
 *         internal operations or return parameters.
 * @retval TSS2_ESYS_RC_BAD_SEQUENCE: if the context has an asynchronous
 *         operation already pending.
 * @retval TSS2_ESYS_RC_TRY_AGAIN: if the timeout counter expires before the
 *         TPM response is received.
 * @retval TSS2_ESYS_RC_INSUFFICIENT_RESPONSE: if the TPM's response does not
 *         at least contain the tag, response length, and response code.
 * @retval TSS2_ESYS_RC_RSP_AUTH_FAILED: if the response HMAC from the TPM did
 *         not verify.
 * @retval TSS2_ESYS_RC_MALFORMED_RESPONSE: if the TPM's response is corrupted.
 * @retval TSS2_RCs produced by lower layers of the software stack may be
 *         returned to the caller unaltered unless handled internally.
 */
TSS2_RC
Esys_Rewrap_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PRIVATE **outDuplicate,
    TPM2B_ENCRYPTED_SECRET **outSymSeed)
{
    TSS2_RC r;
    LOG_TRACE("context=%p, outDuplicate=%p, outSymSeed=%p",
              esysContext, outDuplicate, outSymSeed);

    if (esysContext == NULL) {
        LOG_ERROR("esyscontext is NULL.");
        return TSS2_ESYS_RC_BAD_REFERENCE;
    }

    /* Check for correct sequence and set sequence to irregular for now */
    if (esysContext->state != _ESYS_STATE_SENT &&
        esysContext->state != _ESYS_STATE_RESUBMISSION) {
        LOG_ERROR("Esys called in bad sequence.");
        return TSS2_ESYS_RC_BAD_SEQUENCE;
    }
    esysContext->state = _ESYS_STATE_INTERNALERROR;

    /* Allocate memory for response parameters */
    if (outDuplicate != NULL) {
        *outDuplicate = calloc(1, sizeof(TPM2B_PRIVATE));
        if (*outDuplicate == NULL) {
            return_error(TSS2_ESYS_RC_MEMORY, "Out of memory");
        }
    }
    if (outSymSeed != NULL) {
        *outSymSeed = calloc(1, sizeof(TPM2B_ENCRYPTED_SECRET));
        if (*outSymSeed == NULL) {
            goto_error(r, TSS2_ESYS_RC_MEMORY, "Out of memory", error_cleanup);
        }
    }

    /*Receive the TPM response and handle resubmissions if necessary. */
    r = Tss2_Sys_ExecuteFinish(esysContext->sys, esysContext->timeout);
    if (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN) {
        LOG_DEBUG("A layer below returned TRY_AGAIN: %" PRIx32, r);
        esysContext->state = _ESYS_STATE_SENT;
        goto error_cleanup;
    }
    /* This block handle the resubmission of TPM commands given a certain set of
     * TPM response codes. */
    if (r == TPM2_RC_RETRY || r == TPM2_RC_TESTING || r == TPM2_RC_YIELDED) {
        LOG_DEBUG("TPM returned RETRY, TESTING or YIELDED, which triggers a "
            "resubmission: %" PRIx32, r);
        if (esysContext->submissionCount++ >= _ESYS_MAX_SUBMISSIONS) {
            LOG_WARNING("Maximum number of (re)submissions has been reached.");
            esysContext->state = _ESYS_STATE_INIT;
            goto error_cleanup;
        }
        esysContext->state = _ESYS_STATE_RESUBMISSION;
        r = Tss2_Sys_ExecuteAsync(esysContext->sys);
        if (r != TSS2_RC_SUCCESS) {
            LOG_WARNING("Error attempting to resubmit");
            /* We do not set esysContext->state here but inherit the most recent
             * state of the _async function. */
            goto error_cleanup;
        }
        r = TSS2_ESYS_RC_TRY_AGAIN;
        LOG_DEBUG("Resubmission initiated and returning RC_TRY_AGAIN.");
        goto error_cleanup;
    }
    /* The following is the "regular error" handling. */
    if (iesys_tpm_error(r)) {
        LOG_WARNING("Received TPM Error");
        esysContext->state = _ESYS_STATE_INIT;
        goto error_cleanup;
    } else if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Received a non-TPM Error");
        esysContext->state = _ESYS_STATE_INTERNALERROR;
        goto error_cleanup;
    }

    /*
     * Now the verification of the response (hmac check) and if necessary the
     * parameter decryption have to be done.
     */
    r = iesys_check_response(esysContext);
    goto_state_if_error(r, _ESYS_STATE_INTERNALERROR, "Error: check response",
                        error_cleanup);

    /*
     * After the verification of the response we call the complete function
     * to deliver the result.
     */
    r = Tss2_Sys_Rewrap_Complete(esysContext->sys,
                                 (outDuplicate != NULL) ? *outDuplicate : NULL,
                                 (outSymSeed != NULL) ? *outSymSeed : NULL);
    goto_state_if_error(r, _ESYS_STATE_INTERNALERROR,
                        "Received error from SAPI unmarshaling" ,
                        error_cleanup);

    esysContext->state = _ESYS_STATE_INIT;

    return TSS2_RC_SUCCESS;

error_cleanup:
    if (outDuplicate != NULL)
        SAFE_FREE(*outDuplicate);
    if (outSymSeed != NULL)
        SAFE_FREE(*outSymSeed);

    return r;
}
