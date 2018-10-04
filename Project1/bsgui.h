/**
 * @file bsgui.h
 *
 * BSAPI default callback implementation
 *
 * Copyright (C) 2007 UPEK Inc.
 */
 
#ifndef bsgui_h
#define bsgui_h

#include "bstypes.h"

#ifdef __cplusplus
extern "C" {
#endif

/** 
 * The following flag can be used in structure ABS_DEFAULT_CALLBACK_CONTEXT.
 */
#define ABS_DEFAULT_CALLBACK_FLAG_ENABLE_SOUND    0x1    ///< Enables the callback to play a sound on success.



/** 
 * Structure to be optionally passed as a context data into ABSDefaultCallback.
 */
typedef struct abs_default_callback_context {
  ABS_DWORD Version; 	///< Version of the structure. Set to 1.
  HWND ParentWindow; 	///< Set to handle of parent window or NULL.
  ABS_DWORD Flags; 	///< Bitmask of flags. Currently only flag ABS_DEFAULT_CALLBACK_FLAG_ENABLE_SOUND is supported.
} ABS_DEFAULT_CALLBACK_CONTEXT;



/** 
 * @name Default Callback Implementation
 */

/** 
 * Default BSAPI callback implementation.
 * 
 * @param pOperation Pointer to ABS_OPERATION structure used when calling 
 * the interactive biometric operation.
 * @param dwMsgID ID of message. See description of ABS_MSG_xxxx constants.
 * @param pMsgData Pointer to data with additional information related with 
 * the message. 
 */
void BSAPI ABSDefaultCallback(
    IN const ABS_OPERATION* pOperation,
    IN ABS_DWORD dwMsgID,
    IN void* pMsgData
);




#ifdef __cplusplus
} 		/* extern "C" */
#endif

#endif	/* bsgui_h */

