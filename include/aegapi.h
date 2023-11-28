/*
 *	Copyright (C) ActivCard 1996-1997.
 *
 *	Module : aeg/inc/aegapi.h
 *	Purpose: ActivEngine Security Services API public header file
 *	Version: 2.0.1.4 F9706F
 */
/*
 *
 *      ActivCard, Inc.
 *      303 Twin Dolphin Drive, Suite 420
 *      Redwood City, CA   94065
 *      www.activcard.com
 *
 *      Copyright (C) ActivCard 1996-1997.
 *
 *      This software is provided by Lucent Remote Access under license from ActivCard, Inc.,
 *      
 *      ActivCard, Inc. makes no representations or warranties with
 *      respect to the contents or use of this software, and specifically
 *      disclaims any express or implied warranties of merchantability or
 *      fitness for any particular purpose. Further, ActivCard reserves the
 *      right to revise this software and to make changes to its content,
 *      at any time, without obligation to notify any person or entity of
 *      such revisions or changes.
 *
 */

#ifndef _AEGAPI_H_
#define _AEGAPI_H_

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Macros, defines, constants, ...
 * ===============================
 */

/*---------------------- Value definitions ---------------------------- */
#define IDENTITY_SIZE 		(25+1)
#define APPLICATION_ID_SIZE	(20+1)

#define CHALLENGE_SIZE		(8+1)
#define CODE_SIZE		(16+1)
#define SECRET_VALUE_SIZE	(16+1)

#define PUBLIC_KEY_SIZE		(256+1)

#define AEG_MAX_CERTIFICATE_LENGTH	CODE_SIZE
#define AEG_MAX_CERTDATA_LENGTH		8192

#define AEG_MAJOR_VERSION(x)	((int)(((unsigned long)(x) >> 24) & 0xFF))
#define AEG_MINOR_VERSION(x)	((int)(((unsigned long)(x) >> 16) & 0xFF))
#define AEG_BUILD_VERSION(x)	((int)(((unsigned long)(x) >>  8) & 0xFF))


/*---------------------- Identity Type  ------------------------------ */

typedef enum
{
	SERIAL_NUMBER_TYPE,	/* SerialNumber Type */
	LOGIN_NAME_TYPE 	/* LoginName Type */
} aeIdentityType;


/*----------------- Identity Code definitions ------------------------- */

typedef struct
{
	aeIdentityType  Type;	/* LoginNameType or SerialNumberType */
	char           *pVal;
} aeIdentity;

/*------------------------- Return Value ------------------------------ */

typedef enum {
AEG_ERR_NO_ERROR = 0,		/* No Error */
	
AEG_ERR_INTERNAL_ERROR = 1,	/* Internal parser error: should not happen */
AEG_ERR_UNKNOWN_SESSION_ID = 10,/* Wrong session identifier */
AEG_ERR_UNKNOWN_APPLICATION = 11,/* Unknown application name or
				 * application not available for
				 * the token
				 */

AEG_ERR_UNKNOWN_IDENTITY = 12,	/* Unknown identity, either the serial number or
				 * the login name is wrong
				 */
AEG_ERR_INVALID_DIRECTIVE = 13,
AEG_ERR_ACCESS_TO_SERVICE_DENIED = 14,/* Access to service denied or service not
				  * available for the user
				  */
AEG_ERR_AUTH_CODE_CHECK_FAILED = 15,/* Authentication failed */
AEG_ERR_INVALID_CHALLENGE = 16,	/* Challenge not valid */
AEG_ERR_INVALID_AUTH_CODE = 17,	/* Authentication code not valid */
AEG_ERR_BAD_PARAM = 18,		/* One of the parameter is NULL or invalid */
	
AEG_ERR_MEMORY_CLIENT = 19,	/* Out of memory (in the client API) */
AEG_ERR_MEMORY_SERVER = 20,	/* Out of memory (in the server) */
AEG_ERR_SERVER_BUSY = 21,	/* Server busy */
AEG_ERR_SLAVEMODE = 22,		/* The Server is in slave mode, and the service
				 * requested is not allowed in slave mode
				 */

AEG_ERR_OBJECT_ALREADY_EXIST = 23, /* cannot add a database object (application user...)
				    * that already exists in the database
				    * Should not happen in this API
				    */
AEG_ERR_OBJECT_NOT_FOUND = 24, /* Should not happen in this API */
AEG_ERR_INVALID_CHARACTER = 25, /* Should not happen in this API */

AEG_ERR_SECURE_CLIENT_FAILED = 100,/* Crypto negociation failure (client side) */
AEG_ERR_SECURE_SERVER_FAILED = 101,/* Crypto negociation failure (server side) */
AEG_ERR_SECURE_BAD_MAC = 102,	/* Invalid MAC */
AEG_ERR_SECURE_WRONG_DH_PUBLIC = 103,/* Wrong ActivEngine server Diffie-Hellman public value */

	/* Network subsystem not ready or incompatible or bad configuration */
	/* Not enough memory or network resource (file descriptor, buffer) */
	/* Network subsystem general failure */
	/* The read/write packet format is not correct */
AEG_ERR_NETWORK_FAILURE = 200,

AEG_ERR_NETWORK_BROKENPIPE = 201,/* Connection lost */
	/* Invalid IP Adress or port number */
  	/* Unable to connect to given host, or failure during connection */
AEG_ERR_NETWORK_CONNECT = 202,

	/* Network timeout */
AEG_ERR_NETWORK_TIMEOUT = 203,
	/* Service not implemented in this version */
AEG_ERR_NOTIMPLEMENTED = 204

} aeErrorCode;

#define AEG_SERVICE_SUCCEEDED		AEG_ERR_NO_ERROR 
#define AEG_ERR_BAD_CERTIF_CODE		AEG_ERR_AUTH_CODE_CHECK_FAILED

/*----------------- DirAuthMode Code definitions ---------------------- */

typedef enum
{
	ASYNCHRONOUS_MODE,
	SYNCHRONOUS_MODE,
	DUAL_AUTH_MODE
} aeAuthMode;


#ifndef _ADMAPI_H_
typedef enum {
	AEG_SECURE_ALL, /* the API is completely free to negociate whatever protocol 
			it wants down to the no encryption protocol if the server 
			does not support anything better */
	AEG_SECURE_ENCRYPTED_ONLY, /* If the target server does not support encryption, 
			the connection will fails with an AEG_SECURE_NEGOCIATION_FAILED 
			error.*/
	AEG_SECURE_NOENCRYPTED_ONLY /* A non encrypted protocol is mandatory. If the server does not support
			a non secure channel an AEG_SECURE_NEGOCIATION_FAILED error will be 
			returned. */
} aegFlagSecure;
#endif

typedef enum {
	AEG_INFO_SERVERNAME,
	AEG_INFO_SERVERIPADD,
	AEG_INFO_CNXTIMEOUT,
	AEG_INFO_ENCRYPTION,
	AEG_INFO_VERSION_AEG,
	AEG_INFO_VERSION_API
} aegInfo;

#define AEG_MAX_SERVERNAME_LEN	65
#define AEG_ENCRYPTION_OFF	0
#define AEG_ENCRYPTION_ON	1

/* ---------------- Certification definitions -------- */
typedef enum {
	AEG_CERT_DATA_FIELD,
	AEG_CERT_DATA_BUFFER 
} aegCertifDataType;

/*----------------- get security param definitions ------------------------ */
typedef enum {
	AEG_CERTIFICATION_PARAM,
	AEG_VERIF_AFTER_AUTH_PARAM,
	AEG_AUTH_MODE_PARAM
} aegSecurityType;

#define CERTIF_MODE_NONE		0
#define CERTIF_MODE_ASYNCHRONOUS	1
#define CERTIF_MODE_SYNCHRONOUS		2

typedef struct aeCertifDataTAG {
	int	len_min[5];
	int	len_max[5];
	int	period_options[5];
	int	mode;	/* 0=none, 1=Async mode, 2=Sync mode */
	int flag_verif;	/* Server authentication after certification (1) or not (0) */
} aeCertifData;

/*----------------- Application Id definitions ------------------------ */

int             aeg_open_session_ex (
#if defined(__STDC__)
			unsigned long *SessionId,
	                const char *AEGServerId,
	                const char *AEGPublicKey,
			const char *ApplicationId,
  			aegFlagSecure	AEGSecureFlag
#endif	/* __STDC__ */
	                );

int             aeg_close_session (
#if defined(__STDC__)
			unsigned long SessionId
#endif	/* __STDC__ */
	                );

int aeg_get_security_param (
#if defined(__STDC__)
			unsigned long	SessionId,
			const aeIdentity *Identity,
			aegSecurityType	InfoType,
			void		*Info
#endif	/* __STDC__ */
			  );

int             aeg_get_info (
#if defined(__STDC__)
			unsigned long SessionId,
			aegInfo keyword,
			void *pResult
#endif	/* __STDC__ */
	                );


int             aeg_get_async_auth_challenge (
#if defined(__STDC__)
			unsigned long SessionId,
	                const aeIdentity * Identity,
	                char *Challenge
#endif	/* __STDC__ */
	                );
	                
int             aeg_check_async_auth_code (
#if defined(__STDC__)
			unsigned long SessionId,
	                const aeIdentity * Identity,
	                const char *Challenge,
	                const char *Code
#endif	/* __STDC__ */
	                );

int             aeg_check_sync_auth_code (
#if defined(__STDC__)
			unsigned long SessionId,
	                const aeIdentity * Identity,
	                const char *Code
#endif	/* __STDC__ */
	                );

int             aeg_get_challenge_secret_value (
#if defined(__STDC__)
			unsigned long SessionId,
	                const aeIdentity * Identity,
	                char *Challenge
#endif	/* __STDC__ */
	                );
	                
int             aeg_extract_secret_value (
#if defined(__STDC__)
			unsigned long SessionId,
	                const aeIdentity * Identity,
	                const char *Challenge,
	                const char *Code,
	                char *SecretValue
#endif	/* __STDC__ */
	                );


int		aeg_check_certificate(
#if defined(__STDC__)
			unsigned long SessionId,
			const aeIdentity *Identity,
			char *Certificate,
			char *Data,
			aegCertifDataType DataType,
			int DataLen
#endif	/* __STDC__ */
			);

int		aeg_get_server_auth_code(
#if defined(__STDC__)
			unsigned long SessionId,
			const aeIdentity *Identity,
			char *Challenge,
			char * ServerAuthCode
#endif	/* __STDC__ */
			);

/* --------------------------------------------------------- */

int             aeg_open_session (
#if defined(__STDC__)
			unsigned long *SessionId,
	                const char *ApplicationId,
	                const char *ApplicationPrivateKey,
	                const char *AEGServerId,
	                const char *AEGPublicKey
#endif	/* __STDC__ */
	                );

int             aeg_get_client_api_version (
#if defined(__STDC__)
			unsigned long SessionId,
	                unsigned long *VersionNumber
#endif	/* __STDC__ */
	                );
	                
int             aeg_get_server_version (
#if defined(__STDC__)
			unsigned long SessionId,
	                unsigned long *VersionNumber
#endif	/* __STDC__ */
	                );

int             aeg_get_auth_mode (
#if defined(__STDC__)
			unsigned long SessionId,
	                const aeIdentity * Identity,
	                aeAuthMode * DirAuthMode
#endif	/* __STDC__ */
	                );

/* --------------------------------------------------------- */

#ifdef	__cplusplus
}
#endif

#endif	/* _AEGAPI_H_ */
