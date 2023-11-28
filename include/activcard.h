/*
 *	Copyright (C) ActivCard 1996-1997.
 *
 *	Module : activcard.h
 *	Purpose: ActivEngine API
 *	Version: 2.0.1.4 F9706F
 */

/* used to store configuration parameters */
struct ac_config {
	char application[APPLICATION_ID_SIZE];
	char connection[AEG_MAX_SERVERNAME_LEN];
	char public[PUBLIC_KEY_SIZE];
	aegFlagSecure policy;
};

#define ACTIVCARD_APPLICATION   "ACTIVCARD_APPLICATION"
#define ACTIVCARD_CHALLENGE     "ACTIVCARD_CHALLENGE"
#define ACTIVCARD_HOST          "ACTIVCARD_HOST"
#define ACTIVCARD_PUBKEY        "ACTIVCARD_PUBKEY"
#define ACTIVCARD_AUTHPORT      "ACTIVCARD_AUTHPORT"
#define ACTIVCARD_SESSTIMEOUT   "ACTIVCARD_SESSTIMEOUT"
#define ACTIVCARD_SECPOLICY     "ACTIVCARD_SECPOLICY"

