/*
 *	Copyright (C) ActivCard 1996-1997.
 *
 *	Module : activcard.c
 *	Purpose: ActivEngine API
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
 *      This software is provided by Lucent Technologies Remote Access under license from ActivCard, Inc.,
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

#include <config.h>

#include <stdio.h>
#include <netdb.h>
#include <fcntl.h>
#include <pwd.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <setjmp.h>
#include <errno.h>

#include "radius.h"
#include "aegapi.h"
#include "activcard.h"

/* globals */
unsigned long ac_session;
char ac_challenge[AUTH_PASS_LEN];

void 
activcard_strip( char *ptr )
{
	int nspaces;

	nspaces = 0;
	while(*ptr) {
		while(isspace(*(ptr+nspaces))) nspaces++;
		*ptr = *(ptr+nspaces);
		ptr++;
	}
}

int 
activcard_getpair( char *line, **in_attr, **in_val )
{
	static char attr[BUFSIZ], val[BUFSIZ];
	char *ptr;

	*in_attr = attr;
	*in_val  = val;

	/* initialize containers for attribute pair*/
	memset(attr, '\0', sizeof(attr));
	memset(val , '\0', sizeof(val));


	/* copy this token into the attribute field */
	while(isspace(*line)) line++; /* get read of leading spaces */
	if(*line == '#') return(-1);   /* comment line */
	ptr = attr;
	while(isgraph(*line) && *line != ':' && *line != '#') *ptr++=*line++;

	/* next token should be an equal sign, strip spaces */
	while(isspace(*line)) line++;
	if(*line != ':') return(-1);
	line++; /* go on */

	/* next token should be the attribute value */
	while(isspace(*line)) line++; /* get read of leading spaces */
	ptr = val;
	while(isgraph(*line) && *line != '#') *ptr++=*line++;

	/* ignore any thing else */

	return(0);
}

int
activcard_readcnf( char *config_file, struct ac_config *ac_cnf )
{
	FILE *fd;
	char buffer[BUFSIZ];
	char *attr, *val;
	char port[10+1], timeout[10+1];

	/* initialize  */
	memset(ac_cnf, '\0', sizeof(struct ac_config));
	memset(port, '\0', sizeof(port));
	memset(timeout, '\0', sizeof(timeout));
	ac_session = -1;

	/* open activcard configuration file */
	if((fd = fopen(config_file, "r")) == NULL) {
		log_err("activcard_readcnf: could not open config file %s\n", \
			config_file);
		return(-1);
	}

	while(fgets(buffer, sizeof(buffer)-1, fd)) {
		if(activcard_getpair(buffer, &attr, &val)) continue; /* not pair */

		if(!strcmp(attr, ACTIVCARD_APPLICATION)) {
			strcpy(ac_cnf->application, val);
		}
		else if(!strcmp(attr, ACTIVCARD_CHALLENGE)) {
			strcpy(ac_challenge, val);
		}
		else if(!strcmp(attr, ACTIVCARD_HOST)) {
			strcpy(ac_cnf->connection, val);
			strcat(ac_cnf->connection, "/");
		}
		else if(!strcmp(attr, ACTIVCARD_PUBKEY)) {
			strcpy(ac_cnf->public, val);
		}
		else if(!strcmp(attr, ACTIVCARD_AUTHPORT)) {
			strcpy(port, val);
		}
		else if(!strcmp(attr, ACTIVCARD_SESSTIMEOUT)) {
			strcpy(timeout, val);
		}
		else if(!strcmp(attr, ACTIVCARD_SECPOLICY)) {
			ac_cnf->policy = (aegFlagSecure )atoi(val);
		}
	}
	fclose(fd);

	/* finish connection string to open the session */
	if(ac_cnf->connection[0] != '\0') { /* aeg host */
		strcat(ac_cnf->connection, port);
		strcat(ac_cnf->connection, "/");
		strcat(ac_cnf->connection, timeout);
	}
	else {
		log_err("activcard_readcnf: bad configuration file %s\n", config_file);
		return(-1);
	}
	
	return(0);
}

int 
activcard_init( void )
{
	int result;
	char config_file[BUFSIZ];
	struct ac_config ac_cnf;


	/* path to configuration file, we follow radius_dir */
	snprintf(config_file, sizeof(config_file), "%s/%s", radius_dir, ACTIVCARD_CONFIG);

	/* check configuration file for activcard support */
	if(access(config_file, F_OK)) {
		debug("activcard_init: activcard support not configured\n");
		return(0);
	}

	/* read configuration file at this point */
	if(activcard_readcnf(config_file, &ac_cnf) != 0) {
		log_err("activcard_init: error reading configuration file\n");
		return(-1);
	}

	/* open activcard session */
	result = aeg_open_session_ex(&ac_session, ac_cnf.connection, \
		ac_cnf.public, ac_cnf.application, ac_cnf.policy);
	if (result != AEG_SERVICE_SUCCEEDED) {
		ac_session = -1;
		log_err("activcard_init: aeg_open_session_ex error %d\n", result);
		log_err("activcard_init: activcard support disabled\n");

		return(-1);
	}
	else {
		debug("activcard_init: opened session %d (%s) to "\
			"%s (policy %d)\n", ac_session, ac_cnf.application, \
			ac_cnf.connection, ac_cnf.policy);
	}

	return(0);
}

int
activcard_auth( char *auth_name,char *password,AUTH_REQ	*authreq,VALUE_PAIR *user_reply,int activefd )
{
	aeIdentity userId;
	aeAuthMode method;
	VALUE_PAIR *namepair, *get_attribute();
	int result;
	char chall[CHALLENGE_SIZE], *pfr, *pto;
	char msg[128], state_value[128];
	int response, challenge;
	void pairfree(), reqfree(), send_accept(), send_challenge();
	void send_reject();

	/* initialize... */
	memset(msg, '\0', sizeof(msg));
	userId.Type = LOGIN_NAME_TYPE;
	userId.pVal = auth_name;
	response  = -1;
  
	/* get the state */
	namepair = get_attribute(authreq->request, PW_STATE);

	if(namepair == (VALUE_PAIR *)NULL) { /* first time arround */
		debug("activcard_auth: authenticating user %s\n", auth_name);

		/* authentication mode */
		result = aeg_get_security_param(ac_session, &userId, \
			AEG_AUTH_MODE_PARAM, &method);
		if(result != AEG_SERVICE_SUCCEEDED) {
			log_err("activcard_auth: aeg_get_security_param error %d\n", \
				result);
			response = -1;
		}
		else if( !strcmp(ac_challenge, password) ) {
			switch(method) {
			case ASYNCHRONOUS_MODE:
			case DUAL_AUTH_MODE:
				memset(chall, '\0', sizeof(chall));
				result = \
				aeg_get_async_auth_challenge(ac_session, &userId, chall);
				if(result != AEG_SERVICE_SUCCEEDED) {
					log_err("activcard_auth: aeg_get_async_auth_challenge "\
						"error %d\n", result);
					response = -1;
				}
				else {
					response = 1;
				}
				break;

			/* async mode not allowed, falls here */
			case SYNCHRONOUS_MODE: 
			default:
				log_err("activcard_auth: bad authentication mode %d "\
					"(sync).\n", method);
				response = -1;
			}
		}
		else {
			switch(method) {
			case SYNCHRONOUS_MODE:
			case DUAL_AUTH_MODE:
				result=aeg_check_sync_auth_code(ac_session, &userId, password);
				if(result != AEG_SERVICE_SUCCEEDED) {
					response = -1;
				}
				else {
					response = 0;
				}
				break;

			/* sync mode not allowed, falls here */
			case ASYNCHRONOUS_MODE: 
			default:
				log_err("activcard_auth: bad authentication mode %d "\
					"(async).\n", method);
				response = -1;
			}
		}
	}
	else { /* response to challenge */
		/* strip any spaces in the response */
		activcard_strip(password);

		debug("activcard_auth: response to challenge %s for %s\n", 
			password, auth_name);

		memset(chall, '\0', sizeof(chall));
		pfr = namepair->strvalue+10;
		pto = chall;
		while(isdigit(*pfr)) *pto++ = *pfr++;

		result = aeg_check_async_auth_code (ac_session, &userId,\
			chall, password);
		if(result != AEG_SERVICE_SUCCEEDED) {
			response = -1;
		}
		else {
			response = 0;
		}
	}

	/* send response accordingly */
	switch(response) {
	case  0:
		send_accept(authreq, user_reply, (char *)NULL, activefd);
		challenge = 0;
		break;
	case  1:
		snprintf(msg,sizeof(msg), \
			"\nChallenge/Response Authentication requested...\n"
			"\rChallenge: %s\n\rResponse: ", chall);
		snprintf(state_value,sizeof(state_value), 
			"ACTIVCARD_%s=%u", chall, getpid());

		send_challenge(authreq, msg, state_value, activefd);
		challenge = 1;
		break;
	case -1:
		send_reject(authreq, (char *)NULL, activefd);
		challenge = 0;
		break;
	}

	reqfree(authreq,"activcard_auth");
	pairfree(user_reply,"activcard_auth");
	return(challenge);
}
  
void 
activcard_exit( void )
{
	if(ac_session != -1) { /* do we have a session opened */
		aeg_close_session(ac_session); /* close activcard session */
		debug("activcard_exit: closed session %d\n", ac_session);
	}
}
