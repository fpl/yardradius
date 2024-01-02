/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

#include	<stdio.h>
#include	<errno.h>

#include	<sys/types.h>

#include	"radius.h"

/* To compile this source you will need to get the header files
 * distributed with SecurID by Security Dynamics
 */

#include	"sdi_athd.h"
#include	"sdi_defs.h"
#include	"sdi_size.h"
#include	"sdi_type.h"
#include	"sdacmvls.h"
#include	"sdconf.h"

union config_record configure;

struct SD_CLIENT	sd_dat;

#define CANCELLED	1

int 
securid(char*username,char*password,AUTH_REQ*authreq,VALUE_PAIR*user_reply,int activefd)
{
	struct SD_CLIENT	*sd_p;
	int			retcode;
	VALUE_PAIR		*attr;
	static int		securid_active;
	int			challenge;
	char			msg[256];
	char			pintype[16];
	char			pinsize[16];
	char			state_value[128];

	sd_p = &sd_dat;
	if(securid_active != 1) {
		/* clear struct */
		memset((u_char *)sd_p, 0, sizeof(sd_dat));
		/*  accesses sdconf.rec  */
		if (creadcfg()) {
			log_err("securid: error reading sdconf.rec\n");
			reqfree(authreq,"securid");
			pairfree(user_reply,"securid");
			return(0);
		}

		if(sd_init(sd_p)) {
			log_err("securid: cannot initialize connection to SecurID server\n");
			reqfree(authreq,"securid");
			pairfree(user_reply,"securid");
			return(0);
		}
		securid_active = 1;
	}

	/*
	 * In some cases, SecurID will require two Cardcodes to properly
	 * authenticate.  When it wants a second one, we will store the
	 * SD_CLIENT data so we have state.  The scond time around (after
	 * the challenge) we will have what we need to use sd_next().
	 * This keeps us stateless.
	 */

	attr = get_attribute(authreq->request, PW_STATE);
	if (attr != (VALUE_PAIR *)NULL) {
		if (strncmp(attr->strvalue, "SECURID_NEXT=", 13) == 0){
			strcpy(sd_p->username, username);
			retcode = sd_next(password, sd_p);
			debug("securid: sd_next retcode=%d\n", retcode);
		} else if (strncmp(attr->strvalue, "SECURID_NPIN=", 13) == 0){
			strcpy(sd_p->username, username);
			retcode = sd_pin(password, 0, sd_p);
			debug("securid: sd_pin retcode=%d\n", retcode);
		} else if (strncmp(attr->strvalue, "SECURID_WAIT=", 13) == 0){
			send_reject(authreq,"Log in with new PIN and code.\r\n",activefd);
			reqfree(authreq,"securid");
			pairfree(user_reply,"securid");
			sd_close();
			securid_active = 0;
			return(0);
		} else {
			log_err("securid: unexpected STATE=\"%s\"\n",attr->strvalue);
			retcode = -1;
		}
	} else {
/* The following line removed in 2.0.1 to enable SDI to function properly */
	/*	memset(sd_p, 0, sizeof(sd_dat)); */
		retcode = sd_check(password, username, sd_p);
		debug("securid: sd_check retcode=%d\n", retcode);
	}

	challenge = 0;
	switch (retcode) {

	case ACM_OK:
		send_accept(authreq, user_reply, (char *)NULL, activefd);
		break;

	case ACM_ACCESS_DENIED:
		send_reject(authreq, (char *)NULL, activefd);
		break;

	case ACM_NEXT_CODE_REQUIRED:
		challenge = 1;
		sprintf(state_value, "SECURID_NEXT=%lu", (UINT4)getpid());
		send_challenge(authreq, "Enter next Cardcode: ", 
			state_value, activefd);
		break;

	case ACM_NEW_PIN_REQUIRED:
		if (sd_p->user_selectable == CANNOT_CHOOSE_PIN) {
		    	if (sd_pin(sd_p->system_pin, 0, sd_p) == ACM_NEW_PIN_ACCEPTED) {
				challenge = 1;
				sprintf(msg,"%s is your new PIN.  Press RETURN to disconnect, wait for token\r\n code to change, log in with new PIN and code.\r\n",sd_p->system_pin);
 				sprintf(state_value, "SECURID_WAIT=%u", (unsigned int)getpid());
				send_challenge(authreq,msg,state_value,activefd);
			}
			else {
				send_reject(authreq,"PIN rejected. Please try again.\r\n",activefd);
			}
    		}
		else if (sd_p->user_selectable == USER_SELECTABLE ||
			 sd_p->user_selectable == MUST_CHOOSE_PIN) {
			challenge = 1;
			sprintf(state_value, "SECURID_NPIN=%u", (unsigned int)getpid());
			if (sd_p->alphanumeric)
				strcpy(pintype, "characters");
			else 
				strcpy(pintype, "digits");
			if (sd_p->min_pin_len == sd_p->max_pin_len)
				sprintf(pinsize, "%d", sd_p->min_pin_len);
			else 
				sprintf(pinsize, "%d to %d",
				sd_p->min_pin_len, sd_p->max_pin_len);
			sprintf(msg,"Enter your new PIN, containing %s %s:",
				pinsize,pintype); 
			send_challenge(authreq, msg, state_value, activefd);
		}
		else {
			log_err("securid: New Pin required but user select has unknown value %d, sending reject\n",sd_p->user_selectable);
			send_reject(authreq,(char *)NULL,activefd);
		}
		break;

	case ACM_NEW_PIN_ACCEPTED:
		send_reject(authreq,"New Pin Accepted.\r\nWait for next card code and then login.\r\n", activefd);
		break;
	case -1:
		send_reject(authreq, (char *)NULL, activefd);
		break;
	default:
		log_err("securid: SecurID server returned unknown code %d for user %s\n", retcode, username);
		send_reject(authreq, (char *)NULL, activefd);
		break;
	}
	reqfree(authreq,"securid");
	pairfree(user_reply,"securid");
/* The following line added in 2.0.1 so that the connection between RADIUS
 * and SDI is broken after each request, as it should according to SDI.
 */
	if(challenge==0) {
		sd_close();
		securid_active = 0;
	}
 
	return(challenge);
}

int 
__ansi_fflush(FILE *f)
{
	return fflush(f);
}
