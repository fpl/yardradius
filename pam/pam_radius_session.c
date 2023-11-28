/* pam_radius_session module */

/*
 * Written by Cristian Gafton <gafton@sorosis.ro> 1997/07/23
 * See the end of the file for Copyright Information
 */
  
#include <sys/types.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <time.h>	/* for time() */
#include <fcntl.h>
#include <ctype.h>

#include <sys/time.h>
#include <unistd.h>

/* indicate the following groups are defined */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/_pam_macros.h>
#include <security/pam_modules.h>

#include "../src/radius.h"

/* some syslogging */

static void _pam_log(int err, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    openlog("PAM_radius_session", LOG_CONS|LOG_PID, LOG_AUTH);
    vsyslog(err, format, args);
    va_end(args);
    closelog();
}
/* argument parsing */

#define PAM_DEBUG_ARG       0x0001

static int _pam_parse(int argc, const char **argv)
{
    int ctrl = 0;

    /* step through arguments */
    for (ctrl=0; argc-- > 0; ++argv) {
	/* generic options */
	if (!strcmp(*argv,"debug"))
	    ctrl |= PAM_DEBUG_ARG;
	else {
	    _pam_log(LOG_ERR,"pam_parse: unknown option; %s",*argv);
	}
    }

    return ctrl;
}

/*
 * PAM framework looks for these entry-points to pass control to the
 * authentication module.
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
    _pam_log(LOG_ERR, "there is no point using this module for auth services");
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
			      int argc, const char **argv)
{
    _pam_log(LOG_ERR, "there is no point using this module for auth services");
    return PAM_IGNORE;
}

/*
 * PAM framework looks for these entry-points to pass control to the
 * account management module.
 */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
				int argc, const char **argv)
{
    _pam_log(LOG_ERR, "there is no point using this module for account services");
    return PAM_IGNORE;
}

/*
 * PAM framework looks for these entry-points to pass control to the
 * session module.
 */ 
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
    int		retval;
    struct	pam_conv  *conv;
    int		ctrl;

    
    retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
    ctrl = pam_parse(argc, argv);
    if (retval != PAM_SUCCESS) {
	_pam_log(LOG_ERR, "Could not get the application conv data");
	return PAM_SESSION_ERR;
    } else
	if (ctrl & PAM_DEBUG_ARG)
	    _pam_log(LOG_DEBUG, "opening radius session...");
    if (ctrl & PAM_DEBUG_ARG) {
	VALUE_PAIR	*pair;
	pair = (VALUE_PAIR *)(conv->appdata_ptr);
	while (pair != (VALUE_PAIR *)NULL) {
	    switch (pair->type) {
		case PW_TYPE_STRING:
		    _pam_log(LOG_DEBUG, "Item: %s, value: %s\n",
			     pair->name, pair->strvalue);
		    break;
		case PW_TYPE_INTEGER:
		    _pam_log(LOG_DEBUG, "Item: %s, value: %d\n",
			     pair->name, pair->lvalue);
		    break;
		case PW_TYPE_IPADDR:
		    _pam_log(LOG_DEBUG, "Item: %s, value: %d.%d.%d.%d\n",
			     pair->name,
			     (pair->lvalue >> 24) & 0xFF,
			     (pair->lvalue >> 16) & 0xFF,
			     (pair->lvalue >> 8) & 0xFF,
			     pair->lvalue & 0xFF);
		    break;
		default:
		    _pam_log(LOG_DEBUG, "Item: %s, value: (unknown: UINT4=%d, STRING='%s')\n",
			     pair->name, pair->lvalue, pair->strvalue);
	    }
	    pair = pair->next;
	}
    }
    if (ctrl & PAM_DEBUG_ARG)
	_pam_log(LOG_DEBUG, "done opening radius session");
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
				    int argc, const char **argv)
{
    int		retval;
    struct	pam_conv  *conv;
    int ctrl;

    ctrl = _pam_parse(argc, argv);
    retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
    if (retval != PAM_SUCCESS) {
	_pam_log(LOG_ERR, "Could not get the application conv data");
	return PAM_SESSION_ERR;
    } else
	if (ctrl & PAM_DEBUG_ARG)
	    _pam_log(LOG_DEBUG, "closing radius session...");
    if (ctrl & PAM_DEBUG_ARG) {
	VALUE_PAIR	*pair;
	pair = (VALUE_PAIR *)(conv->appdata_ptr);
	while (pair != (VALUE_PAIR *)NULL) {
	    switch (pair->type) {
		case PW_TYPE_STRING:
		    _pam_log(LOG_DEBUG, "Item: %s, value: %s\n",
			     pair->name, pair->strvalue);
		    break;
		case PW_TYPE_INTEGER:
		    _pam_log(LOG_DEBUG, "Item: %s, value: %d\n",
			     pair->name, pair->lvalue);
		    break;
		case PW_TYPE_IPADDR:
		    _pam_log(LOG_DEBUG, "Item: %s, value: %d.%d.%d.%d\n",
			     pair->name,
			     (pair->lvalue >> 24) & 0xFF,
			     (pair->lvalue >> 16) & 0xFF,
			     (pair->lvalue >> 8) & 0xFF,
			     pair->lvalue & 0xFF);
		    break;
		default:
		    _pam_log(LOG_DEBUG, "Item: %s, value: (unknown: UINT4=%d, STRING='%s')\n",
			     pair->name, pair->lvalue, pair->strvalue);
	    }
	    pair = pair->next;
	}
    }
    if (ctrl & PAM_DEBUG_ARG)
	_pam_log(LOG_DEBUG, "done closing radius session");
    return PAM_SUCCESS;
}

/*
 * PAM framework looks for these entry-points to pass control to the
 * password changing module.
 */ 
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
				int argc, const char **argv)
{
    _pam_log(LOG_ERR, "there is no point using this module for password services");
    return PAM_IGNORE;
}

#ifdef PAM_STATIC
/* static module data */
struct pam_module _pam_radius_session_modstruct = {
    "pam_radius_session",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok,
};
#endif

/*
 * Copyright (c) Cristian Gafton <gafton@sorosis.ro>, 1997.
 *                                              All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED `AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
