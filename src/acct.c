/*
 * Copyright (C) 1999-2004 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

#include "yard.h"
#include "global.h"

#define SIGN_NOCLIENT	-1
#define SIGN_MATCH	0
#define SIGN_ZERO	1	/* only returned if accept_zero is set */
#define SIGN_NOMATCH	2

void
rad_acctreq(int fd)
{
	AUTH_REQ                *authreq;
	UINT4                   addr;
	char			secret[20];
	int			logok;
	int			proxied;
	int			retsig;
	int                     result;
	size_t                  salen;
	struct  sockaddr_in     *sin;
	u_short                 port;

	salen = sizeof(rad_saremote);
        sin = (struct sockaddr_in *) & rad_saremote;
        result = recvfrom (fd, (char *) recv_buffer,
                (int) sizeof(recv_buffer),
                (int) 0, (struct sockaddr *)&rad_saremote, &salen);

        if (result < AUTH_HDR_LEN) {
                log_err("accounting: runt packet of %d bytes\n",result);
                return;
        }

        addr = ntohl(sin->sin_addr.s_addr);
        port = ntohs(sin->sin_port);
	
	/* Verify the client -- returns shared secret in secret */
	retsig=calc_acctreq(addr,secret,sizeof(secret),recv_buffer,sizeof(recv_buffer));

	/* To be strictly compliant with the RADIUS Accounting RFC
	   we only accept packets that returned SIGN_MATCH to
	   indicate the Request-Authenticator is valid.
	   This requires ComOS 3.3.1 or later.

	   If accept_flag is set then we also accept all-zero
	   Request-Authenticator.
         */

	if (retsig == SIGN_NOCLIENT) {
		/* We do not respond when this fails */
		log_err("accounting: unknown client %s/%d ignored\n", ipaddr2strp(addr),port);
		return;
	} else if (retsig == SIGN_NOMATCH) {
		log_err("accounting: client %s/%d sent accounting-request with invalid request authenticator: %s\n",ipaddr2strp(addr),port,secret);
		if (debug_flag > 2) {
			hexdump((u_char*)recv_buffer, result);
		}
		return;
	} 

	authreq = radrecv( addr, port, secret, recv_buffer, result );

	if (authreq == (AUTH_REQ *)NULL) {
		return;
	}

	/* log it locally */
	logok = rad_accounting(authreq,retsig);

	/* handle_proxy returns 
		1 if it forwarded the packet,
		0 if it did not forward the packet,
	   and -1 if there was an error 
	 */
	proxied = handle_proxy(authreq);
	if (authreq->flags & REQ_ERR) {
		reqfree(authreq,"rad_acctreq");
		return;
	}

	/* If we did not forward this to a remote server, we now
	   let NAS know it is OK to delete from buffer
	   If we did forward it to a proxy server, we will notify
	   NAS to delete when we get the ack back from the remote
	   server.  This means it may wind up in our own logs 
	   multiple times, but that is useful to know
	 */
	if (proxied == 0) {
		if (logok == 1) {
			send_acct_reply(authreq, (VALUE_PAIR *)NULL, fd);
		}
		reqfree(authreq,"rad_acctreq");
	}
	if (proxied == 1 && (authreq->flags & REQ_FREE)) {
		reqfree(authreq,"rad_acctreq");
	}
	return;
}

int 
rad_accounting( AUTH_REQ *authreq, int sign )
{
	FILE		*outfd;
	char		buffer[PATH_MAX];
	char		clientname[MAX_HOST_SIZE];
	VALUE_PAIR	*pair;
	time_t		curtime;
        struct tm       *time_info;


	if (authreq == (AUTH_REQ *)NULL) {
		return 0;
	}

#ifdef VPORTS
        if (vports_flag == 1) {
                vp_update_cid(authreq);
	}
#endif /* VPORTS */


	strncpy(clientname, client_hostname(authreq->ipaddr), MAX_HOST_SIZE);

	/*
	 * Create a directory for this client.
	 */

	curtime = time(0);
        time_info = localtime(&curtime);

	mkdir(radacct_dir,0755);
	snprintf(buffer,sizeof(buffer),"%s/%s",radacct_dir,clientname);
	mkdir(buffer, (mode_t) 0755);
	snprintf(buffer,sizeof(buffer),"%s/%s/%d",radacct_dir,clientname,
	        1900+time_info->tm_year);
	mkdir(buffer, 0755);

	/*
	 * Write Detail file.
	 */
	snprintf(buffer,sizeof(buffer),"%s/%s/%d/detail-%02d",radacct_dir,clientname,
	                1900+time_info->tm_year,time_info->tm_mon+1);
	if((outfd = fopen(buffer, "a")) == (FILE *)NULL) {
		log_err("accounting: could not append to file %s\n", buffer);
		/* do not respond if we cannot save record */
		return 0;
	}

	/* Post a timestamp */
	fputs(ctime(&curtime), outfd);

	/* Write each attribute/value to the log file */
	pair = authreq->request;
	while(pair != (VALUE_PAIR *)NULL) {
		if (pair->attribute != PW_PROXY) {
			fputs("\t", outfd);
			fprint_attr_val(outfd, pair);
			fputs("\n", outfd);
		}
		pair = pair->next;
	}

	/* print the seconds since epoch for easier processing */

	snprintf(buffer,sizeof(buffer),"\tTimestamp = %ld\n",(long)curtime);
	fputs(buffer,outfd);
	if (sign == SIGN_ZERO) {
		fputs("\tRequest-Authenticator = None\n",outfd);
	}
	fputs("\n", outfd);
	fclose(outfd);

        if (validate_acct_packet(authreq) == 1) {
#if defined(PAM) && defined(HAVE_LIBPAM)
            if (usepamacct) pam_session(authreq);
#endif
            if (update_user_status(authreq)) return 0;
        }
	return 1;
}

/*************************************************************************
 *
 *	Function: send_acct_reply
 *
 *	Purpose: Reply to the request with an ACKNOWLEDGE.  Also attach
 *		 reply attribute value pairs (not that there should be any)
 *
 *************************************************************************/

void 
send_acct_reply( AUTH_REQ *authreq,VALUE_PAIR *reply,int activefd)
{
	extern int		report[];
	int			total_length;

	debug("sending acct-response to %s\n", req2strp(authreq));

	total_length = build_packet(authreq,reply,(char *)NULL,PW_ACCOUNTING_RESPONSE,FW_REPLY,send_buffer,sizeof(send_buffer));

	send_packet(activefd,authreq->ipaddr,authreq->udp_port,
		    send_buffer,total_length);

	report[RR_ACCOUNT]++;

}

/*************************************************************************
 *
 *	Function: calc_acctreq
 *
 *	Purpose: Validates the requesting client NAS.  Calculates 
 *		 the accounting-request signature based on the 
 *		 client's private key.
 *	Returns: -1 Client not found
 *		  0 signature matched expected value
 *		  1 signature was all-zero and accept_zero flag is true
 *		  2 signature was non-zero and did not match
 *
 *************************************************************************/

int 
calc_acctreq( UINT4	client,char *secret,int secretlen,u_char *buffer,int buflen ) 
{
	extern int	accept_zero;
	AUTH_HDR *auth;
	u_char	digest[AUTH_VECTOR_LEN];
	u_char	savedigest[AUTH_VECTOR_LEN];
	char	hostnm[256];
	int	len;
	int	slen;

	/*
	 * Validate the requesting IP address -
	 * Not secure, but worth the check for accidental requests
	 * find_client() logs an error message if needed
	 */
	if(find_client(client, secret, secretlen, hostnm, sizeof(hostnm)) != 0) {
		return(SIGN_NOCLIENT);
	}

	/*
	 * The NAS and RADIUS accounting server share a secret.
	 * The Request Authenticator field in Accounting-Request packets
	 * contains a one-way MD5 hash calculated over a stream of octets
	 * consisting of the Code + Identifier + Length + 16 zero octets +
	 * request attributes + shared secret (where + indicates
	 * concatenation).  The 16 octet MD5 hash value is stored in the
	 * Authenticator field of the Accounting-Request packet.
 	 */

	auth = (AUTH_HDR *)buffer;
	memset(savedigest, 0, AUTH_VECTOR_LEN);
	if (accept_zero && memcmp(savedigest,auth->vector,AUTH_VECTOR_LEN) == 0) {
		return(SIGN_ZERO);
	}
	len = ntohs(auth->length);
	slen = strlen(secret);
	memcpy(savedigest,auth->vector,AUTH_VECTOR_LEN);
	memset(auth->vector, 0, AUTH_VECTOR_LEN);
	memcpy(buffer+len,secret,(buflen>(secretlen+len) ? secretlen : 0 ));
	md5_calc(digest, buffer, (buflen>(secretlen+len) ? len+secretlen : buflen ));
	memcpy(auth->vector,savedigest,AUTH_VECTOR_LEN);
	memset(buffer+len,0,buflen-len);
	if (memcmp(digest,savedigest,AUTH_VECTOR_LEN) == 0) {
		return(SIGN_MATCH);
	} else {
		static char buf1[AUTH_VECTOR_LEN+1];
		static char buf2[AUTH_VECTOR_LEN+1];

		memcpy(buf1,(const char*)digest,AUTH_VECTOR_LEN);
		memcpy(buf2,(const char*)savedigest,AUTH_VECTOR_LEN);
		buf1[AUTH_VECTOR_LEN]=buf2[AUTH_VECTOR_LEN]='\0';
		log_err("Acct digest (%s) and client digest (%s) do not match\n",buf1,buf2);
		return(SIGN_NOMATCH);
	}
	/* secret is returned as a side-effect */	
}



