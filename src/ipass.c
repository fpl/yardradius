/*
 *	ipass.c - Ipass alliance routines
 *
 * These routines are called by the main program to talk to an Ipass server.
 *
 * The samples we have provided here may be used at a site running RADIUS
 */

/*
 *
 * Copyright 1996 iPass Alliance Inc.  All rights reserved.
 *
 *	Portions may be copyright by:
 *
 *	Lucent Technologies Remote Access
 *	4464 Willow Road
 *	Pleasanton, CA   94588
 *
 *	Copyright 1992-1999 Lucent Technologies, Inc.
 *
 */

/*
 * Copyright (C) 1999 Francesco P. Lovergine. All rights reserved.
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
 * 4. Any modification to the program, as well as redistribution in binary
 *    or derived source form must be advertised to the author.
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

#include "yard.h"				/* includes local md5.h */
#include "global.h"

#ifdef IPASS

#ident	"@(#)$Name$:$Id: ipass.c 75 2004-08-02 18:40:07Z flovergine $"

#include <ipassconf.h>
#include <ipassgen.h>

#ifdef HAVE_SYS_CDEFS_H
# include <sys/cdefs.h>
#endif

#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif

#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#ifdef HAVE_MEMORY_H
# include <memory.h>
#endif

#ifdef STDC_HEADERS
# include <string.h>
#else
# ifndef HAVE_STRCHR
#  define strchr index
#  define strrchr rindex
# endif
char *strchr(),*strrchr();
# ifndef HAVE_MEMCPY
#  define memcpy(d,s,n) bcopy((s),(d),(n))
#  define memmove(d,s,n) bcopy((s),(d),(n))
# endif
#endif

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>


#define IPASS_REMOTE_ID_CHAR '@' 

struct sockaddr_in rad_addr,cli_addr;

/* forward declarations */
int ipassinit();

int decode_passwd (char *, UINT4, char *, char *);
void handle_response (int, AUTH_REQ *, ipinfo_t *, ipauth_t *, int, int);

void dump_to_disk (char *, int, char *);

int raddebug = 0;

int
ipassinit( void )
{
	/* init iPass library */
	return ipass_init(0, (char **) NULL, IPASS_PROGNM_AUTHD);

}


int
rad_forw_ipass( AUTH_REQ *authreq,int radius_fd,char *buff )
{
	AUTH_HDR *auth;
	ipinfo_t ipinfo;
	ipauth_t ipauth;
	ipacct_t ipacct;
	char *ptr,*sptr, *p;
	char ibuff[BUFSIZ];
	char vector[16];
	char passwd[128];
	char user_name[IPASS_MAXNAMLEN+IPASS_MAXDOMLEN+1+1];
	char nas_ip[(4*3)+3+1];
	int attrvalue, i,j;
	u_short length, attribute, attrlen;
	int ret_code = 0;
	time_t ttime;

	auth = (AUTH_HDR*)buff;

	ipinfo.service = IPASS_SERV_UNKNOWN; 
	ipinfo.direction = IPASS_DIR_UNKNOWN;
	ipinfo.nas_ses_id[0] = '\0';
	ipauth.host_ip.s_addr = INADDR_ANY;
	ipacct.user_ip.s_addr = INADDR_ANY;
	ipacct.user_mask.s_addr = INADDR_ANY;

	passwd[0] = '\0';
	ipauth.passwd[0] = '\0';
	switch(auth->code){
		case PW_AUTHENTICATION_REQUEST:
			trace("received authentication request, id: %d", auth->id);
			break;
		case PW_ACCOUNTING_REQUEST:
			trace("received accounting request, id: %d", auth->id);
			break;
		default:
			trace("received unknown request: %d", auth->code);
			return;
	}

	ptr=&buff[4];
	for (i=0;i<AUTH_VECTOR_LEN;i++)
		vector[i] = *ptr++;

	length=ntohs(auth->length);
	
	ptr=&buff[0];
	ptr+=AUTH_HDR_LEN;
	length-=AUTH_HDR_LEN;

/* now pointing at code of first data field */

	if (raddebug){
		dump_to_disk((char *)buff,(int)auth->length,"Request");
	}
	while (length > 2) {

		attribute = *ptr++;
		attrlen = *ptr++;
		sptr=ptr;
		if (attrlen < 2) {
		/* malformed packet, can't do anything but quit */
			length = 0;
			continue;
		}
		if (attrlen == 2){
		/*
		   this is illegal, but one site who shall remain nameless 
		   sends these packets all the time 
		*/
			length -= 2;
			continue;
		}
		attrlen -= 2;
		ptr+=attrlen-1;
		attrvalue=*ptr++;

		switch (attribute){
			case PW_CLIENT_ID:
				memcpy(&ipinfo.nas_ip, sptr, sizeof(UINT4));
				sptr += 4;
				break;
			case PW_LOGIN_HOST:
				memcpy(&ipauth.host_ip, sptr, sizeof(UINT4));
				sptr += 4;
				break;
			case PW_PASSWORD:
				for(i=0;i<attrlen;i++)
					passwd[i]=*sptr++;
				break;
			case PW_CHAP_PASSWORD:
				ipauth.chap_ident = *sptr++; /* get ident */
				for(i=0;i<CHAP_VALUE_LENGTH;i++){
					ipauth.chap_passwd[i]=*sptr++;
					ipauth.chap_challenge[i]=vector[i];
				}
				break;
			case PW_USER_NAME:
				for(i=0;i<attrlen;i++)
					user_name[i]=*sptr++;
				user_name[i]='\0';
				break;
			case PW_FRAMED_PROTOCOL:
				switch (attrvalue){
					case PW_PPP:
						ipinfo.service=IPASS_SERV_PPP;
						break;
					case PW_SLIP:
						ipinfo.service=IPASS_SERV_SLIP;
						break;
					default:
						break;
				}
				break;
			case PW_FRAMED_ADDRESS:
 				memcpy(&ipacct.user_ip, sptr, sizeof(UINT4));
                                sptr += 4;
				break;
			case PW_FRAMED_NETMASK:
 				memcpy(&ipacct.user_mask, sptr, sizeof(UINT4));
                                sptr += 4;
				break;
			case PW_LOGIN_SERVICE:	
				switch (attrvalue){
					case PW_TELNET:
  						ipinfo.service=
							IPASS_SERV_TELNET;
  						break;
					case PW_RLOGIN:
						ipinfo.service=
							IPASS_SERV_RLOGIN;
						break;
					default:
						break;
				}
				break;
			case PW_ACCT_SESSION_ID:
				for (i=0;i<attrlen;i++)
					ibuff[i]=*sptr++;
				ibuff[i] = '\0';	
					
				strncpy(ipinfo.nas_ses_id, ibuff,
					sizeof(ipinfo.nas_ses_id) - 1);
			ipinfo.nas_ses_id[sizeof(ipinfo.nas_ses_id) - 1] = '\0';
				break;
			case PW_ACCT_STATUS_TYPE:
				switch (attrvalue){
				case PW_STATUS_START:
					ipacct.acct_type = IPASS_ACCT_START;
					break;
				case PW_STATUS_STOP:
					ipacct.acct_type = IPASS_ACCT_STOP;
					break;
				default:
				trace("rad_forw_req: bad acct_status_type %d",
					attrvalue);
					return -1;
				}
				break;
			case PW_CLIENT_PORT_ID:
				ipinfo.nas_port = attrvalue; /* XXX ??? ntohl(attrvalue); */
				break;
			case PW_ACCT_SESSION_TIME:
				ttime =  (*sptr++)<<24;
				ttime |= (*sptr++)<<16;
				ttime |= (*sptr++)<<8;
				ttime |= (*sptr++);

				ipacct.ses_len=ttime;
				break;
			default:
				break;
		}
		length -= (attrlen + 2);
	}
        if ((p = strchr(user_name, IPASS_REMOTE_ID_CHAR)) == NULL) {
		return -1;
	}
	if (ipass_setuserid(ipinfo.user_name,
			    ipinfo.ipass_domain, user_name) == EOF)
		return -1;

	if (auth->code == PW_AUTHENTICATION_REQUEST){
		if (passwd[0]) {
			if (!decode_passwd(passwd, authreq->ipaddr,
				   auth->vector, authreq->secret))
				return -1;
			strncpy(ipauth.passwd, passwd, 
				sizeof(ipauth.passwd) - 1);
			ipauth.passwd[sizeof(ipauth.passwd) - 1] = '\0';
		}
		ipass_remote_auth(&ipinfo, &ipauth);
		if (ipauth.errcode != IPASS_STATUS_OK) {
			trace("ipass_remote_auth: failed %d: %s",
			      ipauth.errcode,
			      ipauth.status ? ipauth.status : "<no-message>");
			return -1;
		}
		ret_code = ipauth.auth_reply == IPASS_AUTH_OK ? 1 : 0;
	}
	else{
		ipacct.ip = 0;
		ipacct.op = 0;
		ipacct.ic = 0;
		ipacct.oc = 0;
		ipass_remote_acct(&ipinfo, &ipacct);
		if (ipacct.errcode != IPASS_STATUS_OK) {
			trace("ipass_remote_acct: failed %d: %s",
			      ipacct.errcode,
			      ipacct.status ? ipacct.status : "<no-message>");
			return -1;
		}
		ret_code = 1;
	}

	handle_response(radius_fd,authreq,
		&ipinfo,&ipauth,auth->code,ret_code);

	return 1;
}
/* 
handle_response - decode reply from ipass and send the return packet back to NAS
*/
void
handle_response ( int radius_fd, AUTH_REQ *authreq, ipinfo_t *ipinfop, ipauth_t *ipauthp, int auth_code, int ret_code )
{
	AUTH_HDR *authreply;
	int i;
	char *ptr;
	UINT4 lvalue;
	u_short length;
	unsigned char replybuff[4096];
	unsigned char vector[AUTH_VECTOR_LEN];
	struct sockaddr_in nas_addr;

	authreply = (AUTH_HDR *)replybuff;

	memset(replybuff,0,sizeof(replybuff));

	/* start building reply packet */
	authreply->id = authreq->id;
	memcpy(authreply->vector,authreq->vector,AUTH_VECTOR_LEN);
	length=AUTH_HDR_LEN;

	authreply->code = PW_AUTHENTICATION_REJECT;

	if (ret_code) {
		ptr = (char *) authreply->data;
		if (auth_code == PW_AUTHENTICATION_REQUEST) {
			authreply->code = PW_AUTHENTICATION_ACK;
			if ((ipauthp->serv_req == IPASS_SERV_RLOGIN)||
			    (ipauthp->serv_req == IPASS_SERV_TELNET)||
			    (ipauthp->serv_req == IPASS_SERV_PPP)||
			    (ipauthp->serv_req == IPASS_SERV_SLIP)){

				*ptr++ = PW_USER_SERVICE_TYPE;
				*ptr = 6;
				length += *ptr;
				ptr += 4;
				switch (ipauthp->serv_req) {
				case IPASS_SERV_RLOGIN:
				case IPASS_SERV_TELNET:
					*ptr++ = PW_LOGIN_USER;
					*ptr++ = PW_LOGIN_SERVICE;
					*ptr = 6;
					length += *ptr;
					ptr += 4;
					if (ipauthp->serv_req == IPASS_SERV_TELNET)
						*ptr++ = PW_TELNET;
					else
						*ptr++ = PW_RLOGIN;
					break;
				case IPASS_SERV_PPP:
				case IPASS_SERV_SLIP:
					*ptr++ = PW_FRAMED_USER;
					*ptr++ = PW_FRAMED_PROTOCOL;
					*ptr = 6;
					length += *ptr;
					ptr += 4;
					if (ipauthp->serv_req == IPASS_SERV_PPP)
						*ptr++ = PW_PPP;
					else
						*ptr++ = PW_SLIP;
					break;
				}
				if (ipauthp->host_ip.s_addr != INADDR_ANY) {
					*ptr++ = PW_LOGIN_HOST; 

					*ptr++ = sizeof(UINT4) + 2;
					memcpy(ptr, &ipauthp->host_ip.s_addr, sizeof(UINT4));
					ptr += sizeof(UINT4);
					length += sizeof(UINT4) + 2;
				}
				if (ipauthp->host_port) {
					*ptr++ = PW_LOGIN_TCP_PORT;
					*ptr++ = sizeof(UINT4) + 2;
					lvalue = htons(ipauthp->host_port);
					memcpy(ptr, &lvalue, sizeof(UINT4));
					ptr += sizeof(UINT4);
					length += sizeof(UINT4) + 2;
				}
			}
			else{
			trace("unsupported iPass service request %d, ignored.",
					      ipauthp->serv_req);
			}
		} else
			authreply->code = PW_ACCOUNTING_RESPONSE;
	}
	
	authreply->length = htons(length);
	memcpy(replybuff+length,authreq->secret,strlen(authreq->secret));
	md5_calc(vector,replybuff,length+strlen(authreq->secret));
	memcpy(authreply->vector,vector,AUTH_VECTOR_LEN);

	/* don't need secret anymore, trash it from reply packet */
	memset(replybuff+length,0,strlen(authreq->secret));

	memset((char*) &nas_addr,0, sizeof(nas_addr));

	nas_addr.sin_family      = AF_INET;
	nas_addr.sin_addr.s_addr = htonl(authreq->ipaddr);
	nas_addr.sin_port        = htons(authreq->udp_port);

	if (sendto(radius_fd,(char*)replybuff,length,0,
		(struct sockaddr*)&nas_addr,sizeof(nas_addr)) == -1) {
		trace("remote sendto NAS %s failed, error %d",
		      ipaddr2strp(ntohl(nas_addr.sin_addr.s_addr)), errno);
	} else {
		trace("remote sendto NAS %s okay",
		      ipaddr2strp(ntohl(nas_addr.sin_addr.s_addr)));
	}

	if (raddebug) {
		dump_to_disk((char *)replybuff,(int)length,"Reply");
	}

	return;
}


int
decode_passwd ( char *passwd, UINT4 ipaddr, char *vector, char *shared_secret )
{
	unsigned char md5obuf[256];
	unsigned char md5ibuf[256];
	int i,j;
	
	for (i=0;i<strlen((char*)shared_secret);i++)
		md5ibuf[i] = shared_secret[i];

	for (j=0; i<AUTH_VECTOR_LEN+strlen((char*)shared_secret);i++,j++)
		md5ibuf[i]=vector[j];

	md5_calc(md5obuf,md5ibuf,AUTH_VECTOR_LEN+strlen((char*)shared_secret));

	for(i = 0;i < AUTH_PASS_LEN;i++) {
		passwd[i] ^= md5obuf[i];
	}
	passwd[i]='\0';
	return(1);
}


/*
	dump - display data at specified address
*/
void
dump_to_disk ( char *bp, int count, char *msg )
{
	int i,j, lines;
	char ASC[17], *X2();
	/**/
	FILE *fp;

	fp = fopen("/tmp/radlog","a");
/**/
	lines = count/16 + (count%16 != 0);
	j=0;
	fprintf(fp,"\n\n======== %s =======\n",msg);
	while (lines-- > 0) {
		fprintf(fp,"%3x  ",j);
		j+=16;
		for (i=0; i<16; i++,bp++,count--) {
			if (count > 0) {
				fprintf(fp,"%s ",X2(*bp));
				ASC[i] = '.';
				if (*bp >= ' ' && *bp <= '~') ASC[i] = *bp;
				}
			else {
				fprintf(fp,"   ");
				ASC[i] = ' ';
				}
			if (i == 7) fprintf(fp,"  ");
			}
		ASC[16] = 0;
		fprintf(fp,"  *%s*\n",ASC);
		}
	/**/
	fclose(fp);
	/**/
}

char *
X2 ( register int val )
{
	static char buff[3];
	register int x;

	x = (val>>4) & 0xf;
	if (x >= 10)
		x += 'A' - 10;
	else
		x+= '0';

	buff[0] = (char) x;

	x = val & 0xf;
	if (x >= 10)
		x += 'A' - 10;
	else
		x+= '0';

	buff[1] = (char) x;
	buff[2] = 0;
	return(buff);
}

#if !defined(HAVE_STRERROR)
/*
 * system has no strerror in standard libraries, so define our own
 */
char *
strerror(int err)
{
	extern int sys_nerr;
	extern char sys_errlist[];

	static char *unknown = "unknown errno";

	if (err < sys_nerr) {
		return sys_errlist[err];
	}
	return unknown;
}
#endif

#else /* IPASS */

/* dummy entry points */

int
ipassinit( void ) 
{
	return 0;
}

int
rad_forw_ipass( AUTH_REQ *authreq, int activefd, char *buffer )
{
	extern char	*progname;
	char 		*req2strp();

	log_err("%s: no ipass support, %s cannot be forwarded\n",
		progname, req2strp(authreq));
	return 0;
}

#endif /* IPASS */

