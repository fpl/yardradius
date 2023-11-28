/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

/*

	RADIUS client test program

RADIUS 2.1 includes an example client program called radtest, that 
sends a RADIUS packet to a server running on the same host as radtest,
and prints out the attributes returned.  It doesn't support accounting
packets yet.  It always fills in the NAS-IP-Address as 127.0.0.1 and
the NAS-Port as 1.  Passwords longer than 16 characters are not supported. 
It looks for its dictionary in the same directory its run from. 
 
radtest -v prints the version.
radtest -h prints help:
 
./radtest -d called_id -f -g calling_id -h -i id -p port -s secret
-t type -v -x -u username password
 
The other flags work as follows: 
-a (not implemented yet)
-d Called Station Id
-f Send framed dialin hint 
-g Calling Station Id 
-i Use id as the packet identifier
-n (not implemented yet)
-p Use port as the port (defaults to definition in /etc/services, or 1645)
-r (not implemented yet)
-s to specify shared secret (defaults to "localkey")
-t send type as service type (overrides -f)
-u Specifies username and password (notice that this takes two arguments)
-x sets debugging level (not used for anything yet)

*/

static char rcsid[] = "$Id: radtest.c 83 2004-08-28 13:32:47Z flovergine $ Copyright (C) 1999-2004 Francesco P. Lovergine";


#include "yard.h"

int			fd;
char *			host_name;
struct sockaddr_in	addr;
struct hostent *	hostent;
char *			secret;
int			secret_len;
char *			progname;

u_char req_id;

char r_buf[4096];
char s_buf[4096];
char u_name[256];
char u_passwd[256];
int  u_name_len;
int  u_passwd_len;

int	debug_flag = 0;
int	debug_mem  = 0;
char	*radius_dir = ".";
char	*radius_log = "/dev/tty";
UINT4	now = 0;

int
main(int argc,char **argv)
{
	static AUTH_HDR		*ah;
	static AUTH_REQ		*authreq;
	static VALUE_PAIR	*pair;
	static char		*called_id;
	static char		*calling_id;
	static char		argnum;
	static char		argval;
	static fd_set		fdset;
	static int		acct_flag;
	static int		count;
	static int		frame_flag;
	static int		host;
	static int		i;
	static int		len;
	static int		rc;
	static int		sa_len;
	static int		service_type;
	static int		val;
	static int		verbose_flag;
	static struct		sockaddr_in sa_ihd;
	static struct		timeval tv;
	static struct servent *	svp;
	static u_char		*cp;
	static u_char		alen;
	static u_char		id;
	static u_short		radius_port;
        static u_short          lport;

	static char passwd[AUTH_PASS_LEN];
	static char md5_buf[1024];

	acct_flag = 0;
	count = 1;
	frame_flag = 0;
	id = 0;
	service_type = 0;	/* default is not to send service type */
	verbose_flag = 0;
	secret = "localkey";
	host_name = "localhost";
	radius_port = 0;
	radius_dir = RADIUS_DIR;
	called_id = NULL;
	calling_id = NULL;

        progname = *argv++;
        argc--;

	while(argc > 0) {
		if(**argv != '-') {
			usage();
		}

		argval = *(*argv + 1);
		argnum = *(*argv + 2);
		argc--;
		argv++;

		switch(argval) {
		case 'a':	/* accounting packet */
			acct_flag = 1;
			break;

		case 'd':	/* calleD station id */
			if(argc == 0) {
				usage();
			}
			called_id = *argv;
			argc--;
			argv++;
			break;

		case 'f':
			frame_flag = 1;
			break;

		case 'g':	/* callinG station id */
			if(argc == 0) {
				usage();
			}
			calling_id = *argv;
			argc--;
			argv++;
			break;

		case 'h':
			usage();
			break;

		case 'i':	/* id to use */
			if(argc == 0) {
				usage();
			}
			id = (u_char)(strtol(*argv, 0, 10) & 0x000000ff);
			argc--;
			argv++;
			break;

		case 'n':	/* count not implemented yet */
			usage();
			if(argc == 0) {
				usage();
			}
			count = (u_short)strtol(*argv, 0, 10);
			argc--;
			argv++;
			break;

		case 'p':	/* set radius port */
			if(argc == 0) {
				usage();
			}
			radius_port = (u_short)atoi(*argv);
			argc--;
			argv++;
			break;

		case 'r':	/* RADIUS server to send to */
			if(argc == 0) {
				usage();
			}
			host_name = *argv;
			argc--;
			argv++;
			break;

		case 's':	/* shared secret */
			if(argc == 0) {
				usage();
			}
			secret = *argv;
			argc--;
			argv++;
			break;

		case 't':	/* set service type */
			if(argc == 0) {
				usage();
			}
			service_type = (u_short)atoi(*argv);
			argc--;
			argv++;
			break;

		case 'u':	/* username and password */
			if(argc < 2) {
				usage();
			}
			strncpy(u_name,*argv,sizeof(u_name)-1);
			u_name[sizeof(u_name)-1]='\0';
			argv++;
			strncpy(u_passwd,*argv,sizeof(u_passwd)-1);
			u_passwd[sizeof(u_passwd)-1]='\0';
			argv++;
			argc -= 2;
			break;

		case 'v':
			version();
			break;

		case 'x':
			if (isdigit(argnum)) {
				verbose_flag = argnum - '0';
			} else {
				verbose_flag++;
			}
			break;

		default:
			usage();
			break;
		}
	}

	/* Initialize the dictionary */
	if(dict_init() != 0) {
		rad_exit(-1);
	}

	secret_len = strlen(secret);

	if (radius_port) {
		lport = htons(radius_port);
	} else {
		if (acct_flag) {
			svp = getservbyname ("radacct", "udp");
			if (svp != (struct servent *) 0) {
				lport = (u_short) svp->s_port;
			} else {
				lport = htons(ntohs(PW_AUTH_UDP_PORT));
			}
		} else {
			svp = getservbyname ("radius", "udp");
			if (svp != (struct servent *) 0) {
				lport = (u_short) svp->s_port;
			} else {
				lport = htons(ntohs(PW_ACCT_UDP_PORT));
			}
		}
	}

	if ((hostent = gethostbyname(host_name))
					== (struct hostent *)NULL) {
		fprintf(stderr, "gethostbyname<%s> error<%d>\n",
				host_name, errno);
		exit(1);
	}

	memcpy( &addr.sin_addr.s_addr,
		hostent->h_addr,
		hostent->h_length);

	host = ntohl(addr.sin_addr.s_addr);
	addr.sin_family = AF_INET;
	addr.sin_port = lport;

	printf("Radius client: server is host: %s %s  Port: %d\n",
		host_name,
		inet_ntoa(addr.sin_addr),
		ntohs(lport));

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		exit(errno);
	}


	/*
	 *	build packet and send it
	 */

	ah = (AUTH_HDR *)s_buf;
	memset(ah, 0, sizeof(*ah));
	if (acct_flag) {
		ah->code = PW_ACCOUNTING_REQUEST;
	} else {
		ah->code = PW_AUTHENTICATION_REQUEST;
	}
	ah->id = id;
	len = AUTH_HDR_LEN;
	u_name_len = strlen(u_name);
	u_passwd_len = strlen(u_passwd);

	/*
	 * user name is mandatory
	 */
	cp = ah->data;
	*cp++ = PW_USER_NAME;
	*cp++ = u_name_len + 2;
	memcpy(cp, u_name, u_name_len);
	cp += u_name_len;
	len += u_name_len + 2;

	/*
	 * password doesn't handle longer than 16 characters, for now
	 */
	if (passwd && service_type != PW_CALL_CHECK_USER ) {
		*cp++ = PW_PASSWORD;
		*cp++ = AUTH_PASS_LEN + 2;
		if (u_passwd_len > AUTH_PASS_LEN) {
			u_passwd_len = AUTH_PASS_LEN;
		}

		memset(passwd, 0, AUTH_PASS_LEN);
		memcpy(passwd, u_passwd, u_passwd_len);
		strncpy(md5_buf, secret, sizeof(md5_buf)-1);
		md5_buf[sizeof(md5_buf)-1]='\0';
		memcpy(md5_buf + secret_len, ah->vector, AUTH_VECTOR_LEN);
		md5_calc(cp, md5_buf, secret_len + AUTH_VECTOR_LEN);
		for (i = 0; i < AUTH_PASS_LEN; i++) {
			*cp++ ^= passwd[i];
		}
		len += AUTH_PASS_LEN + 2;
	}

	/*
	 * client id
	 */
	alen = 4;
	*cp++ = PW_CLIENT_ID;
	*cp++ = alen + 2;
	val = htonl(0x7f000001);	/* 127.0.0.1 */
	memcpy(cp, &val, alen);
	cp += alen;
	len += alen + 2;

	/*
	 * client port id
	 */
	alen = 4;
	*cp++ = PW_CLIENT_PORT_ID;
	*cp++ = alen + 2;
	val = htonl(1);
	memcpy(cp, &val, alen);
	cp += alen;
	len += alen + 2;

	/*
	 * framed hint
	 */
	if (service_type) {
		alen = 4;
		*cp++ = PW_USER_SERVICE_TYPE;
		*cp++ = alen + 2;
		val = htonl(service_type);
		memcpy(cp, &val, alen);
		cp += alen;
		len += alen + 2;

	} else if (frame_flag) {
		alen = 4;
		*cp++ = PW_USER_SERVICE_TYPE;
		*cp++ = alen + 2;
		val = htonl(PW_FRAMED_USER);
		memcpy(cp, &val, alen);
		cp += alen;
		len += alen + 2;

		alen = 4;
		*cp++ = PW_FRAMED_PROTOCOL;
		*cp++ = alen + 2;
		val = htonl(PW_PPP);
		memcpy(cp, &val, alen);
		cp += alen;
		len += alen + 2;
	}

	/*
	 * called station id
	 */
	if (called_id!= NULL) {
		alen = (u_char)strlen(called_id);
		*cp++ = PW_CALLED;
		*cp++ = alen + 2;
		memcpy(cp, called_id, alen);
		cp += alen;
		len += alen + 2;
	}

	/*
	 * calling station id
	 */

	if (calling_id!= NULL) {
		alen = (u_char)strlen(calling_id);
		*cp++ = PW_CALLING;
		*cp++ = alen + 2;
		memcpy(cp, calling_id, alen);
		cp += alen;
		len += alen + 2;
	}

	ah->length = htons(len);

	if (acct_flag) {
		/* sign it */
		/* STUB */
	}

	if ((rc = sendto(fd, (char *)ah, len, 0, 
		(struct sockaddr *)&addr, sizeof addr)) < 0) {
		perror("sendto: ");
		rad_exit(errno);
	}

	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	if (select(32, &fdset, NULL, NULL, &tv) < 0) {
		perror("select: ");
		rad_exit(errno);
	}
	if (FD_ISSET(fd, &fdset)) {
		sa_len = sizeof sa_ihd;
		if ((rc = recvfrom(fd, r_buf, sizeof r_buf, 0,
			(struct sockaddr *)&sa_ihd, &sa_len)) < 0) {
			perror("recvfrom: ");
			rad_exit(errno);
		}
	} else {
		printf("recv timeout\n");
		rad_exit(errno);
	}

	/* STUB - does not check response authenticator yet */

	ah = (AUTH_HDR *)r_buf;
	switch(ah->code) {
	case PW_AUTHENTICATION_ACK:
		printf("Received Accept\n");
		break;

	case PW_AUTHENTICATION_REJECT:
		printf("Received Reject\n");
		break;

	case PW_ACCESS_CHALLENGE:
		printf("Received Challenge\n");
		break;

	case PW_ACCOUNTING_RESPONSE:
		printf("Received Accounting Response\n");
		break;

	default:
		printf("ERROR Received code %d id %d length %d\n",
			ah->code,
			ah->id,
			ah->length);
		return;
		break;
	}

	authreq = radrecv(host, ntohs(lport), secret, (u_char*)r_buf, rc);

	if (authreq != (AUTH_REQ *)NULL) {
		pair = authreq->request;
		while (pair != (VALUE_PAIR *)NULL) {
			fputs("\t", stdout);
			fprint_attr_val(stdout, pair);
			fputs("\n", stdout);
			pair = pair->next;
		}
        }

	close(fd);
}


/*************************************************************************
 *
 *	Function: radrecv
 *
 *	Purpose: Receive UDP client requests, build an authorization request
 *		 structure, and attach attribute-value pairs contained in
 *		 the request to the new structure.
 *
 *************************************************************************/

AUTH_REQ *
radrecv( UINT4 host, u_short udp_port, char *secret, u_char *buffer,int length )
{
	u_char		*ptr;
	char		*bufalloc();
	AUTH_HDR	*auth;
	int		totallen;
	int		attribute;
	int		attrlen;
	int		vendor;
	int		vsa;
	int		vsattrlen;
	DICT_ATTR	*attr;
	DICT_ATTR	*dict_attrget();
	DICT_ATTR	*dict_vsattrget();
	UINT4		lvalue;
	VALUE_PAIR	*first_pair;
	VALUE_PAIR	*prev;
	VALUE_PAIR	*pair;
	VALUE_PAIR	*pairalloc();
	AUTH_REQ	*authreq;
	AUTH_REQ	*reqalloc();
	void		hexdump();
	void		pairfree();
	void		rad_exit();
	void		reqfree();

	if (length < AUTH_HDR_LEN) {            /* too short to be real */
                log_err("radrecv: runt packet of %d bytes from %s/%d\n",
			length, ipaddr2strp(host), udp_port);
                return ((AUTH_REQ *)NULL);
        }

	/*
	 * Pre-allocate the new request data structure
	 */

	authreq = reqalloc("radrecv");

	auth = (AUTH_HDR *)buffer;
	totallen = ntohs(auth->length);
	if (totallen > length) {	/* truncated packet, ignore */
		log_err("radrecv: message from %s/%d claimed length %d, only %d bytes received\n", ipaddr2strp(host), udp_port, totallen, length);
		reqfree(authreq,"radrecv");
		return((AUTH_REQ *)NULL);
	}

	debug("message received from %s/%d.%d code=%d, length=%d\n",
		ipaddr2strp(host), udp_port, auth->id, auth->code, totallen);

	if (debug_flag > 1) {
		hexdump(buffer,totallen);
	}
	/*
	 * Fill header fields
	 */
	authreq->ipaddr = host;
	authreq->udp_port = udp_port;
	authreq->id = auth->id;
	authreq->code = auth->code;
	memcpy(authreq->vector, auth->vector, AUTH_VECTOR_LEN);
	strncpy(authreq->secret,secret,20);
	authreq->secret[19]='\0';

	/*
	 * Extract attribute-value pairs
	 */
	ptr = auth->data;
	length = totallen - AUTH_HDR_LEN;
	first_pair = (VALUE_PAIR *)NULL;
	prev = (VALUE_PAIR *)NULL;

	while(length > 0) {

		attribute = *ptr++;
		attrlen = *ptr++;
		if(attrlen < 2) {
			length = 0;
			continue;
		}
		attrlen -= 2;
		if ( attrlen > AUTH_STRING_LEN ) {
			log_err("radrecv: attribute %d from %s too long, length of %d > %d\n",
				attribute, req2strp(authreq), attrlen, AUTH_STRING_LEN);
			reqfree(authreq,"radrecv");
			return((AUTH_REQ *)NULL);
		}
		pair = pairalloc("radrecv");

		if((attr = dict_attrget(attribute)) == (DICT_ATTR *)NULL) {
			snprintf(pair->name,VALUE_PAIR_NAME_LEN,"Unknown-%d",attribute);
			pair->attribute = attribute;
			pair->type = PW_TYPE_STRING;
		} else {
			strncpy(pair->name, attr->name, VALUE_PAIR_NAME_LEN-1 );
			pair->name[VALUE_PAIR_NAME_LEN-1]='\0';
			pair->attribute = attr->value;
			pair->type = attr->type;
		}

		if (pair->attribute == PW_VENDOR) {	
			if (attrlen < 6 || 
			    ((vsattrlen = *(ptr+5)) != (attrlen-4))) {
				pair->vendor = 0;
				pair->vsattribute = 0;
				pair->type = PW_TYPE_STRING;
			} else {
				memcpy(&vendor, ptr, sizeof(UINT4));
				vendor = ntohl(vendor);
				ptr += 4;
				vsa = *ptr++;
				attrlen = vsattrlen - 2;
				ptr++;
				length -= 6;
				pair->vendor = vendor;
				pair->vsattribute = vsa;
				if((attr = dict_vsattrget(vendor,vsa)) != (DICT_ATTR *)NULL) {
					strncpy(pair->name, attr->name, VALUE_PAIR_NAME_LEN-1 );
					pair->name[VALUE_PAIR_NAME_LEN-1]='\0';
					pair->type = attr->type;
				} else {
					snprintf(pair->name,VALUE_PAIR_NAME_LEN,"Vendor-Specific-%d-%d",vendor,vsa);
					pair->type = PW_TYPE_STRING;
				}
			}
		}

		switch(pair->type) {

		case PW_TYPE_STRING:
#if defined(ASCEND_BINARY)
		case PW_TYPE_ABINARY:
#endif
			memcpy(pair->strvalue, ptr, attrlen);
			pair->strvalue[attrlen] = '\0';
			pair->lvalue = attrlen;
			if(first_pair == (VALUE_PAIR *)NULL) {
				first_pair = pair;
			}
			else {
				prev->next = pair;
			}
			prev = pair;
			break;

		case PW_TYPE_INTEGER:
		case PW_TYPE_IPADDR:
		case PW_TYPE_DATE:
			memcpy(&lvalue, ptr, sizeof(UINT4));
			pair->lvalue = ntohl(lvalue);
			if(first_pair == (VALUE_PAIR *)NULL) {
				first_pair = pair;
			}
			else {
				prev->next = pair;
			}
			prev = pair;
			break;

		default:
			debug("    %s (Unknown Type %d)\n",
				attr->name,attr->type);
			pairfree(pair,"radrecv");
			break;
		}
		ptr += attrlen;
		length -= attrlen + 2;
	}
	authreq->request = first_pair;

	authreq->timestamp = now;	/* now was set in main() */

	/* copy the packet */
	authreq->packet = bufalloc(totallen,"radrecv");
	memcpy(authreq->packet,buffer,totallen);

	return(authreq);
}

void
usage(void)
{
	printf("usage: %s -d called_id -f -g calling_id -h -i id -p port -s secret -t type -v -x -u username password\n", progname);
	exit(0);
}

void
rad_exit(int rc)
{
	exit(rc);
}

void
version(void)
{
	printf("%s $Date: 2004-08-28 15:32:47 +0200 (sab, 28 ago 2004) $\n", progname);
	exit(0);
}
