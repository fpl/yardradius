/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

#include "yard.h"
#include "global.h"

static  AUTH_REQ *first_forwarded = (AUTH_REQ *)NULL;
static	PEER	*servers;
static	PEER	*server_default;
static	PEER	*server_norealm;

/*************************************************************************
 *************************************************************************

	Subroutines related to forwarding a Proxy reply from a server
	to the client:

	rad_proxy(fd)
	pop_proxy(authreq, pstate)
	send_proxy2client(fd, authreq, server, pstate)
	update_proxy()
	find_server()

 *************************************************************************
 *************************************************************************/

/*************************************************************************
 *
 *	Function: rad_proxy
 *
 *	Purpose: Receive UDP Proxy server replies and forward to client
 *
 *	Uses External: sockfd, acctfd
 *
 *************************************************************************/

void 
rad_proxy(int fd)
{
	extern AUTH_REQ		*first_forwarded;
	extern int		max_proxy_time;
	AUTH_HDR		*auth;
	AUTH_REQ		*authreq;
	AUTH_REQ		*oldqp;
	AUTH_REQ		*qp;
	AUTH_REQ		*qpop;
	PEER			*server;
	UINT4			host;
	char			digest[AUTH_VECTOR_LEN];
	char			hold_digest[AUTH_VECTOR_LEN];
	char			*sentreqauth;
	int			result;
	int			secretlen;
	size_t			salen;
	struct	sockaddr_in	*sin;
	struct  sockaddr_in     rad_saremote;
	u_short			port;

	salen = sizeof(rad_saremote);
	sin = (struct sockaddr_in *) & rad_saremote;

	auth = (AUTH_HDR *)recv_buffer;

	result = recvfrom (fd, (char *) recv_buffer,
		(int) sizeof(recv_buffer),
		(int) 0, (struct sockaddr *)&rad_saremote, &salen);

	host = ntohl(sin->sin_addr.s_addr);
	port = ntohs(sin->sin_port);

	/* Drop the packet if we do not know the proxy */
	if ((server = find_server_byaddr(host, port)) == (PEER *)NULL) {
		log_err("auth: packet from unknown proxy server %s.%d ignored\n", ipaddr2strp(host), port);
		return;
	}

	authreq = radrecv( host, port, server->secret, recv_buffer, result);
	secretlen = strlen(server->secret);

        if (authreq == (AUTH_REQ *)NULL) {
                return;
        }

	/* Security check: next memcpy() must not overflow */

	if ((size_t)(result+secretlen)>sizeof(recv_buffer)) {
		log_err("rad_proxy: exceeding size of receiving buffer");
		return;
	}

	/* Verify response authenticator */

	switch (authreq->code) {
		case  PW_AUTHENTICATION_ACK:
		case  PW_AUTHENTICATION_REJECT:
		case  PW_ACCESS_CHALLENGE:
			fd = sockfd;
			break;
		case  PW_ACCOUNTING_RESPONSE:
			fd = acctfd;
			break;
		case  PW_AUTHENTICATION_REQUEST:
		case  PW_ACCOUNTING_REQUEST:
		default:
			log_err("rad_proxy: proxy server %s/%d.%d sent back invalid packet type %d, ignoring\n", ipaddr2strp(host), port, authreq->id, authreq->code);
			reqfree(authreq, "rad_proxy");
			return;
			break;
	}

	debug("proxy server %s/%d.%d replied with code=%d, length=%d\n", ipaddr2strp(host), port, authreq->id, authreq->code, result);
	if (debug_flag > 2) {
		hexdump((u_char*)recv_buffer,result);
	}

	/* Find original request authenticator */

	oldqp = (AUTH_REQ *)NULL;
	qp = first_forwarded;
	while ((qp != (AUTH_REQ *)NULL) && (qp->forw_id != authreq->id)) {
		oldqp = qp;
		if (qp == qp->next) {	/* should never happen */
			log_err("ERROR: circular queue detected at %d\n", __LINE__);
			qp->next = (AUTH_REQ *)NULL;
		}
		qp = qp->next;
	}

	if (qp != (AUTH_REQ *)NULL) {
		if (oldqp == (AUTH_REQ *)NULL) {
			first_forwarded = qp->next;
		} else {
			oldqp->next = qp->next;
		}
		qp->next = (AUTH_REQ *)NULL;
		sentreqauth = qp->forw_vector;
	}

	qpop = (AUTH_REQ *)NULL;
	if (server->flags & PEER_NOPROXY) { /* server can't do proxy */
		if (qp == (AUTH_REQ *)NULL) {	/* not found in queue */
			debug("rad_proxy: response from %s/%d.%d not matched in forwarded queue, dropped\n", ipaddr2strp(host), port, authreq->id);
			reqfree(authreq, "rad_proxy");
			return;
		} else {
			qpop = qp;
		}
	} else { /* proxy-capable server */
		 /* pop last Proxy-State and fill in qp, if needed */
	    	if ((qpop = pop_proxy(authreq, qp)) == (AUTH_REQ *)NULL) {
			log_err("rad_proxy: invalid Proxy-State from proxy server %s/%d.%d, dropped\n", ipaddr2strp(host), port, authreq->id);
			if (debug_flag > 0) {
				hexdump((u_char*)authreq->packet,result);
			}
			reqfree(authreq, "rad_proxy");
			return;
		}
	}

	if (qp == (AUTH_REQ *)NULL) {
		if (authreq->code == PW_ACCOUNTING_RESPONSE) {
			/* radiusd has restarted or we've already
			   forwarded this response, so drop this response
			 */
			debug("rad_proxy: accounting-response from %s/%d.%d not matched in forwarded queue, dropped\n",
				ipaddr2strp(host), port, authreq->id);
			reqfree(authreq, "rad_proxy");
			reqfree(qpop, "rad_proxy");
			return;
		} else {
			/* for access-responses, we can use the Request
			 * authenticator we included in the proxy, if we
			 * do not find it in our queue
			 */
			qp = qpop;
			sentreqauth = qp->vector;
		}
	}
	if ((authreq->code == PW_ACCOUNTING_RESPONSE) &&
	    (server->flags & PEER_OLDACCT)) {	/* ignore acct signature */
		send_proxy2client(fd, authreq, server, qp);
		reqfree(qp,"rad_proxy");
	} else {
	
		/* Check response authenticator */
		memcpy(hold_digest, auth->vector, AUTH_VECTOR_LEN);
		memcpy(auth->vector, sentreqauth, AUTH_VECTOR_LEN);
		memcpy(recv_buffer + result, server->secret, secretlen);
		md5_calc((u_char*)digest, (u_char *)auth, result + secretlen);
		memset(recv_buffer + result, 0, secretlen);
		/* no need to restore auth->vector */

		if (memcmp(hold_digest, digest, AUTH_VECTOR_LEN) == 0) {
			send_proxy2client(fd, authreq, server, qp);
			reqfree(qp,"rad_proxy");
		} else {
			log_err("rad_proxy: remote server %s/%d.%d sent invalid reply, dropping\n", ipaddr2strp(host), port, authreq->id);
			if (debug_flag > 0) {
				hexdump((u_char*)authreq->packet,result);
			}
			/* requeue qp if it hasn't timed out */
			if (qp != (AUTH_REQ *)NULL) {
				if (qp->timestamp + max_proxy_time > now) {
					qp->next = first_forwarded;
					first_forwarded = qp;
				} else {
					reqfree(qp,"rad_proxy");
				}
                	}

		}
	}
	reqfree(authreq,"rad_proxy");
	return;
}

/*************************************************************************
 *
 *	Function: pop_proxy
 *
 *      Purpose: Remove the last proxy-state attribute from authreq->request,
 *	and returns a pointer to qp, allocating it if necessary.
 *
 *	Any format changes made here must also be made in push_proxy()
 *
 *************************************************************************/

AUTH_REQ *
pop_proxy(AUTH_REQ *authreq,AUTH_REQ *qp)
{
	VALUE_PAIR	*value_list;
	VALUE_PAIR	*old_value;
	VALUE_PAIR	*prev_value;
	VALUE_PAIR	*lastproxy;
	UINT4		tmp;
	u_short		tmps;
	u_char		hostnm[256];	/* passed as an argument, but unused */

	old_value = (VALUE_PAIR *) NULL;
	prev_value = (VALUE_PAIR *) NULL;
	lastproxy = (VALUE_PAIR *) NULL;

	value_list = authreq->request;

	while(value_list != (VALUE_PAIR *)NULL) {
		if(value_list->attribute == PW_PROXY) {
			lastproxy = value_list;
			prev_value = old_value;
		}
		old_value = value_list;
		value_list = value_list->next;
	}
	if (lastproxy == (VALUE_PAIR *)NULL) { /* not found */
		return (qp);
	}

	/* pop lastproxy from linked list */
	if (prev_value != (VALUE_PAIR *)NULL) {
		prev_value->next = lastproxy->next;
	} else {
		authreq->request = lastproxy->next;
	}
	lastproxy->next = (VALUE_PAIR *)NULL;

	/* Proxy-State contains: Timestamp, Client, Port, Id in network order,
	   a pad byte, and 16 octets of Request Authenticator */
	if (lastproxy->lvalue < 28) {
		log_err("pop_proxy: Proxy-State from %s has too short length %d < 28, ignoring\n", req2strp(authreq), lastproxy->lvalue);
	}

	if (qp != (AUTH_REQ *)NULL) {
		pairfree(lastproxy, "pop_proxy");
		return (qp);
	} else {
		qp = reqalloc("pop_proxy");
	}

	memcpy((char *)&tmp, lastproxy->strvalue, 4);
	qp->timestamp = ntohl(tmp);
	memcpy((char *)&tmp, lastproxy->strvalue+4, 4);
	qp->ipaddr = ntohl(tmp);
	memcpy((char *)&tmps, lastproxy->strvalue+8, 2);
	qp->udp_port = ntohs(tmps);
	memcpy((char *)&(qp->id), lastproxy->strvalue+10, 1);
	memcpy((char *)qp->vector, lastproxy->strvalue+12, AUTH_VECTOR_LEN);

	pairfree(lastproxy, "pop_proxy");

	if(find_client(qp->ipaddr, qp->secret, AUTH_REQ_FORW_SECRET_LEN, hostnm, sizeof(hostnm)) != 0) {
		reqfree(qp, "pop_proxy");
		qp = (AUTH_REQ *)NULL;
	}

	return qp;
}


/*************************************************************************
 *
 *	Function: send_proxy2client
 *
 *	Purpose: Forward a proxy reply to a client defined in qp.
 *		 Calling routine has already removed our Proxy-State
 *
 *************************************************************************/

void 
send_proxy2client(int fd,AUTH_REQ*authreq,PEER*server,AUTH_REQ*qp)
{
	AUTH_HDR		*auth;
	VALUE_PAIR		*curpair;
	VALUE_PAIR		*pair;
	VALUE_PAIR		*reply;
	char			ip_str[32];
	u_short			total_length;

	auth = (AUTH_HDR *)send_buffer;

	reply = authreq->request;

	req2str(ip_str,sizeof(ip_str),authreq);

	/* if realm is marked insecure and has returned a Admin or NAS-Prompt
	   service type, send a reject to the client instead, and log it */
	if ( (!(server->flags & PEER_ADMINOK))
	     && (((pair = get_attribute(authreq->request,
			PW_USER_SERVICE_TYPE)) != (VALUE_PAIR *)NULL)
		    && ((pair->lvalue == PW_ADMIN_USER)
		       || (pair->lvalue == PW_PROMPT_USER)))) {

		authreq->code = PW_AUTHENTICATION_REJECT;
		log_err("remote server %s returned insecure service for client %s, sending reject instead\n",
			ip_str, req2strp(qp));
		/* copy over only proxy-states */
		authreq->request = (VALUE_PAIR *)NULL;
		curpair = (VALUE_PAIR *)NULL;
		while(reply != (VALUE_PAIR *)NULL) {
			if (reply->attribute == PW_PROXY) {
				if (curpair == (VALUE_PAIR *)NULL) {
					curpair = reply;
					authreq->request = reply;
				} else {
					curpair->next = reply;
					curpair = reply;
				}
			} else {
				pairfree(reply, "send_proxy2client");
			}
			reply=reply->next;
		}
		if (curpair != (VALUE_PAIR *)NULL) {
			curpair->next = (VALUE_PAIR *)NULL;
		}
	}

	debug("forwarding reply code %d from %s to %s\n",
		authreq->code, ip_str, req2strp(qp));

	/* Load up the configuration values for the user */
	total_length = build_packet(qp, authreq->request, (char *)NULL,
				    authreq->code, FW_CLIENT, send_buffer, sizeof(send_buffer));

	/* send it to the client */
	send_packet(fd, qp->ipaddr, qp->udp_port, send_buffer, total_length);

}


/*************************************************************************
 *
 *	Function: update_proxy
 *
 *	Purpose: Check last modified time on proxy file and build a
 *		 new servers list if the file has been changed.
 *
 *************************************************************************/

int 
update_proxy(void)
{
	extern u_short	radacct_port;
	extern u_short	radius_port;
	static UINT4	ouraddress = 0;
	static int	first = 0;
	static time_t	last_update_time;
	FILE		*fd;
	PEER		*curserv;
	PEER		*server;
	UINT4		ipaddr;
	char		*arg;
	char		*hostnm;
	char		*realm;
	char		*secret;
	char		ourname[256];
	int		lineno;
	int		nproxy;
	struct stat 	statbuf;
	u_char		buffer[PATH_MAX];
	u_short		rport;

	nproxy = 0;

	/* Check last modified time of proxy file */
	snprintf((char *)buffer,sizeof(buffer),"%s/%s", radius_dir, RADIUS_PROXY);
	if(stat(buffer, &statbuf) != 0) {
		if (first == 0) {
			log_err("proxy file %s not found; not using proxy\n", 
			buffer);
			first++;
		}
		return(0);
	}
	if(statbuf.st_mtime == last_update_time) {
		/* nothing to update */
		return(0);
	}

	/* Get our address if we have not already */
	/* This will need to be changed to support multi-homed hosts */

	if (ouraddress == 0) {
		errno = 0;
		if (gethostname(ourname, 128) != 0) {
			log_err("update_proxy: unable to get own hostname; %s\n",
				strerror(errno));
		}
		ouraddress = get_ipaddr(ourname);
		if (ouraddress == 0) {
			log_err("update_proxy: unable to resolve own hostname \"%s\"\n",ourname);
		}
	}

	/* Proxy file format:
	 *	hostname secret realm options...
	 *
	 * realm can be user@realm or a Called-Station-Id
	 *
	 */

	/* Open the proxy file */
	if((fd = fopen((const char *)buffer, "r")) == (FILE *)NULL) {
		log_err("Error: could not read proxy file %s; %s\n", buffer,
			strerror(errno));
		return(-1);
	}

	/* free up existing linked list of servers */

	while (servers != (PEER *)NULL) {
		server = servers;
		servers = servers->next;
		server->next = (PEER *)NULL;
		peerfree(server, "update_proxy");
	}
	server = (PEER *)NULL;
	server_default = (PEER *)NULL;
	server_norealm = (PEER *)NULL;

	lineno=0;
	while (fgets((char *)buffer, sizeof(buffer), fd) != (char *)NULL) {
		lineno++;
		if(*buffer == '#' || *buffer == ' ' || *buffer == '\t'
		   || *buffer == '\n') {
			continue;
		}
		hostnm = strtok(buffer, " \t\n");
		secret = strtok((char *)NULL, " \t\n");
		realm = strtok((char *)NULL, " \t\n");
		if (realm == (char *)NULL) {
			log_err("syntax error on line %d in proxy file\n", lineno);
			continue;
		}
		if((ipaddr = get_ipaddr(hostnm)) == (UINT4)0) {
			log_err("could not resolve proxy hostname %s at line %d\n", hostnm, lineno);
			continue;
		}

		/* store in realm linked list */
		server = peeralloc("update_proxy");

		/* parse arguments to proxy line */

		while ((arg = strtok((char *)NULL, " \t\n, ")) != (char *)NULL) {
			if (isdigit(arg[0])) {
				rport = atoi(arg);
				if (rport > 0) {
					if (server->radport == 0) {
						server->radport = rport;
					} else if (server->acctport == 0) {
						server->acctport = rport;
					} else {
						log_err("unknown argument \"%s\" on line %d in proxy file\n", arg, lineno);
					}
				}
				continue;
			}

			if (strcmp(arg, "old") == 0) {
				server->flags |= PEER_NOPROXY;
				server->flags |= PEER_OLDACCT;
			}
			else if (strcmp(arg, "secure") == 0) {
				server->flags |= PEER_ADMINOK;
			}
			else if (strcmp(arg, "ipass") == 0) {
				server->flags |= PEER_IPASS;
			} else {
				log_err("unknown argument \"%s\" on line %d in proxy file ignored\n", arg, lineno);
			}

		}
		if (server->radport == 0) {
			server->radport = radius_port;
		}
		if (server->acctport == 0) {
			server->acctport = radacct_port;
		}

		if ((ipaddr == ouraddress)
		    && ((server->radport == radius_port)
			|| (server->acctport == radacct_port))) {
			ipaddr = 0;	/* handle ourselves, do not forward */
		}
		server->ipaddr = ipaddr;

		memcpy(server->secret, secret, strlen(secret));
		memcpy(server->realm, realm, strlen(realm));

		if (strcmp(realm, "DEFAULT") == 0) {
			server_default = server;
		} else if (strcmp(realm, "NOREALM") == 0) {
			server_norealm = server;
		} 

		if (servers == (PEER *)NULL) {	/* first one */
			servers = server;
			curserv = server;
		} else {
			curserv->next = server;
			curserv = server;
		}
		nproxy++;
	}
	fclose(fd);
	last_update_time = statbuf.st_mtime;
	debug("found %d proxy realms\n", nproxy);
	return(0);
}



/*************************************************************************
 *************************************************************************

	Subroutines related to forwarding a Proxy request from a client
	to the appropriate server

	handle_proxy(authreq)
	push_proxy(authreq)
	find_server(number, realm)
	find_server_byaddr(ipaddr, port)
	send_proxy2server(authreq, server)
	getnextid(authreq)

 *************************************************************************
 *************************************************************************/


/*************************************************************************
 *
 *	Function: handle_proxy
 *
 *	Purpose: Called by rad_request() to check if access-request should
 *		 be forwarded to another server.
 *		 Called by rad_acctreq() to forward acct-request if needed.
 *
 *	Returns:
 *		-1 on error
 *		 0 if this request was not forwarded
 *		 1 if this request was forwarded
 *	Side-Effects:
 *		Sets REQ_PROXY flag in authreq if request was forwarded
 *
 *
 *************************************************************************/

int 
handle_proxy(AUTH_REQ*authreq)
{
	PEER		*server;
	VALUE_PAIR	*namepair;
	VALUE_PAIR	*pair;
	char		*name;
	char		namebuf[256];
	char		*number;
	char		*ptr;
	char		*realm;
	int		ret;

	realm = (char *)NULL;
	number = (char *)NULL;
	namebuf[0] = '\0';
	name = namebuf;

	if (authreq == (AUTH_REQ *)NULL) {
		return -1;
	}

	if (authreq->code != PW_AUTHENTICATION_REQUEST &&
	    authreq->code != PW_ACCOUNTING_REQUEST) {
		/* should not happen unless client sent bogus message */
		debug("handle_proxy called for packet type %d unexpectedly\n",
			authreq->code);
		authreq->flags |= REQ_ERR|REQ_FREE;
		return -1;
	}

        namepair = get_attribute(authreq->request, PW_USER_NAME);
        if (namepair != (VALUE_PAIR *)NULL) {
		memcpy(namebuf, namepair->strvalue, namepair->lvalue);
		namebuf[namepair->lvalue] = '\0';
		if ((realm=strchr((const char *)name, '@')) != (char *)NULL) {
			*realm = '\0';
			realm++;
		} else if ((ptr=strchr((const char *)name, '/')) != (char *)NULL) {
			*ptr = '\0';
			ptr++;
			realm = name;
			name = ptr;
		} else {
			realm = (char *)NULL;
		}
	}

        pair = get_attribute(authreq->request, PW_CALLED);
	if (pair != (VALUE_PAIR *)NULL) {
		number = pair->strvalue;
	}

	/*	look up number or realm in the list of servers.  If a proxy
	 *	is found, parse the packet, unencrypt the password if
	 *	any, re-encrypt the password (if any), attach a
	 *	proxy-state with push_proxy(), and forward it to the proxy.
	 *	Use the same Request Authenticator (in case of CHAP) but
	 *	use a new Id
	 */

	if ((server = find_server(number, realm)) == (PEER *)NULL) {
		if (namepair != (VALUE_PAIR *)NULL) {
			strncpy(authreq->name, namepair->strvalue, 64);
			authreq->name[63] = '\0';
		} else {
			authreq->name[0] = '\0';
		}
		return 0;	/* no proxy */
	}

	strncpy(authreq->realm, server->realm, 64);
	strncpy(authreq->name, name, 64);
	authreq->name[63] = '\0';

	if (server->ipaddr == 0) {	/* this is the server for this realm */
		return 0;
	}

	authreq->flags |= REQ_PROXY;

	if (server->flags & PEER_IPASS) {
		if (authreq->code == PW_AUTHENTICATION_REQUEST) {
			ret = rad_forw_ipass(authreq, sockfd, authreq->packet);
			authreq->flags |= REQ_FREE;
			return ret;
		} else if (authreq->code == PW_ACCOUNTING_REQUEST) {
			ret = rad_forw_ipass(authreq, acctfd, authreq->packet);
			authreq->flags |= REQ_FREE;
			return 0;
		} else {
			authreq->flags |= REQ_ERR|REQ_FREE;
			return -1;
		}
	}

	if (authreq->code == PW_AUTHENTICATION_REQUEST) {
		if (decrypt_password(authreq, authreq->secret) != (char *)NULL) {
			encrypt_password(authreq, server->secret);
		}
	}
	/* If remote server cannot handle proxy, delete realm from User-Name */
	if ( server->flags & PEER_NOPROXY ) {
		if (namepair != (VALUE_PAIR *)NULL) {
			strcpy(namepair->strvalue,name);
			namepair->lvalue = strlen(name);
		}
	} else {
		push_proxy(authreq);
	}

	send_proxy2server(authreq, server);

	return 1;
}


/*************************************************************************
 *
 *	Function: push_proxy
 *
 *	Purpose: Adds a Proxy-State to the end of a packet
 *		 Note that RADIUS requires that Proxy-State always be
 *		 added after any existing Proxy-State attributes.
 *
 *		 Any changes made here must also be made in pop_proxy()
 *
 *************************************************************************/

void
push_proxy(AUTH_REQ*authreq)
{
	DICT_ATTR       *attr;
	VALUE_PAIR	*pair;
	VALUE_PAIR	*list;
	UINT4		tmp;
	u_short		tmps;

	pair = pairalloc("push_proxy");

	/* Proxy-State contains: Timestamp, Client, Port, Id in network order,
	   a pad byte, and 16 octets of Request Authenticator */

 	if((attr = dict_attrget(PW_PROXY)) == (DICT_ATTR *)NULL) {
		debug("add Proxy (%d) to dictionary\n", PW_PROXY);
		strcpy(pair->name, "Proxy");
		pair->type = PW_TYPE_STRING;
	} else {
		strcpy(pair->name, attr->name);
		pair->type = attr->type;
	}

	pair->attribute = PW_PROXY;
	pair->lvalue = 28;	/* length of data */

	tmp = htonl(authreq->timestamp);
	memcpy(pair->strvalue, (char *)&tmp, 4);
	tmp = htonl(authreq->ipaddr);
	memcpy(pair->strvalue+4, (char *)&tmp, 4);
	tmps = htons(authreq->udp_port);
	memcpy(pair->strvalue+8, (char *)&tmps, 2);
	memcpy(pair->strvalue+10, (char *)&(authreq->id), 1);
	memset(pair->strvalue+11, 0, 1);			/* zero pad */
	memcpy(pair->strvalue+12, authreq->vector, AUTH_VECTOR_LEN);

	if ((list = authreq->request) == (VALUE_PAIR *)NULL) {
		authreq->request = pair;
	} else {
		while(list->next != (VALUE_PAIR *)NULL) {
			list = list->next;
		}
		list->next = pair;
	}
}


/*************************************************************************
 *
 *	Function: find_server
 *
 *	Purpose: Returns server to forward to based on number or realm
 *		 Number takes precedence
 *
 *************************************************************************/

PEER * 
find_server(char *number,char *realm)
{
	extern PEER	*servers;
	extern PEER	*server_default;
	extern PEER	*server_norealm;
	PEER	*server;
	PEER	*maybe;

	maybe = (PEER *)NULL;

	server=servers;

	/* In a future version we may want to match with or without area code */

	while(server != (PEER *)NULL) {
		if ((number != (char *)NULL)
		    && (strcmp(server->realm, number) == 0)) {
			return server;
		}
		if ((realm != (char *)NULL)
		    && (strcmp(server->realm, realm) == 0)) {
			maybe = server;
		}
		server = server->next;
	}
 	if (maybe == (PEER *)NULL) {
		if (realm != (char *)NULL) {
			maybe = server_default;
		} else {
			maybe = server_norealm;
		}
	}
	return maybe;
}


/*************************************************************************
 *
 *	Function: find_server_byaddr
 *
 *	Purpose: Returns proxy server based on IP address and source port
 *
 *************************************************************************/

PEER *
find_server_byaddr(UINT4 ipaddr,u_short port)
{
	PEER	*server;
	extern PEER	*servers;

	server=servers;

	while ((server != (PEER *)NULL) && !((server->ipaddr == ipaddr) &&
		((server->acctport == port) || (server->radport == port))) ) {

		server = server->next;
	}
	return server;
}


/*************************************************************************
 *
 *	Function: send_proxy2server
 *
 *	Purpose: Forward a proxy request to a server
 *		 Calling routine has already encrypted password (if any)
 *		 and added our Proxy-State
 *
 *************************************************************************/

void 
send_proxy2server(AUTH_REQ*authreq,PEER*server)
{
	extern AUTH_REQ		*first_forwarded;
	AUTH_HDR		*auth;
	char			ip_str[32];
	int			fd;
	u_char			saveid;
	u_short			total_length;

	req2str(ip_str, sizeof(ip_str), authreq);

	auth = (AUTH_HDR *)send_buffer;

	if (authreq->code == PW_AUTHENTICATION_REQUEST) {
		authreq->forw_port = server->radport;
		fd = proxyfd;
	} else if (authreq->code == PW_ACCOUNTING_REQUEST) {
		authreq->forw_port = server->acctport;
		fd = proxyacctfd;
	} else {
		log_err("unknown request type %d from %s ignored\n",
			authreq->code, ip_str);
		authreq->flags |= REQ_ERR|REQ_FREE;
		return;
	}

	authreq->forw_id = getnextid(authreq);
	/* getnextid sets REQ_ERR flag if unable to allocate id */
	if ((authreq->flags & REQ_ERR) == REQ_ERR) {
		return;
	}
	saveid = authreq->id;
	authreq->id = authreq->forw_id;

	authreq->forw_addr = server->ipaddr;
	memcpy(authreq->forw_vector, authreq->vector, AUTH_VECTOR_LEN);
	strcpy(authreq->forw_secret, server->secret);

	debug("forwarding request from %s to %s/%d.%d for %s\n",
		ip_str, ipaddr2strp(authreq->forw_addr), authreq->forw_port,
		authreq->forw_id, authreq->realm);

	total_length = build_packet(authreq, authreq->request, (char *)NULL,
				    authreq->code, FW_SERVER, send_buffer, sizeof(send_buffer));

	authreq->id = saveid;
	memcpy(authreq->forw_vector, auth->vector, AUTH_VECTOR_LEN);

	/* forward it to the server */
        send_packet(fd, authreq->forw_addr, authreq->forw_port,
		    send_buffer, total_length);

	if (!(authreq->flags & REQ_DUP)) {
		authreq->next = first_forwarded;
		first_forwarded = authreq;
		if (authreq == authreq->next) {
			log_err("ERROR: circular queue detected at %d\n", __LINE__);
		}
	}
	return;
}

/*************************************************************************
 *
 *	Function: getnextid
 *
 *	Purpose: Returns next ID for use in forwarding to this server
 *		 Use one ID counter 0..255 for all forwarded packets
 *
 *************************************************************************/

u_char 
getnextid(AUTH_REQ *authreq)
{
	extern AUTH_REQ	*first_forwarded;
	AUTH_REQ	*qp;
	AUTH_REQ	*prevqp;
	static char	inuse[256];
	u_short	 	newid;
	static u_char	curid = 0;
	static int	flushcount = 0;
	extern int	max_proxy_time;
	extern UINT4	now;

	memset(inuse, 0, 256);
	prevqp = (AUTH_REQ *)NULL;

	qp = first_forwarded;

	while (qp != (AUTH_REQ *)NULL) {
		if (qp->timestamp + max_proxy_time < now) {
			if (++flushcount % 100 == 0) {
				debug("%d proxy requests expired unanswered\n",flushcount);
			}
			if (prevqp == (AUTH_REQ *)NULL) {
				first_forwarded = qp->next;
				reqfree(qp,"getnextid");
				qp = first_forwarded;
			} else {
				prevqp->next = qp->next;
				reqfree(qp,"getnextid");
				qp = prevqp->next;
			}
		} else {
			if (authreq->ipaddr == qp->ipaddr &&
			    authreq->udp_port == qp->udp_port &&
			    authreq->id == qp->id) {
				authreq->flags |= REQ_DUP|REQ_FREE;
				return qp->forw_id;
			}
			inuse[qp->forw_id]++;
			if (qp == qp->next) {
				log_err("ERROR: circular queue detected at %d\n", __LINE__);
				qp->next = (AUTH_REQ *)NULL;
			}
			prevqp = qp;
			qp = qp->next;
		}
	}
	for (newid = curid; newid <= 255; newid++) {
		if (inuse[newid] == 0) {
			curid = ((newid+1) & 0xff);
			return newid;
		}
	}
	for (newid = 0; newid < curid; newid++) {
		if (inuse[newid] == 0) {
			curid = ((newid+1) & 0xff);
			return newid;
		}
	}
	/* no ids left, so log an error and mark packet for discard */
	log_err("getnextid: out of IDs, dropping packet from %s\n",
		req2strp(authreq));
	authreq->flags |= REQ_ERR|REQ_FREE;

	return 0;
}



/*************************************************************************
 *************************************************************************

	Misc subroutines for proxy

 *************************************************************************
 *************************************************************************/

/*************************************************************************
 *
 *	Function: proxy_report
 *
 *	Purpose: Log proxy queue status for debugging purposes
 *
 *	Uses External: first_forwarded
 *
 *************************************************************************/

void 
proxy_report(void)
{
	AUTH_REQ	*qp;
	UINT4		oldest;
	UINT4		clock;
	int		n;

	if (first_forwarded != (AUTH_REQ *)NULL) {
		qp = first_forwarded;
		n = 0;
		clock = (UINT4)time((time_t *)NULL);
		oldest = clock;
		while (qp != (AUTH_REQ *)NULL) {
			n++;
			if (qp->timestamp < oldest) {
				oldest = qp->timestamp;
			}
			qp = qp->next;
		}
		clock = clock - oldest;
		log_err("%d in proxy queue, oldest %d seconds ago\n", n, clock);
	} else {
		log_err("no entries in proxy queue\n");
	}
}
