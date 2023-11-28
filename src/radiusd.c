/*
 * Copyright (C) 1999-2004 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

static char rcsid[] = "$Id: radiusd.c 83 2004-08-28 13:32:47Z flovergine $";


#define __MAIN__
#include        "yard.h"
#include        "global.h"


static AUTH_REQ	*first_request;

/*
 *	
 */

int 
main( int argc,char **argv )
{
  UINT4	then;
  char	argval;
  char	argnum;
  int	i;
  int	t;
  int	pid;
  fd_set	readfds;
  int		status;

  progname = *argv++;
  argc--;

  sockaddr = 0;
  debug_flag = 0;
  debug_mem = 0;
  spawn_flag = 0;
  radius_gdbm = 0;
  accept_zero = 0;
  do_clean = 0;
  max_requests = MAX_REQUESTS;
  max_request_time = MAX_REQUEST_TIME;
  max_proxy_time = MAX_PROXY_TIME;
  radacct_dir = RADACCT_DIR;
  radius_dir = RADIUS_DIR;
  alt_passwd = (char *)NULL;

  signal(SIGHUP, sig_hup);
  signal(SIGINT, sig_fatal);	  /* disable handler when debugging */
  signal(SIGQUIT, sig_fatal);
  signal(SIGILL, sig_fatal);
  signal(SIGTRAP, sig_fatal);
#if defined(SIGABRT)		/* SIGABRT is POSIX.1 */
  signal(SIGABRT, sig_fatal);
#else
  signal(SIGIOT, sig_fatal);	/* SIGIOT is obsolete */
#endif
  signal(SIGFPE, sig_fatal);
  signal(SIGTERM, sig_fatal);
  signal(SIGCHLD, sig_cleanup);
#if defined(SIGWINCH)
  signal(SIGWINCH, sig_hup);
#endif
  signal(SIGUSR1, sig_usr1);
  signal(SIGUSR2, sig_usr2);

  for (i=0; i< RR_MAX; i++) { report[i] = 0; }

  while(argc) {
  	if(**argv != '-') usage();

  	argval = *(*argv + 1);
  	argnum = *(*argv + 2);
  	argc--;
  	argv++;

  	switch(argval) {
  	case 'a':
  		if(argc == 0) usage();
  		radacct_dir = *argv;
  		argc--;
  		argv++;
  		break;

  	case 'b':	/* use gdbm users file */
  		radius_gdbm = 1;
  		break;

        case 'c':
              	do_clean++;
              	break;

  	case 'd':
  		if(argc == 0) usage();
  		radius_dir = *argv;
  		argc--;
  		argv++;
  		break;

  	case 'f':
  		if(argc == 0) usage();
  		alt_passwd = *argv;
  		argc--;
  		argv++;
  		break;

  	case 'h':
  		usage();
  		break;

  	case 'i':
  		if(argc == 0) usage();
  		sockaddr = get_ipaddr(*argv);
  		argc--;
  		argv++;
  		break;

  	case 'l':	/* change logging from syslog */
  		if(argc == 0) usage();
  		radius_log = *argv;
  		argc--;
  		argv++;
  		break;

  	case 'm':	/* debug memory */
  		if (isdigit(argnum)) debug_mem = argnum - '0';
  		else debug_mem++;
  		break;

  	case 'p':	/* set radius port */
  		if(argc == 0) usage();
  		radius_port = (u_short)atoi(*argv);
  		argc--;
  		argv++;
  		break;

  	case 'o':	/* accept all-zero accounting request authenticators */
  		accept_zero = 1;
  		break;

  	case 'q':	/* set max queue size */
  		if(argc == 0) usage();
  		max_requests = (int)atoi(*argv);
  		argc--;
  		argv++;
  		break;

  	case 's':	/* spawing processes mode */
  		spawn_flag = 1;
  		break;

  	case 't':	/* set max time out in seconds */
  		if(argc == 0) usage();
  		max_request_time = (int)atoi(*argv);
  		argc--;
  		argv++;
  		break;

  	case 'v':
  		version();
  		break;

  	case 'w':	/* set proxy time in seconds */
  		if(argc == 0) usage();
  		max_proxy_time = (int)atoi(*argv);
  		argc--;
  		argv++;
  		break;

  	case 'x':
  		if (isdigit(argnum))
  		  debug_flag = argnum - '0';
  		else debug_flag++;
  		break;

  	case 'z':
  		/* debugging: -b -s -x -d . -a ra */
  		radius_gdbm = 1;
  		spawn_flag = 0;
  		debug_flag++;
  		radius_dir = ".";
  		radacct_dir = "ra";
  		break;

#if defined(PAM)
	
	case 'P':
		usepamauth=1;
		break;

	case 'A':
		usepamacct=1;
		break;

#endif

  	default:
  		usage();
  		break;
  	}
  }

  if (debug_flag) {
  	if (radius_log == NULL) {
  		/*
  		 * for backward compatibility
  		 * send messages to users tty
  		 */
  		radius_log = "/dev/tty";
  	} else if (strcmp(radius_log, "syslog") == 0) {
  		/*
  		 * allow user to override backward compatibility
  		 * and send debug to syslog
  		 */
  		radius_log = (char *)NULL;
  	}
  }

  debug("initializing dictionary\n");
  /* Initialize the dictionary */
  if(dict_init() != 0) { rad_exit(-1); }
  dict_dump();

  debug("initializing configuration values\n");
  /* Initialize Configuration Values */
  if(config_init() != 0) { rad_exit(-1); }

  /*
   *	Disconnect from session
   */
  debug("Disconnecting from session\n");
  if(debug_flag == 0) {
  	pid = fork();
  	if(pid < 0) {
  		log_err("system error: could not fork at startup\n");
  		rad_exit(-1);
  	}
  	if(pid > 0) {
  		exit(0);
  	}
  }


  /*
   *	Disconnect from tty
   */
  debug("Disconnecting from tty\n");
  for (t = 32; t >= 3; t--) { close(t); }

  /* Show our stuff */
  log_version();
  if (debug_flag) { log_err("debug mode %d\n",debug_flag); }
  if (debug_mem)  { log_err("memory debug mode %d\n",debug_mem); }

  /* Open RADIUS socket */
  sockfd = open_udpsock(&radius_port,PW_AUTH_UDP_PORT,"radius");

  /* Open Accounting socket */
  radacct_port = radius_port + 1;
  acctfd = open_udpsock(&radacct_port,PW_ACCT_UDP_PORT,"radacct");

  /*
   * Open Proxy Socket.
   * We send to proxy servers from this socket, so replies return to it
   */
  radproxy_port = radius_port + 5;
  radpracct_port = radius_port + 6;
  proxyfd = open_udpsock(&radproxy_port,PW_PROXY_UDP_PORT,"radius-proxy");
  proxyacctfd = open_udpsock(&radpracct_port,PW_PROXYACCT_UDP_PORT,"radacct-proxy");

  if (ipassinit() != 0) { log_err("ipass not in use\n"); }

#ifdef ACTIVCARD
  /* establish aeg session before attending to any user requests */
  if (activcard_init() < 0) { log_err("activcard not in use\n"); }
#endif

  update_clients();
  update_proxy();

#ifdef VPORTS
         vports_flag = vports_init();
         if (vports_flag == 1 && spawn_flag == 1) {
                 spawn_flag = 0;
                 debug("virtual ports disable spawning\n");
         }
#endif /* VPORTS */

  /*
   * If we are able to spawn processes, we will start a child
   * to listen for Accounting-Requests.  If not, we will 
   * listen for them ourself.
   */
  if(spawn_flag) {
  	acct_pid = fork();
  	if(acct_pid < 0) {
  		log_err("could not fork to spawn accounting daemon\n");
  		rad_exit(-1);
  	}
  	if(acct_pid > 0) {
  		close(acctfd);
  		acctfd = -1;
  		close(proxyacctfd);
  		proxyacctfd = -1;
  	}
  	else {
  		close(sockfd);
  		sockfd = -1;
  		close(proxyfd);
  		proxyfd = -1;
  	}
  }


  then = 0;
  /*
   *	Receive user requests
   */
  for(;;) {

  	FD_ZERO(&readfds);
  	if(sockfd >= 0) { FD_SET(sockfd, &readfds); }
  	if(proxyfd >= 0) { FD_SET(proxyfd, &readfds); }
  	if(acctfd >= 0) { FD_SET(acctfd, &readfds); }
  	if(proxyacctfd >= 0) { FD_SET(proxyacctfd, &readfds); }

  	status = select(32, &readfds, NULL, NULL, (struct timeval *)NULL);
  	if(status == -1) {
  		if (errno == EINTR)
  			continue;
  		log_err("exiting after select returned error %d, %s\n",errno,strerror(errno));
  		sig_fatal(101);
  	}

  	now = (UINT4)time((time_t *)NULL);

  	if (now > then) {
  		then = now;
  		if(sockfd != -1) { update_clients(); }
  		update_proxy();
  	}

  	if(proxyfd >=0 && FD_ISSET(proxyfd, &readfds)) {
  		rad_proxy(proxyfd);
  		report[RR_PORT3]++;
  	}
  	if(sockfd >= 0 && FD_ISSET(sockfd, &readfds)) {
  		rad_request(sockfd);
  		report[RR_PORT1]++;
  	}
  	if(proxyacctfd >=0 && FD_ISSET(proxyacctfd, &readfds)) {
  		rad_proxy(proxyacctfd);
  		report[RR_PORT4]++;
  	}
  	if(acctfd >=0 && FD_ISSET(acctfd, &readfds)) {
  		rad_acctreq(acctfd);
  		report[RR_PORT2]++;
  	}
  }
}


/*************************************************************************
  *
  *	Function: open_udpsock
  *
  *	Purpose: open desired UDP socket and return file descripter
  *		 Exit program if socket is unavailable
  *		 place port number used in first argument
  *
  *************************************************************************/

int 
open_udpsock(u_short *port,int defport,char *service)
{

  int		fd;
  int		result;
  struct	servent		*svp;
  struct	sockaddr_in	*sin;
  struct	sockaddr_in	salocal;
  u_short       lport;

  if (*port>5) { 
	lport = htons(*port); 
  } else {
  	svp = getservbyname(service, "udp");
  	if (svp != (struct servent *) NULL) {
  		lport = (u_short) svp->s_port;
  	} else {
  		lport = htons(defport);
  	}
  	*port = ntohs(lport);
  }
  debug("using udp port %d for %s\n", *port,service);

  fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
  	log_err("%s socket error %s\n", service, strerror(errno));
  	rad_exit(-1);
  }

  sin = (struct sockaddr_in *) & salocal;
  memset ((char *) sin, '\0', sizeof (salocal));
  sin->sin_family = AF_INET;
  if (sockaddr != 0) {
  	sin->sin_addr.s_addr = htonl(sockaddr);
  } else {
  	sin->sin_addr.s_addr = INADDR_ANY;
  }
  sin->sin_port = lport;

  result = bind (fd, (struct sockaddr *)&salocal, sizeof (*sin));
  if (result < 0) {
  	log_err("%s bind error %s\n", service, strerror(errno));
  	rad_exit(-1);
  }

  return fd;
}

/*************************************************************************
  *
  *	Function: send_packet
  *
  *	Purpose: Send RADIUS UDP packet
  *
  *************************************************************************/

void 
send_packet(int fd, UINT4 ipaddr, u_short port, char * buffer, int length)
{
  AUTH_HDR		*auth;
  struct	sockaddr_in	saremote;
  struct	sockaddr_in	*sin;

  sin = (struct sockaddr_in *) &saremote;
         memset ((char *) sin, '\0', sizeof (saremote));
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = htonl(ipaddr);
  sin->sin_port = htons(port);

  auth = (AUTH_HDR *)buffer;
  debug("message sent to %s/%d.%d code=%d, length=%d\n",
  	ipaddr2strp(ipaddr), port, auth->id, auth->code, length);

  if (debug_flag > 1) {
  	hexdump((u_char*)buffer,length);
  }

  /* Send it */
  sendto(fd, buffer, (int)length, (int)0,
  	(struct sockaddr *)&saremote, sizeof(struct sockaddr_in));
}


/*************************************************************************
  *
  *	Function: rad_request
  *
  *	Purpose: Receive UDP client requests
  *
  *************************************************************************/

void 
rad_request(int fd)
{
  AUTH_REQ		*authreq;
  UINT4			addr;
  char			secret[20];
  char			hostnm[128];
  int			result;
  size_t			salen;
  struct	sockaddr_in	*sin;
  u_short			port;

#if defined(SMARTCARD)
  int			child_pid;
  AUTH_HDR		*auth;
  AUTH_REQ		*curreq;
  VALUE_PAIR		*pair;
  key_t			msg_key;
  int			msg_id;
  char			*buf;
#endif

  salen = sizeof (rad_saremote);
  sin = (struct sockaddr_in *) & rad_saremote;
  result = recvfrom (fd, (char *) recv_buffer,
  	(int) sizeof(recv_buffer),
  	(int) 0, (struct sockaddr *)&rad_saremote, &salen);

  addr = ntohl(sin->sin_addr.s_addr);
  port = ntohs(sin->sin_port);

  if (result < AUTH_HDR_LEN) {
  	log_err("rad_request: runt packet of %d bytes from %s.%d\n",
  		result,ipaddr2strp(addr),port);
  	return;
  }

         /*
          * Validate the requesting IP address -
          * Not secure, but worth the check for accidental requests
          * find_client() logs an error message if needed
          */
         if(find_client(addr, secret, sizeof(secret), hostnm, sizeof(hostnm)) != 0) {
                 log_err("rad_request: request from unknown" 
  	        " client %s.%d ignored\n",ipaddr2strp(addr),port);
                 return;
         }

  authreq = radrecv( addr, port, secret, recv_buffer, result );

  if (authreq == (AUTH_REQ *)NULL) {	/* malformed packet */
  	return;
  }

  /* handle_proxy places the user name in authreq->name,
   * and forwards request to a proxy server if necessary
   */
  if (handle_proxy(authreq) != 0) {	/* error or forwarded */
  	if (authreq->flags & REQ_FREE) {
  		reqfree(authreq,"rad_request");
  	}
  	/* otherwise authreq will be freed when proxy response is seen */
  	return;
  }

#if defined(SMARTCARD)

  if (spawn_flag == 0) {
  	radrespond(authreq, fd);
  	return;
  }
  /*
   * We need to see if this is a challenge response
   */
  child_pid = -1;

  if ((pair = get_attribute(authreq->request,PW_STATE)) != (VALUE_PAIR *)NULL) {
  	buf = pair->strvalue;
  	debug("rad_request: PW_STATE<%s>\n", buf);
#ifdef SECURID
  	/*
  	 * the format for SECURID state string is
  	 *
  	 *	SECURID_xxxx=n
  	 *
  	 * xxxx is commands: next or npin or wait
  	 * n is the child pid
  	 */
  	if (strncmp(buf, "SECURID_", 8) == 0) {
  		child_pid = (int)atoi(&buf[13]);
  	}
#endif /* SECURID */
#ifdef ACTIVCARD
  	/*
  	 * the format for ACTIVCARD state string is
  	 *
  	 *      ACTIVCARD_999...=n
  	 *
  	 * 999... is the challenge returned by ActivEngine
  	 * n is the child pid
  	 */
  	if (strncmp(buf, "ACTIVCARD_", 10) == 0) {
  		child_pid = (int)atoi(strchr(buf, (int)'=')+1);
  	}
#endif /* ACTIVCARD */
  }

  if (child_pid == -1) {
  	radrespond(authreq, fd);
  	return;
  }
  debug("rad_request: challenge_response from %s for child %d\n",
  		req2strp(authreq), child_pid);

  curreq = first_request;
  while(curreq != (AUTH_REQ *)NULL) {
  	if (curreq->child_pid == child_pid) {
  		break;
  	}
  	curreq = curreq->next;
  }
  if (curreq == (AUTH_REQ *)NULL) {
  	log_err("rad_request: child %d not found\n", child_pid);
  	reqfree(authreq,"rad_request");
  	return;
  }
  if (curreq->ipaddr != addr) {
  	log_err("rad_request: error: mismatched IP addresses in request %x != %x for ID %d %d\n",
  		curreq->ipaddr, addr, curreq->id, auth->id);
  	reqfree(authreq,"rad_request");
  	return;
  }
  if (curreq->udp_port != port) {
  	log_err("rad_request: error: mismatched source ports in request %d != %d for ID %d %d\n",
  		curreq->udp_port, port, curreq->id, auth->id);
  	reqfree(authreq,"rad_request");
  	return;
  }
  if (curreq->id == authreq->id) {
  	/* This is a duplicate request - just drop it */
  	log_err("rad_request: dropped duplicate ID %d\n", authreq->id);
  	reqfree(authreq,"rad_request");
  	return;
  }

  msg_key = RADIUS_MSG_KEY(child_pid);
  if ((msg_id = msgget(msg_key, 0600)) == -1) {
  	log_err("rad_request: error: msgget for key %x for id %d returned error %d\n",msg_key, msg_id, errno);
  	reqfree(authreq,"rad_request");
  	return;
  }
  if (msgsnd(msg_id, recv_buffer, result, IPC_NOWAIT) == -1) {
  	log_err("rad_request: error: msgsnd for key %x for id %d returned error %d\n", msg_key, msg_id, errno);
  	reqfree(authreq,"rad_request");
  	return;
  }
  curreq->id = authreq->id;

#else /* not SMARTCARD */

  radrespond(authreq, fd);

#endif /* not SMARTCARD */

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
radrecv(UINT4	host,u_short udp_port,char* secret,u_char* buffer,int length)
{
  u_char	*ptr;
  AUTH_HDR	*auth;
  int		totallen;
  int		attribute;
  int		attrlen;
  int		vendor;
  int		vsa;
  int		vsattrlen;
  DICT_ATTR	*attr;
  UINT4		lvalue;
  VALUE_PAIR	*first_pair;
  VALUE_PAIR	*prev;
  VALUE_PAIR	*pair;
  AUTH_REQ	*authreq;

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
  	hexdump((u_char*)buffer,totallen);
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
  		snprintf(pair->name,(size_t)ID_LENGTH,"Unknown-%d",attribute);
  		pair->attribute = attribute;
  		pair->type = PW_TYPE_STRING;
  	} else {
  		strncpy(pair->name, attr->name, VALUE_PAIR_NAME_LEN-1);
		pair->name[VALUE_PAIR_NAME_LEN-1]='\0';
  		pair->attribute = attr->value;
  		pair->type = attr->type;
  	}

  	if (pair->attribute == PW_VENDOR) {	
  		if (attrlen < 6) {
  			pair->vendor = 0;
  			pair->vsattribute = 0;
  			pair->type = PW_TYPE_STRING;
  		} else {
  			memcpy(&vendor, ptr, sizeof(int));
  			vendor = ntohl(vendor);
  			ptr += 4;
			vsattrlen = *ptr;
			if ( vendor == VENDOR_USROBOTICS ) {
			  if (attrlen < 8) { 
  				pair->vendor = 0;
  				pair->vsattribute = 0;
  				pair->type = PW_TYPE_STRING;
			  }
			  else {
  			  	memcpy(&vsa, ptr, sizeof(int));
			  	vsa = ntohl(vsa);
  			  	ptr += 4;
  			  	attrlen -= 8;
			  	length -= 8;
			  }
			}
			else
			  {
  			  vsa = *ptr;
  			  ptr += 2;
  			  attrlen -= 6;
  			  length -= 6;
			  }
  			pair->vendor = vendor;
  			pair->vsattribute = vsa;
  			if((attr = dict_vsattrget(vendor,vsa)) != NULL) {
  				strncpy(pair->name, attr->name, VALUE_PAIR_NAME_LEN-1);
				pair->name[VALUE_PAIR_NAME_LEN-1]='\0';
  				pair->type = attr->type;
  			} else {
				log_debug("Attribute %d for vendor %d not found\n",vsa,vendor);
  				snprintf(pair->name,(size_t)ID_LENGTH,"Vendor-Specific-%d-%d",vendor,vsa);
  				pair->type = PW_TYPE_STRING;
  			}
  		}
  	}

  	switch(pair->type) {

#if defined(ASCEND_BINARY)
	case PW_TYPE_ABINARY:
#endif
  	case PW_TYPE_STRING:
  		memcpy(pair->strvalue, ptr, attrlen);
  		pair->strvalue[attrlen] = '\0';
  		pair->lvalue = attrlen;
  		debug_pair(pair);
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
  		debug_pair(pair);
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

/*************************************************************************
  *
  *	Function: radrespond
  *
  *	Purpose: Respond to supported requests
  *
  *		 PW_AUTHENTICATION_REQUEST - Authentication request from
  *				a client network access server.
  *
  *************************************************************************/

void 
radrespond(AUTH_REQ *authreq,int activefd)
{
         if (authreq == (AUTH_REQ *)NULL) {
                 return;
         }

  switch(authreq->code) {

  case PW_AUTHENTICATION_REQUEST:
  	if(spawn_flag) {
  		rad_spawn_child(authreq, activefd);
  	}
  	else {
  		rad_authenticate(authreq, activefd);
  	}
  	break;
  
  default:
  	log_err("unknown request type %d from %s ignored\n",
  		authreq->code, req2strp(authreq));
  	reqfree(authreq,"radrespond");
  	break;
  }
}

/*************************************************************************
  *
  *	Function: rad_spawn_child
  *
  *	Purpose: Spawns child processes to perform password authentication
  *		 and respond to RADIUS clients.  This functions also
  *		 cleans up complete child requests, and verifies that there
  *		 is only one process responding to each request (duplicate
  *		 requests are filtered out.
  *
  *************************************************************************/

int rad_spawned_child_pid;

void 
rad_spawn_child(AUTH_REQ *authreq,int activefd)
{
  AUTH_REQ	*curreq;
  AUTH_REQ	*prevreq;
  UINT4		curtime;
  int		request_count;
  int		child_pid;
#ifdef SMARTCARD
  key_t		msg_key;
  int		msg_id;
#endif

  curtime = authreq->timestamp;
  request_count = 0;
  curreq = first_request;
  prevreq = (AUTH_REQ *)NULL;

  while(curreq != (AUTH_REQ *)NULL) {
  	if(curreq->child_pid == -1 &&
  			curreq->timestamp + CLEANUP_DELAY <= curtime) {
  		/* Request completed, delete it */
  		if(prevreq == (AUTH_REQ *)NULL) {
  			first_request = curreq->next;
  			reqfree(curreq,"rad_spawn_child");
  			curreq = first_request;
  		}
  		else {
  			prevreq->next = curreq->next;
  			reqfree(curreq,"rad_spawn_child");
  			curreq = prevreq->next;
  		}
  	}
  	else if(curreq->ipaddr == authreq->ipaddr &&
  			curreq->udp_port == authreq->udp_port &&
  			curreq->id == authreq->id) {
  		/* This is a duplicate request - just drop it */
  		log_err("dropping duplicate request from %s\n",
  			req2strp(authreq));
  		reqfree(authreq,"rad_spawn_child");
  		return;
  	}
  	else {
  		if(curreq->timestamp + max_request_time <= curtime &&
  					curreq->child_pid != -1) {
  			/* This request seems to have hung - kill it */
  			child_pid = curreq->child_pid;
  			log_err("sending SIGHUP to unresponsive child process %d\n",
  							child_pid);
  			curreq->child_pid = -1;
  			kill(child_pid, SIGHUP);
#ifdef SMARTCARD
  			/*
  			 * delete childs message queue
  			 */
  			msg_key = RADIUS_MSG_KEY(child_pid);
  			if ((msg_id = msgget(msg_key, 0600)) != -1) {
  				msgctl(msg_id, IPC_RMID, 0);
  			}
#endif /* SMARTCARD */
  		}
  		prevreq = curreq;
  		curreq = curreq->next;
  		request_count++;
  	}
  }

  /* This is a new request */
  if(request_count > max_requests) {
  	request_count--;
  	log_err("dropping request from %s; %d requests already in queue\n",
  		req2strp(authreq), request_count);
  	reqfree(authreq,"rad_spawn_child");
  	return;
  }

  /* Add this request to the list */
  /* authreq->timestamp already set by radrecv */
  authreq->next = (AUTH_REQ *)NULL;
  authreq->child_pid = -1;

  if(prevreq == (AUTH_REQ *)NULL) {
  	first_request = authreq;
  }
  else {
  	prevreq->next = authreq;
  }

  /* fork our child */
  cleanup_pid = -1;
  rad_spawned_child_pid = fork();
  if(rad_spawned_child_pid < 0) {
  	log_err("system error: fork failed with error %d for request from %s\n",
  		errno,req2strp(authreq));
  	reqfree(authreq,"rad_spawn_child");
  	return;
  }
  if(rad_spawned_child_pid == 0) {
  	/* This is the child, it should go ahead and respond */
  	child_authenticate(authreq, activefd);
  	exit(0);
  }

  /* Register the Child */
  authreq->child_pid = rad_spawned_child_pid;

  /*
   * If cleanup_pid is not -1, then we received a SIGCHLD between
   * the time we forked and the time we got here, so clean up after it
   */
  if(cleanup_pid != -1) {
  	clean_child(cleanup_pid);
  	cleanup_pid = -1;
  }
}

void 
clean_child(int pid)
{
  AUTH_REQ	*curreq;

  curreq = first_request;
  while(curreq != (AUTH_REQ *)NULL) {
  	if(curreq->child_pid == pid) {
  		curreq->child_pid = -1;
  		curreq->timestamp = (UINT4)time((time_t *)NULL);
  		return;
  	}
  	curreq = curreq->next;
  }
  cleanup_pid = (int)pid;
  return;
}

void 
sig_cleanup(int sig)
{
  int		status;
         pid_t		pid;
  
         for (;;) {
  	pid = waitpid((pid_t)-1,&status,WNOHANG);
  	signal(SIGCHLD, sig_cleanup);
                 if (pid <= 0)
                         return;

#if defined (aix)
  	kill(pid, SIGKILL);
#endif

  	if(pid == acct_pid) {
  		sig_fatal(100);
  	}
  	clean_child(pid);
         }
}


/*************************************************************************
  *
  *	Function: child_authenticate
  *
  *	Purpose: Process and reply to an authentication request
  *
  *************************************************************************/

void 
child_authenticate(AUTH_REQ *authreq,int activefd)
{
#ifdef SMARTCARD
  key_t			msg_key;
  int			msg_id;
  int			length;
  struct	sockaddr_in	*sin;

  msg_key = RADIUS_MSG_KEY(getpid());
#endif /* SMARTCARD */
  for (;;) {
  	if (rad_authenticate(authreq, activefd) == 0) {
  		break;
  	}
#ifdef SMARTCARD
  	if ((msg_id = msgget(msg_key, IPC_CREAT | 0600)) == -1) {
  		log_err("child_authenticate: msgget for key %x for id %d returned error: %s\n", msg_key, msg_id, strerror(errno));
  		break;
  	}
  	if ((length = msgrcv(msg_id, recv_buffer, 
  			sizeof recv_buffer - sizeof(long),
  			0, 0)) == -1) {
  		log_err("child_authenticate: msgrcv for msgid %d returned error: %s\n", msg_id, strerror(errno));
  		break;
  	}
  	if (msgctl(msg_id, IPC_RMID, 0) == -1) {
  		log_err("child_authenticate: msgctl for msgid %d returned error: %s\n", msg_id, strerror(errno));
  	}
  	sin = (struct sockaddr_in *) &rad_saremote;
  	authreq = radrecv(
  		ntohl(sin->sin_addr.s_addr),
  		ntohs(sin->sin_port),
  		authreq->secret, recv_buffer, length);
#else /* not SMARTCARD */
  	break;
#endif /* not SMARTCARD */
  }
}

/*************************************************************************
  *
  *	Function: rad_authenticate
  *
  *	Purpose: Process and reply to an authentication request
  *
  *************************************************************************/

int 
rad_authenticate(AUTH_REQ *authreq,int activefd)
{
  USER_FILE	user_desc;
  VALUE_PAIR	*attr;
  VALUE_PAIR	*auth_item;
  VALUE_PAIR	*callpair;
  VALUE_PAIR	*challenge;
  VALUE_PAIR	*check_item;
  VALUE_PAIR	*password_item;
  VALUE_PAIR	*user_check;
  VALUE_PAIR	*user_reply;
  char		auth_name[AUTH_STRING_LEN + 2];
  char		callfrom[ID_LENGTH];
  char		pw_digest[16];
  char		string[AUTH_STRING_LEN + 20 + 2];
  char		umsg[AUTH_STRING_LEN + 2];
  char		*encpw;
  char		*ptr;
  char		*user_msg;
  char		*pass;
  int		authtype;
  int		chlen;
  int		result;
  int		retval;
  int		speed;

  /* The username was placed in authreq->name by handle_proxy */
  if(strlen(authreq->name) <= (size_t)0) {
  	log_err("auth: access-request from %s ignored; no user name\n",
  		req2strp(authreq));
  	reqfree(authreq,"rad_authenticate");
  	return(0);
  }

#ifdef VPORTS
         if (vports_flag == 1) {
                 switch(vp_check_req(authreq)) {
  	case VP_RET_REJECT:
  		send_reject(authreq, (char *)NULL, activefd);
  		reqfree(authreq,"rad_authenticate");
  		return(0);
  		break;

  	case VP_RET_ACCEPT:
  		send_accept(authreq, (VALUE_PAIR *)NULL, (char *)NULL, activefd);
  		reqfree(authreq,"rad_authenticate");
  		return(0);
  		break;

  	case VP_RET_IGNORE:
  	default:
  		break;
  }
}
#endif /* VPORTS */

  /* calculate the MD5 Password Digest */
  calc_digest((u_char*)pw_digest, authreq, (u_char*)authreq->secret);

  /*
   * If the request is processing a menu, service it here.
   */
  if((attr = get_attribute(authreq->request, PW_STATE)) !=
  	(VALUE_PAIR *)NULL && strncmp(attr->strvalue, "MENU=", 5) == 0){
  	process_menu(authreq, activefd, pw_digest);
  	return(0);
  }

  callpair = get_attribute(authreq->request, PW_CALLING);
  if (callpair == (VALUE_PAIR *)NULL || callpair->lvalue > 20) {
  	callfrom[0] = '\0';
  } else {
  	snprintf(callfrom,(size_t)ID_LENGTH," at %s",callpair->strvalue);
  }

  /*
   * Open the user table
   */
  user_desc = user_open();
  if(user_desc.gdbm == NULL && user_desc.flat == NULL) {
  	reqfree(authreq,"rad_authenticate");
  	return(0);
  }

  for (;;) {
  	/* Get the user from the database */
  	if ((result = user_find(authreq->name,
  				auth_name,
  				&user_check,
  				&user_reply,
  				user_desc)) != 0) {
  		log_err("auth: access-request from %s denied for unknown user \"%s\"%s\n",
  			req2strp(authreq), authreq->name, callfrom);
  		send_reject(authreq, (char *)NULL, activefd);
  		reqfree(authreq,"rad_authenticate");
  		user_close(user_desc);
  		return(0);
  	}

  	/* Validate the user */

  	/* Look for matching check items */
  	password_item = (VALUE_PAIR *)NULL;
  	authtype = PW_AUTHTYPE_NONE;
  	user_msg = (char *)NULL;
  	check_item = user_check;

	result = allow_user(authreq->name);
	if (result != 0) {
	  result = deny_user(authreq->name);
	  if (result != 0) {
		log_err("auth: denied connection for '%s' (listed in '%s/%s')",
			authreq->name,radius_dir,
			(result==-2)?"denyusers":"stopusers");
	  }
	}

  	while(result == 0 && check_item != (VALUE_PAIR *)NULL) {

  		auth_item = get_attribute(authreq->request,
  						check_item->attribute);
  
  		switch(check_item->attribute) {

  		case PW_PREFIX:
  		case PW_SUFFIX:
  			break;

  		case PW_EXPIRATION:
  			/*
  			 * Check expiration date if we are
  			 * doing password aging.
  			 */
#if defined(SHADOW_EXPIRATION)
 			if (!strncasecmp(check_item->strvalue,"SHADOW", 6))
                        	retval = shadow_expired(authreq->name);
                     	else
#endif
  				retval = pw_expired(check_item->lvalue);
  			if(retval < 0) {
  				result = -2;
  				snprintf(umsg,sizeof(umsg),"Password Has Expired\r\n");
  				user_msg = umsg;
                       		log_err("auth: Password expired for '%s'\n",authreq->name);
  			} else {
  				if(retval > 0) {
  					snprintf(umsg,(size_t)(AUTH_STRING_LEN)+2,"Password Will Expire in %d Days\r\n",
  					  retval);
  					user_msg = umsg;
                            		log_err("auth: Password for '%s' will expire in %d days\n", retval);
  				}
  			}
  			break;
  
  		case PW_PASSWORD:
  			if(strcmp(check_item->strvalue, "UNIX") == 0) {
  				authtype = PW_AUTHTYPE_UNIX;
  			}
  			else {
  				authtype = PW_AUTHTYPE_LOCAL;
  				password_item = check_item;
  			}
  			break;

  		case PW_AUTHTYPE:
  			authtype = check_item->lvalue;
  			break;
  
  		case PW_GROUP:
  			if(!unix_group(auth_name, check_item->strvalue)) {
  				result = -1;
  			}
  			break;

  		case PW_CRYPT_PASSWORD:
  			authtype = PW_AUTHTYPE_CRYPT;
  			password_item = check_item;
  			break;
  
/** FIXME 

	This is a problem for Yard.
	Connect-Info or Connect-Info-Old are often not used by
	non-Livingston boxes, so this check item is unuseful.
	Ascend and USR boxes uses their VSAs to register connection
	speed. Cisco too. Not RFC compliant at this moment.

**/
		case PW_CONNECT_RATE:
                      	auth_item = get_attribute(authreq->request,
  					      PW_CONNECT_INFO);
         	        if (auth_item != (VALUE_PAIR *)NULL) {
                 	       	if ( sscanf(auth_item->strvalue,"%d/%*d%*s",&speed)==1|| (speed=atoi(auth_item->strvalue)) ) 
				  if ( speed>check_item->lvalue ) result=-1;
                     	} else {
                        	auth_item = get_attribute(authreq->request,
                                                   PW_CONNECT_INFO_OLD);
                         	if (auth_item != (VALUE_PAIR *)NULL) {
                            		speed = atoi(auth_item->strvalue);
                            		if (speed > check_item->lvalue) result=-1;
                         	}
                     	   }
                     	   break;
#if defined(PAM) && defined(HAVE_LIBPAM)
                case PW_PAM_AUTH:
                	pam_auth = check_item->strvalue;
                     	break;
#endif
        	case PW_LOGINS:
                	retval = check_logins(auth_name, check_item->lvalue);
                     	if (retval != 0) {
                       		result = -2;
                       		snprintf(umsg,(size_t)(AUTH_STRING_LEN+2),"Too many logins - max %d\r\n",(unsigned int)check_item->lvalue);
                       		user_msg = umsg;
                       		log_err("Too many logins for '%s' (max %d)\n",authreq->name,(unsigned int)check_item->lvalue);
                       	}
                       	break;

                case PW_MAXDTIME:
                     retval = check_maxtime(auth_name,check_item->lvalue,DAY_LIMIT);
                     if (retval != 0) {
                         result = -2;
                         snprintf(umsg,sizeof(umsg),"Total on-line daily time expired (%d hours)\r\n",(unsigned int)check_item->lvalue);
                         user_msg = umsg;
                         log_err("Total on-line daily time expired (%d hours) for '%s'\n", (unsigned int)check_item->lvalue, authreq->name);
                     }
                     break;

                 case PW_MAXMTIME:
                     retval = check_maxtime(auth_name,check_item->lvalue,MONTH_LIMIT);
                     if (retval != 0) {
                         result = -2;
                         snprintf(umsg,sizeof(umsg),"Total on-line time expired (%d hours)\r\n", (unsigned int)check_item->lvalue);
                         user_msg = umsg;
                         log_err("Total on-line time expired (%d hours) for '%s'\n", (unsigned int)check_item->lvalue, authreq->name);
                     }
                     break;

                 case PW_MAXYTIME:
                     retval = check_maxtime(auth_name,check_item->lvalue,YEAR_LIMIT);
                     if (retval != 0) {
                         result = -2;
                         snprintf(umsg,sizeof(umsg),"Total on-line yearly time expired (%d hours)\r\n", (unsigned int)check_item->lvalue);
                         user_msg = umsg;
                         log_err("Total on-line yearly time expired (%d hours) for '%s'\n", (unsigned int)check_item->lvalue, authreq->name);
                     }
                     break;

                 case PW_TIME:
                     retval = allowed_time(check_item->strvalue);
                     if (retval != 0) {
                         result = -2;
                         snprintf(umsg,sizeof(umsg),"Not allowed to login at this time\r\n");
                         user_msg = umsg;
                         log_err( "Not allowed to login at this time for '%s'\n",authreq->name );
                     }
                     break;

                 case PW_MAXDTRAFFIC:
                     retval = check_maxtraffic(auth_name,check_item->lvalue,DAY_LIMIT);
                     if (retval != 0) {
                         result = -2;
                         snprintf(umsg,sizeof(umsg),"Maximum allowed daily traffic size reached (%d KB)\r\n",(unsigned int)check_item->lvalue);
                         user_msg=umsg;
                         log_err("Maximum allowed daily traffic size reached (%dKB) for '%s'\r\n", (unsigned int)check_item->lvalue, authreq->name);
                     }
                     break;

                 case PW_MAXMTRAFFIC:
                     retval = check_maxtraffic(auth_name,check_item->lvalue,MONTH_LIMIT);
                     if (retval != 0) {
                         result = -2;
                         snprintf(umsg,sizeof(umsg),"Maximum allowed monthly traffic size reached (%d KB)\r\n", (unsigned int)check_item->lvalue);
                         user_msg=umsg;
                         log_err("Maximum allowed monthly traffic size reached (%d KB) for '%s'\r\n", (unsigned int)check_item->lvalue, authreq->name);
                     }
                     break;

                 case PW_MAXYTRAFFIC:
                     retval = check_maxtraffic(auth_name,check_item->lvalue,YEAR_LIMIT);
                     if (retval != 0) {
                         result = -2;
                         snprintf(umsg,sizeof(umsg),"Maximum allowed yearly traffic size reached (%d KB)\r\n", (unsigned int)check_item->lvalue);
                         user_msg=umsg;
                         log_err("Maximum allowed yearly traffic size reached (%d KB) for '%s'\r\n", (unsigned int)check_item->lvalue, authreq->name);
                     }
                     break;


  		default:
  			if(auth_item == (VALUE_PAIR *)NULL) {
  				result = -1;
  				break;
  			}

  			switch(check_item->type) {

  			case PW_TYPE_STRING:
  				if(strcmp(check_item->strvalue,
  					  auth_item->strvalue) != 0) {
  					result = -1;
  				}
  				break;

  			case PW_TYPE_INTEGER:
  			case PW_TYPE_IPADDR:
  				if(check_item->lvalue
  						!= auth_item->lvalue) {
  					result = -1;
  				}
  				break;

  			default:
  				result = -1;
  				break;
  			}
  			break;
  		}
  		check_item = check_item->next;
  	}
  	if (result != -1) {
  		break;
  	}
  	pairfree(user_check,"rad_authenticate");
  	pairfree(user_reply,"rad_authenticate");
  }
  user_close(user_desc);

  /*
   * At this point we have validated all normal comparisons
   * for the user.  All that is left is the actual authentication.
   * Authentication will be done based on the authentication type
   * previously specified.
   */

  if(result == 0) {

  	/*
  	 * Decrypt the password in the request.
  	 */
  	pass = decrypt_password(authreq,authreq->secret);
  	if (pass != (char *)NULL) {
  		strncpy(string,pass,AUTH_STRING_LEN);
  		string[AUTH_STRING_LEN] = '\0'; /* always null-term */
  	}
  	else {
  		string[0] = '\0';
  	}

  	switch(authtype) {

  	case PW_AUTHTYPE_LOCAL:
  		/*
  		 * The local authentication type supports normal
  		 * password comparison and the Three-Way CHAP.
  		 */
  		if (password_item == (VALUE_PAIR *)NULL) {
  			log_err("Warning: entry for user \"%s\" is missing Password check item\n",authreq->name);
  			result = -1;
  		}
  		/*
  		 * Check to see if we have a CHAP password.
  		 */
  		else if ((auth_item = get_attribute(authreq->request,
  			PW_CHAP_PASSWORD)) != (VALUE_PAIR *)NULL) {

  			/* Use MD5 to verify */
  			ptr = string;
  			*ptr++ = *auth_item->strvalue;
  			strcpy(ptr, password_item->strvalue);
  			ptr += strlen(password_item->strvalue);
  			if ((challenge = get_attribute(authreq->request,
  				PW_CHAP_CHALLENGE)) != (VALUE_PAIR *)NULL) {
  				chlen = challenge->lvalue;
  				memcpy(ptr, challenge->strvalue, chlen);
  			} else {
  				chlen = AUTH_VECTOR_LEN;
  				memcpy(ptr, authreq->vector, chlen);
  			}
  			md5_calc(pw_digest, string, 1 + chlen +
  				strlen(password_item->strvalue));
  			/* Compare them */
  			if(memcmp(pw_digest, auth_item->strvalue + 1,
  					CHAP_VALUE_LENGTH) != 0) {
  				result = -1;
  			} else {
  				result = 0;
  			}
  		}
  		else if (strcmp(password_item->strvalue, string) == 0) {
  			result = 0;
  		}
  		else {
  			result = -1;
  		}
  		break;

  	case PW_AUTHTYPE_UNIX:
  		if(unix_pass(auth_name, string, callfrom) != 0) {
  			result = -1;
  		}
  		break;

#ifdef SECURID
  	case PW_AUTHTYPE_SECURID:
  		if(pass != (char *)NULL) {
  			pairfree(user_check,"rad_authenticate");
  			return( securid(auth_name, string,
  				authreq, user_reply, activefd) );
  		}
  		else {
  			result = -1;
  		}
  		break;
#endif /* SECURID */
  	case PW_AUTHTYPE_CRYPT:
  		/* password is stored encrypted in string */
  		if(password_item == (VALUE_PAIR *)NULL) {
  			if(string[0] != '\0') {
  				result = -1;
  			}
  		}
  		else if (pass != NULL) {
  			encpw = (char*)crypt(string,password_item->strvalue);
  			if(strcmp(encpw,password_item->strvalue) != 0) {
  				result = -1;
  			}
  		}
  		else {
  			result = -1;
  		}
  		break;
  	case PW_AUTHTYPE_REJECT:
  		result = -1;
  		break;
#if defined(PAM) && defined(HAVE_LIBPAM)
        case PW_AUTHTYPE_PAM:
		if (usepamauth) {
                     	if (unix_pam(auth_name, string, pam_auth) != 0) {
                       		result = -1;
                       		user_msg = (char *)NULL;
                    	}
		}
		else {
			log_err("PAM auth not enabled. Please re-run daemon with the correct argument");
                       	user_msg = (char *)NULL;
			result=-1;
		}
                break;
#endif
#ifdef ACTIVCARD
  	case PW_AUTHTYPE_ACTIVCARD:
  		if (pass != (char *)NULL) {
  		      pairfree(user_check,"rad_authenticate");
  			/* activcard calls send_*() as needed */
  		      return ( activcard_auth(auth_name, string,
  			      authreq, user_reply, activefd) );
  		}
  		else {
  		      result = -1;
  		}
  		break;
#endif /* ACTIVCARD */
  	case PW_AUTHTYPE_NONE:
  		/* No Password or Auth-Type found in check-items */
  		debug("entry for user \"%s\" has no Password or Auth-Type check-item\n",authreq->name);
  		result = 0;
  		break;

  	default:
  		log_err("Warning: entry for user \"%s\" has unknown Auth-Type = %d\n",authreq->name, authtype);
  		result = -1;
  		break;
  	}
  }

  if(result != 0) {
  	send_reject(authreq, user_msg, activefd);
  }
  else {
  	send_accept(authreq, user_reply, user_msg, activefd);
  }

  reqfree(authreq,"rad_authenticate");
  pairfree(user_check,"rad_authenticate");
  pairfree(user_reply,"rad_authenticate");
  return(0);
}

/*************************************************************************
  *
  *	Function: send_reject
  *
  *	Purpose: Reply to the request with a REJECT.  Also attach
  *		 any user message provided.
  *
  *************************************************************************/

void 
send_reject(AUTH_REQ *authreq,char *msg,int activefd)
{
  u_char			code;
  int			total_length;

  code = PW_AUTHENTICATION_REJECT;
  report[RR_REJECT]++;

  debug("sending reject to %s\n", req2strp(authreq));
  total_length = build_packet(authreq,(VALUE_PAIR *)NULL,msg,code,
                              FW_REPLY,send_buffer,sizeof(send_buffer));

  /* Send it to the user */
         send_packet(activefd, authreq->ipaddr, authreq->udp_port,
  		(u_char*)send_buffer, total_length);
}

/*************************************************************************
  *
  *	Function: send_challenge
  *
  *	Purpose: Reply to the request with a CHALLENGE.  Also attach
  *		 any user message provided and a state value.
  *
  *************************************************************************/

void 
send_challenge(AUTH_REQ *authreq,char *msg,char *state,int activefd)
{
  VALUE_PAIR *reply;
  int len;
  int total_length;

  report[RR_CHALLENGE]++;

  if((state != (char *)NULL) && ((len=strlen(state)) > (size_t)0)) {
  	reply = pairalloc("send_challenge");
  	memcpy(reply->name,"State",5);
  	reply->attribute = PW_STATE;
  	reply->type = PW_TYPE_STRING;
  	if (len > AUTH_STRING_LEN) {
  		len = AUTH_STRING_LEN;
  	}
  	reply->lvalue = len;
  	memcpy(reply->strvalue,state,len);
  } else {
  	reply = (VALUE_PAIR *)NULL;
  }

  debug("sending challenge to %s\n", req2strp(authreq));

  total_length = build_packet(authreq,reply,msg,PW_ACCESS_CHALLENGE,FW_REPLY,send_buffer,sizeof(send_buffer));

         send_packet(activefd,authreq->ipaddr,authreq->udp_port,send_buffer,total_length); 

}

/*************************************************************************
  *
  *	Function: send_accept
  *
  *	Purpose: Reply to the request with an ACKNOWLEDGE.  Also attach
  *		 reply attribute value pairs and any user message provided.
  *
  *************************************************************************/

void 
send_accept(AUTH_REQ *authreq,VALUE_PAIR *reply,char *msg,int activefd)
{
  VALUE_PAIR		*menu_attr;
  char			state_value[120];
  int			total_length;

  /* Check to see if the response is a menu */
  if((menu_attr = get_attribute(reply, PW_MENU)) != (VALUE_PAIR *)NULL) {
  	msg = get_menu(menu_attr->strvalue);
  	snprintf(state_value,sizeof(state_value),"MENU=%s", menu_attr->strvalue);
  	send_challenge(authreq, msg, state_value, activefd);
  	return;
  }

  report[RR_ACCEPT]++;

  debug("sending accept to %s\n", req2strp(authreq));

  total_length = build_packet(authreq,reply,msg,PW_AUTHENTICATION_ACK,FW_REPLY,send_buffer,sizeof(send_buffer));

  /* Send it to the user */
         send_packet(activefd, authreq->ipaddr, authreq->udp_port,
  		(u_char*)send_buffer, total_length);

}

/*************************************************************************
  *
  *	Function: build_packet
  *
  *	Purpose: called by routines to build RADIUS packet
  *
  *	forward = 0     FW_REPLY	replying to client
  *		  1     FW_SERVER	forwarding request to remote server
  *		  2	FW_CLIENT	forwarding response to client
  *
  *************************************************************************/

int 
build_packet(AUTH_REQ*authreq,VALUE_PAIR*reply,char*msg,u_char code,int forward,u_char*buffer,size_t buflen )
{
  AUTH_HDR		*auth;
  VALUE_PAIR		*item;
  u_short		total_length;
  u_char		*ptr;
  u_char		*lptr;
  int			len;
  UINT4			lvalue;
  UINT4			vendor;
  u_char		digest[16];
  int			secretlen;
  int			block_len;
  
  auth = (AUTH_HDR *)buffer;

  /* Build standard header */
  auth->code = code;
  auth->id = authreq->id;

  total_length = AUTH_HDR_LEN;

  /* Load up the configuration values for the user */
  ptr = auth->data;
  while(reply != (VALUE_PAIR *)NULL) {
  	debug_pair(reply);
  	*ptr++ = reply->attribute;
  	lptr = ptr;
                 if (reply->attribute == PW_VENDOR && reply->vendor != 0) {
  		ptr++;
                         total_length += 6;
                         vendor = htonl(reply->vendor);
                         memcpy(ptr,&vendor,sizeof(UINT4));
                         ptr += 4;
                         *ptr++ = reply->vsattribute;
                         if (reply->type == PW_TYPE_STRING) {
                                 *lptr = reply->lvalue + 8;
                         } else {
                                 *lptr = 12;
                         }
                 }
  	switch(reply->type) {

#if defined(ASCEND_BINARY)
	case PW_TYPE_ABINARY:
#endif
  	case PW_TYPE_STRING:
  		len = reply->lvalue;
  		if (len > AUTH_STRING_LEN) {
  			len = AUTH_STRING_LEN;
  		}
  		*ptr++ = len + 2;
  		memcpy(ptr, reply->strvalue,len);
  		ptr += len;
  		total_length += len + 2;
  		break;

  	case PW_TYPE_INTEGER:
  	case PW_TYPE_IPADDR:
  	case PW_TYPE_DATE:
  		*ptr++ = sizeof(UINT4) + 2;
  		lvalue = htonl(reply->lvalue);
  		memcpy(ptr, &lvalue, sizeof(UINT4));
  		ptr += sizeof(UINT4);
  		total_length += sizeof(UINT4) + 2;
  		break;

  	default:
  		break;
  	}
  
  	reply = reply->next;
  }

  /* Append the user message */
  if(msg != (char *)NULL && (len = strlen(msg)) > 0) {
  	while(len > 0) {
  		if(len > AUTH_STRING_LEN) {
  			block_len = AUTH_STRING_LEN;
  		}
  		else {
  			block_len = len;
  		}

  		*ptr++ = PW_PORT_MESSAGE;
  		*ptr++ = block_len + 2;
  		memcpy(ptr, msg, block_len);
  		msg += block_len;
  		ptr += block_len;
  		total_length += block_len + 2;
  		len -= block_len;
  	}
  }

  /* Copy over any proxy-states, in order */
  if (forward == FW_REPLY) {
  	item = authreq->request;
  	while (item != (VALUE_PAIR *)NULL) {
  		if (item->attribute == PW_PROXY) {
  			debug_pair(item);
  			*ptr++ = PW_PROXY;
  			len = item->lvalue;
  			*ptr++ = len + 2;
  			memcpy(ptr,item->strvalue,len);
  			ptr += len;
  			total_length += len + 2;
  		}
  		item = item->next;
  	}
  }

  auth->length = htons(total_length);

  if (code == PW_AUTHENTICATION_ACK ||
      code == PW_AUTHENTICATION_REJECT ||
      code == PW_ACCESS_CHALLENGE ||
      code == PW_ACCOUNTING_RESPONSE) {

         	/*
  	   The Authenticator field in an Response packet is
  	   called the Response Authenticator, and contains a
  	   one-way MD5 hash calculated over a stream of octets
  	   consisting of the Response Code, Identifier, Length,
  	   the Request Authenticator field from the Request
  	   packet being replied to, and the response attributes
  	   if any, followed by the shared secret.  The
  	   resulting 16 octet MD5 hash value is stored in the
  	   Authenticator field of the Response packet.
  	 */

  	/* Append secret and calculate the response digest */
  	memcpy(auth->vector, authreq->vector, AUTH_VECTOR_LEN);
  	secretlen = strlen((const char *)authreq->secret);
	if ((size_t)(total_length+secretlen)<=buflen) {
  		memcpy(buffer + total_length, authreq->secret, secretlen);
  		md5_calc(digest, (u_char *)auth, total_length + secretlen);
  		memcpy(auth->vector, digest, AUTH_VECTOR_LEN);
  		memset(buffer + total_length, 0, secretlen);
	}
	else { log_err("build_packet: execeeding buffer size"); }

  } else if (code == PW_ACCOUNTING_REQUEST) {	/* Forwarding */
  		 memset(auth->vector, 0, AUTH_VECTOR_LEN);
  		 secretlen = strlen(authreq->forw_secret);
		 if ((size_t)(total_length+secretlen)<=buflen) {
                 	memcpy(buffer + total_length, authreq->forw_secret, secretlen);
                 	md5_calc(digest, buffer, total_length + secretlen);
                 	memcpy(auth->vector,digest,AUTH_VECTOR_LEN);
                 	memset(buffer + total_length, 0, secretlen);
		 }
		 else { log_err("build_packet: execeeding buffer size"); }

  } else if (code == PW_AUTHENTICATION_REQUEST) {	/* Forwarding */
  	memcpy(auth->vector, authreq->vector, AUTH_VECTOR_LEN);
  }

  return ((int)total_length);
}

/*************************************************************************
  *
  *	Function: decrypt_password
  *
  *	Purpose: decrypts the User-Password attribute in place in
  *		 authreq->request using authreq->vector and
  *		 secret and the algorithm specified in the
  *		 RADIUS RFC, and returns a pointer to the Password 
  *		 if successful, otherwise NULL
  *
  *************************************************************************/

char * 
decrypt_password(AUTH_REQ *authreq,char *secret)
{
  VALUE_PAIR 	*auth_item;
  int		i;
  int		j;
  int		passlen;
  char		hold_vector[AUTH_VECTOR_LEN];
  char		pw_digest[16];
  char		*string;
  char		*ptr;

  calc_digest(pw_digest, authreq, secret);

  /*
   * Decrypt the password in the request.
   */
  if((auth_item = get_attribute(authreq->request,
  			PW_PASSWORD)) == (VALUE_PAIR *)NULL) {
  	return (char *)NULL;
  }

  passlen = auth_item->lvalue;
  if(passlen > AUTH_MAXPASS_LEN) {
  	log_err("decrypt_password: Password length %d > %d max not allowed\n",passlen, AUTH_MAXPASS_LEN);
  	passlen = AUTH_MAXPASS_LEN;
  }
  string = auth_item->strvalue;
  ptr = string;
  for(i = 0;i < passlen;i += AUTH_PASS_LEN) {
  	/*
  	 * Store the vector to be used in next segment
  	 * of the encrypted password.
  	 */
  	memcpy(hold_vector, ptr, AUTH_VECTOR_LEN);

  	/* Decrypt from the digest */
  	for(j = 0;j < AUTH_PASS_LEN;j++) {
  		*ptr ^= pw_digest[j];
  		ptr++;
  	}

  	/* Calculate the next digest if necessary */
  	if(i + AUTH_PASS_LEN < passlen) {
  		calc_next_digest((u_char*)pw_digest, (u_char*)secret, (u_char*)hold_vector);
  	}
  }
  *ptr = '\0';	/* this depends on the fact that auth_item->strvalue
  			always has an extra byte available */
  return string;
}


/*************************************************************************
  *
  *	Function: encrypt_password
  *
  *	Purpose: encrypts the User-Password attribute in place in
  *		 authreq->request using authreq->vector and
  *		 secret and the algorithm specified in the
  *		 RADIUS RFC, and returns a pointer to the Password 
  *		 if successful, otherwise NULL
  *
  *************************************************************************/

char * 
encrypt_password(AUTH_REQ *authreq,char *secret)
{
  VALUE_PAIR 	*auth_item;
  int		i;
  int		j;
  int		passlen;
  char		*hold_vector;
  char		pw_digest[16];
  char		*string;
  char		*ptr;

  calc_digest((u_char*)pw_digest, authreq, (u_char*)secret);

  /*
   * Decrypt the password in the request.
   */
  if((auth_item = get_attribute(authreq->request,
  			PW_PASSWORD)) == (VALUE_PAIR *)NULL) {
  	return (char *)NULL;
  }

  passlen = auth_item->lvalue;
  if(passlen > AUTH_MAXPASS_LEN) {
  	log_err("encrypt_password: Password length %d > %d not allowed, truncating\n",passlen, AUTH_MAXPASS_LEN);
  	passlen = AUTH_MAXPASS_LEN;
  	auth_item->lvalue = AUTH_MAXPASS_LEN;
  	auth_item->strvalue[AUTH_MAXPASS_LEN] = '\0';
  }
  string = auth_item->strvalue;
  ptr = string;
  for(i = 0;i < passlen;i += AUTH_PASS_LEN) {
  	/* Encrypt using the digest */
  	hold_vector = ptr;
  	for(j = 0;j < AUTH_PASS_LEN;j++) {
  		*ptr ^= pw_digest[j];
  		ptr++;
  	}

  	/* Calculate the next digest if necessary */
  	if(i < passlen) {
  		calc_next_digest((u_char*)pw_digest, (u_char*)secret, (u_char*)hold_vector);
  	}
  }
  *ptr = '\0';	/* this depends on the fact that auth_item->strvalue
  			always has an extra byte available */
  return string;
}


/*************************************************************************
  *
  *	Function: calc_digest
  *
  *	Purpose: Validates the requesting client NAS.  Calculates the
  *		 digest to be used for decrypting the users password
  *		 based on the clients private key.
  *
  *************************************************************************/

void 
calc_digest(u_char *digest,AUTH_REQ *authreq,u_char *secret)
{
  u_char	buffer[128];
  int	secretlen;

  /* Use the secret to setup the decryption digest */
  memset(buffer, 0, sizeof(buffer));
  secretlen = strlen((char *)secret);
  memcpy((char *)buffer, (char *)secret,secretlen);
  memcpy(buffer + secretlen, authreq->vector, AUTH_VECTOR_LEN);
  md5_calc(digest, buffer, secretlen + AUTH_VECTOR_LEN);
  memset(buffer, 0, secretlen+AUTH_VECTOR_LEN);
  return;
}

/*************************************************************************
  *
  *	Function: calc_next_digest
  *
  *	Purpose: Calculates the digest to be used for decrypting the 
  *	users password past the first 16 octets based on the clients
  *	private key.
  *
  *************************************************************************/

void 
calc_next_digest(u_char*digest,u_char*secret,u_char*vector)
{
  u_char	buffer[128];
  int	secretlen;

  /* Use the secret to setup the decryption digest */
  memset(buffer, 0, sizeof(buffer));
  secretlen = strlen((const char *)secret);
  strcpy((char *)buffer, (const char *)secret);
  memcpy(buffer + secretlen, vector, AUTH_VECTOR_LEN);
  md5_calc(digest, buffer, secretlen + AUTH_VECTOR_LEN);
  memset(buffer, 0, sizeof(buffer));
}

/*************************************************************************
  *
  *	Function: client_hostname
  *
  *	Purpose: Return the cached client name if we have one.  Otherwise
  *		 use the regular ip_hostname() function.
  *
  *************************************************************************/

char* 
client_hostname(UINT4 ipaddr)
{
  u_char secret[64];
  char	hostnm[MAX_HOST_SIZE];

  /* Look at the last used entry first */
  if(ipaddr == cached_ipaddr) {
  	return(cached_hostnm);
  }
  if(find_client(ipaddr, secret, sizeof(secret), hostnm, sizeof(hostnm)) != 0) {
  	memset(secret, 0, sizeof(secret));
  	return(cached_hostnm);	/* set by find_client() */
  }
  return(ip_hostname(ipaddr));
}

/*************************************************************************
  *
  *	Function: find_client
  *
  *	Purpose: Retrieve the client name and secret from the temporary
  *		 DBM client database.
  *
  *************************************************************************/

int 
find_client(UINT4 ipaddr,char*secret,int secretlen,char*hostnm,size_t hostnmlen)
{
  GDBM_FILE       db;
  char		buffer[MAX_LINE_SIZE];
  char		ip_str[32];
  datum		contentd;
  datum		named;
  int		ret;
  char		fmt[16];


  if (snprintf(fmt,sizeof(fmt), "%%%ds%%%ds", secretlen, hostnmlen)>=sizeof(fmt)) {
    log_err("format too long\n");
    return(-1);
  }  

  /* Find the client in the database */
  snprintf((char *)buffer,sizeof(buffer),"%s/%s", radius_dir, 
           RADIUS_CLIENT_CACHE);

  if ((db = gdbm_open(buffer,0,GDBM_READER,0600,NULL )) == NULL)
           {
    log_err("could not read %s to find clients\n", buffer);
    return(-1);
    }

  ipaddr2str(ip_str, sizeof(ip_str), ipaddr);
  named.dptr = ip_str;
  named.dsize = strlen(ip_str);

  contentd = gdbm_fetch(db, named);
  if(contentd.dsize == 0 || contentd.dptr == NULL) {
  	gdbm_close(db);
         	log_err("client %s not found in client cache\n",ip_str);
  	if (contentd.dptr!=NULL) free(contentd.dptr);
  	return(-1);
  }
  if (contentd.dsize >= MAX_LINE_SIZE) {
  	gdbm_close(db);
  	log_err("client %s length %d > %d in client cache\n", ip_str,
  		contentd.dsize, MAX_LINE_SIZE-1);
  	free(contentd.dptr);
  	return(-1);
  }
  /* convoluted method of working around Solaris x86 2.5 bug */
         memcpy(buffer,contentd.dptr,contentd.dsize-1);
  buffer[contentd.dsize - 1] = '\n';
  buffer[contentd.dsize] = '\0';

  if((ret=sscanf((const char *)buffer, fmt, hostnm, secret)) != 2) {
  	gdbm_close(db);
  	log_err("client cache entry for %s could not be parsed (%d)\n", ip_str,ret);
  	free(contentd.dptr);
  	return(-1);
  }

  /* Build a cached hostname entry for client_hostname() to use */
  strncpy(cached_hostnm, hostnm, MAX_HOST_SIZE);
  cached_hostnm[MAX_HOST_SIZE-1] = '\0';
  cached_ipaddr = ipaddr;

  gdbm_close(db);
  free(contentd.dptr);
  return(0);
}

/*************************************************************************
  *
  *	Function: update_clients
  *
  *	Purpose: Check last modified time on clients file and build a
  *		 new temporary DBM client database if the file has been
  *		 changed.
  *
  *************************************************************************/

int 
update_clients(void)
{
  static time_t	last_update_time;
  struct stat 	statbuf;
  struct stat 	statbuf2;
  datum		named;
  datum		contentd;
     	GDBM_FILE   	db;
  FILE		*clientfd;
  u_char		buffer[256];
  u_char		oldcache[256];
  u_char		newcache[256];
  u_char		secret[64];
  char		hostnm[128];
  char		ip_str[64];
  int		nclients;
  int		rcode;
  int		s1;
  int		s2;
  UINT4		ipaddr;

  nclients = 0;
  rcode = 0;

  /* Check last modified time of clients file */
  snprintf((char *)buffer,sizeof(buffer),"%s/%s", radius_dir, RADIUS_CLIENTS);
  if(stat(buffer, &statbuf) != 0) {
  	log_err("Error: clients file %s not found\n", buffer);
  	return(-1);
  }
  if(statbuf.st_mtime == last_update_time) {
  	/* nothing to update */
  	return(0);
  }
  cached_ipaddr = 0;

  /* Open the standard clients file */

  if((clientfd = fopen((const char *)buffer, "r")) == (FILE *)NULL) {
  	log_err("Error: could not read clients file %s\n", buffer);
  	return(-1);
  }

  /* Open and truncate the clients DBM cache file */
  snprintf((char *)oldcache,sizeof(oldcache),"%s/%s", radius_dir, RADIUS_CLIENT_CACHE);
  snprintf((char *)newcache,sizeof(oldcache),"%s.lock", oldcache);

     	if((db=gdbm_open(newcache,0,GDBM_NEWDB,0600,NULL)) == NULL) {
         	log_err("Error: could not create temporary client cache file %s\n",newcache);
         return(-1);
     }


  while(fgets((char *)buffer, sizeof(buffer), clientfd)
  					!= (char *)NULL) {
  	if(*buffer == '#') {
  		continue;
  	}
  	if(sscanf((const char *)buffer, "%s%s", hostnm, secret) != 2) {
  		continue;
  	}
  	if((ipaddr = get_ipaddr(hostnm)) != (UINT4)0) {
  		ipaddr2str(ip_str, sizeof(ip_str), ipaddr);
  		named.dptr = ip_str;
  		named.dsize = strlen(ip_str);
  		contentd.dptr = (char *)buffer;
  		contentd.dsize = strlen(buffer);
  		if(gdbm_store(db, named, contentd, GDBM_INSERT) != 0) {

  			log_err("could not cache client datum for host %s\n", hostnm);
  			rcode = -1;
  		} else {
  			nclients++;
  		}
  	}
  }
  gdbm_close(db);
  fclose(clientfd);

     	if (rename(newcache,oldcache) != 0) {
             log_err("Error: could not move client cache file %s to %s,"
                     "error %d\n",newcache,oldcache,errno);
             return(-1);
     	} else { debug("updated client cache with %d clients\n",nclients); }

  if (rcode == 0) last_update_time = statbuf.st_mtime;
  return(rcode);
}

/*************************************************************************
  *
  *	Function: debug_pair
  *
  *	Purpose: Print the Attribute-value pair to the desired File.
  *
  *************************************************************************/

void 
debug_pair(VALUE_PAIR * pair)
{
  if(debug_flag) { fprint_attr_val(stdout, pair); }
}

/*************************************************************************
  *
  *	Function: usage
  *
  *	Purpose: Display the syntax for starting this program.
  *
  *************************************************************************/

void 
usage(void)
{
  fprintf(stderr, "Usage: %s\n", progname);
  fprintf(stderr, " [-a <acct_dir>] set accounting directory\n");
  fprintf(stderr, " [-b] use GDBM for users file\n");
  fprintf(stderr, " [-c] clear user stats database\n");
  fprintf(stderr, " [-d <db_dir>] set radiusd database directory\n");
  fprintf(stderr, " [-h] print this usage\n");
  fprintf(stderr, " [-f <alt_passwd_file>] set alternate password file\n");
  fprintf(stderr, " [-i <ip_address>] set alternate IP\n");
  fprintf(stderr, " [-l <log_file>] set radius log file\n");
  fprintf(stderr, " [-o] accept all-zero accounting requests authenticator\n");
  fprintf(stderr, " [-p <udp_port>] set alternate radius port number\n");
  fprintf(stderr, " [-q <max outstanding requests>] set incoming packets queue size\n");
  fprintf(stderr, " [-s] do fork\n");
  fprintf(stderr, " [-t <max seconds in queue>] set time out for requests queue\n");
  fprintf(stderr, " [-v] print version\n");
  fprintf(stderr, " [-w <max seconds for proxy>] set time out for proxy requests\n");
  fprintf(stderr, " [-x] set debug mode on\n");
#if defined(PAM)
  fprintf(stderr, " [-P] set PAM auth mode on\n");
  fprintf(stderr, " [-A] set PAM acct mode on\n");
#endif
  fprintf(stderr, " [-z] as -b -x -d . -a ra\n\n");
  exit(-1);
}

/*************************************************************************
  *
  *	Function: config_init
  *
  *	Purpose: intializes configuration values
  *
  *		 expiration_seconds - When updating a user password,
  *			the amount of time to add to the current time
  *			to set the time when the password will expire.
  *			This is stored as the VALUE Password-Expiration
  *			in the dictionary as number of days.
  *
  *		warning_seconds - When acknowledging a user authentication
  *			time remaining for valid password to notify user
  *			of password expiration.
  *
  *************************************************************************/

int 
config_init(void)
{
  DICT_VALUE	*dval;
  DICT_VALUE	*dict_valfind();

  if((dval = dict_valfind("Password-Expiration")) == (DICT_VALUE *)NULL) {
  	expiration_seconds = (UINT4)0;
  }
  else {
  	expiration_seconds = dval->value * (UINT4)SECONDS_PER_DAY;
  }
  if((dval = dict_valfind("Password-Warning")) == (DICT_VALUE *)NULL) {
  	warning_seconds = (UINT4)0;
  }
  else {
  	warning_seconds = dval->value * (UINT4)SECONDS_PER_DAY;
  }
  strcpy(unknown,"unknown");	/* for client caching error return */
  return(0);
}

/*************************************************************************
  *
  *	Function: set_expiration
  *
  *	Purpose: Set the new expiration time by updating or adding
  	 the Expiration attribute-value pair.
  *
  *************************************************************************/

int 
set_expiration(VALUE_PAIR*user_check,UINT4 expiration)
{
  VALUE_PAIR	*exppair;
  VALUE_PAIR	*prev;
  struct timeval	tp;
  struct timezone	tzp;

  if(user_check == (VALUE_PAIR *)NULL) {
  	return(-1);
  }

  /* Look for an existing expiration entry */
  exppair = user_check;
  prev = (VALUE_PAIR *)NULL;
  while(exppair != (VALUE_PAIR *)NULL) {
  	if(exppair->attribute == PW_EXPIRATION) {
  		break;
  	}
  	prev = exppair;
  	exppair = exppair->next;
  }
  if(exppair == (VALUE_PAIR *)NULL) {
  	/* Add a new attr-value pair */
  	exppair = pairalloc("set_expiration");
  
  	/* Initialize it */
  	strcpy(exppair->name, "Expiration");
  	exppair->attribute = PW_EXPIRATION;
  	exppair->type = PW_TYPE_DATE;

  	/* Attach it to the list. */
  	prev->next = exppair;
  }

  /* calculate a new expiration */
  gettimeofday(&tp, &tzp);
  exppair->lvalue = tp.tv_sec + expiration;
  return(0);
}

/*************************************************************************
  *
  *	Function: pw_expired
  *
  *	Purpose: Tests to see if the users password has expired.
  *
  *	Return: Number of days before expiration if a warning is required
  *		otherwise 0 for success and -1 for failure.
  *
  *************************************************************************/

int 
pw_expired(UINT4 exptime)
{
  struct timeval	tp;
  struct timezone	tzp;
  UINT4		exp_remain;
  int		exp_remain_int;

  if(expiration_seconds == (UINT4)0) {	/* expiration not enabled */
  	return(0);
  }

  gettimeofday(&tp, &tzp);
  if(tp.tv_sec > exptime) {
  	return(-1);
  }
  if(warning_seconds != (UINT4)0) {
  	if(tp.tv_sec > exptime - warning_seconds) {
  		exp_remain = exptime - tp.tv_sec;
  		exp_remain /= (UINT4)SECONDS_PER_DAY;
  		exp_remain_int = exp_remain;
  		return(exp_remain_int);
  	}
  }
  return(0);
}

/*************************************************************************
  *
  *	Function: get_attribute
  *
  *	Purpose: Retrieve a specific value-pair from a list of value-pairs.
  *
  *************************************************************************/

VALUE_PAIR* 
get_attribute(VALUE_PAIR*value_list,int attribute)
{
  while(value_list != (VALUE_PAIR *)NULL) {
  	if(value_list->attribute == attribute) {
  		return(value_list);
  	}
  	value_list = value_list->next;
  }
  return((VALUE_PAIR *)NULL);
}


void 
sig_fatal(int sig)
{
  if(acct_pid > 0) {
  	kill(acct_pid, SIGKILL);
  }

#ifdef ACTIVCARD
  activcard_exit(); /* close activcard session */
#endif
  log_err("exit on signal %d\n", sig);
  rad_exit(1);
}

void 
sig_hup(int sig)
{
  return;
}

void 
sig_usr1(int sig)
{
  extern int debug_flag;

  debug_flag++;
  log_err("debug mode %d\n",debug_flag);
  log_counters();
  return;
}

void 
sig_usr2(int sig)
{
  extern int debug_flag;

  if (debug_flag) {
  	log_err("debug mode 0\n");
  }
  debug_flag = 0;
  log_counters();
  return;
}

void 
rad_exit(int rc)
{
#ifdef SECURID
  AUTH_REQ	*curreq;
  key_t		msg_key;
  int		msg_id;

  if (rad_spawned_child_pid == 0) {
  	/*
  	 * child clean up
  	 */
  	msg_key = RADIUS_MSG_KEY(getpid());
  	if ((msg_id = msgget(msg_key, 0600)) != -1) {
  		msgctl(msg_id, IPC_RMID, 0);
  	}
  } else {
  	/*
  	 * parent clean up
  	 */
  	curreq = first_request;
  	while(curreq != (AUTH_REQ *)NULL) {
  		msg_key = RADIUS_MSG_KEY(curreq->child_pid);
  		if ((msg_id = msgget(msg_key, 0600)) != -1) {
  			msgctl(msg_id, IPC_RMID, 0);
  		}
  		curreq = curreq->next;
  	}
  }

#endif /* SECURID */
  log_counters();
  exit(rc);
}

void 
log_counters(void)
{
  extern int report[];

  log_err("counters %d %d / %d %d / accept %d reject %d challenge %d response %d\n", 
  report[RR_PORT1],report[RR_PORT2],report[RR_PORT3],report[RR_PORT4],
  report[RR_ACCEPT],report[RR_REJECT],report[RR_CHALLENGE],
  report[RR_ACCOUNT]);
  memreport();
  proxy_report();
}

