/*
 * Copyright (C) 1999-2004 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

static char rcsid[] = "$Id: util.c 81 2004-08-27 21:45:17Z flovergine $";

#include "yard.h"
#include "global.h"

/* Memory structures allocated, for debugging purposes */

int hmembuf = 0;	/* highwater marks */
int hmempair = 0;
int hmempeer = 0;
int hmemreq = 0;

int nmembuf = 0;	/* number allocated but not freed */
int nmempair = 0;
int nmempeer = 0;
int nmemreq = 0;

int tmembuf = 0;	/* total number allocated */
int tmempair = 0;
int tmempeer = 0;
int tmemreq = 0;

/*************************************************************************
 *
 *	Function: ip_hostname
 *
 *	Purpose: Return a printable host name (or IP address in dot notation)
 *		 for the supplied IP address.
 *
 *************************************************************************/

char* 
ip_hostname(UINT4 ipaddr)
{
	struct	hostent *hp;
	static char	hstname[128];
	UINT4	n_ipaddr;

	n_ipaddr = htonl(ipaddr);
	hp = gethostbyaddr((char *)&n_ipaddr, sizeof (struct in_addr), AF_INET);
	if (hp == 0) {
		ipaddr2str(hstname, sizeof(hstname), ipaddr);
		return(hstname);
	}
	return(hp->h_name);
}

/*************************************************************************
 *
 *	Function: get_ipaddr
 *
 *	Purpose: Return an IP address in host long notation from a host
 *		 name or address in dot notation.
 *
 *************************************************************************/

UINT4 
get_ipaddr(char *host)
{
	struct hostent *hp;

	if(good_ipaddr(host) == 0) {
		return(ipstr2long(host));
	}
	else if((hp = gethostbyname(host)) == (struct hostent *)NULL) {
		return((UINT4)0);
	}
	return(ntohl(*(UINT4 *)hp->h_addr));
}

/*************************************************************************
 *
 *	Function: good_ipaddr
 *
 *	Purpose: Check for valid IP address in standard dot notation.
 *
 *************************************************************************/

int 
good_ipaddr(char*addr)
{
	int	dot_count;
	int	digit_count;

	dot_count = 0;
	digit_count = 0;
	while(*addr != '\0' && *addr != ' ') {
		if(*addr == '.') {
			dot_count++;
			digit_count = 0;
		}
		else if(!isdigit(*addr)) {
			dot_count = 5;
		}
		else {
			digit_count++;
			if(digit_count > 3) {
				dot_count = 5;
			}
		}
		addr++;
	}
	if(dot_count != 3) {
		return(-1);
	}
	else {
		return(0);
	}
}

/*************************************************************************
 *
 *	Function: ipaddr2str
 *
 *	Purpose: Return an IP address in standard dot notation for the
 *		 provided address in host long notation.
 *
 *************************************************************************/

void 
ipaddr2str(char*buffer,size_t buflen,UINT4 ipaddr)
{
	int	addr_byte[4];
	int	i;
	UINT4	xbyte;

	for(i = 0;i < 4;i++) {
		xbyte = ipaddr >> (i*8);
		xbyte = xbyte & (UINT4)0x000000FF;
		addr_byte[i] = xbyte;
	}
	snprintf(buffer, buflen, "%u.%u.%u.%u", addr_byte[3], addr_byte[2],
		addr_byte[1], addr_byte[0]);
}

/*************************************************************************
 *
 *	Function: ipaddr2strp
 *
 *	Purpose: Return an IP address in standard dot notation for the
 *		 provided address in host long notation.
 *
 *************************************************************************/

char*
ipaddr2strp(UINT4 ipaddr)
{
	int	addr_byte[4];
	int	i;
	UINT4	xbyte;
	static char buffer[32];

	for(i = 0;i < 4;i++) {
		xbyte = ipaddr >> (i*8);
		xbyte = xbyte & (UINT4)0x000000FF;
		addr_byte[i] = xbyte;
	}
	snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", addr_byte[3], addr_byte[2],
		addr_byte[1], addr_byte[0]);
	return(buffer);
}


/*************************************************************************
 *
 *	Function: ipstr2long
 *
 *	Purpose: Return an IP address in host long notation from
 *		 one supplied in standard dot notation.
 *
 *************************************************************************/

UINT4 
ipstr2long(char*ip_str)
{
	char	buf[6];
	char	*ptr;
	int	i;
	int	count;
	UINT4	ipaddr;
	int	cur_byte;

	ipaddr = (UINT4)0;
	for(i = 0;i < 4;i++) {
		ptr = buf;
		count = 0;
		*ptr = '\0';
		while(*ip_str != '.' && *ip_str != '\0' && count < 4) {
			if(!isdigit(*ip_str)) {
				return((UINT4)0);
			}
			*ptr++ = *ip_str++;
			count++;
		}
		if(count >= 4 || count == 0) {
			return((UINT4)0);
		}
		*ptr = '\0';
		cur_byte = atoi(buf);
		if(cur_byte < 0 || cur_byte > 255) {
			return((UINT4)0);
		}
		ip_str++;
		ipaddr = ipaddr << 8 | (UINT4)cur_byte;
	}
	return(ipaddr);
}


/*************************************************************************
 *
 *	Function: req2str
 *		  req2strp
 *
 *	Purpose: Return an IP address in standard dot notation,
 *		 followed by / port . id, for the provided authreq
 *
 *************************************************************************/

char* 
req2str(char *buffer,size_t buflen,AUTH_REQ *authreq)
{
	int	addr_byte[4];
	int	i;
	UINT4	xbyte;
	UINT4	ipaddr;

	if (buffer == (char *)NULL) {
		return buffer;
	}

	if (authreq == (AUTH_REQ *)NULL) {
		memcpy(buffer,"(unidentified)",15);
		return (buffer);
	}

	ipaddr = authreq->ipaddr;

	for(i = 0;i < 4;i++) {
		xbyte = ipaddr >> (i*8);
		xbyte = xbyte & (UINT4)0x000000FF;
		addr_byte[i] = xbyte;
	}
	snprintf(buffer, buflen, "%u.%u.%u.%u/%u.%u", addr_byte[3], addr_byte[2],
		addr_byte[1], addr_byte[0], authreq->udp_port, authreq->id);

	return(buffer);
}


char* 
req2strp(AUTH_REQ *authreq)
{
	static char buffer[32];

	return req2str(buffer,sizeof(buffer),authreq);
}


/*************************************************************************
 *
 *      Function: bufalloc
 *
 *      Purpose: Allocate memory for use by a buffer
 *
 *************************************************************************/

char * 
bufalloc(int size,char*where)
{
	char 		*buf;

	if((buf = (char *)malloc((unsigned)size)) == (char *)NULL) {
                log_err("%s: fatal system error: out of memory, exiting\n",where);
                rad_exit(-1);
        }

	/* no need to zero buffer since we'll be copying into it */
	nmembuf++;
	tmembuf++;
	if (nmembuf > hmembuf) {
		hmembuf = nmembuf;
	}
	if (debug_mem) {
		log_err("called bufalloc(%d,%s) = %p %d\n",size,where,(void*)buf,nmembuf);
	}

	return buf;
}



/*************************************************************************
 *
 *      Function: buffree
 *
 *      Purpose: Release the memory allocated by bufalloc();
 *
 *************************************************************************/

void 
buffree(char*buf,char*where)
{
	if (debug_mem) {
		log_err("called buffree(%p,%s) = %d\n",(void*)buf,where,nmembuf);
	}
        if (buf == (char *)NULL) {
		log_err("%s called buffree with NULL pointer\n",where);
        } else {
                free(buf);
		nmembuf--;
	}
	/* calling routine took care to zero buffer if it had anything sensitive */ 
}


/*************************************************************************
 *
 *      Function: pairalloc
 *
 *      Purpose: Allocate memory for VALUE_PAIR
 *
 *************************************************************************/

VALUE_PAIR *
pairalloc(char*where)
{
	VALUE_PAIR	*pair;

	if((pair = (VALUE_PAIR *)malloc(sizeof(VALUE_PAIR))) == (VALUE_PAIR *)NULL) {
                log_err("%s: fatal system error: out of memory, exiting\n",where);
                rad_exit(-1);
        }

        memset(pair,0,sizeof(VALUE_PAIR));
	pair->next = (VALUE_PAIR *)NULL;

	nmempair++;
	tmempair++;
	if (nmempair > hmempair) {
		hmempair = nmempair;
	}

	return pair;

}


/*************************************************************************
 *
 *	Function: pairfree
 *
 *	Purpose: Release the memory used by a list of attribute-value
 *		 pairs.
 *
 *************************************************************************/

void 
pairfree(VALUE_PAIR*pair,char*where)
{
	VALUE_PAIR	*next;

	while(pair != (VALUE_PAIR *)NULL) {
		next = pair->next;
		memset(pair,0,sizeof(VALUE_PAIR));
		free(pair);
		pair = next;
		nmempair--;
	}
}



/*************************************************************************
 *
 *      Function: peeralloc
 *
 *      Purpose: Allocate memory for PEER
 *
 *************************************************************************/

PEER * 
peeralloc(char *where)
{
	PEER		*peer;

	if((peer = (PEER *)malloc(sizeof(PEER))) == (PEER *)NULL) {
                log_err("%s: fatal system error: out of memory, exiting\n",
			where);
                rad_exit(-1);
        }

        memset(peer,0,sizeof(PEER));
	peer->next = (PEER *)NULL;

	nmempeer++;
	tmempeer++;
	if (nmempeer > hmempeer) {
		hmempeer = nmempeer;
	}

	return peer;

}


/*************************************************************************
 *
 *	Function: peerfree
 *
 *	Purpose: Release the memory used by a PEER structure
 *
 *************************************************************************/

void 
peerfree(PEER*peer,char*where)
{
	if (peer == (PEER *)NULL) {
		log_err("%s called peerfree with NULL pointer\n",where);
	} else {
		if (peer->next != (PEER *)NULL) {
			debug("%s called peerfree with live next pointer\n",
				where);
		}
		memset(peer,0,sizeof(PEER));
		free(peer);
		nmempeer--;
	}
}




/*************************************************************************
 *
 *      Function: reqalloc
 *
 *      Purpose: Allocate memory for use by an AUTH_REQ structure
 *
 *************************************************************************/

AUTH_REQ *
reqalloc(char *where)
{
	AUTH_REQ	*authreq;

	if((authreq = (AUTH_REQ *)malloc(sizeof(AUTH_REQ))) == (AUTH_REQ *)NULL) {
                log_err("%s: fatal system error: out of memory, exiting\n",where);
                rad_exit(-1);
        }

        memset(authreq,0,sizeof(AUTH_REQ));
	authreq->request = (VALUE_PAIR *)NULL;
	authreq->next = (AUTH_REQ *)NULL;
	authreq->packet = (char *)NULL;

	nmemreq++;
	tmemreq++;
	if (nmemreq > hmemreq) {
		hmemreq = nmemreq;
	}
	if (debug_mem) {
		log_err("called reqalloc(%s) = %p %d\n",where,(void*)authreq,nmemreq);
	}

	return authreq;

}



/*************************************************************************
 *
 *      Function: reqfree
 *
 *      Purpose: Release the memory used by an AUTH_REQ structure
 *
 *************************************************************************/

void 
reqfree( AUTH_REQ*authreq,char*where)
{
	if (debug_mem) {
		log_err("called reqfree(%p,%s) = %d\n",(void*)authreq,where,nmemreq);
	}
        if (authreq == (AUTH_REQ *)NULL) {
		log_err("%s called reqfree with NULL pointer\n",where);
        } else {
                pairfree(authreq->request,where);
		if (authreq->packet != (char *) NULL) {
			buffree(authreq->packet,where);
		}
                memset(authreq, 0, sizeof(AUTH_REQ));
                free(authreq);
		nmemreq--;
	}
}

void 
memreport(void)
{
	log_err("memory usage = pair %d/%d/%d  peer %d/%d/%d  req %d/%d/%d  buf %d/%d/%d\n",
	nmempair,hmempair,tmempair, nmempeer,hmempeer,tmempeer, 
	nmemreq,hmemreq,tmemreq, nmembuf,hmembuf,tmembuf );
     
}


/*************************************************************************
 *
 *	Function: fprint_attr_val
 *
 *	Purpose: Write a printable version of the attribute-value
 *		 pair to the supplied File.
 *
 *************************************************************************/

void 
fprint_attr_val(FILE*fd,VALUE_PAIR*pair)
{
	DICT_VALUE	*dval;
	char		buffer[32];
	char		prtbuf[1060];
	int		len;
	u_char		*ptr;

	switch(pair->type) {

	case PW_TYPE_STRING:
		snprintf(prtbuf,sizeof(prtbuf),"%s = \"", pair->name);
		ptr = (u_char *)pair->strvalue;
		len = pair->lvalue;
		if ( ptr[len-1]=='\0' ) len--; /* ASCEND: ignore a trailing 0 */
		while(len-- > 0) {
			if(!(isprint(*ptr))) {
				snprintf(buffer,sizeof(buffer),"\\%03o", *ptr);
				strcat(prtbuf, buffer);
			}
			else {
				fprint_attr_putc(*ptr, (u_char*)prtbuf);
			}
			ptr++;
		}
		fprint_attr_putc('"', prtbuf);
		break;
			
	case PW_TYPE_INTEGER:
		dval = dict_valget(pair->lvalue, pair->name);
		if(dval != (DICT_VALUE *)NULL) {
			snprintf(prtbuf,sizeof(prtbuf),"%s = %s", pair->name, dval->name);
		}
		else {
			snprintf(prtbuf,sizeof(prtbuf),"%s = %ld", pair->name, pair->lvalue);
		}
		break;

	case PW_TYPE_IPADDR:
		ipaddr2str(buffer,sizeof(buffer),pair->lvalue);
		snprintf(prtbuf,sizeof(prtbuf),"%s = %s", pair->name, buffer);
		break;

	case PW_TYPE_DATE:
		strftime(buffer, sizeof(buffer), "%b %e %Y",
					gmtime((time_t *)&pair->lvalue));
		snprintf(prtbuf,sizeof(prtbuf),"%s = \"%s\"", pair->name, buffer);
		break;

#if defined(ASCEND_BINARY)
       case PW_TYPE_ABINARY:
               {
                       int i;
               
                       snprintf( prtbuf, sizeof(prtbuf),"%s =", pair->name );
		       ptr = (u_char *)pair->strvalue;
		       len = pair->lvalue;
                       for ( i=0; i<len; i++ ) {
                                snprintf( buffer, sizeof(buffer)," %02x", ptr[i] );
				strncat( prtbuf,buffer,sizeof(prtbuf)-strlen(prtbuf)-1 );
                       }
               }
               break;
#endif


	default:
		snprintf(prtbuf,sizeof(prtbuf),"Unknown type %d", pair->type);
		break;
	}
	if (fd == (FILE *)-1) {
		/*
		 * send to debug log
		 */
		log_debug("%s\n", prtbuf);
	} else {
		fputs(prtbuf, fd);
	}
}

void 
fprint_attr_putc(u_char cc,u_char *buf)
{
	int len;

	len = strlen((const char *)buf);
	buf[len] = cc;
	buf[len+1] = (u_char)0;
}


/*************************************************************************
 *
 *      Function: hexdump
 *
 *      Purpose: log buffer in hex
 *
 *************************************************************************/

void 
hexdump(u_char*buf,int n)
{
	int i;
	int j;
	char s[64];

	if (n > 200) {
		n = 200;
	}
	s[48] = '\n';
	s[48] = '\0';
	for (i = 0; i < n; i++) {	
		j = i & 0x0f;
		snprintf(&s[3*j], sizeof(s), "%02x ", (int)buf[i]);
		if (j == 15) {
			log_debug("%s\n",s);
		}
	}
	if (n > 0 && j < 15) {
		s[3*j+3] = '\n';
		s[3*j+3] = '\0';
		log_debug("%s\n",s);
	}

}
