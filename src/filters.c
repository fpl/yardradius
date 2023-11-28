/*
 * Copyright (c) 1994 Ascend Communications, Inc.
 * All rights reserved.
 *
 * Permission to copy all or part of this material for any purpose is
 * granted provided that the above copyright notice and this paragraph
 * are duplicated in all copies.  THIS SOFTWARE IS PROVIDED ``AS IS''
 * AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 *
 * Modifications to this file for yardradius are under YardRadius copyright,
 * as follows:
 * 
 * Copyright (C) 2004, Francesco P. Lovergine. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */


/* FIXME: A bit revised for inclusion in yardradius, needs major revision */

/* $Id: filters.c 81 2004-08-27 21:45:17Z flovergine $ */

#include "yard.h"

#if defined(ASCEND_BINARY)

VALUE_PAIR*	prevRadPair = NULL;

#define NO_TOKEN -1

typedef struct {
    const char*	name;
    int 	value;
} KeywordStruct;

    /*
     * FilterPortType:
     *
     * Ascii names of some well known tcp/udp services.
     * Used for filtering on a port type.
     *
     */

static KeywordStruct _filterPortType[] = {
    { "ftp-data", 20 },
    { "ftp", 21 },
    { "telnet", 23 },
    { "smtp", 25 },
    { "nameserver", 42 },
    { "domain", 53 },
    { "tftp", 69 },
    { "gopher", 70 },
    { "finger", 79 },
    { "www", 80 },
    { "kerberos", 88 },
    { "hostname", 101 },
    { "nntp", 119 },
    { "ntp", 123 },
    { "exec", 512 },
    { "login", 513 },
    { "cmd", 514 },
    { "talk", 517 },
    {  NULL , NO_TOKEN },
};

typedef enum {
    FILTER_IP_TYPE,
    FILTER_GENERIC_TYPE,
    FILTER_IN,
    FILTER_OUT,
    FILTER_FORWARD,
    FILTER_DROP,
    FILTER_GENERIC_OFFSET,
    FILTER_GENERIC_MASK,
    FILTER_GENERIC_VALUE,
    FILTER_GENERIC_COMPNEQ,
    FILTER_GENERIC_COMPEQ,
    FILTER_MORE,
    FILTER_IP_DST,
    FILTER_IP_SRC,
    FILTER_IP_PROTO,
    FILTER_IP_DST_PORT,
    FILTER_IP_SRC_PORT,
    FILTER_EST,
    FILTER_IPX_TYPE,
    FILTER_IPX_DST_IPXNET,
    FILTER_IPX_DST_IPXNODE,
    FILTER_IPX_DST_IPXSOCK,
    FILTER_IPX_SRC_IPXNET,
    FILTER_IPX_SRC_IPXNODE,
    FILTER_IPX_SRC_IPXSOCK
} FilterTokens;


static KeywordStruct _filterKeywords[] = {
    { "ip", 	FILTER_IP_TYPE },
    { "generic",FILTER_GENERIC_TYPE },
    { "in", 	FILTER_IN },
    { "out",	FILTER_OUT },
    { "forward",FILTER_FORWARD },
    { "drop",	FILTER_DROP },
    { "dstip",  FILTER_IP_DST },
    { "srcip",  FILTER_IP_SRC },
    { "dstport",FILTER_IP_DST_PORT },
    { "srcport",FILTER_IP_SRC_PORT },
    { "est",	FILTER_EST },
    { "more",	FILTER_MORE },
    { "!=",	FILTER_GENERIC_COMPNEQ },
    { "==",	FILTER_GENERIC_COMPEQ  },
    { "ipx",	FILTER_IPX_TYPE  },
    { "dstipxnet",	FILTER_IPX_DST_IPXNET  },
    { "dstipxnode",	FILTER_IPX_DST_IPXNODE  },
    { "dstipxsock",	FILTER_IPX_DST_IPXSOCK  },
    { "srcipxnet",	FILTER_IPX_SRC_IPXNET  },
    { "srcipxnode",	FILTER_IPX_SRC_IPXNODE  },
    { "srcipxsock",	FILTER_IPX_SRC_IPXSOCK  },
    {  NULL , NO_TOKEN },
};

#define FILTER_DIRECTION 	0
#define FILTER_DISPOSITION	1
#define IP_FILTER_COMPLETE  	0x3	/* bits shifted by FILTER_DIRECTION */
					/* FILTER_DISPOSITION */

#define IPX_FILTER_COMPLETE      0x3     /* bits shifted by FILTER_DIRECTION */
                                        /* FILTER_DISPOSITION */

#define GENERIC_FILTER_COMPLETE 0x1c3	/* bits shifted for FILTER_DIRECTION */
					/* FILTER_DISPOSITION, FILTER_GENERIC_OFFSET*/
					/* FILTER_GENERIC_MASK, FILTER_GENERIC_VALUE*/

    /*
     * FilterProtoName:
     *
     * Ascii name of protocols used for filtering.
     *
     */
static KeywordStruct _filterProtoName[] = {
    { "tcp",  6 },
    { "udp",  17 },
    { "ospf", 89 },
    { "icmp", 1 },
    {  NULL , NO_TOKEN },
};

static KeywordStruct _filterCompare[] = {
    { ">", RAD_COMPARE_GREATER },
    { "=", RAD_COMPARE_EQUAL },
    { "<", RAD_COMPARE_LESS },
    { "!=", RAD_COMPARE_NOT_EQUAL },
    {  NULL , NO_TOKEN },
};

static char	_curString[512];

static int _findKey ( char *string, KeywordStruct *list );
static int _isAllDigit ( char *token );
static short _a2octet ( char *tok, char *retBuf );
static char _defaultNetmask ( unsigned long address );
static int _ipAddressStringToValue ( char *string, unsigned long *ipAddress,
					 char *netmask);
static int _parseIpFilter ( RadFilter *curEntry );
static int _parseGenericFilter ( RadFilter *curEntry );
static int _parseIpxFilter ( RadFilter *curEntry );
static int _stringToNode   ( unsigned char* dest,  unsigned char* src );

    /*
     * _findKey:
     *
     * Given a table of keywords, it will try and match string to an
     * entry. If it does it returns that keyword value. if no NO_TOKEN is
     * returned. A sanity check is made for upper case characters.
     *
     *	string:			Pointer to the token to match.
     *
     *	list:			Point to the list of keywords.
     *
     *	returns:		Keyword value on a match or NO_TOKEN.
     */

static int 
_findKey(char *string, KeywordStruct *list)
{
    KeywordStruct *entry;
    char *buf, *ptr;

    buf = strdup(string);
    for( ptr = buf ; buf && *ptr ; ptr++ ) {
	if ( isupper( *ptr ) ) *ptr = tolower( *ptr );
    }
    entry = list;
    while( entry->name ) {
   	if( strcmp( entry->name, buf ) == 0 ) {
	    break;
	}
	entry++;
    }
    free(buf);
    return( entry->value );
}

    /*
     * _isAllDigit:
     *
     * Routine checks a string to make sure all values are digits.
     *
     *	token:			Pointer to sting to check.
     *
     * 	returns:		TRUE if all digits, or FALSE.
     *
     */

static int
_isAllDigit(char *token)
{
    int i;

    i = strlen( (char *) token );
    while( i-- ) {
	if( isdigit( *token ) ) {
	    token++;
	} else {
	    break;
	}
    }
    if( i > 0 ) {
	return( FALSE );
    } 

    return( TRUE );
}

    /*
     * _a2octet:
     *
     * Converts the ascii mask and value for generic filters into octets.
     * It also does a sanity check to see if the string is greater than
     * MAX_FILTER_LEN. It assumes the sting is hex with NO leading "0x"
     *
     *	tok:			Pointer to the string.
     *
     *  retBuf:			Pointer to place the octets.
     *
     *	returns:		Number of octects or -1 for error.
     * 
     */
static short
_a2octet(char *tok,char *retBuf)
{
    short	rc, len, val, retLen, i;
    char	buf[ RAD_MAX_FILTER_LEN *2 ];
    char	*octet = buf;

    rc = -1;
    retLen = 0;

    if( ( len = strlen( (char*) tok ) ) <= ( RAD_MAX_FILTER_LEN*2 ) ) {
	retLen = len/2;
	if( len % 2 ) {
	    retLen++;
	}
	memset( buf, '\0', RAD_MAX_FILTER_LEN * 2 );
	for( ; len; len-- ) {
	    if( *tok <= '9' && *tok >= '0' ) {
		val = '0';
	        *octet++ = *tok++ - val;
	    } else if( isxdigit( *tok ) ) {
		if( *tok > 'Z' ) {
		    val = 'a';
		} else {
		    val = 'A';
		}
	        *octet++ = ( *tok++ - val ) + 10;
	    } else {
		break;	
	    }
	}
	if( !len ) {
	    /* merge the values */
	    for( i = 0; i < RAD_MAX_FILTER_LEN*2; i+=2 ) {
		*retBuf++ = (buf[i] << 4) | buf[i+1];
	    }
	}
    }

    if( len ) {
	rc = -1;
    } else {
	rc = retLen;
    }
    return( rc );
}



    /*
     * _defaultNetMask:
     *
     *	Given an ip address this routine calculate a default netmask.
     *
     *	address:		Ip address.
     *
     *	returns:		Number of bits for the netmask
     *
     */
static char
_defaultNetmask(unsigned long address)
{
    char netmask;

    if ( ! address ) {
	netmask = 0;
    } else if (( address & htonl( 0x80000000 ) ) == 0 ) {
	netmask = 8;
    } else if (( address & htonl( 0xc0000000 ) ) == htonl( 0x80000000 ) ) {
	netmask = 16;
    } else if (( address & htonl( 0xe0000000 ) ) == htonl( 0xc0000000 ) ) {
	netmask = 24;
    } else {
	netmask = 32;
    }
    return netmask;
}

		
    /*
     * This functions attempts to convert an IP address in ASCII dot
     * with an optional netmask part to a pair of IpAddress.  Note:
     * An IpAddress is always stored in network byte order.
     *
     * Parameters:
     *
     *  string:		Pointer to a NULL terminated IP address in dot 
     *			notation followed by an optional /nn to indicate
     *			the number leading of bits in the netmask.
     * 
     *  ipAddress:	Pointer to an IpAddress where the converted
     *			address will be stored.
     *
     *	netmask:	Pointer to an IpAddress where the netmask
     *			will be stored.  If no netmask is passed as
     *			as part of the address the default netmask will
     *			be stored here.
     *
     * Returns:
     *	<>		TRUE if valid conversion, FALSE otherwise.
     *
     *	*ipAddress:	If function returns TRUE, the IP address in NBO.
     *	*netmask:	If function returns TRUE, the netmask in NBO.
     */

static int
_ipAddressStringToValue(char *string, unsigned long *ipAddress, char *netmask)
{
    u_char*	dst;
    char*	cp;
    int		numDots;
    int		i;
    long	value;

    if ( ! string ) {
    	return(FALSE);
    }

    /* Allow an IP address to be blanked instead of forcing entry of
       0.0.0.0 -- the user will like it. */

    if ( *string == 0 ) {
	*ipAddress = 0;
	*netmask = 0;
	return TRUE;
    }

    /* First just count the number of dots in the address.  If there
       are more or less than three the address is invalid. */

    cp = string;
    numDots = 0;
    while( *cp ) {
	if( !strchr( (char*)"1234567890./", *cp) ) {
	    return( FALSE );
	}
	if ( *cp == '.') {
	    ++numDots;
	}
	++cp;
    }
    if ( numDots != 3 ) {
	return( FALSE );
    }

    dst = (u_char *) ipAddress;
    cp = string;

    for ( i = 0; i < sizeof( *ipAddress ); i++ ) {
	value = strtol( cp, (char**) &cp, 10 );
	if (( value < 0 ) || ( value > 255 )) {
	    return( FALSE );
	}
	*dst++ = (u_char) value;
	if ( *cp == '.' ) {
	    cp += 1;
	}
    }

    /* If there is a netmask part, parse it, otherwise figure out the
       default netmask for this class of address. */

    if ( *cp == '/' ) {
	value = strtol( cp + 1, (char**) &cp, 10 );
	if (( *cp != 0 ) || ( value < 0 ) || ( value > 32 )) {
	    return FALSE;
	}
	*netmask = (char) value;
    } else {
	*netmask = _defaultNetmask( *ipAddress );
    }
    return TRUE;
}

    /*
     * Convert a 12 digit string representation of a hex data field to a
     * value.
     */
static int
_stringToNode( unsigned char*dest, unsigned char*src )
{
    int         srcIx = 0;
    int         ix;
    int         nibble1;
    int         nibble2;
    int		temp;
    unsigned char *src1;

    src1 = (unsigned char *) strchr(src, 'x');

    if (src1 == NULL)
	src1 = (unsigned char *) strchr(src,'X');

    if (src1 == NULL)
	src1 = src;
    else
	src1++;

    /* skip any leading 0x or 0X 's */
    temp = strlen( (char*) src1 );
    if( strlen( (unsigned char*) src1 ) != ( IPX_NODE_ADDR_LEN * 2 ) ) {
        return( FALSE );
    }

    for ( ix = 0; ix < IPX_NODE_ADDR_LEN; ++ix ) {
        if ( src1[ srcIx ] <= '9' ) {
            nibble1 = src1[ srcIx ] & 0x0f;
        } else {
            nibble1 = (src1[ srcIx ] & 0x0f) + 9;
        }
        srcIx += 1;
        if ( src1[ srcIx ] <= '9' ) {
            nibble2 = src1[ srcIx ] & 0x0f;
        } else {
            nibble2 = (src1[ srcIx ] & 0x0f) + 9;
        }
        srcIx += 1;
        ((unsigned char *) dest)[ ix ] = (unsigned char) (nibble1 << 4) + nibble2;
    }

    return( TRUE );
}


    /*
     * _parseIpxFilter:
     *
     * This routine parses an IPX filter string from a RADIUS
     * reply. The format of the string is:
     *
     *	ipx dir action [ srcipxnet nnnn srcipxnode mmmmm [srcipxsoc cmd value ]]
     * 	               [ dstipxnet nnnn dstipxnode mmmmm [dstipxsoc cmd value ]]
     *
     * Fields in [...] are optional.
     *	where:
     *
     *  ipx:		Keyword to designate an IPX filter. Actually this
     *			has been determined by _parseFilter.
     *
     *	dir:		Filter direction. "IN" or "OUT"
     *
     *	action:		Filter action. "FORWARD" or "DROP"
     *
     *  srcipxnet:      Keyword for source IPX address.
     *                  nnnn = IPX Node address.
     *
     *  srcipxnode:     Keyword for source IPX Node address.
     *                  mmmmm = IPX Node Address, could be FFFFFF.
     *                  A vlid ipx node number should accompany ipx net number.
     *
     *  srcipxsoc:      Keyword for source IPX socket address.
     *
     *  cmd:            One of ">" or "<" or "=" or "!=".
     *
     *  value:          Socket value to be compared against, in hex. 
     *			
     *	dstipxnet:	Keyword for destination IPX address.
     *			nnnn = IPX Node address. 
     *			
     *	dstipxnode:	Keyword for destination IPX Node address.
     *  		mmmmm = IPX Node Address, could be FFFFFF.
     *			A vlid ipx node number should accompany ipx net number.
     *			
     *	dstipxsoc:	Keyword for destination IPX socket address.
     *			
     *	cmd:		One of ">" or "<" or "=" or "!=".
     *			
     *	value:		Socket value to be compared against, in hex.		
     *			
     *			
     * expects:
     *
     *	curEntry:	Pointer to place the filter structure
     *
     *	returns:	-1 for error or 0 for OK
     *	
     */

static int 
_parseIpxFilter(RadFilter*curEntry)
{
    unsigned long	elements = 0l;
    int			tok; 
    char*		token;
    RadIpxFilter*	ipx;

    token = (char *) strtok( NULL, " " ); 

    memset( curEntry, '\0', sizeof( RadFilter ) );
    curEntry->type = RAD_FILTER_IPX; 
    ipx = &curEntry->u.ipx;
 
    while( token ) {
  	tok = _findKey( token, _filterKeywords );
	switch( tok ) {
	    case FILTER_IN:
	    case FILTER_OUT:
		curEntry->indirection = tok == FILTER_IN ? TRUE: FALSE;
		debug(" got FILTER %s ", tok == FILTER_IN?"IN":"OUT");
	        elements |= (1 << FILTER_DIRECTION );
		break;

	    case FILTER_FORWARD:
	    case FILTER_DROP:
		debug(" got FILTER %s ",
			tok == FILTER_DROP? "DROP":"FORWARD");

	        elements |= (1 << FILTER_DISPOSITION );
		if( tok == FILTER_FORWARD ) {
		    curEntry->forward = TRUE;
		} else {
		    curEntry->forward = FALSE;
		}
		break;

	    case FILTER_IPX_DST_IPXNET:
	    case FILTER_IPX_SRC_IPXNET:
                debug(" got FILTER_IPX %s IPXNET ",
                        tok == FILTER_IPX_DST_IPXNET ? "DST":"SRC");
		token = (char *) strtok( NULL, " " );

		if ( token ) {
		    if( tok == FILTER_IPX_DST_IPXNET ) {
			ipx->dstIpxNet = ntohl( strtol( token, 0, 16 ));
			debug("D.Net: %08lX  token: %s \n", htonl(ipx->dstIpxNet), token);
		    } else {
			ipx->srcIpxNet = ntohl( strtol( token, 0, 16 ));
			debug("S Net: %08lX token: %s \n", htonl(ipx->srcIpxNet), token);
		    }
		    break;
		} 
		goto doneErr; 

            case FILTER_IPX_DST_IPXNODE:
            case FILTER_IPX_SRC_IPXNODE:
                debug(" got FILTER_IPX %s IPXNODE ",
			tok == FILTER_IPX_DST_IPXNODE ? "DST":"SRC");
		token = (char *) strtok( NULL, " " );

		if ( token ) {
		    if ( tok == FILTER_IPX_DST_IPXNODE) {
			_stringToNode( (unsigned char *)ipx->dstIpxNode, (unsigned char*)token );
			debug("D. Node: %08lX%04X \n", 
				htonl((*(int *)(ipx->dstIpxNode))),
				htons((*(short *)(ipx->dstIpxNode+4))));
		    } else {
			_stringToNode( (unsigned char *)ipx->srcIpxNode, (unsigned char*)token );
			debug("S. Node: %08lX%04X \n", 
				htonl((*(int *)(ipx->srcIpxNode))),
				htons((*(short *)(ipx->srcIpxNode+4))));
		    }
		    break;
		}
                goto doneErr;

            case FILTER_IPX_DST_IPXSOCK:
            case FILTER_IPX_SRC_IPXSOCK:
	    {
		RadFilterComparison cmp;

                debug(" got FILTER_IPX %s IPXSOCK",
			tok == FILTER_IPX_DST_IPXSOCK ? "DST":"SRC");
                token = (char *) strtok( NULL, " " );

		if ( token ) {
		    cmp = _findKey( token, _filterCompare );
		    debug(" cmp value = %d \n", cmp );
		    if( cmp != NO_TOKEN ) {
		    token = (char *) strtok( NULL, " " );
			if ( token ) {
			    if ( tok == FILTER_IPX_DST_IPXSOCK ) {
				ipx->dstSocComp = cmp;
				ipx->dstIpxSoc = 
			    ntohs( (IpxSocket) strtol( token, NULL, 16 ));
				debug("%X \n", htons(ipx->dstIpxSoc));
			    } else {
				ipx->srcSocComp = cmp;
				ipx->srcIpxSoc 
				    = ntohs( (IpxSocket) strtol( token, NULL, 16 ));
				debug("%X \n", htons(ipx->srcIpxSoc));
			    }
			    break;
			}
		    }
		}
		goto doneErr;
	     }

	    default:
		/* no keyword match */
		goto doneErr;
	}
        token = (char *) strtok( NULL, " " ); 
    } 

    if( elements == IPX_FILTER_COMPLETE ) {
	return( 0 );
    }

doneErr:
    debug( "RADIF: IPX Filter syntax error %s \n", token );
    log_err( "ipx filter error: do not recognize %s in %s \n",
	      token, _curString );
    return( -1 );
}

    /*
     * _parseIpFilter:
     *
     * This routine parses an IP filter string from a RADIUS
     * reply. The format of the string is:
     *
     *	ip dir action [ dstip n.n.n.n/nn ] [ srcip n.n.n.n/nn ]
     *	    [ proto [ dstport cmp value ] [ srcport cmd value ] [ est ] ] 
     *
     * Fields in [...] are optional.
     *	where:
     *
     *  ip:		Keyword to designate an IP filter. Actually this
     *			has been determined by _parseFilter.
     *
     *	dir:		Filter direction. "IN" or "OUT"
     *
     *	action:		Filter action. "FORWARD" or "DROP"
     *
     *	dstip:		Keyword for destination IP address.
     *			n.n.n.n = IP address. /nn - netmask. 
     *			
     *	srcip:		Keyword for source IP address.
     *			n.n.n.n = IP address. /nn - netmask. 
     *			
     *	proto:		Optional protocol field. Either a name or
     *			number. Known names are in FilterProtoName[].
     *			
     *	dstpost:	Keyword for destination port. Only valid with tcp
     *			or udp. 'cmp' are in FilterPortType[]. 'value' can be
     *			a name or number.
     *
     *	srcpost:	Keyword for source port. Only valid with tcp
     *			or udp. 'cmp' are in FilterPortType[]. 'value' can be
     *			a name or number.
     *			
     *	est:		Keyword for TCP established. Valid only for tcp.
     *			
     * expects:
     *
     *	curEntry:	Pointer to place the filter structure
     *
     *	returns:	-1 for error or 0 for OK
     *	
     */

static int 
_parseIpFilter(RadFilter *curEntry)
{
 
    unsigned long	elements = 0l;
    int			tok; 
    char*		token;
    RadIpFilter*	ip;

    token = (char *) strtok( NULL, " " ); 

    debug(" in ip  filter \n"); 

    memset( curEntry, '\0', sizeof( RadFilter ) );
    curEntry->type = RAD_FILTER_IP; 
    ip = &curEntry->u.ip;
    ip->established = FALSE;
 
    while( token ) {
	debug(" token %s ", token );
  	tok = _findKey( token, _filterKeywords );
	switch( tok ) {
	    case FILTER_IN:
	    case FILTER_OUT:
		curEntry->indirection = tok == FILTER_IN ? TRUE: FALSE;
		debug(" got %s ", tok == FILTER_IN?"FILTER_IN":"FILTER_OUT");
	        elements |= (1 << FILTER_DIRECTION );
		break;
	    case FILTER_FORWARD:
	    case FILTER_DROP:
		debug(" got %s ", tok == FILTER_DROP?
			"FILTER_DROP":"FILTER_FORWARD");
	        elements |= (1 << FILTER_DISPOSITION );
		if( tok == FILTER_FORWARD ) {
		    curEntry->forward = TRUE;
		} else {
		    curEntry->forward = FALSE;
		}
		break;
	    case FILTER_IP_DST:
	    case FILTER_IP_SRC:
		debug(" got %s ", tok == FILTER_IP_DST?
			"FILTER_IP_DST":"FILTER_IP_SRC");
		token = (char *) strtok( NULL, " " );
		if ( token ) {
		    if( tok == FILTER_IP_DST ) {
			
		        if( _ipAddressStringToValue( (char*)token, 
				 &ip->dstip, (char *)&ip->dstmask ) ) {
			    debug(" ip %lx netmask %lx \n", ip->dstip, 
				     ip->dstmask );
			    break;
			}
		    } else {
		        if( _ipAddressStringToValue( (char *)token, 
				&ip->srcip, (char *)&ip->srcmask ) ) {
			    debug(" ip %lx netmask %lx \n", ip->srcip,
				     ip->srcmask );
			    break;
			}
		    }
		} 

		debug( "RADIF: IP Filter syntax error %s \n", token );
		log_err( "ip filter error: do not recognize %s in %s \n",
			  token, _curString );
		goto doneErr ;

	    case FILTER_IP_DST_PORT:
	    case FILTER_IP_SRC_PORT:
	    {
		RadFilterComparison cmp;
		short		 port;

		debug(" got %s ", tok == FILTER_IP_DST_PORT?
			"FILTER_IP_DST_PORT":"FILTER_IP_SRC_PORT");
		token = (char *) strtok( NULL, " " );
		if ( token ) {
  		    cmp = _findKey( token, _filterCompare );
		    debug(" cmp value = %d \n", cmp );
		    if( cmp != NO_TOKEN ) {
			token = (char *) strtok( NULL, " " );
			if ( token ) {
			    if( _isAllDigit( token ) ) {
				port = atoi( (char *) token );
			    } else {
  		    	        port = _findKey( token, _filterPortType );
			    }
			    if( port != (short) NO_TOKEN ) {
		    	    	debug(" port = %d \n", port );
				if( tok == FILTER_IP_DST_PORT ) {
				    ip->dstPortComp = cmp;
				    ip->dstport = htons( port );
				} else {
				    ip->srcPortComp = cmp;
				    ip->srcport = htons( port );
				}
				break;
			    }
			}
		    }
		}
		log_err( "ip filter error: do not recognize %s in %s \n",
			  token, _curString );
		debug( "RADIF: IP Filter syntax error %s \n", token );
		goto doneErr;
		break;
	    }
	    case FILTER_EST:
		debug(" got est %s ", token );
		ip->established = TRUE;
		break;
	    default:
		/* no keyword match but may match a protocol list */
		if( _isAllDigit( token ) ) {
		    tok = atoi( (char *) token );
		} else {
		    tok = _findKey( token, _filterProtoName );

		    if( tok == NO_TOKEN ) {
			debug( "RADIF: IP proto error %s \n", token );
			log_err( "ip filter error: do not recognize %s in %s \n",
			     token, _curString );
			goto doneErr;
		    }
		}
		ip->proto = tok;
		debug("ip proto cmd = %d ", tok);
	}
        token = (char *) strtok( NULL, " " ); 
    } 

    if( elements == IP_FILTER_COMPLETE ) {
	return( 0 );
    }

doneErr:
    debug((" done err \n"));
    return( -1 );
}

    /*
     * _parseGenericFilter:
     *
     * This routine parses a Generic filter string from a RADIUS
     * reply. The format of the string is:
     *
     *	GENERIC dir action offset mask value [== or != ] [more]
     *
     * Fields in [...] are optional.
     *	where:
     *
     * 	generic:	Keyword to indicate a generic filter. This
     *			has been determined by _parseFilter.
     *
     *	dir:		Filter direction. "IN" or "OUT"
     *
     *	action:		Filter action. "FORWARD" or "DROP"
     *
     *	offset:		A Number. Specifies an offset into a frame 
     *			to start comparing.
     *			
     *	mask:		A hexadecimal mask of bits to compare.
     *			
     *	value:		A value to compare with the masked data.
     *
     *	compNeq:	Defines type of comparison. ( "==" or "!=")
     *			Default is "==".
     *			
     *	more:		Optional keyword MORE, to represent the attachment
     *			to the next entry.
     *
     * expects:
     *
     *	curEntry:	Pointer to place the filter structure
     *
     *	returns:	-1 for error or 0 for OK
     *	
     */

static int
_parseGenericFilter(RadFilter *curEntry)
{
    unsigned long	elements = 0l; 
    int			tok; 
    int			gstate = FILTER_GENERIC_OFFSET;
    char*		token;
    short		valLen, maskLen;
    RadGenericFilter*	gen;

    token = (char *) strtok( NULL, " " ); 

    debug(" in parse generic filter"); 

    maskLen = 0;
    memset( (char *)curEntry, '\0', sizeof( RadFilter ) );
    curEntry->type = RAD_FILTER_GENERIC;
    gen = &curEntry->u.generic;
    gen->more = FALSE; 
    gen->compNeq = FALSE;	

    while( token ) {
	debug(" token %s ", token );
  	tok = _findKey( token, _filterKeywords );
   	debug("tok %d ", tok);
	switch( tok ) {
	    case FILTER_IN:
	    case FILTER_OUT:
		curEntry->indirection = tok == FILTER_IN ? TRUE: FALSE;
	        elements |= (1 << FILTER_DIRECTION );
		debug(" got %s ", tok == FILTER_IN?"FILTER_IN":"FILTER_OUT");
		break;
	    case FILTER_FORWARD:
	    case FILTER_DROP:
	        elements |= (1 << FILTER_DISPOSITION );
		debug(" got %s ", tok == FILTER_DROP?
			"FILTER_DROP":"FILTER_FORWARD");
		if( tok == FILTER_FORWARD ) {
		    curEntry->forward = TRUE;
		} else {
		    curEntry->forward = FALSE;
		}
		break;
	    case FILTER_GENERIC_COMPNEQ:
		gen->compNeq = TRUE;
		debug(" got compare %s ", token);
		break;
	    case FILTER_GENERIC_COMPEQ:
		gen->compNeq = FALSE;
		debug(" got compare %s ", token);
		break;
	    case FILTER_MORE:
		gen->more = htons( TRUE );
		debug(" got more %s ", token );
		break;
	    default:
	        elements |= ( 1 << gstate );
		switch( gstate ) {
		    case FILTER_GENERIC_OFFSET:
			gstate = FILTER_GENERIC_MASK;
			gen->offset = htons( atoi( (char *) token ) );
			break;
		    case FILTER_GENERIC_MASK:
			gstate = FILTER_GENERIC_VALUE;
			maskLen = _a2octet( token, (char *)gen->mask );
			if( maskLen == (short) -1 ) {
			    log_err( "filter mask error: %s", _curString );
			    goto doneErr;
			}
			debug(" octet retlen = %d ", maskLen );
			for( tok = 0; tok < maskLen; tok++) {
        		    debug("%2x", gen->mask[tok]);
		        }

			break;
		    case FILTER_GENERIC_VALUE:
			gstate ++;
			valLen = _a2octet( token, (char *)gen->value );
			if( valLen != maskLen ) {
			    log_err( "filter value size is not the same size as the filter mask: %s", 
				     _curString );
			    goto doneErr;
			}
			gen->len = htons( valLen );
			debug(" octet retlen = %d ", maskLen );
			for( tok = 0; tok < maskLen; tok++) {
        		    debug("%2x", gen->value[tok]);
		        }

			break;
		    default:
			log_err( "filter: do not know %s in %s", token, _curString );
			debug( "RADIF: Filter syntax error %s", token );
			goto doneErr;    
		}
	}
        token = (char *) strtok( NULL, " " ); 
    }

    if( elements == GENERIC_FILTER_COMPLETE ) {
	return( 0 );
    }

doneErr:
    debug(" done err");
    return( -1 );
}
		       
    /*
     * filterBinary:
     *
     * This routine will call routines to parse entries from an ASCII format
     * to a binary format recognized by the Ascend boxes.
     *
     *	pair:			Pointer to value_pair to place return.
     *
     *	valstr:			The string to parse	
     *
     *	return:			-1 for error or 0.
     */
int 
filterBinary(VALUE_PAIR	*pair,char*valstr)
{
    char*		token;
    unsigned long	tok;
    int			rc;
    RadFilter		radFil, *filt;
    RadGenericFilter*	gen;

    rc = -1;
    strncpy( _curString, valstr,sizeof(_curString)-1 );
    _curString[sizeof(_curString)-1]='\0';

    token = (char *) strtok( (char *)valstr, " " );
    tok = _findKey( token, _filterKeywords );
    pair->lvalue = sizeof( RadFilter );
    switch( tok ) {
      case FILTER_IP_TYPE:
	rc = _parseIpFilter( &radFil );
	break;
      case FILTER_GENERIC_TYPE:
	rc = _parseGenericFilter( &radFil );
	break;
      case  FILTER_IPX_TYPE:
	rc = _parseIpxFilter( &radFil );
        break;
    }

    /*
     * if more is set then this new entry must exist, be a 
     * FILTER_GENERIC_TYPE, direction and disposition must match for 
     * the previous more to be valid. If any should fail then TURN OFF 
     * previos more
     */
    if( prevRadPair ) {
	filt = ( RadFilter * )prevRadPair->strvalue;
	if(( tok != FILTER_GENERIC_TYPE ) || (rc == -1 ) ||
	   ( prevRadPair->attribute != pair->attribute ) || 
	   ( filt->indirection != radFil.indirection ) || 
	   ( filt->forward != radFil.forward ) ) {
	    gen = &filt->u.generic;
	    gen->more = FALSE;
	    log_err( "filterBinary:  'more' for previous entry doesn't match: %s.\n",_curString );
	}
    }
    prevRadPair = NULL;
    if( rc != -1 && tok == FILTER_GENERIC_TYPE ) {
	if( radFil.u.generic.more ) {
	    prevRadPair = pair;
	} 
    }

    if( rc != -1 ) {
	memcpy( pair->strvalue, (char *) &radFil, pair->lvalue );
    }
    return(rc);
}

#endif /* ASCEND_BINARY */
