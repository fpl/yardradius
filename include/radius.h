#ifndef __RADIUS_H
#define __RADIUS_H
/*
 * Copyright (C) 1999-2004, Francesco P. Lovergine. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

#define AUTH_VECTOR_LEN		16
#define AUTH_PASS_LEN		16
#define AUTH_MAXPASS_LEN	48
#define AUTH_STRING_LEN		253	/* maximum of 253 */
#define MAX_LINE_SIZE		256
#define MAX_HOST_SIZE		128

typedef struct pw_auth_hdr {
	u_char		code;
	u_char		id;
	u_short		length;
	char		vector[AUTH_VECTOR_LEN];
	u_char		data[2];
} AUTH_HDR;

#define VENDOR_USROBOTICS		429

#define AUTH_HDR_LEN			20
#define CHAP_VALUE_LENGTH		16

#define PW_AUTH_UDP_PORT		1645
#define PW_ACCT_UDP_PORT		1646
#define PW_PROXY_UDP_PORT		1815
#define PW_PROXYACCT_UDP_PORT		1816

#define PW_TYPE_STRING			0
#define PW_TYPE_INTEGER			1
#define PW_TYPE_IPADDR			2
#define PW_TYPE_DATE			3

#if defined(ASCEND_BINARY)
#define PW_TYPE_ABINARY			4
#endif

#define	PW_AUTHENTICATION_REQUEST	1
#define	PW_AUTHENTICATION_ACK		2
#define	PW_AUTHENTICATION_REJECT	3
#define	PW_ACCOUNTING_REQUEST		4
#define	PW_ACCOUNTING_RESPONSE		5

#ifdef PASSCHANGE
#define PW_PASSWORD_REQUEST		7
#define PW_PASSWORD_ACK			8
#define PW_PASSWORD_REJECT		9
#endif /* PASSCHANGE */

#define PW_ACCESS_CHALLENGE		11

#define	PW_USER_NAME			1
#define	PW_PASSWORD			2
#define	PW_CHAP_PASSWORD		3
#define	PW_CLIENT_ID			4
#define	PW_CLIENT_PORT_ID		5
#define	PW_USER_SERVICE_TYPE		6
#define	PW_FRAMED_PROTOCOL		7
#define	PW_FRAMED_ADDRESS		8
#define	PW_FRAMED_NETMASK		9
#define	PW_FRAMED_ROUTING		10
#define	PW_FRAMED_FILTER_ID		11
#define	PW_FRAMED_MTU			12
#define	PW_FRAMED_COMPRESSION		13
#define	PW_LOGIN_HOST			14
#define	PW_LOGIN_SERVICE		15
#define	PW_LOGIN_TCP_PORT		16

#ifdef PASSCHANGE
#define PW_OLD_PASSWORD			17
#endif

#define PW_PORT_MESSAGE			18
#define PW_DIALBACK_NO			19
#define PW_DIALBACK_NAME		20
#define PW_FRAMED_ROUTE			22
#define PW_FRAMED_IPXNET		23
#define PW_STATE			24
#define PW_VENDOR			26
#define PW_TERMINATION			29
#define PW_CALLED			30
#define PW_CALLING			31
#define PW_PROXY			33

#define PW_ACCT_STATUS_TYPE		40
#define PW_ACCT_DELAY_TIME		41
#define PW_ACCT_INPUT_OCTETS		42
#define PW_ACCT_OUTPUT_OCTETS		43
#define PW_ACCT_SESSION_ID		44
#define PW_ACCT_AUTHENTIC		45
#define PW_ACCT_SESSION_TIME		46
#
#define PW_CHAP_CHALLENGE		60
#define PW_CONNECT_INFO			77

/* new items for radiusd 2.0 */
#define PW_ACCT_TERMINATE_CAUSE         49
#define PW_NAS_PORT_TYPE                61

/* attributes for new accounting stats */

#define PW_ACCT_CALLED_STATION_ID       30
#define PW_ACCT_CALLING_STATION_ID      31
#define PW_ACCT_ASCEND_DATA_RATE        197
#define PW_ACCT_ASCEND_XMIT_RATE        255
#define PW_ACCT_USR_CONNECT_SPEED	0X9023
#define PW_CONNECT_INFO                 77
#define PW_CONNECT_INFO_OLD             65

/*
 * Non-Protocol Attributes
 */
#define PW_EXPIRATION			  21
#define PW_AUTHTYPE			1000
#define PW_MENU				1001
#define PW_TERMINATION_MENU		1002
#define PW_PREFIX			1003
#define PW_SUFFIX			1004
#define PW_GROUP			1005
#define PW_CRYPT_PASSWORD		1006
#define PW_CONNECT_RATE			1007

#if defined(HAVE_LIBPAM)
#define PW_PAM_AUTH                     2001
#endif 

#define PW_LOGINS                       2002
#define PW_MAXMTIME                     2003
#define PW_TIME                         2004
#define PW_MAXMTRAFFIC                  2005
#define PW_MAXDTIME                     2006
#define PW_MAXDTRAFFIC                  2007
#define PW_MAXYTIME                     2008
#define PW_MAXYTRAFFIC                  2009

/*
 *	INTEGER TRANSLATIONS
 */

/*	USER TYPES	*/

#define	PW_LOGIN_USER			1
#define	PW_FRAMED_USER			2
#define	PW_DIALBACK_LOGIN_USER		3
#define	PW_DIALBACK_FRAMED_USER		4
#define	PW_OUTBOUND_USER		5
#define	PW_ADMIN_USER			6
#define	PW_PROMPT_USER			7
#define PW_CALL_CHECK_USER      	10
#define PW_OLD_CALL_CHECK_USER      	129

/*	FRAMED PROTOCOLS	*/

#define	PW_PPP				1
#define	PW_SLIP				2

/*	FRAMED ROUTING VALUES	*/

#define	PW_NONE				0
#define	PW_BROADCAST			1
#define	PW_LISTEN			2
#define	PW_BROADCAST_LISTEN		3

/*	FRAMED COMPRESSION TYPES	*/

#define	PW_VAN_JACOBSON_TCP_IP		1

/*	LOGIN SERVICES	*/

#define	PW_TELNET			0
#define	PW_RLOGIN			1
#define	PW_TCP_CLEAR			2
#define	PW_PORTMASTER			3

/*	AUTHENTICATION LEVEL	*/

#define PW_AUTH_NONE			0
#define PW_AUTH_RADIUS			1
#define PW_AUTH_LOCAL			2

/*	STATUS TYPES	*/

#define PW_STATUS_START			1
#define PW_STATUS_STOP			2

/*	TERMINATION OPTIONS	*/

#define PW_TERM_DEFAULT			0
#define PW_TERM_RADIUS_REQUEST		1

/*	Internal Authentication Types	*/

#define PW_AUTHTYPE_NONE		-1
#define PW_AUTHTYPE_LOCAL		0
#define PW_AUTHTYPE_UNIX		1
#define PW_AUTHTYPE_SECURID		2
#define PW_AUTHTYPE_CRYPT		3
#define PW_AUTHTYPE_REJECT		4
#define PW_AUTHTYPE_ACTIVCARD		5

#if defined(HAVE_LIBPAM)
#define PW_AUTHTYPE_PAM                 7
#endif 


/*	Proxy Flags			*/

#define PEER_NOPROXY			1  /* do not include Proxy-State */
#define PEER_OLDACCT			2  /* do not check sig on acct-response */
#define PEER_ADMINOK			4  /* allow admin logins by proxy */
#define PEER_IPASS			8  /* forward using ipass protocol */

/*	AUTH_REQ Flags			*/

#define REQ_PROXY			1  /* packet was forwarded */
#define REQ_DUP				2  /* packet is a duplicate */
#define REQ_ERR				4  /* packet is in error */
#define REQ_FREE			8  /* packet can be freed */

/*	build_packet Flags		*/

/*	Report Indices			*/

#define FW_REPLY			0  /* reply to client */
#define FW_SERVER			1  /* forward to server */
#define FW_CLIENT			2  /* forward reply to client */


#define	RR_PORT1			1 /* packets received on RADIUS port */
#define	RR_PORT2			2 /* packets received on RADIUS accounting port */
#define	RR_PORT3			3 /* packets received on RADIUS proxy port */
#define	RR_PORT4			4 /* packets received on RADIUS acct proxy port */
#define	RR_ACCEPT			5 /* access-accepts sent */
#define	RR_REJECT			6 /* access-rejects sent */
#define	RR_CHALLENGE			7 /* access-challenges sent */
#define	RR_ACCOUNT			8 /* accounting-responses sent */

#define RR_MAX				20

/* Default Database File Names */

#include "default-paths.h"

#define RADIUS_DICTIONARY	"dictionary"
#define RADIUS_CLIENTS		"clients"
#define RADIUS_CLIENT_CACHE	"clcache"
#define RADIUS_PROXY		"proxy"
#define RADIUS_USERS		"users"
#define RADIUS_USERSDB		"users.db"

#ifdef VPORTS
#define RADIUS_VPORTS           "vports"
#endif

#ifdef ACTIVCARD
#define ACTIVCARD_CONFIG	"config.aeg"
#endif

/* Server data structures */

#define DICT_ATTR_NAME_LEN 32

typedef struct dict_attr {
	char			name[DICT_ATTR_NAME_LEN];
	int			value;
	int			type;
	int			vendor;	/* non-zero for Vendor-Specific */
	int			vsvalue;
	struct dict_attr	*next;
} DICT_ATTR;

#define DICT_VALUE_NAME_LEN 32
#define DICT_VALUE_ATTRNAME_LEN 32

typedef struct dict_value {
	char			attrname[DICT_VALUE_ATTRNAME_LEN];
	char			name[DICT_VALUE_NAME_LEN];
	int			value;
	struct dict_value	*next;
} DICT_VALUE;

#define VALUE_PAIR_NAME_LEN 32
#define VALUE_PAIR_STRVALUE_LEN AUTH_STRING_LEN

typedef struct value_pair {
	char			name[VALUE_PAIR_NAME_LEN];
	int			attribute;
	int			type;
	int			vendor;
	int			vsattribute;
	UINT4			lvalue;	
	char			strvalue[VALUE_PAIR_STRVALUE_LEN];
	struct value_pair	*next;
} VALUE_PAIR;

#define AUTH_REQ_FORW_SECRET_LEN 20
#define AUTH_REQ_SECRET_LEN 20
#define AUTH_REQ_NAME_LEN 64
#define AUTH_REQ_REALM_LEN 64

typedef struct auth_req {
	UINT4			ipaddr;
	u_short			udp_port;
	u_char			id;
	u_char			code;
	char			vector[AUTH_VECTOR_LEN];
	char			secret[AUTH_REQ_SECRET_LEN];	/* max length supported is 16 */
	VALUE_PAIR		*request;
	int			child_pid;	/* Process ID of child */
	UINT4			timestamp;
	struct auth_req		*next;		/* Next active request */
	UINT4			forw_addr;
	u_short			forw_port;
	u_char			forw_id;
	u_char			flags;
	char			forw_vector[AUTH_VECTOR_LEN];
	char			forw_secret[AUTH_REQ_FORW_SECRET_LEN];
	char			name[AUTH_REQ_NAME_LEN];
	char			realm[AUTH_REQ_REALM_LEN];
	char			*packet;
} AUTH_REQ;

typedef struct peer {
	UINT4			ipaddr;
	struct peer		*next;
	u_short			radport;
	u_short			acctport;
	char			realm[AUTH_REQ_REALM_LEN];
	char			secret[AUTH_REQ_SECRET_LEN];
	u_char			id;
	u_char			flags;
} PEER;





#define SECONDS_PER_DAY		86400
#define CLEANUP_DELAY		5
#define MAX_REQUESTS		100	/* -q */
#if defined(SECURID)
#define MAX_REQUEST_TIME	120
#else 
#define MAX_REQUEST_TIME	30	/* -t */
#endif
#define MAX_PROXY_TIME		30	/* -w */

#define RADIUS_MSG_KEY(pid)	(('r' << 24) + ((pid) & 0x00ffffff))

extern int debug_flag;

#endif
