#ifndef __YARD_H
#define __YARD_H

/*
 * Copyright (C) 1999-2004, Francesco P. Lovergine. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

/* $Id: yard.h 81 2004-08-27 21:45:17Z flovergine $ */

/*
 * The main header file with all needed declarations
 */

/* Header files included */

#include	<config.h>

#ifdef IPASS
#define USE_SSL
#endif

#ifdef HAVE_SYS_TYPES_H
#include        <sys/types.h>
#endif
#include        <sys/socket.h>

#ifdef HAVE_SYS_FILE_H
#include        <sys/file.h>
#endif
#include        <sys/ipc.h>
#include        <netinet/in.h>
#ifdef HAVE_SYS_STAT_H
#include	<sys/stat.h>
#endif
#include        <stdlib.h>
#include        <stdio.h>
#include        <netdb.h>

#ifdef HAVE_SYS_TIME_H
#include 	<sys/time.h>
#include    <time.h>
#endif

#include    <ctype.h>
#include    <pwd.h>
#include	<grp.h>
#ifdef HAVE_SYSLOG_H
#include        <syslog.h>
#endif
#include        <signal.h>
#include        <errno.h>
#ifdef	HAVE_FCNTL_H
#include        <fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
#include        <unistd.h>
#endif
#ifdef 	HAVE_SYS_WAIT_H
#include        <sys/wait.h>
#endif
#ifdef	HAVE_LIMITS_H
#include        <limits.h>
#endif
#include        <stdarg.h>
#ifdef 	HAVE_SHADOW_H
#include 	<shadow.h>
#endif
#ifdef	HAVE_SECURITY_PAM_APPL_H
#include 	<security/pam_appl.h>
#endif

#if defined(HAVE_STRINGS_H)
#include        <strings.h>
#endif
#if defined(HAVE_STRING_H)
#include        <string.h>
#endif

#if defined(HAVE_MACHINE_ENDIAN_H)
#include	<machine/endian.h>
#endif
#if defined(HAVE_MACHINE_INLINE_H)
#include	<machine/inline.h>
#endif

#if defined(HAVE_SYS_SELECT_H)
#include	<sys/select.h>
#endif

#include 	"gdbm.h"

/* 
  The following is for compatibility with GDBM 1.7.3
  That old version assumes no fast mode as default which is not the
  default with version 1.8 
 */

#if !defined(GDBM_SYNC)
#define GDBM_SYNC	0
#endif

#if defined(__alpha)
typedef unsigned int    UINT4;
#else
typedef unsigned long   UINT4;
#endif

#include	"radius.h"
#include	"users.h"
#include	"md5.h"
#include 	"prototypes.h"
#include	"vports.h"

#if defined(ASCEND_BINARY)
#include	"filters.h"
#endif

/*
 * FIXME: Needs some finest autoconf tests to discover if C compiler can handle properly variadic macros.
 */

#if defined(__GNUC__)
#define debug(args...)	do { if (debug_flag) log_debug(args); } while(0)
#else /* C99 syntax */
#define debug(...) do { if (debug_flag) log_debug( __VA_ARGS__ ); } while(0)
#endif

#if !defined(USE_PORTABLE_SNPRINTF)

#ifndef HAVE_SNPRINTF
#ifdef HAVE___SNPRINTF
#define HAVE_LOCAL_SNPRINTF
#define snprintf __snprintf
#endif
#else
#define HAVE_LOCAL_SNPRINTF
#endif

#ifndef HAVE_VSNPRINTF
#ifdef HAVE___VSNPRINTF
#define HAVE_LOCAL_SNPRINTF
#define snprintf __vsnprintf
#endif
#else
#define HAVE_LOCAL_SNPRINTF
#endif

#endif /* !USE_PORTABLE_SNPRINTF */

/*
 * Defines
 */

#define RADIUS_HOLD		"holdusers"
#define RADIUS_USER_STATS	"user-stats"
#define RADIUS_LAST             "radlast"
#define RADIUS_DENY             "denyuser"
#define RADIUS_STOP             "stopuser"
#define RADIUS_ALLOW            "allowuser"

#if defined(HAVE_LIBPAM)
#define RADIUS_PAM_SERVICE	"yard"
#endif

/* maximum username size to keep in databases */
#define USERNAME_MAX   32
    
/* Internal protocol specifiers */
#define P_LOGIN_UNK    -2
#define P_FRAMED_UNK   -1
#define P_UNKNOWN       0
#define P_TELNET        1
#define P_RLOGIN        2
#define P_TCP_CLEAR     3
#define P_PORTMASTER    4
#define P_PPP           5
#define P_SLIP          6
#define P_CSLIP         7

/* Queue management */

#define	MAX_ACCT_QUEUE	1000 /* maximum size of the acct packets queue */

/* Bitflag days */

#define Su_DAY 		0001
#define Mo_DAY 		0002
#define Tu_DAY 		0004
#define We_DAY 		0010
#define Th_DAY 		0020
#define Fr_DAY 		0040
#define Sa_DAY 		0100

/* communists, watch out ! :-) */

#define Wk_DAY   Mo_DAY | Tu_DAY | We_DAY | Th_DAY | Fr_DAY 
#define Al_DAY   Wk_DAY | Sa_DAY | Su_DAY


typedef char STRING[254]; /* This is the string type in radius dictionary */

/*
 * Structures
 */
typedef struct {
    time_t		time;
    UINT4               nas_ip;
    unsigned int        port_type;
    unsigned int        port_number;
    UINT4               client_ip;
    int                 proto;
} port_entry;

typedef struct {
    unsigned int   	on_line;       /* total online seconds today */
    unsigned long	input_octets;  /* inbound traffic today */
    unsigned long	output_octets; /* outbound traffic today */
    unsigned int	nr_logins;     /* number of logins today */
} today_user_entry;

# define MONTHS         12
# define DAYS_PER_MONTH 31

# define DAY_LIMIT   1
# define MONTH_LIMIT 2
# define YEAR_LIMIT  3

typedef struct {
    unsigned int     logins;        /* concurrent logins */
    today_user_entry day[MONTHS][DAYS_PER_MONTH]; 
} user_entry;

typedef struct {
    char port;
    char proto;
    char port_type;
    char term_cause;
} log_entry;

typedef struct {
    char 	login[USERNAME_MAX]; /* Loginname      			*/
    log_entry 	ent;   		/* Port information 			*/
    UINT4 	nas_ip;        	/* IP of portmaster. 			*/
    UINT4 	client_ip;     	/* SLIP/PPP address or login-host. 	*/
    time_t 	ut_time;       	/* Start of session. 			*/
    time_t 	length;        	/* Session length in seconds. 		*/
    UINT4 	inb;	       	/* IN bytes 				*/
    UINT4 	outb;	       	/* OUT bytes 				*/
    UINT4	rxrate;		/* Input transmission rate              */
    UINT4	txrate;		/* Output transmission rate             */
    STRING	callingid;	/* CLI of caller 			*/
    STRING	calledid;	/* CLI of NAS 				*/
} radlast;

/* The internal queue structure we use... */
typedef struct acct_packet {
    char 	username[USERNAME_MAX];
    char 	sessionid[11];		/* this should be fixed length... */
    int 	port;
    UINT4	nas_ip;
    int		type; /* stop or start */
    struct acct_packet	*next;
} acct_packet;			

/*
 *      t_days - bit array for each day of the week (0 = Sunday)
 *      t_start - starting time for this entry
 *      t_end - ending time for this entry
 */
struct  time_frame {
    short 	t_days;
    short 	t_start;
    short 	t_end;
};

/* workaround for missing PATH_MAX definition */

#ifndef	PATH_MAX
#ifdef 	_POSIX_PATH_MAX
#define PATH_MAX _POSIX_PATH_MAX
#else /* _POSIX_PATH_MAX */
#define PATH_MAX 512
#endif /* _POSIX_PATH_MAX */
#endif /* PATH_MAX */

#define ID_LENGTH 32

#if defined(SECURID) || defined(ACTIVCARD)
#define SMARTCARD
#endif

#if defined(__MAIN__)

#if defined(PAM)
int usepamacct=0;
int usepamauth=0;
#endif

#else /* ! __MAIN__ */

#if defined(PAM)
extern int usepamacct;
extern int usepamauth;
#endif

#endif /* __MAIN__ */

#endif /* __YARD_H */

