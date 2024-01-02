#ifndef __GLOBAL_H
#define __GLOBAL_H
/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be 
 * enclosed with sources.
 */

/*
 * Contains global data definitions and declarations
 */

#ifdef __MAIN__

unsigned char recv_buffer[4096];
unsigned char send_buffer[4096];
char *progname;
UINT4 sockaddr;
int sockfd;
int acctfd;
int proxyfd;
int proxyacctfd;
int debug_flag;
int debug_mem;
int spawn_flag;
int accept_zero;
int acct_pid;
int radius_gdbm;
int max_proxy_time;
int max_requests;
int max_request_time;
const char *radius_dir;
const char *radacct_dir;
const char *radius_log;
char *alt_passwd;
u_short radius_port;
u_short radacct_port;
u_short radproxy_port;
u_short radpracct_port;
UINT4 expiration_seconds;
UINT4 now;
UINT4 warning_seconds;
extern int errno;
int cleanup_pid;
int report[RR_MAX];
char cached_hostnm[MAX_HOST_SIZE];
char unknown[8];
UINT4 cached_ipaddr;
int do_clean;
struct sockaddr_in rad_saremote;

#if defined(HAVE_LIBPAM)
const char *pam_auth = RADIUS_PAM_SERVICE;
#endif

#ifdef VPORTS
int vports_flag;
#endif

#else 

extern unsigned char recv_buffer[4096];
extern unsigned char send_buffer[4096];
extern char *progname;
extern UINT4 sockaddr;
extern int sockfd;
extern int acctfd;
extern int proxyfd;
extern int proxyacctfd;
extern int debug_flag;
extern int debug_mem;
extern int spawn_flag;
extern int accept_zero;
extern int acct_pid;
extern int radius_gdbm;
extern int max_proxy_time;
extern int max_requests;
extern int max_request_time;
extern const char *radius_dir;
extern const char *radacct_dir;
extern const char *radius_log;
extern char *alt_passwd;
extern u_short radius_port;
extern u_short radacct_port;
extern u_short radproxy_port;
extern u_short radpracct_port;
extern UINT4 expiration_seconds;
extern UINT4 now;
extern UINT4 warning_seconds;
extern int errno;
extern int cleanup_pid;
extern int report[RR_MAX];
extern char cached_hostnm[MAX_HOST_SIZE];
extern char unknown[8];
extern UINT4 cached_ipaddr;
extern int do_clean;
extern struct sockaddr_in rad_saremote;

#if defined(HAVE_LIBPAM)
extern const char *pam_auth;
#endif

#ifdef VPORTS
extern int vports_flag;
#endif

#endif /* __MAIN___ */

#endif /* __GLOBAL_H */
