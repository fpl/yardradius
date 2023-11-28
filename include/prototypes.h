#ifndef __PROTOTYPES_H
#define __PROTOTYPES_H

/*
 * Copyright (C) 1999-2002, Francesco P. Lovergine. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

/* $Id: prototypes.h 81 2004-08-27 21:45:17Z flovergine $ */

/* 
 * PROTOTYPES
 *
 * This file lists relevant prototypes of all the functions in this
 * distribution.
 */

/*--- acct.c */
void rad_acctreq(int fd);
int rad_accounting(AUTH_REQ *authreq, int sign);
void send_acct_reply(AUTH_REQ *authreq,VALUE_PAIR *reply,int activefd);
int calc_acctreq( UINT4 client,char *secret,int secretlen,u_char *buffer,int buflen );

/*-- dict.c */
int dict_init(void);
DICT_ATTR*dict_attrget(int attribute);
DICT_ATTR*dict_vsattrget(int vendor,int vsa);
DICT_ATTR*dict_attrfind(char*attrname);
DICT_VALUE*dict_valfind(char *valname);
DICT_VALUE*dict_valget(UINT4 value,char*attrname);
int dict_vendor(char *vendname);

/*--- extens.c */
int is_on_group(const char *user_name, const char *group_name);
int check_logins(char *user, const int max_logins);
int check_maxtime(char *user, const int hours,const int kind);
int clean_user_stats(void);
int deny_user(const char *username);
int update_user_status(AUTH_REQ *authreq);
int shadow_expired(const char *user);
int validate_acct_packet(AUTH_REQ *authreq);
char *crypt_md5(const char *pw, const char *salt);
int allowed_time(const char *time_str);
int check_maxtraffic(char *user, const int size,const int kind);

/*--- log.c */
void log_err(char *fmt, ...);
void log_debug(char *fmt, ...);
void log_msg(int priority, char *fmt, va_list args);

/*--- md5.c */
void md5_calc(unsigned char *output, unsigned char *input, unsigned int inlen);

/*--- menu.c */
void process_menu(AUTH_REQ *authreq, int activefd, char *pw_digest);
char *get_menu(char *menu_name);
VALUE_PAIR *menu_pairs(char *menu_name, char *menu_selection);

/*--- pam.c */
int unix_pam(const char *name, const char *passwd, const char *pamauth);
void pam_session(AUTH_REQ *authreq);

/*--- pass.c */
int unix_pass(char*name,char*passwd,char*from);
int unix_group(const char*name,const char*group);
char * unix_gecos(const char*name);
char * unix_shell(const char*name);
struct passwd *getownpwnam(const char*name);

/*--- proxy.c */
void rad_proxy(int fd);
AUTH_REQ *pop_proxy(AUTH_REQ *authreq,AUTH_REQ *qp);
void send_proxy2client(int fd,AUTH_REQ*authreq,PEER*server,AUTH_REQ*qp);
int update_proxy(void);
int handle_proxy(AUTH_REQ*authreq);
void push_proxy(AUTH_REQ*authreq);
PEER * find_server(char *number,char *realm);
PEER *find_server_byaddr(UINT4 ipaddr,u_short port);
void send_proxy2server(AUTH_REQ*authreq,PEER*server);
u_char getnextid(AUTH_REQ *authreq);
void proxy_report(void);

/*--- radiusd.c */
int open_udpsock(u_short *port,int defport,char *service);
void send_packet(int fd, UINT4 ipaddr, u_short port, char * buffer, int length);
void rad_request(int fd);
AUTH_REQ *radrecv(UINT4 host,u_short udp_port,char* secret,u_char* buffer,int length);
void radrespond(AUTH_REQ *authreq,int activefd);
void rad_spawn_child(AUTH_REQ *authreq,int activefd);
void clean_child(int pid);
void sig_cleanup(int sig);
void child_authenticate(AUTH_REQ *authreq,int activefd);
int rad_authenticate(AUTH_REQ *authreq,int activefd);
void send_reject(AUTH_REQ *authreq,char *msg,int activefd);
void send_challenge(AUTH_REQ *authreq,char *msg,char *state,int activefd);
void send_accept(AUTH_REQ *authreq,VALUE_PAIR *reply,char *msg,int activefd);
int build_packet(AUTH_REQ*authreq,VALUE_PAIR*reply,char*msg,u_char code,int forward,u_char*buffer,size_t buflen);
char * decrypt_password(AUTH_REQ *authreq,char *secret);
char * encrypt_password(AUTH_REQ *authreq,char *secret);
void calc_digest(u_char *digest,AUTH_REQ *authreq,u_char *secret);
void calc_next_digest(u_char*digest,u_char*secret,u_char*vector);
char* client_hostname(UINT4 ipaddr);
int find_client(UINT4 ipaddr,char*secret,int secretlen,char*hostnm,size_t hostnmlen);
int update_clients(void);
void debug_pair(VALUE_PAIR * pair);
void usage(void);
int config_init(void);
int set_expiration(VALUE_PAIR*user_check,UINT4 expiration);
int pw_expired(UINT4 exptime);
VALUE_PAIR* get_attribute(VALUE_PAIR*value_list,int attribute);
void sig_fatal(int sig);
void sig_hup(int sig);
void sig_usr1(int sig);
void sig_usr2(int sig);
void rad_exit(int rc);
void log_counters(void);
int main( int argc,char **argv );

/*--- securid.c */
int securid(char *username, char *password, AUTH_REQ *authreq, VALUE_PAIR *user_reply, int activefd);

/*--- users.c */
int user_find(char*req_name, char*auth_name,VALUE_PAIR**check_pairs,VALUE_PAIR**reply_pairs,USER_FILE user_desc);
int user_auth_name(char*rname,char*auth_name,VALUE_PAIR*check_first);
int userparse(char*buffer,VALUE_PAIR**first_pair);
int user_gettime( char*valstr,struct tm*tm );
USER_FILE user_open(void);
FILE * user_open_flat(char*file_name);
void user_close(USER_FILE user_file);

/*--- util.c */
char* ip_hostname(UINT4 ipaddr);
UINT4 get_ipaddr(char *host);
int good_ipaddr(char*addr);
void ipaddr2str(char*buffer,size_t buflen,UINT4 ipaddr);
char*ipaddr2strp(UINT4 ipaddr);
UINT4 ipstr2long(char*ip_str);
char* req2str(char *buffer,size_t buflen,AUTH_REQ *authreq);
char* req2strp(AUTH_REQ *authreq);
char * bufalloc(int size,char*where);
void buffree(char*buf,char*where);
VALUE_PAIR *pairalloc(char*where);
void pairfree(VALUE_PAIR*pair,char*where);
PEER * peeralloc(char *where);
void peerfree(PEER*peer,char*where);
AUTH_REQ *reqalloc(char*where);
void reqfree( AUTH_REQ*authreq,char*where);
void memreport(void);
void fprint_attr_val(FILE*fd,VALUE_PAIR*pair);
void fprint_attr_putc(u_char cc,u_char *buf);
void hexdump(u_char*buf,int n);

/*--- version.c */
void version(void);
void log_version(void);
void build_version(char *bp,size_t sizeofbp);

/*--- radwatch.c */
int check_user_time(const char *id, time_t when);

/*--- filters.c */
#if defined(ASCEND_BINARY)
int filterBinary(VALUE_PAIR *pair,char*valstr);
#endif

/*--- snprintf.c */
#if !defined(HAVE_LOCAL_SNPRINTF)
int snprintf (char *str, size_t count, const char *fmt, ...);
int vsnprintf (char *str, size_t count, const char *fmt, va_list arg);
#endif

#endif
