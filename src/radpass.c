/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

static char rcsid[] = "$Id: radpass.c 75 2004-08-02 18:40:07Z flovergine $";

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<unistd.h>
#include	<netdb.h>
#include	<pwd.h>

#include	"radius.h"

#define MAXPWNAM	8
#define MAXPASS		16

u_char		recv_buffer[4096];
u_char		send_buffer[4096];
u_char		*progname;
int		sockfd;
u_char		vector[AUTH_VECTOR_LEN];
u_char		oldpass[AUTH_PASS_LEN];

int 
main(int argc, char *argv)
{
	int			salen;
	int			result;
	struct	sockaddr	salocal;
	struct	sockaddr	saremote;
	struct	sockaddr_in	*sin;
	struct	servent		*svp;
        u_short                 svc_port;
	AUTH_HDR		*auth;
	u_char			*username;
	u_char			newpass1[AUTH_PASS_LEN];
	u_char			newpass2[AUTH_PASS_LEN];
	u_char			passbuf[AUTH_PASS_LEN];
	u_char			md5buf[256];
	u_char			*oldvector;
	UINT4			auth_ipaddr;
	u_short			local_port;
	int			total_length;
	u_char			*ptr;
	int			length;
	int			secretlen;
	int			i;

	progname = argv[0];

	if(argc != 2) { usage(); }

	/* Get the user name */

	username = argv[1];

	svp = getservbyname ("radius", "udp");
	if (svp == (struct servent *) 0) {
		fprintf (stderr, "No such service: %s/%s\n", "radius", "udp");
		exit(-1);
	}
	svc_port = ntohs((u_short) svp->s_port);

	/* Get the IP address of the authentication server */
	if((auth_ipaddr = get_ipaddr("radius-server")) == (UINT4)0) {
		fprintf(stderr, "Couldn't find host radius-server\n");
		exit(-1);
	}

	sockfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		(void) perror ("socket");
		exit(-1);
	}

	sin = (struct sockaddr_in *) & salocal;
        memset ((char *) sin, '\0', sizeof (salocal));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = INADDR_ANY;

	local_port = 1025;
	do {
		local_port++;
		sin->sin_port = htons((u_short)local_port);
	} while((bind(sockfd, &salocal, sizeof (struct sockaddr_in)) < 0) &&
						local_port < 64000);
	if(local_port >= 64000) {
		close(sockfd);
		(void) perror ("bind");
		exit(-1);
	}

	printf("Changing Password for user %s\n", username);

	/* Get their old password */
	strcpy((char *)oldpass, getpass("Old Password:"));
	if(*oldpass == '\0') {
		exit(0);
	}

	/* Get their new password */
	strcpy((char *)newpass1, getpass("New Password:"));
	if(*newpass1 == '\0') {
		exit(0);
	}

	/* Get their new password again */
	strcpy((char *)newpass2, getpass("Re-type New Password:"));
	if(strcmp(newpass1, newpass2) != 0) {
		printf("New Passwords didn't match\n");
		exit(-1);
	}

	/* Build a password change request */
	auth = (AUTH_HDR *)send_buffer;
	auth->code = PW_PASSWORD_REQUEST;
	auth->id = 0;
	random_vector(vector);
	memcpy(auth->vector, vector, AUTH_VECTOR_LEN);
	total_length = AUTH_HDR_LEN;
	ptr = auth->data;

	/* User Name */
	*ptr++ = PW_USER_NAME;
	length = strlen(username);
	if(length > MAXPWNAM) {
		length = MAXPWNAM;
	}
	*ptr++ = length + 2;
	memcpy(ptr, username, length);
	ptr += length;
	total_length += length + 2;

	/* New Password */
	*ptr++ = PW_PASSWORD;
	*ptr++ = AUTH_PASS_LEN + 2;

	/* Encrypt the Password */
	length = strlen(newpass1);
	if(length > MAXPASS) {
		length = MAXPASS;
	}
	memset(passbuf, 0, AUTH_PASS_LEN);
	memcpy(passbuf, newpass1, length);
	/* Calculate the MD5 Digest */
	secretlen = strlen(oldpass);
	strcpy(md5buf, oldpass);
	memcpy(md5buf + secretlen, auth->vector, AUTH_VECTOR_LEN);
	md5_calc(ptr, md5buf, secretlen + AUTH_VECTOR_LEN);
	oldvector = ptr;
	/* Xor the password into the MD5 digest */
	for(i = 0;i < AUTH_PASS_LEN;i++) {
		*ptr++ ^= passbuf[i];
	}
	total_length += AUTH_PASS_LEN + 2;

	/* Old Password */
	*ptr++ = PW_OLD_PASSWORD;
	*ptr++ = AUTH_PASS_LEN + 2;

	/* Encrypt the Password */
	length = strlen(oldpass);
	if(length > MAXPASS) {
		length = MAXPASS;
	}
	memset(passbuf, 0, AUTH_PASS_LEN);
	memcpy(passbuf, oldpass, length);
	/* Calculate the MD5 Digest */
	secretlen = strlen(oldpass);
	strcpy(md5buf, oldpass);
	memcpy(md5buf + secretlen, oldvector, AUTH_VECTOR_LEN);
	md5_calc(ptr, md5buf, secretlen + AUTH_VECTOR_LEN);

	/* Xor the password into the MD5 digest */
	for(i = 0;i < AUTH_PASS_LEN;i++) {
		*ptr++ ^= passbuf[i];
	}
	total_length += AUTH_PASS_LEN + 2;

	auth->length = htonl(total_length);

	sin = (struct sockaddr_in *) & saremote;
        memset ((char *) sin, '\0', sizeof (saremote));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(auth_ipaddr);
	sin->sin_port = htons(svc_port);

	sendto(sockfd, (char *)auth, (int)total_length, (int)0,
			&saremote, sizeof(struct sockaddr_in));

	salen = sizeof (saremote);
	result = recvfrom (sockfd, (char *) recv_buffer,
			(int) sizeof(recv_buffer),
			(int) 0, & saremote, & salen);

	if(result > 0) {
		result_recv(sin->sin_addr.s_addr,
					sin->sin_port, recv_buffer, result);
		exit(0);
	}
	(void) perror ("recv");
	close(sockfd);
	exit(0);
}

int
result_recv( UINT4 host, u_short udp_port, u_char *bufferr, int length )
{
	AUTH_HDR	*auth;
	int		totallen;
	char		*ip_hostname();
	u_char		reply_digest[AUTH_VECTOR_LEN];
	u_char		calc_digest[AUTH_VECTOR_LEN];
	int		secretlen;

	auth = (AUTH_HDR *)buffer;
	totallen = ntohs(auth->length);

	if(totallen != AUTH_HDR_LEN) {
		printf("Received invalid reply length from server\n");
		exit(-1);
	}

	/* Verify the reply digest */
	memcpy(reply_digest, auth->vector, AUTH_VECTOR_LEN);
	memcpy(auth->vector, vector, AUTH_VECTOR_LEN);
	secretlen = strlen(oldpass);
	memcpy(buffer + AUTH_HDR_LEN, oldpass, secretlen);
	md5_calc(calc_digest, (char *)auth, AUTH_HDR_LEN);

	if(memcmp(reply_digest, calc_digest, AUTH_VECTOR_LEN) != 0) {
		printf("Warning: Received invalid reply digest from server\n");
	}

	if(auth->code == PW_PASSWORD_ACK) {
		printf("Password successfully changed\n");
	}
	else {
		printf("Request Denied\n");
	}
}

int
usage( void )
{
	printf("Usage: %s username\n", progname);
	exit(-1);
}

int
random_vector( u_char *vector )
{
	int	randno;
	int	i;

	srand(time(0));
	for(i = 0;i < AUTH_VECTOR_LEN;) {
		randno = rand();
		memcpy(vector, &randno, sizeof(int));
		vector += sizeof(int);
		i += sizeof(int);
	}
}
