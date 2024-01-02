/*
 *	md5test - calculate md5 checksum for testing purposes
 */

/***********************************************************************

RADIUS
Remote Authentication Dial In User Service

Lucent Technologies Remote Access
4464 Willow Road
Pleasanton, CA   94588

Copyright 1992-1999 Lucent Technologies Inc.  All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

   * Redistributions in binary form must reproduce the above
     copyright notice, this list of conditions and the following
     disclaimer in the documentation and/or other materials provided
     with the distribution.

   * All advertising materials mentioning features or use of this
     software must display the following acknowledgement:

	  This product includes software developed by Lucent
	  Technologies and its contributors.

   * Neither the name of the copyright holder nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.

This software is provided by the copyright holders and contributors
``as is'' and any express or implied warranties, including, but not
limited to, the implied warranties of merchantability and fitness for a
particular purpose are disclaimed. In no event shall the copyright
holder or contributors be liable for any direct, indirect, incidental,
special, exemplary, or consequential damages (including, but not
limited to, procurement of substitute goods or services; loss of use,
data, or profits; or business interruption) however caused and on any
theory of liability, whether in contract, strict liability, or tort
(including negligence or otherwise) arising in any way out of the use
of this software, even if advised of the possibility of such damage.

************************************************************************/

/*	Usage:	md5test takes the shared secret as an argument,
		reads a hex dump on standard input, and outputs
		the length, shared secret, standard input, followed
		by the MD5 checksum of that input followed by the
		shared secret.

		This skeleton program is useful combined with 
		radiusd -x -x to make sure that the right checksums are
		being calculated

 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

extern void md5_calc( unsigned char *output, unsigned char *input, unsigned int inlen );

int
main( int argc, char **argv )
{
	u_char buf[256],pw_digest[16];
	int h;
	int i,n = 0,len;

	*argv++;
	while (scanf("%2x",&h) != EOF) {
		buf[n++] = h & 0xff;
	}
	printf("%d %s\n",n,*argv);
	len=strlen(*argv);
	memcpy(&buf[n],*argv,len);
	md5_calc((u_char*)pw_digest, (u_char*)buf, n+len);
	for (i=0;i<n;i++) {
		printf("%02x ",buf[i]);
		if ((i&0xf) == 0xf) {
			printf("\n");
		}
	}
	printf ("\n");
	for (i=0;i<16;i++) {
		printf("%02x ",pw_digest[i]);
	}
	printf ("\n");
}

