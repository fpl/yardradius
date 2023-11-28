/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

/*
 * testuser - test program to retrieve an entry from the user table
 */ 

static char rcsid[] = "$Id: testuser.c 75 2004-08-02 18:40:07Z flovergine $";

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdarg.h>
#include	"radius.h"
#include	"users.h"
#include	"prototypes.h"

char		*progname;
int		debug_flag;
int		radius_gdbm;
char		*radius_dir;
char		*radius_log;

int		accept_zero = 0;
int		debug_mem = 0;

void 
dump_pair(VALUE_PAIR * vp)
{
	while (vp) {
		if (vp->attribute == PW_PORT_MESSAGE) {
			printf(" from %s\n", vp->strvalue);
		}
		vp = vp->next;
	}
}

void 
usage(void)
{
	printf("usage: testuser <username>\n");
	exit(1);
}

VALUE_PAIR* 
get_attribute(VALUE_PAIR*value_list,int attribute)
{
	while(value_list != (VALUE_PAIR *)NULL) {
		if(value_list->attribute == attribute) {
			return(value_list);
		}
		value_list = value_list->next;
	}
	return (VALUE_PAIR *)NULL;
}

void 
rad_exit(int rc)
{
	exit(rc);
}


int 
main(int argc, char **argv)
{
	USER_FILE	user_desc;
	VALUE_PAIR	*user_check;
	VALUE_PAIR	*user_reply;
	char		auth_name[AUTH_STRING_LEN + 2];
	char		*req_name;
	int		i;

	debug_flag = 1;
	radius_gdbm = 0;
	req_name = (char *)NULL;
	for (i=1; i<argc; i++) {
		if (*argv[i] == '-') {
			radius_gdbm = 1;
		} else {
			req_name = argv[i];
		}
	}
	if (req_name == (char *)NULL) {
		usage();
	}
	progname = argv[0];
	radius_dir = "raddb";
	radius_log = "/dev/tty";

	log_version();

	if(dict_init() != 0) {
		printf("dict_init FAILED\n");
		exit(1);
	}

	/*
	 * Open the user table
	 */
	user_desc = user_open();
	if( user_desc.gdbm == NULL && user_desc.flat == NULL ) {
		return(-1);
	}

	for (;;) {
		if (user_find(	req_name,
				auth_name,
				&user_check,
				&user_reply,
				user_desc) != 0) {
			printf("user req_name <%s> NOT Found!\n", req_name);
			break;
		}
		printf("Found user req_name <%s> auth_name <%s>\n",
			req_name, auth_name);
		dump_pair(user_reply);
		pairfree(user_check,"main");
		pairfree(user_reply,"main");
	}
	user_close(user_desc);
	exit(0);
}

