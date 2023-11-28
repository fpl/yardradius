/*
 * Copyright (C) 1999-2004 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

static char rcsid[] = "$Id: dbmkeys.c 80 2004-08-19 16:19:18Z flovergine $";

#include	<stddef.h>
#include	<fcntl.h>
#include	"radius.h"
#include	"gdbm.h"

extern int errno;

int 
main(int argc, char **argv)
{
	datum		key;
	GDBM_FILE	db;
	int		i;

	if ((db=gdbm_open(RADIUS_USERSDB,0,GDBM_READER,0600,NULL)) == NULL)
	{
		printf("Couldn't open GDBM file error <%s>\n",
				gdbm_strerror(gdbm_errno));
		exit(errno);
	}

	for (i=1; ; i++) {
		if (i == 1) {
			key = gdbm_firstkey(db);
		} else {
			key = gdbm_nextkey(db);
		}
		if(key.dsize == 0) {
			break;
		}
		key.dptr[key.dsize] = 0;
		printf(" %4d key <%s>\n", i, key.dptr);
	}

	gdbm_close(db);
	exit(0);
}
