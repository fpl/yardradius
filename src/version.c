/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

static char rcsid[] = "$Id: version.c 75 2004-08-02 18:40:07Z flovergine $";

#include "yard.h"
#include "global.h"
#include "hostinfo.h"

/*  If you make any changes to this software please update this version number
 */

#define	 STRVER "%s : YARD Radius Server %s $Date: 2004-08-02 20:40:07 +0200 (lun, 02 ago 2004) $ "

/*************************************************************************
 *
 *	Function: version
 *
 *	Purpose: Display the revision number for this program
 *
 *************************************************************************/

void 
version(void)
{
	char buffer[1024];

	build_version(buffer,sizeof(buffer));
	fprintf(stderr, buffer);
	exit(-1);
}

void 
log_version(void)
{
	char buffer[1024];

	build_version(buffer,sizeof(buffer));
	log_info("%s",buffer);
}

void 
build_version(char *bp,size_t sizeofbp)
{
	snprintf(bp,sizeofbp-1,STRVER, progname, VERSION);

	/* here are all the conditional feature flags */

# if defined(ACTIVCARD)
	strncat(bp," ACTIVCARD",sizeofbp-strlen(bp)-1);
# endif

# if defined(IPASS)
	strncat(bp," IPASS",sizeofbp-strlen(bp)-1);
# endif

# if defined(SECURID)
	strncat(bp," SECURID",sizeofbp-strlen(bp)-1);
# endif

#if defined(SHADOW_PASSWORD)
	strncat(bp," SHADOW",sizeofbp-strlen(bp)-1);	/* system has no /usr/include/shadow.h */
#endif

	/* here are all the system definitions compilation uses */

	strncat(bp," ",sizeofbp-strlen(bp)-1); 
	strncat(bp,HOSTINFO,sizeofbp-strlen(bp)-1);
	if (accept_zero) {
		strncat(bp," zero_accepted",sizeofbp-strlen(bp)-1);
	}
	strncat(bp, radius_gdbm ? " gdbm_users" : " flat_users",sizeofbp-strlen(bp)-1);
	strncat(bp,"\n",sizeofbp-strlen(bp)-1);
}
