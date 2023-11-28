/*
 * Copyright (C) 1999-2004 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

static char rcsid[] = "$Id: dbmrec.c 80 2004-08-19 16:19:18Z flovergine $";

#include	<stddef.h>
#include	<fcntl.h>

#include	"radius.h"

#ifdef NDBM
# include	<ndbm.h>
#else /* not NDBM */
# include	<dbm.h>
#endif /* NDBM */

int		radius_dbm;
char		*radius_dir;
char		*radius_log;
char		*progname;

int		accept_zero = 0;
int		debug_flag = 0;
int		debug_mem = 0;

extern int errno;

int
main( int argc,char *argv[] )
{
	VALUE_PAIR	*values;
	char 		*ptr;
	datum		key;
	datum		rec;
	int		dict_init();
	int		userparse();
	void		pairfree();
	void		show_val();
	void		usage();
	void		log_version();
#ifdef NDBM
	DBM		*db;
#endif /* NDBM */

	progname = argv[0];
	if (argc != 2) {
		usage();
	}
	radius_dbm = 1;
	radius_dir = "raddb";
	radius_log = "/dev/tty";


	log_version();
	if(dict_init() != 0) {
		printf("dict_init FAILED\n");
		exit(1);
	}

#ifdef NDBM
	if ((db = dbm_open("raddb/users", O_RDONLY, 0)) == (DBM *)NULL)
#else /* not NDBM */
	if(dbminit("raddb/users") != 0)
#endif /* NDBM */
	{
		printf("Couldn't open DBM file error<%s>\n",
				strerror(errno));
		exit(errno);
	}

	key.dptr = argv[1];
	key.dsize = strlen(key.dptr);

#ifdef NDBM
	rec = dbm_fetch(db, key);
#else /* not NDBM */
	rec = fetch(key);
#endif /* NDBM */

	if (rec.dsize == 0) {
		printf("Record <%s> not found!\n", key.dptr);
	} else {
		printf("Recode <%s> len %d\n", key.dptr, rec.dsize);
		ptr = rec.dptr;
		rec.dptr[rec.dsize] = '\0';

		values = (VALUE_PAIR *)NULL;

		/*
		 * Parse check values
		 */
		if(userparse(ptr, &values) != 0) {
			log_err("userparse ERROR\n");
		}
		show_val("Check", values);
		pairfree(values,"main");
		values = (VALUE_PAIR *)NULL;

		while(*ptr != '\n' && *ptr != '\0') {
			ptr++;
		}
		if(*ptr == '\n') {
			ptr++;

			/*
			 * Parse reply values
			 */
			if(userparse(ptr, &values) != 0) {
				log_err("userparse ERROR\n");
			}
			show_val("Reply", values);
			pairfree(values,"main");
		}
	}

#ifdef NDBM
	dbm_close(db);
#else /* not NDBM */
	dbmclose();
#endif /* NDBM */
	exit(0);
}

void
show_val( char *str,VALUE_PAIR *vp )
{
	printf("%s values:\n", str);
	while (vp) {
		printf("  <%s> = ", vp->name);
		switch(vp->type) {
		case PW_TYPE_STRING:
			printf("<%s>\n", vp->strvalue);
			break;
		case PW_TYPE_INTEGER:
		case PW_TYPE_IPADDR:
		case PW_TYPE_DATE:
			printf("<%x>\n",(unsigned int)vp->lvalue);
			break;
		}
		vp = vp->next;
	}
}

VALUE_PAIR *
get_attribute( VALUE_PAIR *value_list,int attribute )
{
	while(value_list != (VALUE_PAIR *)NULL) {
		if(value_list->attribute == attribute) {
			return(value_list);
		}
		value_list = value_list->next;
	}
	return((VALUE_PAIR *)NULL);
}

void
usage( void )
{
	printf("usage: %s <key>\n", progname);
	exit(1);
}

void
rad_exit( int rc )
{
	exit(rc);
}
