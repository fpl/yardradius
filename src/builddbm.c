/*
 * Copyright (C) 1999-2004 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

static char rcsid[] = "$Id: builddbm.c 80 2004-08-19 16:19:18Z flovergine $";

#include	<config.h>

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<sys/file.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<netdb.h>
#include	<pwd.h>
#include	<time.h>
#include	<ctype.h>
#include        <errno.h>

#include	"yard.h"

/*--- Some global variables ---*/

char		*progname;
char		*radius_dir;
char		*radius_log;
int		debug_flag = 0;
int		radius_gdbm = 1;	/* needed for version() */
int		accept_zero = 0;

#define FIND_MODE_NAME	0
#define FIND_MODE_REPLY	1
#define FIND_MODE_SKIP	2
#define FIND_MODE_FLUSH	3

FILE		*userfd;
int		default_count;	/* number of DEFAULT entries found */
int		linenum;	/* line in users file, for error messages */
int		lineuser;	/* line current user started on, for error messages */

/*--- Exit codes for the program follow ---*/

#define EXITCODE_OK     0 /* all is ok */
#define EXITCODE_USAGE  1 /* incorrect usage */
#define EXITCODE_RADDIR 2 /* cannot access radius directory */
#define EXITCODE_DB     3 /* error accessing gdbm users file */
#define EXITCODE_UPDATE 4 /* error updating gdbm users file */
#define EXITCODE_USERS  5 /* cannot access radius users src file */


/*************************************************************************
 *
 *	Function: usage
 *
 *	Purpose: Display the syntax for starting this program.
 *
 *************************************************************************/

void 
usage(void)
{
	fprintf(stderr, "Usage: %s", progname);
	fprintf(stderr, " [-d <db_dir>]");
	fprintf(stderr, " [-l <logfile>]");
	fprintf(stderr, " [-h]");
	fprintf(stderr, " [-v]");
	fprintf(stderr, " [-x]\n");
	exit(EXITCODE_USAGE);
}



int 
main(int argc,char **argv)
{
	char	argval;
	char	content[1024];
	char	name[128];
	datum	contentd;
	datum	named;
	int	errcount;	/* number of users not stored, usually dups */ 
	int	usercount;	/* number of users stored */
	GDBM_FILE db;
	int	xx;


	/* Parse arguments */

	progname = *argv++;
	argc--;
	radius_dir = RADIUS_DIR;

	while(argc) {

		if(**argv != '-') {
			usage();
		}

		argval = *(*argv + 1);
		argc--;
		argv++;

		switch(argval) {

		case 'd':
			if(argc == 0) {
				usage();
			}
			radius_dir = *argv;
			argc--;
			argv++;
			break;

		case 'h':
			usage();
			break;

                case 'l':       /* change logging from syslog */
                        if(argc == 0) {
                                usage();
                        }
                        radius_log = *argv;
                        argc--;
                        argv++;
                        break;

		case 'v':
			version();
			break;

		case 'x':
			debug_flag = 1;
			break;
		
		default:
			usage();
			break;
		}
	}


        if (debug_flag) {
                if (radius_log == (char *)NULL) {
                        /*
                         * for backward compatibility
                         * send messages to users tty
                         */
                        radius_log = "/dev/tty";
                } else if (strcmp(radius_log, "syslog") == 0) {
                        /*
                         * allow user to override backward compatibility
                         * and send debug to syslog
                         */
                        radius_log = (char *)NULL;
                }
        }


	/* Open Database */

	errno = 0;
	if (chdir(radius_dir) < 0) {
		fprintf(stderr, "%s: unable to change to directory %s - %s\n",
		        progname,radius_dir,strerror(errno));
		exit(EXITCODE_RADDIR);
	}

	errno = 0;
        if ((db=gdbm_open(RADIUS_USERSDB,0,GDBM_NEWDB|GDBM_SYNC,0600,NULL))==NULL)
	  {
          fprintf(stderr, "%s: gdbm_open() failed - %s\n", progname,
          gdbm_strerror(gdbm_errno));
          exit(EXITCODE_DB);
          } 

	/* Read through users file putting entries into database */

	default_count = 0; errcount = 0; usercount = 0;
	while(user_read(name, content) == 0) {
		named.dptr = name;
		named.dsize = strlen(name);
		contentd.dptr = content;
		contentd.dsize = strlen(content);
                if((xx = gdbm_store(db, named, contentd, GDBM_INSERT)) != 0)
                {
                fprintf(stderr,"%s: could not store %s from line %d,"
                               "check for duplicate\n", progname,name,lineuser);
                errcount++;
                } else { usercount++; }
	}
        gdbm_close(db);

	/* report results */

        printf("%s: %d user%s stored in GDBM file",progname,usercount,usercount==1?"":"s");
        if (default_count > 0) {
                printf(" including %d DEFAULT entries\n",default_count);
        } else {
                printf("\n");                                                   
        }
        if (errcount > 0) {
                printf("%s: %d user%s not written to GDBM file," 
                       " check for duplicates\n",progname,errcount,
			errcount==1?"":"s");
		exit(EXITCODE_UPDATE);
        }                                       
        exit(EXITCODE_OK);                                        
}

/*************************************************************************
 *
 *	Function: user_read
 *
 *	Purpose: Return each user in the database - name is key content
 *		 is 2 strings - check values, and reply values seperated
 *		 by a newline.
 *
 *************************************************************************/

int 
user_read(char*name,char*content)
{
	extern int	linenum;
	extern int	lineuser;
	static char	buffer[256];
	char		*ptr;
	int		mode;
	char 		*base_name = name;

	/*
	 * Open the user table
	 */
	if(userfd == (FILE *)NULL) {
		if((userfd = fopen(RADIUS_USERS, "r")) == (FILE *)NULL) {
			fprintf(stderr, "%s: could not open %s for reading\n",
					progname, buffer);
			exit(EXITCODE_USERS);
		}
		linenum = 0;
		*buffer = '\0';
	}

	mode = FIND_MODE_NAME;

	while(*buffer || (fgets(buffer, sizeof(buffer), userfd) != (char *)NULL)) {
		linenum++;	/* track line number for error messages */
		/* skip comments */
		if (*buffer == '#') {
			*buffer = '\0';
			continue;
		}
		if(mode == FIND_MODE_NAME) {
			/*
			 * Find the entry starting with the users name
			 */
			if(*buffer != '\t' && *buffer != ' '
						&& *buffer != '\n'
						&& *buffer != '\r') {
				ptr = buffer;
				while(*ptr != ' ' && *ptr != '\t' &&
								*ptr != '\0') {
					*name++ = *ptr++;
				}
				*name = '\0';
				if(*ptr == '\0') {
					continue;
				}
				if (strncmp(base_name, "DEFAULT",7) == 0) {
					if (default_count > 0) {
						sprintf(base_name, "DEFAULT%d",
							default_count);
					}  else {
						strcpy(base_name, "DEFAULT");
					}
					default_count++;
				}
				ptr++;
				while(*ptr == ' ' || *ptr == '\t') {
					ptr++;
				}
				strcpy(content, ptr);
				content += strlen(content);
				mode = FIND_MODE_REPLY;
				lineuser = linenum;
			}
			*buffer = '\0';
		}
		else {
			if(*buffer == ' ' || *buffer == '\t') {
				ptr = buffer;
				while(*ptr == ' ' || *ptr == '\t') {
					ptr++;
				}
				strcpy(content, ptr);
				content += strlen(content) - 1;
				/* strip trailing white space and comma */
				while(*content == ' ' || *content == '\t' ||
					*content == '\n' || *content == ',' ) {
					content--;
				}
				content++;
				*content = ',';
				content++;
				*content = '\0';
				*buffer = '\0';
			}
			else {
				/* We are done, leave buffer for next call */
				if (*buffer == '\n') {
					*buffer = '\0';
				} else {
					linenum--;
				}
				if(*(content - 1) == ',') {
					*(content-1) = '\0';
				}
				return(0);
			}
		}
	}
	if (mode == FIND_MODE_REPLY) {	/* return last entry */
		*buffer = '\0';
		if(*(content - 1) == ',') {
			*(content-1) = '\0';
		}
		return (0);
	}
	fclose(userfd);
	return(-1);
}


