/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

#include "yard.h"
#include "global.h"

/*************************************************************************
 *
 *	Function: log_info
 *
 *	Purpose: Log the info message
 *
 *************************************************************************/

void 
log_info(char * fmt, ...)
{
	va_list	args;

	va_start(args, fmt);
	log_msg(LOG_INFO, fmt, args);
	va_end(args);
}

/*************************************************************************
 *
 *	Function: log_err
 *
 *	Purpose: Log the error message
 *
 *************************************************************************/

void 
log_err(char * fmt, ...)
{
	va_list	args;

	va_start(args, fmt);
	log_msg(LOG_ERR, fmt, args);
	va_end(args);
}

/*************************************************************************
 *
 *	Function: log_debug
 *
 *	Purpose: Log the debug message
 *
 *************************************************************************/

void 
log_debug(char * fmt, ...)
{
	va_list	args;
	
	va_start(args, fmt);
	log_msg(LOG_DEBUG, fmt, args);
	va_end(args);
}

/*************************************************************************
 *
 *	Function: log_msg
 *
 *	Purpose: Log the priority message
 *
 *************************************************************************/

void 
log_msg(int priority,char *fmt, va_list args)
{
	FILE	*msgfd;
	time_t	timeval;
	char buffer[1024];

	if (radius_log) {
		/*
		 * use users option logfile [-l <logfile>]
		 */
		if((msgfd = fopen(radius_log, "a")) == NULL) {
			fprintf(stderr, "%s: could not open %s for logging\n",
					progname, radius_log);
			return;
		}
		timeval = time(0);
		fprintf(msgfd, "%-24.24s: [%d] ", ctime(&timeval),getpid());
		vfprintf(msgfd, fmt, args);
		fflush(msgfd);
		fclose(msgfd);
	} else {
		/*
		 * use syslog
		 */
		openlog("radius", LOG_PID | LOG_CONS | LOG_NOWAIT, LOG_AUTH);
#if !defined(HAVE_VSYSLOG)
		vsnprintf(buffer,1024,fmt, args);
#if defined(HAVE_SYSLOG)
		syslog(priority, buffer);
#else
#error "Cannot call syslog() or vsyslog() to talk with the syslog daemon"
#endif
#else 
		vsyslog(priority, fmt, args);
#endif
		closelog();
	}
	return;
}
