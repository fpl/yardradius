/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

static char rcsid[] = "$Id: pass.c 81 2004-08-27 21:45:17Z flovergine $";

#include "yard.h"
#include "global.h"

struct passwd	pw;
char	pwbuf[MAX_LINE_SIZE];

/*************************************************************************
 *
 *	Function: unix_pass
 *
 *	Purpose: Check the users password against the standard UNIX
 *		 password table.
 *
 *************************************************************************/

int 
unix_pass(char*name,char*passwd,char*from)
{
	struct passwd	*pwd;
	char		*encpw;
	char		*encrypted_pass;
	char		*crypt();
#if defined(SHADOW_PASSWORD)
#if defined(HAVE_GETSPNAM)
	struct spwd	*spwd;
#endif 
#endif 

	/* Get encrypted password from alternate password file */
	if (alt_passwd != (char *)NULL) {
		if((pwd = getownpwnam(name)) == NULL) {
			debug("unix_pass: getownpwnam for \"%s\"%s failed\n", 
				name, from);
			return(-1);
		}
		encrypted_pass = pwd->pw_passwd;
	}
	else {
	/* Get encrypted password from password file */
		if((pwd = getpwnam(name)) == NULL) {
			debug("unix_pass: getpwnam for \"%s\"%s failed\n",
				name, from);
			return(-1);
		}

#if defined(BSD4_4)
		/* Return failed if Unix Account is expired (locked out) */
		if (pwd->pw_expire && (pwd->pw_expire < time((time_t *)NULL))) {
			debug("unix_pass: account for \"%s\"%s"
			        " has expired\n",name, from);
			return(-1);
		}
#endif
		encrypted_pass = pwd->pw_passwd;

#if defined(SHADOW_PASSWORD)
		if(strcmp(pwd->pw_passwd, "x") == 0 ||
		   strcmp(pwd->pw_passwd, "*") == 0 ||
		   strcmp(pwd->pw_passwd, "*NP*") == 0) {
#if defined(HAVE_GETSPNAM)
		   if((spwd = getspnam(name)) == NULL) { return(-1); }
		   encrypted_pass = spwd->sp_pwdp;
		}
#endif
#endif
	}

	/* Run encryption algorythm */
	encpw = crypt(passwd, encrypted_pass);

	/* Check it */
	if(strcmp(encpw, encrypted_pass)) {
		debug("unix_pass: password for \"%s\"%s failed\n", name, from);
		return(-1);
	}
	return(0);
}

/*************************************************************************
 *
 *	Function: unix_group
 *
 *	Purpose: Check the user's membership to the standard UNIX
 *		 group table.
 *
 *************************************************************************/

int 
unix_group(const char*name,const char*group)
{
	struct passwd	*pwd;
	char		**gr_mem;
	struct group	*gr_ent;
	
	/* Get encrypted password from alternate password file */
	if (alt_passwd != (char *)NULL) {
		if((pwd = getownpwnam(name)) == NULL) {
			debug("unix_group: getownpwnam for \"%s\" failed\n", name);
			return(-1);
		}
	} else {
	/* Get encrypted password from password file */
		if((pwd = getpwnam(name)) == NULL) {
			debug("unix_group: getpwnam for \"%s\" failed\n", name);
			return(0);
		}
	}

	if((gr_ent = getgrnam(group)) == NULL) {
		debug("unix_group: getgrnam(%s) for \"%s\" failed\n", group,name);
		return(0);
	}

	/* Check the immediate group */
	if(pwd->pw_gid == gr_ent->gr_gid) {
		return(1);
	}
	/* Search for this user */
	gr_mem = gr_ent->gr_mem;
	while(*gr_mem != NULL) {
		if(strcmp(*gr_mem, name) == 0) {
			return(1);
		}
		gr_mem++;
	}
	return(0);
}


/*************************************************************************
 *
 *	Function: unix_gecos
 *
 *	Purpose: Get the user's GECOS field or "" if it is empty.
 *
 *************************************************************************/

char *
unix_gecos(const char*name)
{
	struct passwd	*pwd;
	
	/* get encrypted password from alternate password file */
	if (alt_passwd != (char *)NULL) {
		if((pwd = getownpwnam(name)) == NULL) {
			debug("unix_gecos: getownpwnam for \"%s\" failed\n", name);
			return "";
		}
	} else {
	/* get encrypted password from password file */
		if((pwd = getpwnam(name)) == NULL) {
			debug("unix_gecos: getpwnam for \"%s\" failed\n", name);
			return "";
		}
	}

	return pwd->pw_gecos;
}


/*************************************************************************
 *
 *	Function: unix_shell
 *
 *	Purpose: Get the user's shell or "" if it is empty.
 *
 *************************************************************************/

char *
unix_shell(const char*name)
{
	struct passwd	*pwd;
	
	/* get encrypted password from alternate password file */
	if (alt_passwd != (char *)NULL) {
		if((pwd = getownpwnam(name)) == NULL) {
			debug("unix_gecos: getownpwnam for \"%s\" failed\n", name);
			return "";
		}
	} else {
	/* get encrypted password from password file */
		if((pwd = getpwnam(name)) == NULL) {
			debug("unix_gecos: getpwnam for \"%s\" failed\n", name);
			return "";
		}
	}

	return pwd->pw_shell;
}

struct passwd *
getownpwnam(const char*name)
{
	extern char	*alt_passwd;
	extern char	pwbuf[];
	extern struct passwd	pw;
	FILE		*pwfd;
	char		*ptr;

	if (alt_passwd == (char *)NULL) {
		return (struct passwd *)NULL;
	}
	if((pwfd = fopen(alt_passwd, "r")) == (FILE *)NULL) {
		return (struct passwd *)NULL;
        }

	memset((char *)&pw,0,sizeof(pw));
	while(fgets(pwbuf, MAX_LINE_SIZE, pwfd) != (char *)NULL) {
		ptr = pwbuf;
		while (*ptr && *ptr != ':')
			ptr++;
		*ptr++ = '\0';
		if (strcmp(name,pwbuf) == 0) {
			pw.pw_name = pwbuf;
			pw.pw_passwd = ptr;
			while (*ptr && *ptr != ':')
				ptr++;
			*ptr++ = '\0';
			pw.pw_uid = atoi(ptr);
			while (*ptr && *ptr != ':')
				ptr++;
			*ptr++ = '\0';
			pw.pw_gid = atoi(ptr);
			while (*ptr && *ptr != ':')
				ptr++;
			*ptr++ = '\0';
			pw.pw_gecos = ptr;
			while (*ptr && *ptr != ':')
				ptr++;
			*ptr++ = '\0';
			pw.pw_dir = ptr;
			while (*ptr && *ptr != ':')
				ptr++;
			*ptr++ = '\0';
			pw.pw_shell = ptr;

			return (&pw);
		}
	}
	return (struct passwd *)NULL;
}
