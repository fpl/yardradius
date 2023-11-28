/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

static char rcsid[] = "$Id: users.c 80 2004-08-19 16:19:18Z flovergine $";

#include "yard.h"
#include "global.h"

#define		MAXBUF	1024

int 		db_index;

/*************************************************************************
 *
 *	Function: fieldcpy
 *
 *	Purpose: Copy a data field from the buffer.  Advance the buffer
 *		 past the data field.
 *
 *************************************************************************/

static void 
fieldcpy(char*string,char**uptr)
{
	char	*ptr;

	ptr = *uptr;
	if(*ptr == '"') {
		ptr++;
		while(*ptr != '"' && *ptr != '\0' && *ptr != '\n') {
			*string++ = *ptr++;
		}
		*string = '\0';
		if(*ptr == '"') {
			ptr++;
		}
		*uptr = ptr;
		return;
	}

	while(*ptr != ' ' && *ptr != '\t' && *ptr != '\0' && *ptr != '\n' &&
						*ptr != '=' && *ptr != ',') {
			*string++ = *ptr++;
	}
	*string = '\0';
	*uptr = ptr;
	return;
}

#define FIND_MODE_NAME	0
#define FIND_MODE_REPLY	1
#define FIND_MODE_SKIP	2
#define FIND_MODE_FLUSH	3

/*************************************************************************
 *
 *	Function: user_find
 *
 *	Purpose: Find the named user in the database.  Create the
 *		 set of attribute-value pairs to check and reply with
 *		 for this user from the database.
 *
 *************************************************************************/

int 
user_find(char*req_name, char*auth_name, VALUE_PAIR**check_pairs,VALUE_PAIR**reply_pairs,USER_FILE user_desc)
{
	VALUE_PAIR	*check_first;
	VALUE_PAIR	*reply_first;
	char		*ptr;
	char		buffer[MAXBUF];
	datum		contentd;
	datum		named;
	int		mode;
	int		req_namelen;

	/* 
	 * Check for valid input, zero length names not permitted 
	 */

	mode = FIND_MODE_NAME;

	ptr=req_name;
	while (*ptr != '\0') {
		if (*ptr == ' ' || *ptr == '\t') {
#ifdef SPACECHOP
			*ptr = '\0';
#else
			log_err("user_find: space in username \"%s\" rejected\n",req_name);
			return(-1);
#endif
		} else {
			ptr++;
		}
	}

	req_namelen=strlen(req_name);

	if (req_namelen < 1) {
		log_err("user_find: zero length username rejected\n");
		return(-1);
	}

	check_first = (VALUE_PAIR *)NULL;
	reply_first = (VALUE_PAIR *)NULL;

	if (radius_gdbm != 0) {
		for (;;) {
			if (db_index == -1) {
				named.dptr = req_name;
				named.dsize = strlen(req_name);
			} else if (db_index == 0) {
				snprintf(buffer, sizeof(buffer),"DEFAULT");
				named.dptr = buffer;
				named.dsize = strlen(buffer);
			} else {
				snprintf(buffer, sizeof(buffer),"DEFAULT%d", db_index);
				named.dptr = buffer;
				named.dsize = strlen(buffer);
			}
			db_index++;

			contentd = gdbm_fetch(user_desc.gdbm, named);
			if(contentd.dsize == 0) {
				if (db_index == 0) {
					/*
					 * the request id failed
					 * lets try the defaults
					 */
					continue;
				}
				return(-1);
			}

			/*
			 * Parse the check values
			 */
			if (contentd.dsize > MAXBUF) {
				log_err("user_find: user record for user %s is too big, %d exceeds %d\n", req_name,contentd.dsize,MAXBUF);
				return(-1);
			}
			memcpy(buffer,contentd.dptr,contentd.dsize);
			buffer[contentd.dsize] = '\0';
            		free(contentd.dptr);
			ptr = buffer;

			if(userparse(ptr, &check_first) != 0) {
				log_err("user_find: unable to parse check-items in gdbm entry for user %s\n", req_name);
				pairfree(check_first,"user_find");
				return(-1);
			}

			/*
			 * set authentication name
			 */
			if (user_auth_name( req_name,
					auth_name,
					check_first) != 0) {
				pairfree(check_first,"user_find");
				check_first = (VALUE_PAIR *)NULL;
				continue;
			}
			break;
		}

		while(*ptr != '\n' && *ptr != '\0') { ptr++; }

		if(*ptr == '\n') ptr++; /* Step over end of line if found */

		if(*ptr == '\0') {	/* no reply-items */
			*check_pairs = check_first;
			*reply_pairs = (VALUE_PAIR *)NULL;
			return(0);
		}

		/*
		 * Parse the reply values
		 */
		if(userparse(ptr, &reply_first) != 0) {
			log_err("user_find: unable to parse reply-items in gdbm entry for user %s\n", req_name);
			pairfree(check_first,"user_find");
			pairfree(reply_first,"user_find");
			return(-1);
		}
	} else {
	    while(fgets(buffer,sizeof(buffer),user_desc.flat) !=NULL) {
		if(mode == FIND_MODE_NAME) {
			/*
			 * Find the entry starting with the users name
			 */
			if((strncmp(buffer, req_name, req_namelen) == 0
					&& (buffer[req_namelen] == ' '
					|| buffer[req_namelen] == '\t'))
					|| strncmp(buffer, "DEFAULT", 7) == 0) {
				if(strncmp(buffer, "DEFAULT", 7) == 0) {
					ptr = &buffer[7];
					/*
					 * advance pointer to next white space
					 */
					while (isspace(*ptr) == 0) {
						ptr++;
					}
				}
				else {
					ptr = &buffer[req_namelen];
				}
				/*
				 * Parse the check values
				 */
				if(userparse(ptr, &check_first) != 0) {
					log_err("user_find: unable to parse check-items for user %s\n", req_name);
					pairfree(check_first,"user_find");
					return(-1);
				}
				/*
				 * set authentication name
				 */
				if (user_auth_name( req_name,
						auth_name,
						check_first) != 0) {
					pairfree(check_first,"user_find");
					check_first = (VALUE_PAIR *)NULL;
					continue;
				}
				mode = FIND_MODE_REPLY;
			}
		}
		else {
			if(*buffer == ' ' || *buffer == '\t') {
				/*
				 * Parse the reply values
				 */
				if(userparse(buffer, &reply_first) != 0) {
					log_err("user_find: unable to parse reply-items for user %s\n", req_name);
					pairfree(check_first,"user_find");
					pairfree(reply_first,"user_find");
					return(-1);
				}
			}
			else {
				/* We are done */
				*check_pairs = check_first;
				*reply_pairs = reply_first;
				return(0);
			}
		}
	}
	}
	/* Update the callers pointers */
	if(reply_first != (VALUE_PAIR *)NULL) {
		*check_pairs = check_first;
		*reply_pairs = reply_first;
		return(0);
	}
	return(-1);
}

/*************************************************************************
 *
 *	Function: user_auth_name
 *
 *	Purpose: Set authentication name, stripping pre/suffix
 *
 *************************************************************************/

int 
user_auth_name(char*rname,char*auth_name,VALUE_PAIR*check_first)
{
	VALUE_PAIR	*fix;
	int		req_len;
	int		len;
	char		namebuf[AUTH_STRING_LEN+2];
	char		*req_name;

	req_len = strlen(rname);
	req_name = namebuf;
	if (req_len > AUTH_STRING_LEN) {
		req_len = AUTH_STRING_LEN;
		req_name[req_len] = '\0';
	}
	strncpy(req_name, rname, req_len);
	if ((fix = get_attribute(check_first, PW_PREFIX))!=(VALUE_PAIR*)NULL) {
		len = strlen(fix->strvalue);
		if (req_len <= len || (strncmp(req_name,
						fix->strvalue, len) != 0)) {
			return(-1);
		}
		/*
		 * strip prefix from request name
		 */
		req_name += len;
		req_len -= len;
	}
	if ((fix = get_attribute(check_first, PW_SUFFIX))
			!= (VALUE_PAIR *)NULL) {
		len = strlen(fix->strvalue);
		if (req_len <= len || (strncmp(&req_name[req_len - len],
						fix->strvalue, len) != 0)) {
			return(-1);
		}
		/*
		 * strip suffix from request name
		 */
		req_len -= len;
	}
	strncpy(auth_name, req_name, req_len);
	auth_name[req_len] = '\0';
	return(0);
}

#define PARSE_MODE_NAME		0
#define PARSE_MODE_EQUAL	1
#define PARSE_MODE_VALUE	2
#define PARSE_MODE_INVALID	3

/*************************************************************************
 *
 *	Function: userparse
 *
 *	Purpose: Parses the buffer to extract the attribute-value pairs.
 *
 *************************************************************************/

int 
userparse(char*buffer,VALUE_PAIR**first_pair)
{
	int		mode;
	char		attrstr[64];
	char		valstr[256];
	DICT_ATTR	*attr;
	DICT_VALUE	*dval;
	VALUE_PAIR	*pair;
	VALUE_PAIR	*link;
	struct tm	*tm;
	time_t		timeval;

	mode = PARSE_MODE_NAME;
	while(*buffer != '\n' && *buffer != '\0') {

		if(*buffer == ' ' || *buffer == '\t' || *buffer == ',') {
			buffer++;
			continue;
		}

		switch(mode) {

		case PARSE_MODE_NAME:
			/* Attribute Name */
			fieldcpy(attrstr, &buffer);
			if((attr = dict_attrfind(attrstr)) ==
						(DICT_ATTR *)NULL) {
				return(-1);
			}
			mode = PARSE_MODE_EQUAL;
			break;

		case PARSE_MODE_EQUAL:
			/* Equal sign */
			if(*buffer == '=') {
				mode = PARSE_MODE_VALUE;
				buffer++;
			}
			else {
				return(-1);
			}
			break;

		case PARSE_MODE_VALUE:
			/* Value */
			fieldcpy(valstr, &buffer);

			pair = pairalloc("userparse");

			strcpy(pair->name, attr->name);
			pair->attribute = attr->value;
			pair->type = attr->type;
			pair->vendor = attr->vendor;
			pair->vsattribute = attr->vsvalue;

			switch(pair->type) {

#if defined(ASCEND_BINARY)
                        case PW_TYPE_ABINARY:
                               /*
                                * special case to convert filter to binary
                                */
                               if ( filterBinary( pair, valstr ) == -1 ) {
                                       free(pair);
                                       return(-1);
                               }
                               break;
#endif
			       
			case PW_TYPE_STRING:
				strcpy(pair->strvalue, valstr);
				pair->lvalue = strlen(valstr);
				break;

			case PW_TYPE_INTEGER:
				if(isdigit(*valstr)) {
					pair->lvalue = atoi(valstr);
				}
				else if((dval = dict_valfind(valstr)) ==
							(DICT_VALUE *)NULL) {
					free(pair);
					return(-1);
				}
				else {
					pair->lvalue = dval->value;
				}
				break;

			case PW_TYPE_IPADDR:
				pair->lvalue = get_ipaddr(valstr);
				break;

			case PW_TYPE_DATE:
                                timeval = time(0);
                                tm = localtime(&timeval);
#if defined(SHADOW_EXPIRATION) 
                                if (strncasecmp(valstr,"SHADOW", 6) == 0) {
                                   pair->lvalue = 0;
                                   valstr[6]='\0';
                                   strncpy(pair->strvalue, valstr, 7);
                                   break;
                                }
#endif 
				if (user_gettime(valstr, tm) < 0) {
					pair->lvalue = 0;
					log_err("invalid expiration format \"%s\" rejected\n",valstr);
				} else {
#if defined(HAVE_TIMELOCAL)
				pair->lvalue = (UINT4)timelocal(tm);
#else
				pair->lvalue = (UINT4)mktime(tm);
#endif
				}
				break;

			default:
				free(pair);
				return(-1);
			}
			pair->next = (VALUE_PAIR *)NULL;
			if(*first_pair == (VALUE_PAIR *)NULL) {
				*first_pair = pair;
			}
			else {
				link = *first_pair;
				while(link->next != (VALUE_PAIR *)NULL) {
					link = link->next;
				}
				link->next = pair;
			}
			mode = PARSE_MODE_NAME;
			break;

		default:
			mode = PARSE_MODE_NAME;
			break;
		}
	}
	return(0);
}

/*************************************************************************
 *
 *	Function: user_gettime
 *
 *	Purpose: Turns printable string into correct tm struct entries
 *
 *************************************************************************/

static char *months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

int 
user_gettime( char*valstr,struct tm*tm )
{
	int	i;

	/* Get the month */
	for(i = 0;i < 12;i++) {
		if(strncmp(months[i], valstr, 3) == 0) {
			tm->tm_mon = i;
			i = 13;
		}
	}

	/* Get the Day */
	tm->tm_mday = atoi(&valstr[4]);

	/* Now the year */
	tm->tm_year = atoi(&valstr[7]) - 1900;

	/* Midnight */
	tm->tm_sec = 0;
	tm->tm_min = 0;
	tm->tm_hour = 0;
	
	/* if date makes no sense return failure */
	if (i == 12 || tm->tm_mday < 1 || tm->tm_mday > 31 ||
	    tm->tm_year < 70) {
		return(-1);
	} else {
		return(0);
	}
}

/*************************************************************************
 *
 *	Function: user_open
 *
 *	Purpose: open the users file
 *
 *************************************************************************/

USER_FILE 
user_open(void)
{
	static USER_FILE user_file;
	char buffer[PATH_MAX];

        user_file.flat = NULL;
        user_file.gdbm = NULL;

        if (radius_gdbm == 0) {
                snprintf(buffer, sizeof(buffer), "%s/%s", radius_dir, RADIUS_USERS);
                user_file.flat = user_open_flat(buffer);
                return user_file;
        }

	snprintf(buffer,sizeof(buffer),"%s/%s", radius_dir, RADIUS_USERSDB);
        if((user_file.gdbm=gdbm_open(buffer,0,GDBM_READER,0600,NULL)) == NULL) {
	   log_err("user_open: could not read user gdbm file %s\n", buffer);
	   return user_file;
	}
	db_index = -1;
	return user_file;
}

FILE * 
user_open_flat(char*file_name)
{
	FILE*user_desc;

	/*
	 * Open the user table
	 */
	if((user_desc = fopen(file_name, "r")) == (FILE *)NULL) {
		log_err("user_open: could not read user file %s\n", file_name);
		return((FILE *)NULL);
	}
	return(user_desc);
}

/*************************************************************************
 *
 *	Function: user_close
 *
 *	Purpose: close the users file
 *
 *************************************************************************/

void 
user_close(USER_FILE user_file)
{
        if (radius_gdbm != 0) gdbm_close(user_file.gdbm);
        else fclose(user_file.flat);
}
