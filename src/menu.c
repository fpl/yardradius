/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

static char rcsid[] = "$Id: menu.c 75 2004-08-02 18:40:07Z flovergine $";

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<sys/file.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<netdb.h>
#include	<fcntl.h>
#include	<pwd.h>
#include	<time.h>
#include	<ctype.h>
#include	<unistd.h>
#include	<signal.h>
#include	<errno.h>
#include	<sys/wait.h>

#include	"yard.h"
#include	"global.h"

void 
process_menu(AUTH_REQ*authreq,int activefd,char*pw_digest)
{
	VALUE_PAIR	*attr;
	VALUE_PAIR	*term_attr;
	VALUE_PAIR	*newattr;
	char		menu_name[128];
	char		menu_input[32];
	int		i;
	char		state_value[128];

	if((attr = get_attribute(authreq->request, PW_STATE)) !=
		(VALUE_PAIR *)NULL && strncmp(attr->strvalue, "MENU=", 5) == 0){

		strcpy(menu_name, &attr->strvalue[5]);

		/* The menu input is in the Password Field */
		attr = get_attribute(authreq->request, PW_PASSWORD);
		if(attr == (VALUE_PAIR *)NULL) {
			*menu_input = '\0';
		}
		else {
			/*
			 * Decrypt the password in the request.
			 */
			memcpy(menu_input, attr->strvalue, AUTH_PASS_LEN);
			for(i = 0;i < AUTH_PASS_LEN;i++) {
				menu_input[i] ^= pw_digest[i];
			}
			menu_input[AUTH_PASS_LEN] = '\0';
		}
		attr = menu_pairs(menu_name, menu_input);
	}

	/* handle termination menu */
	if((term_attr = get_attribute(attr, PW_TERMINATION_MENU)) !=
							(VALUE_PAIR *)NULL) {

		/* Change this to a menu state */
		sprintf(state_value, "MENU=%s", term_attr->strvalue);
		term_attr->attribute = PW_STATE;
		strcpy(term_attr->strvalue, state_value);
		strcpy(term_attr->name, "Challenge-State");

		/* Insert RADIUS termination option */
		/* Set termination values */
		newattr = pairalloc("process_menu");

		newattr->attribute = PW_TERMINATION;
		newattr->type = PW_TYPE_INTEGER;
		newattr->lvalue = PW_TERM_RADIUS_REQUEST;
		strcpy(newattr->name, "Termination-Action");

		/* Insert it */
		newattr->next = term_attr->next;
		term_attr->next = newattr;
	}

	if((term_attr = get_attribute(attr, PW_MENU)) != (VALUE_PAIR *)NULL &&
				strcmp(term_attr->strvalue, "EXIT") == 0) {
		send_reject(authreq, (char *)"", activefd);
		pairfree(attr,"process_menu");
	}
	else if(attr != (VALUE_PAIR *)NULL) {
		send_accept(authreq, attr, (char *)NULL, activefd);
		pairfree(attr,"process_menu");
	}
	else {
		send_reject(authreq, (char *)NULL, activefd);
	}
	reqfree(authreq,"process_menu");
	return;
}

char* 
get_menu(char *menu_name)
{
	FILE	*fd;
	static	char menu_buffer[4096];
	int	mode;
	char	*ptr;
	int	nread;
	int	len;

	snprintf(menu_buffer,(size_t)4096,"%s/menus/%s", radius_dir, menu_name);
	if((fd = fopen(menu_buffer, "r")) == (FILE *)NULL) {
		return("\r\n*** User Menu is Not Available ***\r\n");
	}

	mode = 0;
	nread = 0;
	ptr = menu_buffer;
	*ptr = '\0';
	while(fgets(ptr, 4096 - nread, fd) != NULL && nread < 4096) {

		if(mode == 0) {
			if(strncmp(ptr, "menu", 4) == 0) {
				mode = 1;
			}
		}
		else {
			if(strncmp(ptr, "end\n", 4) == 0) {
				if(ptr > menu_buffer) {
					*(ptr - 2) = '\0';
				}
				else {
					*ptr = '\0';
				}
				return(menu_buffer);
			}
			len = strlen(ptr);
			ptr += len - 1;
			*ptr++ = '\r';
			*ptr++ = '\n';
			nread += len + 1;
		}
	}
	*ptr = '\0';
	return(menu_buffer);
}

VALUE_PAIR* 
menu_pairs(char*menu_name,char*menu_selection)
{
	FILE	*fd;
	char 	buffer[4096];
	char	selection[32];
	int	mode;
	char	*ptr;
	int	nread;
	VALUE_PAIR*reply_first;

	sprintf(buffer, "%s/menus/%s", radius_dir, menu_name);
	if((fd = fopen(buffer, "r")) == (FILE *)NULL) {
		return((VALUE_PAIR *)NULL);
	}

	/* Skip past the menu */
	mode = 0; nread = 0;
	while(fgets(buffer, sizeof(buffer), fd) != NULL) {
		if(mode == 0) {
			if(strncmp(buffer, "menu", 4) == 0) {
				mode = 1;
			}
		}
		else {
			if(strncmp(buffer, "end\n", 4) == 0) {
				break;
			}
		}
	}

	/* handle default */
	if(*menu_selection == '\0') { strcpy(selection, "<CR>"); }
	else { strcpy(selection, menu_selection); }
	reply_first = (VALUE_PAIR *)NULL;

	/* Look for a matching menu entry */
	while(fgets(buffer, sizeof(buffer), fd) != NULL) {

		/* Terminate the buffer */
		ptr = buffer;
		while(*ptr != '\n' && *ptr != '\0') {
			ptr++;
		}
		if(*ptr == '\n') {
			*ptr = '\0';
		}

		if(strcmp(selection, buffer) == 0 ||
					strcmp("DEFAULT", buffer) == 0) {
			/* We have a match */
			while(fgets(buffer, sizeof(buffer), fd) != NULL) {
			    if(*buffer == ' ' || *buffer == '\t') {
				/*
				 * Parse the reply values
				 */
				if(userparse(buffer, &reply_first) != 0) {
					log_err("parse error for menu %s\n",menu_name);
					pairfree(reply_first,"menu_pairs");
					fclose(fd);
					return((VALUE_PAIR *)NULL);
				}
			    }
			    else {
				/* We are done */
				fclose(fd);
				return(reply_first);
			    }
			}
			fclose(fd);
			return(reply_first);
		}
	}
	fclose(fd);
	return((VALUE_PAIR *)NULL);
}
