/*
 * Copyright (C) 1999-2004 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

#include	"yard.h"
#include	"global.h"

/* This structure is used for 3COM boxes */

static int usr_speeds[53]={
0, 300, 1200, 2400, 4800, 7200, 9600, 12000, 14400, 16800, 19200, 21600,
28800, 38400, 57600, 115200, 288000, 751200, 120075, 24000, 26400, 31200,
33600, 33333, 37333, 41333, 42666, 44000, 45333, 46666, 48000, 49333, 50666,
52000, 53333, 54666, 56000, 57333, 64000, 25333, 26666, 28000, 29333, 30666,
32000, 34666, 36000, 38666, 40000, 58666, 60000, 61333, 62666
};

/*
 * check_logins - see if maximum number of logins was not reached
 */
int 
check_logins(char *user, const int max_logins)
{
    char       	dbfile_name[PATH_MAX];
    GDBM_FILE	dbf;
    datum      	key, content;
    user_entry	*ue;
    struct tm	*time_info;
    time_t     	crt_time = time(NULL);
		
    time_info = localtime(&crt_time);
    snprintf(dbfile_name,sizeof(dbfile_name), "%s/%d/%s",
	    radacct_dir,1900+time_info->tm_year,RADIUS_USER_STATS);
    dbf = gdbm_open(dbfile_name,0,GDBM_READER,0600,NULL);
    if (dbf == NULL) {
	return 0;
    }
	
    /* Build the key */
    key.dptr = user;
    key.dsize = strlen(user);

    content = gdbm_fetch(dbf,key);
    if (content.dptr == NULL) {
	/* not here, at least one login is allowed */
	gdbm_close(dbf);
	return 0;
    }
    ue = (user_entry *)content.dptr;
    if (ue->logins >= max_logins) {
	gdbm_close(dbf);
	if ( content.dptr!=NULL ) free( content.dptr );
	return -2;
    }
    gdbm_close(dbf);
    if ( content.dptr!=NULL ) free( content.dptr );
    return 0;
}

/*
 * check_maxtime - see if maximum DAILY/MONTHLY/YEARLY online time is reached
 */
int 
check_maxtime(char *user, const int hours, const int kind)
{
    char       	dbfile_name[PATH_MAX];
    GDBM_FILE	dbf;
    datum      	key, content;
    user_entry	*ue;
    struct tm	*time_info;
    UINT4	counter;
    int		i,j;
    time_t     	crt_time = time(NULL);
	
    time_info = localtime(&crt_time);
    snprintf(dbfile_name, sizeof(dbfile_name), "%s/%d/%s",
            radacct_dir,1900+time_info->tm_year,RADIUS_USER_STATS);
    dbf = gdbm_open(dbfile_name,0,GDBM_READER,0600,NULL);
    if (dbf == NULL) {
	return 0;
    }
	
    /* Build the key */
    key.dptr = user;
    key.dsize = strlen(user);

    content = gdbm_fetch(dbf,key);
    if (content.dptr == NULL) {
	/* not here, login is allowed */
	gdbm_close(dbf);
	return 0;
    }
    ue = (user_entry *)content.dptr;
    switch ( kind )
      {
      case DAY_LIMIT:
        if (ue->day[time_info->tm_mon][time_info->tm_mday-1].on_line >= 
	    hours*3600) 
          {
	  gdbm_close(dbf);
	  if ( content.dptr!=NULL ) free( content.dptr );
	  return -2;
	  }
	break;

      case MONTH_LIMIT:
        for ( i=0, counter=0; i<time_info->tm_mday; i++ ) 
	  counter += ue->day[time_info->tm_mon][i].on_line;
	if ( counter >= hours*3600 )
	  {
	  gdbm_close(dbf);
	  if ( content.dptr!=NULL ) free( content.dptr );
	  return -2;
	  }
	break;

      case YEAR_LIMIT:
        for ( i=0, counter=0; i<=time_info->tm_mon; i++ ) 
          for ( j=0; i<time_info->tm_mday; i++ ) 
	    counter += ue->day[i][j].on_line;
	if ( counter >= hours*3600 )
	  {
	  gdbm_close(dbf);
	  if ( content.dptr!=NULL ) free( content.dptr );
	  return -2;
	  }
	break;

      default:
        log_err("internal error: invalid kind of limit in a"
	        "check_maxtime() call\n");
        break;
      }
    gdbm_close(dbf);
    if ( content.dptr!=NULL ) free( content.dptr );
    return 0;
}

/*
 * clean_user_stats()
 *
 * initializes the user_stats database (clear the number of concurent logins)
 * to avoid starting a new radiusd server with invalid data
 *
 */ 
int 
clean_user_stats(void)
{
    char            dbfile_name[PATH_MAX];
    GDBM_FILE       dbf;
    datum           key, content, nextkey;
    struct tm       *time_info;
    time_t          crt_time = time(NULL);
	
    time_info = localtime(&crt_time);
    memset(dbfile_name, 0, PATH_MAX);
    snprintf(dbfile_name, sizeof(dbfile_name), "%s/%d/%s",
            radacct_dir,1900+time_info->tm_year,RADIUS_USER_STATS);
    dbf = gdbm_open(dbfile_name,0,GDBM_WRITER|GDBM_SYNC,0600,NULL );
    if (dbf == NULL) {
	/* we couldn't open the databse. That's "okay" in this case... */
	return 0;
    }
    key = gdbm_firstkey(dbf);
    while (key.dptr != NULL) {
	user_entry *p_ue;
	int        retval;

	content = gdbm_fetch(dbf, key);
	if (content.dptr == NULL) {
	    nextkey = gdbm_nextkey(dbf,key);
	    free(key.dptr);
	    key = nextkey;
	    continue;
	}
	p_ue = (user_entry *)content.dptr;
	p_ue->logins = 0;
	content.dsize = sizeof(user_entry); /* rip off any port_entry */

	/* update this modified entry */

	retval = gdbm_store(dbf, key, content, GDBM_REPLACE);
	if (retval != 0) {

	    /* odd error updating the database */

	    key.dptr[key.dsize] = '\0';
	    log_err("could not reset user_stats entry for '%s'\n",
		    (char *)key.dptr);
	    gdbm_close(dbf);
	    if (content.dptr != NULL) free(content.dptr);
	    if (key.dptr != NULL) free(key.dptr);
	    return -1;
	}
	/* update went okay */
	if (content.dptr != NULL) free(content.dptr);
	nextkey = gdbm_nextkey(dbf,key);
	free(key.dptr);
	key = nextkey;
    }
	
    gdbm_close(dbf); /* close the database */
    /* finished */
    return 0;
}

/*
 * deny_user returns:
 * -2 if user is present in RADIUS_DIR/RADIUS_DENY
 * -3 if user is present in RADIUS_DIR/RADIUS_STOP
 * 1  if no such user (misa)
 * 0 if okay 
 *
 * allow_user returns:
 * -4 if user is NOT present in RADIUS_DIR/RADIUS_ALLOW
 * 0 if okay 
 */


/*
	Function: listed_on_file()

	Purpose: it matches a user against many matching criteria:
		GROUP: the user belongs to a certain group 
		SHELL: the user has a certain shell
		GECOS: the user has a Gecos field which _contains_ a
		       certain string
		USER: the user has a specific name.

	Notes: string match is case-sensitive. Maybe a regex-match
	       could be interesting. A value of ANY match any user.


	Francesco Lovergine <f.lovergine@iesi.ba.cnr.it>

*/

static int 
listed_on_file(const char *filename, const char *username)
{
    FILE *fp;
    char buffer[1024];
    char value[1024];
    static char special[]="ANY";

    if ((fp=fopen(filename, "r")) != NULL) {
        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
            if ( strlen(buffer)==0 || buffer[0] == '\n' || 
	         buffer[0] == '#' || buffer[0] == ';' ) continue;
	    else
	    if ( sscanf(buffer,"USER: %s",value ) == 1 )
	      {
              if (strcmp(value,special)==0 || 
	          strcmp(username,value) == 0) { fclose(fp); return -1; }
	      }
	    else
	    if ( sscanf(buffer,"GROUP: %s",value ) == 1 )
	      {
              if (strcmp(value,special)==0 || 
	          unix_group(username,value)) { fclose(fp); return -1; }
	      }
	    else
	    if ( sscanf(buffer,"GECOS: %s",value ) == 1 )
	      {
	      if (strcmp(value,special)==0 ||
	          (strlen(value) && strstr(unix_gecos(username),value)!=NULL) )
	        {
		fclose(fp); return -1;
		}
	      }
	    else
	    if ( sscanf(buffer,"SHELL: %s",value ) == 1 )
	      {
	      if (strcmp(value,special)==0 ||
	           (strlen(value) && strcmp(unix_shell(username),value)==0))
	        {
		fclose(fp); return -1;
		}
	      }
	    else
	      log_err("warning: syntax error in file '%s', line '%s' ignored",
	               filename,buffer);
	}
    fclose(fp);
    }
    return 0;
}

/*
 * The actual function is quite simple ...
 */
int 
deny_user(const char *username)
{
    char file_name[PATH_MAX];
    char buffer[1024];

    if (!username || (strlen(username) >= sizeof(buffer))) {
	/* well, an error, but for this function purpose 
	 * should respond with okay... I hate this... */
	return 0;
    }
    /* first try to open RADIUS_DIR/RADIUS_DENY */
    snprintf(file_name, sizeof(file_name), "%s/%s", radius_dir, RADIUS_DENY);
    if (listed_on_file(file_name, username) < 0)
	return -2;

    snprintf(file_name, sizeof(file_name), "%s/%s", radius_dir, RADIUS_STOP);
    if (listed_on_file(file_name, username) < 0)
	return -3;

    return 0;
}

int 
allow_user(const char *username)
{
    char file_name[PATH_MAX];
    char buffer[1024];

    if (!username || (strlen(username) >= sizeof(buffer))) {
	return -4;
    }
    snprintf(file_name,sizeof(file_name),"%s/%s", radius_dir, RADIUS_ALLOW);
    if (listed_on_file(file_name, username) < 0) return 0;
    return -4;
}

/*
 * Builds a radlast structure from an AUTHREQ_HDR packet
 */
static int 
build_radlast_from_authreq(radlast *rl, AUTH_REQ *authreq)
{
    int		status_type = 0;
    time_t	crt_time;
    VALUE_PAIR	*pair;
    int		vj = 0;
    
    crt_time = time(NULL);
    if (!rl || !authreq || !authreq->request)
	return -1;
    pair = authreq->request;
    memset(rl, 0, sizeof(radlast));
    rl->ut_time = crt_time;
    while (pair != (VALUE_PAIR *)NULL) {
	switch (pair->attribute) {
	    case PW_ACCT_STATUS_TYPE:
		status_type = pair->lvalue;
		break;
	    case PW_USER_NAME:
		strncpy(rl->login, (char *)pair->strvalue, sizeof(rl->login));
		break;
	    case PW_CLIENT_PORT_ID:
		rl->ent.port = pair->lvalue;
		break;
	    case PW_FRAMED_ADDRESS:
	    case PW_LOGIN_HOST:
		rl->client_ip = pair->lvalue;
		break;
	    case PW_ACCT_SESSION_TIME:
		rl->length = pair->lvalue;
		rl->ut_time -= pair->lvalue;
		break;
	    case PW_ACCT_INPUT_OCTETS:
		rl->inb = pair->lvalue;
		break;
	    case PW_ACCT_OUTPUT_OCTETS:
		rl->outb = pair->lvalue;
		break;
	    case PW_CLIENT_ID:
		rl->nas_ip = pair->lvalue;
		break;
	    case PW_NAS_PORT_TYPE:
		rl->ent.port_type = pair->lvalue;
		break;
	    case PW_LOGIN_SERVICE:
		switch ((int)(pair->lvalue)) {
		    case PW_TELNET:
			rl->ent.proto = P_TELNET;
			break;
		    case PW_RLOGIN:
			rl->ent.proto = P_RLOGIN;
			break;
		    case PW_TCP_CLEAR:
			rl->ent.proto = P_TCP_CLEAR;
			break;
		    case PW_PORTMASTER:
			rl->ent.proto = P_PORTMASTER;
			break;
		    default:
			rl->ent.proto = P_LOGIN_UNK;
		}
		break;
	    case PW_FRAMED_PROTOCOL:
		switch ((int)(pair->lvalue)) {
		    case PW_PPP:
			rl->ent.proto = P_PPP;
			break;
		    case PW_SLIP:
			rl->ent.proto = P_SLIP;
			break;
		    default:
			rl->ent.proto = P_FRAMED_UNK;
		}
		break;
	    case PW_ACCT_DELAY_TIME:
		rl->ut_time -= pair->lvalue;
		break;	
	    case PW_FRAMED_COMPRESSION:
		vj++;
		break;
	    case PW_ACCT_TERMINATE_CAUSE:
		rl->ent.term_cause = pair->lvalue;
		break;

	    case PW_ACCT_CALLED_STATION_ID:
		strncpy(rl->calledid,(char*)pair->strvalue,
		        sizeof(rl->calledid));
	        break;
	    case PW_ACCT_CALLING_STATION_ID:
		strncpy(rl->callingid,(char*)pair->strvalue,
		        sizeof(rl->callingid));
	        break;

	    /* Next attributes are VSAs */

	    case PW_ACCT_ASCEND_DATA_RATE:
		rl->rxrate = pair->lvalue;
	        break;
	    case PW_ACCT_ASCEND_XMIT_RATE:
		rl->txrate = pair->lvalue;
	        break;
	    case PW_CONNECT_INFO_OLD:
	        rl->txrate = (UINT4)atol(pair->strvalue);
		rl->rxrate = rl->txrate;
	        break;
	    case PW_ACCT_USR_CONNECT_SPEED:
		rl->rxrate = rl->txrate = usr_speeds[pair->lvalue%54 - 1];
		break;
	    case PW_CONNECT_INFO:
	        sscanf(pair->strvalue,"%d/%d%*s",&rl->txrate,&rl->rxrate);
	        break;
	};
	pair = pair->next;
    };	
    if ((rl->ent.proto == P_SLIP) && vj) rl->ent.proto = P_CSLIP;
    return status_type;
}

/*
 * Updates the user entry from the user_stats databse (add one more login
 * or clear out an entry...
 */
static int 
update_db_record(int action, datum *content, radlast *rl,int month, int day)
{	
    void *data;
    int datasize;
    user_entry 	*tmp = (user_entry *)(content->dptr);
    port_entry 	*tpe;
		
    /* update fields */

    tmp->day[month][day].on_line += rl->length;
    tmp->day[month][day].input_octets += rl->inb;
    tmp->day[month][day].output_octets += rl->outb;

    /* now it is time to check if this is a start or stop */

    if (action == PW_STATUS_START) {

	tmp->day[month][day].nr_logins++;
	tmp->logins++;

	/* okay, start a new one ... */

	datasize = content->dsize + sizeof(port_entry);
	data = (void *) malloc(datasize);
	if (data==NULL) {
	    /* malloc error */
	    log_err("could not malloc for handling user acct\n");
	    content->dptr = NULL;
	    return -1;
	}

	/* we have the required memory */
	memcpy(data,content->dptr,content->dsize); /* paste the original data */
	tpe = (port_entry *)((char *)data + content->dsize);

	/* store the new entry */
	tpe->time = rl->ut_time;
	tpe->client_ip = rl->client_ip;
	tpe->port_type = rl->ent.port_type;
	tpe->port_number = rl->ent.port;
	tpe->nas_ip = rl->nas_ip;
	tpe->proto = rl->ent.proto;
    } else {
	/* this is a stop record */
	int port_found = 0;

	/* now it is ugly ... */
	datasize = sizeof(user_entry); /* do not attemp to take more */
	data = (void *)malloc(content->dsize); /* make enough room */
	if (data==NULL) {
	    /* malloc error */
	    log_err("could not malloc for handling user acct\n");
	    content->dptr = NULL;
	    return -1;
	}
	/* memory is okay */
	if (content->dsize > sizeof(user_entry)) {
	    /* do we have any port entry to rip off ? */
	    int ports_copied = 0;
	    int nr_port_entry = 0;		
	    port_entry *dptr = (port_entry *)((char*)data+sizeof(user_entry));

	    /* go to first port entry */
	    tpe = (port_entry *)((char *)(content->dptr) + sizeof(user_entry));

	    /* be super-safe */
	    nr_port_entry = (content->dsize-sizeof(user_entry))/sizeof(port_entry);
	    if (nr_port_entry*sizeof(port_entry)+sizeof(user_entry) != content->dsize) {
		/* somehow we've managed to break the port entries, we
		 * don't have a valid number of entries
		 */
		log_err("ERROR: database is inconsistent for user '%s'."
		        " Cleaned up.\n",rl->login);
		/* clean up the mess */
		tmp->logins = 0;
	    } else {
		/* we have a valid number of port entries, 
		 * now just in case tmp->logins have a different opinion ...
		 */
		if (tmp->logins != nr_port_entry)
		    log_err("ERROR: database not okay for '%s': velived %d"
		            "logins, have only %d\n",
			    rl->login, tmp->logins, nr_port_entry);
		tmp->logins = nr_port_entry;
	    }

	    while (ports_copied < tmp->logins) {
		/* is this the port we are looking for ? */
		if ((tpe->nas_ip!=rl->nas_ip) || 
		    (tpe->port_type != rl->ent.port_type) ||
		    (tpe->port_number != rl->ent.port) || port_found) {
		    /* not our port */
		    memcpy((void *)dptr, (void *)tpe, sizeof(port_entry));
		    dptr++;
		    datasize += sizeof(port_entry);
		} else
		    /* port found */
		    port_found++;
		/* skip the current port */
		tpe++;
		/* count any port as a copied one */
		ports_copied++;
	    }
	}
	if (port_found) tmp->logins--;
	/* all done */
	memcpy(data, content->dptr, sizeof(user_entry)); /* paste orig. data */
    }

    /* Now no matter what *data contains our data, with a size of datasize */

    if ( content->dptr != NULL ) free(content->dptr);
    content->dsize = datasize;
    content->dptr = (char*)data;
    return 0;
}

/*
 * inserts a new entry for the username in the user_stats database
 */
static int 
insert_db_record(int action,datum *content,radlast *rl,int month,int day)
{
    user_entry *tmp;

    content->dsize = sizeof(user_entry);
    if (action == PW_STATUS_START) content->dsize += sizeof(port_entry);

    tmp = (user_entry *)malloc(content->dsize);

    if (tmp == NULL) {
	log_err("insert_db_record(): malloc error!\n");
	content->dptr = NULL;
	return -2;
    }

    /* init things */
    memset((char *)tmp, 0, sizeof(user_entry));
    tmp->day[month][day].on_line += rl->length;
    tmp->day[month][day].input_octets += rl->inb;
    tmp->day[month][day].output_octets += rl->outb;

    if (action == PW_STATUS_START) {
	port_entry *tpe;

	tmp->logins = 1;
	tmp->day[month][day].nr_logins = 1;

	/* get the port_entry pointer */

	tpe = (port_entry *)((char *)tmp + sizeof(user_entry));
	tpe->time = rl->ut_time;
	tpe->client_ip = rl->client_ip;
	tpe->port_type = rl->ent.port_type;
	tpe->port_number = rl->ent.port;
	tpe->nas_ip = rl->nas_ip;
	tpe->proto = rl->ent.proto;
    }
    content->dptr = (char *)tmp;
    return 0;
}

/*
 * Updates the radlast logs...
 */
extern int sockfd;
extern int acctfd;

static int 
update_radlast(radlast *rl)
{
    pid_t 	child_pid;
    
    struct tm   *time_info;
    {
	time_t crt_time = time(NULL);
	time_info = localtime(&crt_time);
    }

    /* fork a child to handle this job */
    child_pid = fork();
    if (child_pid < 0) {
	log_err("severe: Cannot fork() to writte radlast information\n");
	return -1;
    }
    if (child_pid > 0)
	/* in the parent all is okay */
	return 0;    

    /* now in the child context do the lastlog update */
    if (child_pid == 0) {
	FILE   *fp;
	char   log_file[PATH_MAX];

	/* first close the acct and sock fd, we don't listen here */
	close(acctfd); acctfd = -1;
	close(sockfd); sockfd = -1;
	memset(log_file, 0, sizeof(log_file));
	snprintf(log_file, sizeof(log_file), "%s/%d/%s-%02d", radacct_dir, 
	        1900+time_info->tm_year,
		RADIUS_LAST, 
		time_info->tm_mon+1);

	/* extra safety never hurts */
	umask(0027);

	/* now we should be safe */
	if ((fp = fopen(log_file, "a")) != NULL) {
	    if (fwrite(rl, sizeof(radlast), 1, fp) < 1)
		log_err("Could not write lastlog info for %s to %s\n",
			rl->login, log_file);
	    else fclose(fp);
	} else log_err("Cannot open lastlog file '%s' for logging\n",log_file);
	exit(0);
    }
    return 0;
}

/*
 *
 * Function: update_user_status
 *
 * Given an acct packet, it updates the internal databse structure to be in
 * sync with the reality...
 *			--cristiang
 */
int 
update_user_status(AUTH_REQ *authreq)
{
    GDBM_FILE 	dbf;
    int 	retval;
    datum 	key, content;
    int 	flag = GDBM_INSERT;
    char 	dbfile_name[PATH_MAX];
    radlast	rl;
    int		action;

    struct tm	*time_info;    

    if (!authreq || !authreq->request)
	return -1;

    /* Now build the radlast packet ... */
    action = build_radlast_from_authreq(&rl, authreq);

    if (!strlen(rl.login))
	return -1;
    if ((action != PW_STATUS_STOP) && (action != PW_STATUS_START))
	return -1;

    time_info = localtime(&rl.ut_time); /* Use start session time */

    debug("acct: %s user='%s', port=%d, time=%d, input=%d, output=%d\n",
	  (action==PW_STATUS_START)?"start":"stop",
	  rl.login, rl.ent.port, rl.length, rl.inb, rl.outb);

    /* Prepare the DB filename... */

    snprintf(dbfile_name,sizeof(dbfile_name),"%s/%d",radacct_dir,1900+time_info->tm_year);
    mkdir(dbfile_name,0755);
    snprintf(dbfile_name,sizeof(dbfile_name), "%s/%d/%s",
            radacct_dir,1900+time_info->tm_year,RADIUS_USER_STATS);
    dbf = gdbm_open(dbfile_name,0,GDBM_WRCREAT|GDBM_SYNC,0600,NULL );
    if (dbf == NULL) {
	log_err("Could not open database %s for updating user stats",
		dbfile_name);
	return -1;
    }

    /* Build the key */
    key.dptr = rl.login;
    key.dsize = strlen(rl.login);

    /* Search for a previous entry */
    content = gdbm_fetch(dbf, key);
    if (content.dptr != NULL) {
	/*  found */
	retval = update_db_record(action, &content, &rl, 
	                          time_info->tm_mon,time_info->tm_mday-1 );
	if (retval < 0) {
	    gdbm_close(dbf);
	    if (content.dptr != NULL) free(content.dptr);
	    return retval;
	}
	flag = GDBM_REPLACE;
    } else {
	/* key not found, insert new */
	retval = insert_db_record(action, &content, &rl,
	                          time_info->tm_mon,time_info->tm_mday-1 );
	if (retval < 0) {
	    gdbm_close(dbf);
	    if (content.dptr != NULL) free(content.dptr);
	    return retval;
	}
	flag = GDBM_INSERT;
    }	

    retval = gdbm_store(dbf, key, content, flag);
    gdbm_close(dbf);
    if (content.dptr != NULL) free(content.dptr);
    if (retval != 0) {
	log_err("acct: could not store entry for '%s' (session %s)\n",
		rl.login, (action==PW_STATUS_START)?"start":"stop");
	return -2;
    }
    if (action == PW_STATUS_STOP) retval = update_radlast(&rl);
    return retval;
}

/*
 * shadow_expire - checks if an account is expired according to
 *		   the shadow aging fields
 */
#if defined(SHADOW_EXPIRATION) && defined(SHADOW)

#ifndef DAY
#define	DAY	(3600*24)
#endif

int 
shadow_expired(const char *user)
{
    struct spwd *spw;
    int crt_day = time(NULL)/DAY; /* today date */
    int expire;
	
    if ((user == NULL) || !strlen(user)) {
	/* invalid call to this function */
	debug("shadow_expired: called with null argument\n");
	/* but the account is not expired... */
	return 0;
    }
    debug("shadow_expired: checking shadow expiration for user '%s'\n", user);	
    setspent();
    spw = getspnam(user);
    if (spw == NULL) {
	/* Oops, sorry, all missing accounts are not expired :-) */
	endspent();
	return 0;
    }
    if ((spw->sp_expire > 0) && (spw->sp_expire < crt_day)) {
	/* Expired */
	endspent();
	return -1;
    }
    if (spw->sp_lstchg == 0) {
	/* expired by root */
	endspent();
	return -1;
    }
    if ((spw->sp_max <= 0) || (spw->sp_max == 99999)) {
	/* password never expires */
	endspent();
	return 0;
    }
    if (spw->sp_lstchg + spw->sp_max + spw->sp_inact < crt_day) {
	/* password expired - password aged */
	endspent();
	return -1;
    }
    /* be nice and also report when password is due to expire */
    expire = spw->sp_lstchg + spw->sp_max + spw->sp_inact - crt_day;
    if ((expire >= 0) && (expire <= spw->sp_warn)) {
	/* warn the looser */
	endspent();
	return expire;
    }
    endspent();
    return 0;
}
#endif	





#if defined(PAM) && defined(HAVE_LIBPAM)

/* local variables */

static const char *PAM_username;
static const char *PAM_password;

/*
 *     Function: PAM_conv
 *     Purpose: Dialogue between RADIUS and PAM modules.
 */

static int 
PAM_conv_acct(int num_msg, const struct pam_message **msg,struct pam_response **resp, void *appdata_ptr)
{
    int count = 0, replies = 0;
    struct pam_response *reply = NULL;
    int size = sizeof(struct pam_response);
    
#define GET_MEM \
    if (reply) realloc(reply, size); \
    else reply = malloc(size); \
    if (!reply) return PAM_CONV_ERR; \
    size += sizeof(struct pam_response);
#define COPY_STRING(s) (s) ? strdup(s) : NULL					 

    for (count = 0; count < num_msg; count++) {
	switch (msg[count]->msg_style) {
	    case PAM_PROMPT_ECHO_ON:
		GET_MEM;
		reply[replies].resp_retcode = PAM_SUCCESS;
		reply[replies++].resp = COPY_STRING(PAM_username);
		/* PAM frees resp */
		break;
	    case PAM_PROMPT_ECHO_OFF:
		GET_MEM;
		reply[replies].resp_retcode = PAM_SUCCESS;
		reply[replies++].resp = COPY_STRING(PAM_password);
		/* PAM frees resp */
		break;
	    case PAM_TEXT_INFO:
		/* ignore it... */
		break;
	    case PAM_ERROR_MSG:
	    default:
		/* Must be an error of some sort... */
		free (reply);
		return PAM_CONV_ERR;
	}
    }
    if (reply)
	*resp = reply;
    return PAM_SUCCESS;
}

static struct pam_conv conv_acct = {
    (int (*)())PAM_conv_acct,
    NULL
};

/*
 *     Function: unix_pam
 *     Purpose: Check the users password against the standard UNIX
 *              password table + PAM.
 */

int 
unix_pam(const char *name, const char *passwd, const char *pamauth)
{
    pam_handle_t *pamh=NULL;
    int retval;
    
    PAM_username = name;
    PAM_password = passwd;
	     
    debug("unix_PAM: using pamauth string <%s> for pam.conf lookup\n", pamauth);    
    retval = pam_start(pamauth, name, &conv_acct, &pamh);
    if (retval == PAM_SUCCESS) {
	debug("unix_PAM: function pam_start succeeded for <%s>\n", name);
	retval = pam_authenticate(pamh, 0);
    }
    if (retval == PAM_SUCCESS) {
	debug("unix_PAM: function pam_authenticate succeeded for <%s>\n", name);
	retval = pam_acct_mgmt(pamh, 0);
    }

    /* do not remove block braces, it could break things due to debug
     * macro */
    
    if (retval == PAM_SUCCESS) {
	debug("unix_PAM: function pam_acct_mgmt succeeded for <%s>\n", name);
    }
    else {
	debug("unix_PAM: PAM FAILED for <%s> failed\n", name);
    }
    if (pam_end(pamh, retval) != PAM_SUCCESS) {
	pamh = NULL;
	log_err("ERROR!!!: PAM failed to release authenticator items");
    }
    return (retval == PAM_SUCCESS)?0:-1;
}

/*
 *     Function: PAM_conv_session
 *     Purpose: A dummy conversation function between the radiusd and the
 *              session modules.
 */
static int 
PAM_conv_session(int num_msg, const struct pam_message **msg,struct pam_response **resp, void *appdata_ptr)
{
    /* this one should never be called; use appdata_ptr instead */
    return PAM_CONV_ERR;
}
    
/*
 * We use this structure to pass the network packet pairs to
 * the session module(s)
 */
static struct pam_conv conv_session = {
    (int (*)())PAM_conv_session,	
    NULL	
};

/*
 * This is to save the handle of the PAM session betwenn incantations...
 */
static pam_handle_t *PAM_handle = NULL;

/*
 *     Function: pam_session
 *     Purpose: This is called when we are using PAM to inform the PAM
 *              library about the new sessions being open or closed by
 *		the NASes.
 */
void 
pam_session(AUTH_REQ *authreq)
{
    char		*username = NULL;
    VALUE_PAIR		*pair;
    int 		retval;
    pam_handle_t	*pamh = NULL;
    int			type=0;
    
    /* First, get some important data: username and the type of the packet */
    pair = authreq->request;
    while (pair != (VALUE_PAIR *)NULL) {
	switch (pair->attribute) {
	    case PW_USER_NAME:
		username = pair->strvalue;
		break;
	    case PW_ACCT_STATUS_TYPE:
		type = pair->lvalue;
		break;
	}
	pair = pair->next;
    }
    /* To do:
     * -we should maybe look at the NAS ip and set the
     *  PAM_RHOST item too. But for now it is not critical,
     *	and I am lazy..
     *		--cristiang
     */
    if ((username == NULL) || !type)
	/* nothing to do */
	return;

    /* initialize the conv_session struct */
    conv_session.appdata_ptr = authreq->request;
    /* we avoid to open to many sessions with pam_start because of the
     * overhead induced by this call. On a busy accounting server,
     * this is critical. We open just one session and reuse it later...
     */
    if (PAM_handle == (pam_handle_t *)NULL) {
	/* we need to open a new session */
	debug("about to init PAM session call for %s\n", username);    
	retval = pam_start(RADIUS_PAM_SERVICE, username, &conv_session, &pamh);
	if (retval != PAM_SUCCESS) {

#if !defined(OLD_PAM)
	    log_err("cannot initialize PAM session for %s (%s)\n",
		    username, pam_strerror(PAM_handle, retval));
#else
	    log_err("cannot initialize PAM session for %s (%s)\n",
		    username, pam_strerror(retval));
#endif 
	    return;
	} else
	    /* opened successfuly - save it for later use... */
	    PAM_handle = pamh;
    } else {
	/* we have already an open session - use that... */
	pamh = PAM_handle;
	/* and update the username */
	retval = pam_set_item(pamh, PAM_USER, username);
	if (retval != PAM_SUCCESS) {
#if !defined(OLD_PAM) /* The new pam libraries have 2 params for pam_strerr - misa*/
	    log_err("can not set username (%s) for acct packet: %s\n",
		  username, pam_strerror(PAM_handle, retval));
#else
	    log_err("can not set username (%s) for acct packet: %s\n",
		  username, pam_strerror(retval));
#endif /*OLD_PAM*/
	    return;
	}
	/* and the conversation structure, to get appdata pointer
	 * updated with the new pointer to the network packet...
	 */
	retval = pam_set_item(pamh, PAM_CONV, &conv_session);
	if (retval != PAM_SUCCESS) {
#if !defined(OLD_PAM) /* The new pam libraries have 2 params for pam_strerr - misa*/
	    log_err("can not pass acct packet for %s: %s\n",
		  username, pam_strerror(PAM_handle, retval));
#else
	    log_err("can not pass acct packet for %s: %s\n",
		  username, pam_strerror(retval));
#endif /*OLD_PAM*/
	    return;
	}
    }
    /* all good, now do we start or close a session ? */
    if (type == PW_STATUS_START) {
	/* start session */
	debug("opening session for user %s\n", username);	
	retval = pam_open_session(pamh, 0);
	if (retval != PAM_SUCCESS) {
#if !defined(OLD_PAM) /* The new pam libraries have 2 params for pam_strerr - misa*/
	    log_err("could not start session for user %s (%s)\n",
		    username, pam_strerror(PAM_handle, retval));
#else
	    log_err("could not start session for user %s (%s)\n",
		    username, pam_strerror(retval));
#endif /*OLD_PAM*/
	    return;
	}
    }
    if (type == PW_STATUS_STOP) {	
	/* close session */
	debug("closing session for user %s\n", username);
	retval = pam_close_session(pamh, 0);
	if (retval != PAM_SUCCESS) {
#if !defined(OLD_PAM) /* The new pam libraries have 2 params for pam_strerr - misa*/
	    log_err("could not close session for user %s (%s)\n",
		    username, pam_strerror(PAM_handle, retval));
#else
	    log_err("could not close session for user %s (%s)\n",
		    username, pam_strerror(retval));
#endif /*OLD_PAM*/
	    return;
	}
    }
    /* we don't call pam_end because this code is not supposed to die()...
     * <sigh!> --cristiang
     */
    return;
}
#else 
#if defined(PAM) && !defined(HAVE_LIBPAM)
#error "PAM development library missed. Check your configuration."
#endif

#endif /* PAM */


/*
 * SOME BASIC PACKET QUEUE MANAGEMENT STUFF
 *
 * Idea: eliminate the duplicate acct packets problem and sort out the
 *	out-of-order packets to get better accounting
 */

static acct_packet *root_acct_packet = NULL;
static int acct_queue_entries = 0;

static acct_packet *
in_acct_queue(acct_packet *packet, int type)
{
    acct_packet *this;
    this = root_acct_packet;
    while (this != (acct_packet *)NULL) {
	if (
	    (this->port == packet->port) &&
	    (this->nas_ip == packet->nas_ip) &&
	    !strncmp(this->username, packet->username, sizeof(packet->username)) &&
	    !strncmp(this->sessionid, packet->sessionid, sizeof(packet->sessionid)) &&
	    (this->type & type)
	    )
	    return this;
	this = this->next;
    }
    return (acct_packet *)NULL;
}

/*
 * Adds a pack to the queue
 */
static int 
add_acct_queue(acct_packet *packet)
{
    acct_packet *this, *temp;

    this = root_acct_packet;
    temp = in_acct_queue(packet, packet->type);
    if (temp != (acct_packet *)NULL)
	return 0;
    temp = in_acct_queue(packet, PW_STATUS_STOP | PW_STATUS_START);
    if (temp != (acct_packet *)NULL) {
	temp->type |= packet->type;
	return 1;
    }
    temp = (acct_packet *)NULL;
    while (this != (acct_packet *)NULL) {
	temp = this;
	this = this->next;
    }
    this = (acct_packet *)malloc(sizeof(acct_packet));
    if (this == (acct_packet *)NULL) {
	log_err("MEMORY ERROR !!! Can not alloc memory for acct packet %s (user %s)",
		packet->sessionid, packet->username);
	return 0;
    }
    if (temp == (acct_packet *)NULL)
	temp = this;
    else {
	temp->next = this;
	temp = this;
    }
    temp->next = (acct_packet *)NULL;
    /* one more entry */
    acct_queue_entries++;
    /* root list empty */
    if (root_acct_packet == (acct_packet *)NULL)
	root_acct_packet = temp;
    /* copy over */
    memcpy(temp, packet, sizeof(acct_packet));
    return 1;
}

/*
 * Removes a packet from the queue
 */
static int 
remove_acct_queue(acct_packet *packet)
{
    acct_packet	*temp, *temp1;
        
    temp = in_acct_queue(packet, PW_STATUS_START | PW_STATUS_STOP);
    if (temp == (acct_packet *)NULL)
	return 0;
    if (temp->type != (PW_STATUS_START | PW_STATUS_STOP))
	return 0;
    if (temp == root_acct_packet) {
	/* oops. the root is here ... */
	root_acct_packet = root_acct_packet->next;
    } else {
	temp1 = root_acct_packet;
	while (temp1->next != temp)
	    temp1 = temp1->next;
	temp1->next = temp->next;
    };
    free(temp);
    acct_queue_entries--;
    return 1;
}

/*
 * Delete the oldest pair of (start,stop) packets from the queue
 * to make room for more
 */
static int 
cleanup_acct_queue(void)
{
    acct_packet *temp;

    temp = root_acct_packet;
    while (temp != (acct_packet*)NULL) {
	if (temp->type == (PW_STATUS_START | PW_STATUS_STOP))
	    return remove_acct_queue(temp);
	temp = temp->next;
    }
    return 1;
}

/*
 * Returns > 0 if the packet passed is valid, 0 otherwise
 * A valid packet is:
 * - a new one (we haven't seen it before)
 * - a stop packet
 * - a start packet which is not out of order (we haven't seen
 *	the corresponsing packet for it yet
 */
int 
validate_acct_packet(AUTH_REQ *authreq)
{
    acct_packet packet;
    VALUE_PAIR	*pair;

    /* Some run-time debugging */
    if (acct_queue_entries > 2*MAX_ACCT_QUEUE) {
	log_debug("WARNING: acct queue is large: %d entries, max %d\n",
		  acct_queue_entries, MAX_ACCT_QUEUE);
	log_debug("possible unreliable communication with term servers ?\n");
    }
      
    pair = authreq->request;
    memset(&packet, 0, sizeof(acct_packet));
    while (pair != (VALUE_PAIR *)NULL) {
	switch (pair->attribute) {
	    case PW_ACCT_STATUS_TYPE:
		packet.type = pair->lvalue;
		break;
	    case PW_USER_NAME:
		strncpy(packet.username, (char *)pair->strvalue, sizeof(packet.username));
		break;
	    case PW_CLIENT_PORT_ID:
		packet.port = pair->lvalue;
		break;
	    case PW_CLIENT_ID:
		packet.nas_ip = pair->lvalue;
		break;
	    case PW_ACCT_SESSION_ID:
		strncpy(packet.sessionid, (char *)pair->strvalue, sizeof(packet.sessionid));
		break;
	};
	pair = pair->next;
    };
    /* we have a complete packet ... */
    if (in_acct_queue(&packet, packet.type) != (acct_packet *)NULL)
	return 0;
    if (packet.type == PW_STATUS_START) {
	if (!add_acct_queue(&packet))
	    log_err("ERROR!!!: could not add acct packet to queue (%s/%s)",
		    packet.sessionid, packet.username);
	if (in_acct_queue(&packet, PW_STATUS_STOP) != (acct_packet *)NULL)
	   return 0;

    } else if (packet.type == PW_STATUS_STOP) {
	if (!add_acct_queue(&packet))
	    log_err("ERROR!!!: could not add acct packet to queue (%s/%s)",
		    packet.sessionid, packet.username);
	if (in_acct_queue(&packet, PW_STATUS_START) != (acct_packet *)NULL)
	    if (acct_queue_entries > MAX_ACCT_QUEUE)
		if (!cleanup_acct_queue())
		    log_err("ERROR!!!: could not cleanup the acct packet queue!");
    } else
	return 0;
    return 1;
}

/*
 * MD5 crypt() support for systems using both DES and MD5
 */


static unsigned char itoa64[] =		/* 0 ... 63 => ascii - 64 */
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void 
to64(char *s, unsigned long v, int n)
{
    while (--n >= 0) {
	*s++ = itoa64[v&0x3f];
	v >>= 6;
    }
}

/*
 * UNIX password
 *
 * Use MD5 for what it is best at...
 */


char * 
crypt_md5(const char *pw, const char *salt)
{
    const char *magic = "$1$";
    /* This string is magic for this algorithm.  Having
     * it this way, we can get get better later on */
    static char passwd[120], *p;
    static const char *sp,*ep;
    unsigned char	final[16];
    int sl,pl,i,j;
    MD5_CTX	ctx,ctx1;
    unsigned long l;

    /* Refine the Salt first */
    sp = salt;

    /* If it starts with the magic string, then skip that */
    if(!strncmp(sp,magic,strlen(magic)))
	sp += strlen(magic);

    /* It stops at the first '$', max 8 chars */
    for(ep=sp;*ep && *ep != '$' && ep < (sp+8);ep++)
	continue;

    /* get the length of the true salt */
    sl = ep - sp;

    MD5Init(&ctx);

    /* The password first, since that is what is most unknown */
    MD5Update(&ctx, (unsigned const char *)pw, strlen(pw));

    /* Then our magic string */
    MD5Update(&ctx, (unsigned const char *)magic,strlen(magic));

    /* Then the raw salt */
    MD5Update(&ctx, (unsigned const char *)sp, sl);

    /* Then just as many characters of the MD5(pw,salt,pw) */
    MD5Init(&ctx1);
    MD5Update(&ctx1, (unsigned const char *)pw, strlen(pw));
    MD5Update(&ctx1, (unsigned const char *)sp, sl);
    MD5Update(&ctx1, (unsigned const char *)pw, strlen(pw));
    MD5Final(final,&ctx1);
    for(pl = strlen(pw); pl > 0; pl -= 16)
	MD5Update(&ctx, (unsigned const char *)final,pl>16 ? 16 : pl);

    /* Don't leave anything around in vm they could use. */
    memset(final,0,sizeof final);

    /* Then something really weird... */
    for (j=0,i = strlen(pw); i ; i >>= 1)
	if(i&1)
	    MD5Update(&ctx, (unsigned const char *)final+j, 1);
	else
	    MD5Update(&ctx, (unsigned const char *)pw+j, 1);

    /* Now make the output string */
    strcpy(passwd,magic);
    strncat(passwd,sp,sl);
    strcat(passwd,"$");

    MD5Final(final,&ctx);

    /*
     * and now, just to make sure things don't run too fast
     * On a 60 Mhz Pentium this takes 34 msec, so you would
     * need 30 seconds to build a 1000 entry dictionary...
     */

    for(i=0; i<1000; i++) {
	MD5Init(&ctx1);
	if(i & 1)
	    MD5Update(&ctx1, (unsigned const char *)pw, strlen(pw));
	else
	    MD5Update(&ctx1, (unsigned const char *)final, 16);

	if(i % 3)
	    MD5Update(&ctx1, (unsigned const char *)sp, sl);

	if(i % 7)
	    MD5Update(&ctx1, (unsigned const char *)pw, strlen(pw));

	if(i & 1)
	    MD5Update(&ctx1, (unsigned const char *)final, 16);
	else
	    MD5Update(&ctx1, (unsigned const char *)pw, strlen(pw));
	MD5Final(final,&ctx1);
    }
    p = passwd + strlen(passwd);

    l = (final[ 0]<<16) | (final[ 6]<<8) | final[12]; to64(p,l,4); p += 4;
    l = (final[ 1]<<16) | (final[ 7]<<8) | final[13]; to64(p,l,4); p += 4;
    l = (final[ 2]<<16) | (final[ 8]<<8) | final[14]; to64(p,l,4); p += 4;
    l = (final[ 3]<<16) | (final[ 9]<<8) | final[15]; to64(p,l,4); p += 4;
    l = (final[ 4]<<16) | (final[10]<<8) | final[ 5]; to64(p,l,4); p += 4;
    l =                    final[11]                ; to64(p,l,2); p += 2;
    *p = '\0';

    /* Don't leave anything around in vm they could use. */
    memset(final,0,sizeof final);

    return passwd;
}


/*
 * Check if the current time is an allowed time to log in according
 * to the parameter
 * Modified by Misa -- time interval function completely rewritten
 */

#define MAX_TIMES 	10	/* max number of time specifications
				 * in one shot using commas */
#define SEPARATOR	';'				
int 
allowed_time(const char *time_str)
{
    struct time_frame	times[MAX_TIMES];
    /* Structures for storing the priorities in the time intervals */
    int 	priority[MAX_TIMES], cur_priority;
    int		i, j, dtime;
    const char	*cp;
    time_t	curtime;
    struct tm 	*tm;
    int		error_tokens; /* Number of bogus tokens */
    long 	session_timeout; /* This is the number of seconds 
    				  * allowed in this session */
    int		beg_day, end_day;
#ifdef EXT_DEBUG
FILE* auxdebug;

auxdebug = fopen("nighthawk","a");
#endif

    if (time_str == NULL) {
	/* cry loud */
	debug("allowed_times: passed a null pointer !!!\n");
	/* After all, it is okay... */
	return 0;
    }
    
    debug("allowed_time: checking time against %s\n", time_str);
#ifdef EXT_DEBUG
Debug(auxdebug,"allowed_time: checking time against %s\n", time_str);
#endif
    /* Initialize the time structures */
    curtime = time(NULL);
    tm = localtime(&curtime);
    error_tokens = 0; /* We assume all tokens are correct */

    cp = time_str;
    beg_day = end_day = 0; 
    for (j = 0; *cp && j < MAX_TIMES; j++) {
	/*
	 * Start off with no days of the week
	 */
	times[j].t_days = 0;
	priority[j] = 1; /* One-day priority, the highest */
	
	/*
	 * Check each two letter sequence to see if it is
	 * one of the abbreviations for the days of the
	 * week or the other two values.
	 */
	for (i = 0; cp[i] && cp[i+1] && isalpha(cp[i]); i+=2) {
	    switch ((cp[i] << 8) | (cp[i+1])) {
		case ('S' << 8) | 'u':
		    times[j].t_days |= Su_DAY;
		    beg_day = Su_DAY;
		    break;
		case ('M' << 8) | 'o':
		    times[j].t_days |= Mo_DAY;
		    beg_day = Mo_DAY;
		    break;
		case ('T' << 8) | 'u':
		    times[j].t_days |= Tu_DAY;
		    beg_day = Tu_DAY;
		    break;
		case ('W' << 8) | 'e':
		    times[j].t_days |= We_DAY;
		    beg_day = We_DAY;
		    break;
		case ('T' << 8) | 'h':
		    times[j].t_days |= Th_DAY;
		    beg_day = Th_DAY;
		    break;
		case ('F' << 8) | 'r':
		    times[j].t_days |= Fr_DAY;
		    beg_day = Fr_DAY;
		    break;
		case ('S' << 8) | 'a':
		    times[j].t_days |= Sa_DAY;
		    beg_day = Sa_DAY;
		    break;
		case ('W' << 8) | 'k':
		    /* communists, watch out ! :-) */
		    times[j].t_days |= (Mo_DAY|Tu_DAY|We_DAY|Th_DAY|Fr_DAY);
		    beg_day = 0; /* Not a valid day to begin an interval */
		    priority[j] = 3; /* The third priority */
		    break;
		case ('A' << 8) | 'l':
		    times[j].t_days |= (Mo_DAY|Tu_DAY|We_DAY|Th_DAY|Fr_DAY|Sa_DAY|Su_DAY);
		    beg_day = 0; /* Not a valid day to begin an interval */
		    priority[j] = 4; /* The lowest priority */
		    break;
		default:
		    log_err("syntax error in string %s specifying times allowed to log in\n",
			    time_str);
		    return 0; /* syntax error, can't continue ... */
	    }
	}
	/*
	 * The default is 'Al' if no days were seen.
	 */
	if (i == 0) {
	    debug("allowed_time: time specification incompete - assuming Al; i=%d\n",i);
	    times[j].t_days = Mo_DAY|Tu_DAY|We_DAY|Th_DAY|Fr_DAY|Sa_DAY|Su_DAY;
	    beg_day = 0; /* Not a valid day to begin an interval */
	}

	/*
	 * Testing if we have a day interval
	 *
	*/	
	if (cp[i]=='-') {
		if (beg_day==0) /* Error, cunt have an interval */
		{
			debug("Error in the token %d: cannot have such a day interval; skipped\n",j+1);
			error_tokens++;
			for (;cp[i] && cp[i]!=SEPARATOR;i++);
			cp += cp[i] ? i+1 : i; /* We jump the bogus token */
			continue;
		}
		i++; 
		cp += i;
		i=0; 
		
		if (cp[0] && cp[1] && isalpha(cp[i])) {
			switch ((cp[0] << 8) | (cp[1])) {
				case ('S' << 8) | 'u':
					times[j].t_days |= Su_DAY;
					end_day = Su_DAY;
					break;
				case ('M' << 8) | 'o':
					times[j].t_days |= Mo_DAY;
					end_day = Mo_DAY;
					break;
				case ('T' << 8) | 'u':
					times[j].t_days |= Tu_DAY;
					end_day = Tu_DAY;
					break;
				case ('W' << 8) | 'e':
					times[j].t_days |= We_DAY;
					end_day = We_DAY;
					break;
				case ('T' << 8) | 'h':
					times[j].t_days |= Th_DAY;
					end_day = Th_DAY;
					break;
				case ('F' << 8) | 'r':
					times[j].t_days |= Fr_DAY;
					end_day = Fr_DAY;
					break;
				case ('S' << 8) | 'a':
					times[j].t_days |= Sa_DAY;
					end_day = Sa_DAY;
					break;
				case ('W' << 8) | 'k':
					/* communists, watch out ! :-) */
					end_day = 0; /* Not a valid day to begin an interval */
					break;
				case ('A' << 8) | 'l':
					end_day = 0; /* Not a valid day to begin an interval */
					break;
				default:
					log_err("syntax error in string %s specifying times allowed to log in\n",
						time_str);
					return 0; /* syntax error, can't continue ... */
			}
		}
		/*
		*  Nothing means error
		*/
		if (end_day==0) {
			debug("Error in the token %d: not a valid day\n",j);
			times[j].t_days = Mo_DAY|Tu_DAY|We_DAY|Th_DAY|Fr_DAY|Sa_DAY|Su_DAY;
			end_day = 0; /* Not a valid day to end an interval */
		}
			for (; beg_day != end_day;)
		{
			/* mark the day */
			times[j].t_days |= beg_day;
			/* go to the next day, with wrapping if needed */
			beg_day = (beg_day==Sa_DAY) ? Su_DAY : beg_day << 1;
		} 
		times[j].t_days |= beg_day;
		priority[j]=2; /* second priority */
		i+=2;
	}

	/*
	 * The start and end times are separated from each
	 * other by a '-'.  The times are four digit numbers
	 * representing the times of day.
	 */

	/*
	 * We jump the checked items, to be able to easily count up to 4 digits
	*/
	cp += i;
	i = 0; 

	for (dtime = 0; i<4 && cp[i] && isdigit(cp[i]); i++)
		dtime = dtime * 10 + cp[i] - '0';
	if (cp[i] && isdigit(cp[i]))
	{
		/* Ooops, problem, too many digits */
		debug("Error in the token %d: too many digits for the begin time; skipped\n",j+1);
		/* 
		 * I try to give up, jumping to the next
		 * token separator
		*/ 
		error_tokens++;
		for (;cp[i] && cp[i]!=SEPARATOR;i++);
		cp += cp[i] ? i+1 : i; /* We jump the bogus token */
		continue;
	}
	
	if (cp[i] != '-' || dtime > 2400 || dtime % 100 > 59)
	{
	    debug("Error in the token %d: begin time invalid; skipped\n",j+1);
	    error_tokens++;
	    /* See the coments above */
	    for (;cp[i] && cp[i]!=SEPARATOR;i++);
	    cp += cp[i] ? i+1 : i; /* We jump the bogus token */
	    continue;
	}
	times[j].t_start = dtime;
	cp += i+1;
	for (dtime = i = 0; i<4 && cp[i] && isdigit (cp[i]); i++)
	    dtime = dtime * 10 + cp[i] - '0';
	if (cp[i] && isdigit(cp[i]))
	{
		/* 
		 * Ooops, problem, too many digits 
		 * But this time we go over this error, since
		 * we have found a valid time stamp
		 */
		debug("Error in the token %d: too many digits for the end time\n",j+1);
		error_tokens = -error_tokens - 1;
	}
	if (dtime > 2400 || dtime % 100 > 59)
	{
	    /* 
	     * Yet another error in the string
	    */
	    debug("Error in the token %d: end time invalid; skipped\n",j+1);
	    error_tokens = error_tokens>=0 ? error_tokens+1 : -error_tokens;
	    for (; cp[i] && cp[i]!=SEPARATOR; i++);
	    cp += cp[i] ? i+1 : i; /* We jump the bogus token */
	    continue;
	}
	if (error_tokens<0) error_tokens = -error_tokens;
	times[j].t_end = dtime;
	for (; cp[i] && cp[i]!=SEPARATOR; i++);
	cp += cp[i] ? i+1 : i;
    }

    /* we now have j entries */
    for (session_timeout = 0, cur_priority = 100, i = 0; i < j; i++) {
	/* check the current time against each timeframe */
	int s_time, e_time;
	
	if ( times[i].t_start <= times[i].t_end ) /* No time wrapping */
	{
		if ( (times[i].t_days & (1<<(tm->tm_wday))) == 0 ) 
				/* No matching for this day */
			continue;
	}
	else /* We do have time wrapping */
	{
		if ( (times[i].t_days & (1<<(tm->tm_wday))) == 0 &&
			(times[i].t_days & (1<<((tm->tm_wday + 6)%7)) ) == 0 )
			/* Hey, don't you like LISP? */
		/* No match for today or yesterday */
			continue;
	}
	e_time = s_time = curtime - tm->tm_hour*3600 - tm->tm_min*60 - tm->tm_sec;
	s_time += (times[i].t_start/100)*3600 + (times[i].t_start%100)*60;
	e_time += (times[i].t_end/100)*3600 + (times[i].t_end%100)*60;
	/* check for time wrap ... */
	if (times[i].t_start > times[i].t_end) {
	    /* time is wrapping accross 0 */
	    if (curtime >= s_time)
		/* current time passed start_time,
		 * end_time will be tomorrow */
		e_time += 24*3600;
	    else if (curtime <= e_time)
		/* current time before end time, start_time was yesterday */
	       s_time -= 24*3600;
	}
	/* now check if it is allowed to log in now */
	if ( priority[i] > cur_priority)
		continue; /* We already have a higher priority option */  
	if (priority[i] == cur_priority && curtime > s_time && 
		session_timeout < e_time - curtime)
	{
		session_timeout = e_time - curtime;
		continue;
	}
	cur_priority = priority[i]; /* This is a higher priority option */
	session_timeout = (s_time < curtime && e_time-curtime>0) ? e_time-curtime : 0; 
    }
    if (error_tokens)
    	debug(" %d error(s) found in the time string\n",error_tokens);
    if (session_timeout <= 0) {
    	debug("allowed_time: access denied\n");
#ifdef EXT_DEBUG
Debug(auxdebug,"allowed_time: access denied\n");
fclose(auxdebug);
#endif
    	return -1;
    }
    debug("allowed_time: access allowed for %d seconds\n",session_timeout);
#ifdef EXT_DEBUg
Debug(auxdebug,"allowed_time: access allowed for %d seconds\n",session_timeout);
fclose(auxdebug);
#endif
    return 0;	
}


/*
 * Implement the traffic quota for an user
 */
int 
check_maxtraffic(char *user, const int size,const int kind)
{	
    char 	dbfile_name[PATH_MAX];
    GDBM_FILE 	dbf;
    datum 	key, content;
    user_entry	*ue;
    struct tm	*time_info;
    int		i,j;
    UINT4	counter;
    time_t 	crt_time = time(NULL);
    
    time_info = localtime(&crt_time);
    memset(dbfile_name, 0, PATH_MAX);
    snprintf(dbfile_name, sizeof(dbfile_name), "%s/%d/%s",
	    radacct_dir, 1900+time_info->tm_year,RADIUS_USER_STATS );
    dbf = gdbm_open(dbfile_name,0,GDBM_READER,0600,NULL );
    if (dbf == NULL) {
	return 0;
    }
		      
    /* sanity checks */
    if (user == NULL)
	return -1;
    
    /* Build the key */
    key.dptr = user;
    key.dsize = strlen(user);
						       
    content = gdbm_fetch(dbf,key);
    if (content.dptr == NULL) {
	/* not here, login is allowed */
	gdbm_close(dbf);
	if ( content.dptr!=NULL ) free( content.dptr );
	return 0;
    }
    ue = (user_entry *)content.dptr;

    switch ( kind )
      {
      case DAY_LIMIT:
        if (ue->day[time_info->tm_mon][time_info->tm_mday-1].input_octets+
	    ue->day[time_info->tm_mon][time_info->tm_mday-1].output_octets >= 
	    size*1024) 
	  {
	  gdbm_close(dbf);
	  if ( content.dptr!=NULL ) free( content.dptr );
	  return -2;
          }
	break;

      case MONTH_LIMIT:
        for ( i=0, counter=0; i<time_info->tm_mday; i++ ) 
	  {
	  counter += ue->day[time_info->tm_mon][i].input_octets;
	  counter += ue->day[time_info->tm_mon][i].output_octets;
	  }
	if ( counter >= size*1024 )
	  {
	  gdbm_close(dbf);
	  if ( content.dptr!=NULL ) free( content.dptr );
	  return -2;
	  }
        break;

      case YEAR_LIMIT:
        for ( i=0, counter=0; i<=time_info->tm_mon; i++ ) 
          for ( j=0; i<time_info->tm_mday; i++ ) 
	    {
	    counter += ue->day[i][j].input_octets;
	    counter += ue->day[i][j].output_octets;
	    }
	if ( counter >= size*1024 )
	  {
	  gdbm_close(dbf);
	  if ( content.dptr!=NULL ) free( content.dptr );
	  return -2;
	  }
        break;

      default:
        log_err("internal error: invalid kind of limit in a "
	        "check_maxtraffic() call\n");
        break;
      }
    gdbm_close(dbf);
    if ( content.dptr!=NULL ) free( content.dptr );
    return 0;
}
