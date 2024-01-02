/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

/*
 * RADWATCH
 *
 * This program is intened to be run from cron every N minutes (were
 * N >= 5) to enforce user login limits between certain hours of the
 * day. Curently only times which DO NOT WRAP at midnight are known 
 * to work, although theoretically the code is able to handle that
 * case too.
 *
 * This program is intended to be used in conjunction with pm_kill
 * program. On normal usage, it will output a list of users which
 * have exceeded their quota (if any) during the time of the 
 * restriction period.
 *
 * For usage examples, check the supplied radwatch.conf file 
 * distributed with this release.
 */

#include "yard.h"

#define REVISION    "$Revision: 81 $"
#define RADWATCH   "radwatch.conf"	/* radwatch config file */

#ifndef min
#define min(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef max
#define max(a,b) ((a)>(b)?(a):(b))
#endif

/*
 * PORT_IDS - Allowable number of IDs per entry.
 * PORT_TTY - Allowable number of TTYs per entry.
 * PORT_TIMES - Allowable number of time entries per entry.
 * PORT_DAY - Day of the week to a bit value (0 = Sunday).
 */

#define	PORT_IDS	64
#define	PORT_TTY	64
#define	PORT_TIMES	24
#define	PORT_DAY(day)	(1<<(day))

int debug_mem=0;

/*
 *	pt_names - pointer to array of device names in /dev/
 *	pt_users - pointer to array of applicable user IDs.
 *	pt_times - pointer to list of allowable time periods.
 */
struct	conf_line	{
    long        restriction;
    char	**users;
    struct	time_frame  *times;
};

struct period {
    time_t start;
    time_t end;
};

typedef struct user_time {
    int  restriction;
    int  counted;
    char username[USERNAME_MAX];
    struct period period;
    struct user_time *next;
} USER_TIME;

static FILE	*ports;
static int      monthly_detail;
const char      *progname = NULL;
const char      *radius_dir = NULL;
const char      *rad_acctdir = NULL;
const char      *radius_log = NULL;
int             debug_flag = 0;
static USER_TIME *user_time_head = NULL;

#if defined(SUN)
	extern char *optarg;
#endif 

/* Inserts a new entry into the linked list of the known users. The space is */
/* malloced and should be free'd later (using empty_user_time_list()) */
static void 
add_user_time_list(char *username, struct period period, int restriction, int counted)
{
    USER_TIME *ut;

    ut = user_time_head;
    while (ut != NULL) {
	if ((strcmp(ut->username, username) == 0) &&
	    (ut->period.start == period.start) &&
	    (ut->period.end == period.end))
	    /* already on list */
	    return;
	ut = ut->next;
    }

    ut = (USER_TIME *)malloc(sizeof(USER_TIME));
    if (ut == NULL) {
	fprintf(stderr, "malloc error - out of memory\n");
	exit(-2);
    }
    memset(ut, 0, sizeof(USER_TIME));
    strncpy(ut->username, username, USERNAME_MAX);
    ut->restriction = restriction;
    ut->counted = counted;
    ut->period.start = period.start;
    ut->period.end = period.end;
    ut->next = user_time_head;
    user_time_head = ut;
}    
	
/* This function traverse the linked list of the known users and free() */
/* the space used by it's elements. */
static void 
empty_user_time_list(void)
{
    USER_TIME *ut;
    
    ut = user_time_head;
    if (ut == NULL)
	return;
    while (ut->next != NULL) {
	USER_TIME *temp;
	temp = ut->next;
	free(ut);
	ut = temp;
    }
}

/* Open the configuration file */
static void 
open_conf_file(void)
{
    static char filename[PATH_MAX];

    if (ports)
	rewind (ports);
    else {
	memset(filename, 0, sizeof(filename));
	sprintf(filename, "%s/%s", radius_dir, RADWATCH);
	ports = fopen(filename, "r");
    }
}

/* Close the configuration file */
static void 
close_conf_file(void)
{
    if (ports)
	fclose (ports);
    
    ports = (FILE *) 0;
}

/* Reads and parses the next valid config line from the program's */
/* configuration file. All the data it returns it is statically */
/* allocated, no need to be free'd. The parser _should_ work... */
static struct conf_line *
get_conf_line(void)
{
    static	struct	conf_line  conf_line;	/* static struct to point to         */
    static	char	buf[BUFSIZ];	/* some space for stuff              */
    static	char	*users[PORT_IDS+1]; /* some pointers to user ids     */
    static	struct	time_frame times[PORT_TIMES+1]; /* time ranges         */
    char	*cp;			/* pointer into line                 */
    int	dtime;			/* scratch time of day               */
    int	i, j;

    /*
     * If the ports file is not open, open the file.  Do not rewind
     * since we want to search from the beginning each time.
     */

    if (! ports)
	open_conf_file();

    if (! ports) {
	fprintf(stderr, "Can not open configuration file (%s/%s).\n",
		radius_dir, RADWATCH);
	exit(-1);
    }

    /*
     * Common point for beginning a new line -
     *
     *	- read a line, and NUL terminate
     *	- skip lines which begin with '#'
     *	- parse off a list of user names
     *  - parse off the restriction value
     *	- parse off a list of days and times
     */

    for(;;) {
	/*
	 * Get the next line and remove the last character, which
	 * is a '\n'.  Lines which begin with '#' are all ignored.
	 */

	if (fgets (buf, sizeof(buf), ports) == 0)
	    return NULL;
	if (buf[0] == '#')
	    continue;

	buf[strlen (buf) - 1] = 0;
	cp = buf;

	/*
	 * Get the list of user names.  It is the first colon
	 * separated field, and is a comma separated list of user
	 * names.  The entry '*' is used to specify all usernames.
	 * The last entry in the list is a (char *) 0 pointer.
	 */

	conf_line.users = users;
	conf_line.users[0] = cp;

	for (j = 1; *cp != ':'; cp++) {
	    if (*cp == ',' && j < PORT_IDS) {
		*cp++ = 0;
		conf_line.users[j++] = cp;
	    }
	}
	conf_line.users[j] = 0;

	if (*cp != ':') /* line format error */
	    continue;

	*cp++ = '\0';

	/* Get the restriction time. Next item should be an int */
	if (!isdigit(*cp))
	    /* line format error */
	    continue;
	else {
	    long restriction;
	    char **endptr = (char **) &cp;
	    restriction = strtol(cp, endptr, 10);
	    if ((restriction == 0) && (*endptr == cp)) /* no chars read */
		continue;
	    conf_line.restriction = restriction;
	    cp = *endptr;
	}

	if (*cp != ':') /* line format error */
	    continue;

	*cp++ = '\0';

	/*
	 * Get the list of valid times.  The times field is the third
	 * colon separated field and is a list of days of the week and
	 * times during which this port may be used by this user.  The
	 * valid days are 'Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', and 'Sa'.
	 *
	 * In addition, the value 'Al' represents all 7 days, and 'Wk'
	 * represents the 5 weekdays.
	 *
	 * Times are given as HHMM-HHMM.  The ending time may be before
	 * the starting time.  Days are presumed to wrap at 0000.
	 */

	if (*cp == '\0') {
	    /* This kind of limit apply to every day, all hours */
	    conf_line.times = 0;
	    return &conf_line;
	}

	conf_line.times = times;
	
	/*
	 * Get the next comma separated entry
	 */

	for (j = 0;*cp && j < PORT_TIMES;j++) {
	    /*
	     * Start off with no days of the week
	     */
	    conf_line.times[j].t_days = 0;

	    /*
	     * Check each two letter sequence to see if it is
	     * one of the abbreviations for the days of the
	     * week or the other two values.
	     */

	    for (i = 0; cp[i] && cp[i+1] && isalpha (cp[i]); i += 2) {
		switch ((cp[i] << 8) | (cp[i+1])) {
		    case ('S' << 8) | 'u':
			conf_line.times[j].t_days |= Su_DAY;
			break;
		    case ('M' << 8) | 'o':
			conf_line.times[j].t_days |= Mo_DAY;
			break;
		    case ('T' << 8) | 'u':
			conf_line.times[j].t_days |= Tu_DAY;
			break;
		    case ('W' << 8) | 'e':
			conf_line.times[j].t_days |= We_DAY;
			break;
		    case ('T' << 8) | 'h':
			conf_line.times[j].t_days |= Th_DAY;
			break;
		    case ('F' << 8) | 'r':
			conf_line.times[j].t_days |= Fr_DAY;
			break;
		    case ('S' << 8) | 'a':
			conf_line.times[j].t_days |= Sa_DAY;
			break;
		    case ('W' << 8) | 'k':
			conf_line.times[j].t_days |= Wk_DAY;
			break;
		    case ('A' << 8) | 'l':
			conf_line.times[j].t_days |= Al_DAY;
			break;
		    default:		    
			return NULL; /* syntax error, can't continue ... */
		}
	    }
	
	    /*
	     * The default is 'Al' if no days were seen.
	     */
	
	    if (i == 0)
		conf_line.times[j].t_days = Al_DAY;
	
	    /*
	     * The start and end times are separated from each
	     * other by a '-'.  The times are four digit numbers
	     * representing the times of day.
	     */

	    for (dtime = 0; cp[i] && isdigit (cp[i]); i++)
		dtime = dtime * 10 + cp[i] - '0';
	    if (cp[i] != '-' || dtime > 2400 || dtime % 100 > 59)
		continue;
	    conf_line.times[j].t_start = dtime;
	    cp = cp + i + 1;
	    for (dtime = i = 0; cp[i] && isdigit (cp[i]); i++)
		dtime = dtime * 10 + cp[i] - '0';
	    if ((cp[i] != ',' && cp[i]) ||
		dtime > 2400 || dtime % 100 > 59)
		continue;
	    conf_line.times[j].t_end = dtime;
	    cp = cp + i + 1;
	}

	/*
	 * The end of the list is indicated by a pair of -1's for the
	 * start and end times.
	 */
	conf_line.times[j].t_start = conf_line.times[j].t_end = -1;
	return &conf_line;
    }
    return NULL; /* NOT REACHEAD... */
}

int 
unix_group(const char *name, const char *group)
{
    struct passwd       *pwd;
    char                **gr_mem;
    struct group        *gr_ent;

    /* Get encrypted password from password file */
    if((pwd = getpwnam(name)) == NULL) {
	debug("unix_group: getpwnam for <%s> failed\n", name);
	return(0);
    }

    if((gr_ent = getgrnam(group)) == NULL) {
	debug("unix_group: getgrnam(%s) for <%s> failed\n", group,name);
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

/*
 * get_user_line - get ports information for user and tty
 *
 *	get_user_line() searches the conf file for an entry with a
 *	user field which match the supplied user name. The file is
 *      searched from the beginning, so the entries are treated as
 *      an ordered list.
 */
static struct conf_line *
get_user_line (const char *user)
{
    int i;
    struct	conf_line	*conf_line;

    open_conf_file();

    while ((conf_line = get_conf_line()) != NULL) {
	if (conf_line->users == NULL)
	    continue;

	for (i = 0; conf_line->users[i]; i++) {
	    /* is this a group name ? */
	    if (conf_line->users[i][0] == '@')
		if (unix_group(user, (conf_line->users[i])+1))
		    break;
	    /* now test if this is an username */
	    if (strcmp(user, conf_line->users[i]) == 0 ||
		strcmp(conf_line->users[i], "*") == 0)
		break;
	}
	if (conf_line->users[i] != 0)
	    break;
    }
    close_conf_file();
    return conf_line;
}

/*
 * given to time frames, return the amount in secs for the common
 * period
 */
static int 
common_time(struct period time1, struct period time2)
{
    time_t t1, t2;

    if (time1.end < time2.start)
	return 0;
    if (time1.start > time2.end)
	return 0;

    t1 = max(time1.start, time2.start);
    t2 = min(time1.end, time2.end);
    return (int)(t2 - t1);
}

static int 
get_period(struct period *period,struct time_frame *tf,time_t when)
{
    struct tm *tm;
    time_t zerotime;

    zerotime = when;
    tm = localtime(&zerotime);
    zerotime -= tm->tm_hour*3600 + tm->tm_min*60 + tm->tm_sec;
    period->start = period->end = zerotime;

    period->start += (tf->t_start/100)*3600 + (tf->t_start%100)*60;
    period->end   += (tf->t_end/100)*3600   + (tf->t_end%100)*60;
    /* check for time wrap ... */
    if (tf->t_start >= tf->t_end) {
	/* time is wrapping accross 0 */
	if (when >= period->start)
	    /* current time passed start_time, 
	     * end_time will be tomorrow */
	    period->end += 24*3600;
	else if (when <= period->end)
	    /* current time before end time, start_time
	     * was yesterday */
	    period->start -= 24*3600;
	else /* some other horror */
	    return -1;
    }
    return 0;
}

/* 
 * This is a debugging function. It prints out the list of the users,
 * along with their time and quota.
 */
static void 
print_user_list(void)
{
    USER_TIME *ut;
 
    printf("List of known users (%p): (user:quota:in_use):\n",
	   user_time_head);
    fflush(stdout);
    ut = user_time_head;
    while (ut != NULL) {
	printf("\t%12s:%5d:%5d\n",
	       ut->username, ut->restriction, ut->counted);
	fflush(stdout);
	ut = ut->next;
    }
    printf("\n");
}

/*
 * Given an entry from the radlast log file, check to see if the user
 * having that entry is a valid user in our linked list, and if it is
 * and the time of the entry matches the window time period recorded
 * as restricted time for this user, count that time in...
 */
static void 
update_user_time(radlast rl)
{
    USER_TIME *ut;
    int t;

    t = strlen(rl.login);
    if (!t || (t > USERNAME_MAX))
	return; /* avoid invalid data */

    ut = user_time_head;

    while (ut != NULL) {
        if (strcmp(ut->username, rl.login) == 0) {
	    /* found on list */
	    struct period u_time;

	    u_time.start = rl.ut_time - rl.length;
	    u_time.end = rl.ut_time;
	    /* add this to this user ... */
	    ut->counted += common_time(ut->period, u_time);
	}
	ut = ut->next;
    }
    return;
}

/* 
 * get_user_time
 * returns the used time by the user withing a certain frame period 
 */
static int 
parse_radacct_file(void)
{
    int fd;
    char filename[PATH_MAX];
    radlast rad_last;
	 
    memset(filename, 0, sizeof(filename));
    if (!monthly_detail)
	sprintf(filename, "%s/%s", rad_acctdir, RADIUS_LAST);
    else {
	time_t crt_time;
	struct tm *time_info;
	
	crt_time = time(NULL);
	time_info = localtime(&crt_time);
	sprintf(filename, "%s/%d/%s-%02d", rad_acctdir, 
	        1900+time_info->tm_year, RADIUS_LAST,
		time_info->tm_mon + 1);
    }

    fd = open(filename, O_RDONLY);
    if (fd < 0)
	return -1;

    if (debug_flag) {
	printf("Parsing radlast (%s) file: ", filename);
	fflush(stdout);
    }
    memset(&rad_last, 0, sizeof(radlast));   
    /* okay, start reading the radlast log file */
    while(read(fd, &rad_last, sizeof(radlast)) == sizeof(radlast)) {
	update_user_time(rad_last);
	memset(&rad_last, 0, sizeof(rad_last));
    }
    /* done reading radlast logging info */
    close(fd);
    if (debug_flag) {
	printf("OK.\n");
	fflush(stdout);
    }
    return 0;
}

/*
 * Print a short (and hopefully clear) usage screen. 
 */
static void 
radwatch_usage(void)
{
    printf("\n%s version %s\n", progname, REVISION);
    printf("Usage: %s <option>\nValid options are:\n", progname);
    printf("\t-a\t\taccounting dir for radiusd\n");
    printf("\t-d\t\tconfiguration dir for radiusd\n");
    printf("\t-h\t\toutput this help screen\n");
    printf("\t-m\t\tuse the monthly status files created by radiusd\n");
    printf("\t-x\t\tenable debugging\n");
    printf("\nNOTE: all these flags should match the flags currently in use\n");
    printf("        by radiusd daemon.\n");
}

/*
 * Open the radlist database for the current month. The algorithm will
 * fail at the end of the month, but this will be fixed in a future
 * release (if the period wraps around midnight - end < start - we
 * won't be able to read the last month statistics. Hopefully no one
 * will be hurt so bad at this stage.... 
 */

static GDBM_FILE 
open_radlist(void)
{
    GDBM_FILE dbf;
    char db_name[PATH_MAX];
    int month;
    time_t crt_time;
    struct tm *time_info;

    crt_time = time(NULL);
    time_info = localtime(&crt_time);
    month = time_info->tm_mon + 1;

    sprintf(db_name, "%s/%d/%s",
            rad_acctdir, 1900+time_info->tm_year,RADIUS_USER_STATS);
    if (debug_flag)
        printf("Using database file %s ...\n", db_name);
    dbf = gdbm_open(db_name,0,GDBM_READER, 0600,NULL);
    if (dbf == NULL)
	fprintf(stderr, "Error opening the radlist (%s) database.\n",db_name);
    return dbf;
}

/* 
 * Well, this programs accepts arguments and flags... 
 * Isn't it cool ? :-) 
 */
static void 
parse_args(int argc, char **argv)
{
    int flag;
    while ((flag = getopt(argc, argv, "ma:d:xh")) != EOF) {
        switch (flag) {
            case 'm':
                monthly_detail++;
                break;
            case 'a':
                rad_acctdir = optarg;
                break;
            case 'd':
                radius_dir = optarg;
                break;
	    case 'h':
		radwatch_usage();
                exit(0);
            case 'x':
                debug_flag++;
                break;
            default:
                radwatch_usage();
                exit(-1);
        }
    }
    return;
}

/*
 * check the timerestriction for a certain user 
 *
 * return:
 *   0 = okay
 * < 0 = time exceeded 
 */
static void 
insert_user_in_list(char *username, struct time_frame *tf, time_t when, int max_seconds, user_entry *ue, int ue_size)
{
    int usr_time = 0;
    struct period period;
    int present_entries;
    int i;

    if (!username || !strlen(username))
	return;
    /* build the start time and the end time for the frame period */
    get_period(&period, tf, when);

    /* if this use is logged in ... */
    present_entries = (ue_size - sizeof(user_entry))/sizeof(port_entry);
    /* be safe */
    present_entries = min(present_entries, (unsigned int)ue->logins);
    for (i=0; i < present_entries; i++) {
	port_entry *pe_tmp;
	struct period u_time;
	
	pe_tmp = (port_entry *)((char *)ue + sizeof(user_entry)) + i;
	u_time.start = pe_tmp->time;
	u_time.end = when;
	if (u_time.end < u_time.start)
	    /* non-sense - claculating for the past... */
	    continue;
	usr_time += common_time(period, u_time);
    }
    add_user_time_list(username, period, max_seconds, usr_time);
}

/* 
 * Opens the radius stop list file, in the mode supplied by argument.
 * Returns the result of the call to fopen
 */
static FILE *
open_radstop_file(const char * mode)
{
    FILE *fp;
    char filename[PATH_MAX];

    sprintf(filename, "%s/%s", radius_dir, RADIUS_STOP);
    fp = fopen(filename, mode);
    return fp;
}


/*
 * Returns true if the account is locked. 
 * used by the lock_accounts function. 
 */
static int 
is_locked(char *user)
{
    FILE *fp;
    char buffer[1024];

    fp = open_radstop_file("r");
    if (fp == NULL) {
	/* file not found, account is no locked */
	return 0;
    }
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
	if (strlen(buffer) == 0)
	    continue;
	buffer[strlen(buffer)-1] = '\0';
	if (strcmp(user, buffer) == 0) {
	    fclose(fp);
	    return 1;
	}
    }
    return 0; /* default: not locked */
}

/* 
 * This function adds the supplied user at the end of the radius stop file
 * No checking for the previous existence in that file is done since this
 * test is supposed to be already done somewhere else
 */
static void 
lock_account(char *user)
{
    FILE *fp;

    fp = open_radstop_file("a");
    if (fp == NULL) {
	/* very odd error */
	fprintf(stderr, "Could not open/creat the radius stop list file !\n");
	exit(-3);
    }
    fprintf(fp, "%s\n", user);
    fclose(fp);
}

/*
 * Iterate through the user list and check for over-quota accounts. If it
 * is not already locked, lock the account.
 */
static void 
lock_accounts(void)
{
    USER_TIME *ut;
    
    ut = user_time_head;
    while (ut != NULL) {
	if (ut->restriction > ut->counted) {
	    ut = ut->next;
	    continue;
	}
	printf("%s\n", ut->username);
	/* this account needs to be locked out */
	if (is_locked(ut->username)) {
	    ut = ut->next;
	    continue;
	}
	lock_account(ut->username);
	ut = ut->next;
    }
}

/* 
 * Given an user, walks through the user_time list and see if this
 * user is over quota. 
 */
static int 
over_quota(char *user)
{
    USER_TIME *ut;

    ut = user_time_head;
    while (ut != NULL) {
	if (strncmp(ut->username, user, USERNAME_MAX) == 0)
	    /* our account */
	    if (ut->restriction < ut->counted)
		return 1;
	ut = ut->next;
    }
    return 0;
}

/* 
 * Verify each account listed in radiusd stop list to see if it
 * still match the restriction time criteria. If it does NOT, then
 * this user should not be black-listed anymore...
 */
static void 
unlock_accounts(void)
{
    FILE *fo, *fn;
    char fileold[PATH_MAX], filenew[PATH_MAX];
    char buffer[1024];

    sprintf(fileold, "%s/%s", radius_dir, RADIUS_STOP);
    sprintf(filenew, "%s/%s.new", radius_dir, RADIUS_STOP);

    fo = fopen(fileold, "r");
    if (fo == NULL) {
	/* no stoplist, bail out */
	if (debug_flag) {
	    printf("!!!");
	    fflush(stdout);
	}
	return;
    }

    fn = fopen(filenew, "w");
    if (!fn) {
	fprintf(stderr, "Error creating file %s (permission problem ?)\n",
		filenew);
	exit(-3);
    }
    while (fgets(buffer, sizeof(buffer), fo) != NULL) {
	if (buffer[strlen(buffer)-1] != '\n') {
	    /* line too long ... */
	    fprintf(stderr, "line too long reading from %s\n", fileold);
	    fclose(fn);
	    fclose(fo);
	    exit(-3);
	}
	if (strlen(buffer) > USERNAME_MAX) {
	    /* not a username line */
	    fprintf(fn, "%s", buffer);
	    if (debug_flag) {
		printf("!-!-!");
		fflush(stdout);
	    }
	    continue;
	}
	buffer[strlen(buffer)-1] = '\0';
	if (over_quota(buffer))
	    /* this user is still over quota */
	    fprintf(fn, "%s\n", buffer);
	else if (debug_flag) {
		printf("%s ", buffer);
		fflush(stdout);
	}
	/* else will be skipped */
    }
    fclose(fo);
    fclose(fn);
    unlink(fileold);
    link(filenew, fileold);
    unlink(filenew);
}    

/*
 * Just to be fancy and put two calls to other functions in their own block...
 * Overall, this is the idea of this program: unlock the accounts which are
 * no longer under quota constraints, and add the new ones after that.
 */
static void 
check_user_times(void)
{
    if (debug_flag)
	print_user_list();
    if (debug_flag) {
	printf("Unlocking accounts no longer over quota: ");
	fflush(stdout);
    }
    unlock_accounts();
    if (debug_flag)
	printf("DONE. \n");

    if (debug_flag) {
	printf("Locking accounts over quota: ");
	fflush(stdout);
    }
    lock_accounts();
    if (debug_flag)
	printf("DONE.\n");
}

/*
 * The Main Thing: make this program work.
 */
int 
main(int argc, char ** argv)
{
    GDBM_FILE dbf;
    datum key, content, nextkey;
    time_t crt_time;

    /* init paramaters */
    progname = argv[0];
    monthly_detail = 0;    
    rad_acctdir = RADACCT_DIR;
    radius_dir = RADIUS_DIR;
    radius_log = NULL;

    parse_args(argc, argv);
    crt_time = time(NULL); /* by default check against current time */

    dbf = open_radlist();
    if (dbf == NULL)
	exit(-1);
    if (debug_flag) {
	printf("Building preliminary list of users: ");
	fflush(stdout);
    }
    key = gdbm_firstkey(dbf);
    while (key.dptr != NULL) {
	static char str_user[1024];
	struct  conf_line *pp;
	struct  tm *tm;
	short   dtime;
	int     i;

	/* init those each time for safety */
	memset(str_user, 0, sizeof(str_user));
	memcpy(str_user, key.dptr, min(key.dsize, sizeof(str_user)-1));

	/*
	 * The current time is converted to HHMM format for
	 * comparision against the time values in the TTY entry.
	 */
	tm = localtime(&crt_time);
	dtime = tm->tm_hour * 100 + tm->tm_min;

	content = gdbm_fetch(dbf, key);
	if (content.dptr == NULL) {
	    fprintf(stderr, "Can not retrieve data for user %s\n",str_user);
	    nextkey = gdbm_nextkey(dbf,key);
	    free(key.dptr);
	    key=nextkey;
	    continue;
	}
	/*
	 * Try to find a matching entry for this user.  Default to
	 * letting the user in - there are pleny of ways to have an
	 * entry to match all users.
	 */
	if ((pp = get_user_line (str_user)) == NULL) {
	    /* no restriction */
	    nextkey = gdbm_nextkey(dbf,key);
	    free(key.dptr);
	    key=nextkey;
            continue;
	}
	if (pp->times == 0) {
	    /*
	     * The entry is there, but has no time entries
	     */
	    nextkey = gdbm_nextkey(dbf,key);
	    free(key.dptr);
	    key=nextkey;
            continue;
	}
	/*
	 * Each time entry is compared against the current
	 * time. For entries with the start after the end time,
	 * the comparision is made so that the time is between
	 * midnight and either the start or end time.
	 */
	for (i = 0; pp->times[i].t_start != -1; i++) {
	    if (! (pp->times[i].t_days & PORT_DAY(tm->tm_wday)))
		continue;
	    if (pp->times[i].t_start <= pp->times[i].t_end) {
		if (dtime >= pp->times[i].t_start && dtime <= pp->times[i].t_end)
		    insert_user_in_list(str_user, pp->times+i, crt_time, pp->restriction, 
					(user_entry *)content.dptr, content.dsize);
	    } else {
		if (dtime >= pp->times[i].t_start || dtime <= pp->times[i].t_end)
		    insert_user_in_list(str_user, pp->times+i, crt_time, pp->restriction, 
					(user_entry *)content.dptr, content.dsize);
	    }
	}
	nextkey = gdbm_nextkey(dbf,key);
	free(key.dptr);
	key=nextkey;
    }
    gdbm_close(dbf);
    if (debug_flag) {
	printf("OK.\n");
	fflush(stdout);
    }
    if (parse_radacct_file() != 0)
	fprintf(stderr, "Unable to open radlast log file !\n");
    else check_user_times();
    empty_user_time_list();
    exit(0);
}

void 
rad_exit(int code)
{
        exit(code);
}

