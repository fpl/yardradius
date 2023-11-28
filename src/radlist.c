/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

static char rcsid[] = "$Id: radlist.c 102 2007-06-28 14:53:34Z flovergine $";
    
#define __MAIN__

#include "yard.h"
#include "global.h"

static char *username = NULL;
static int month = 0;
static int portinfo = 0;
static int brief = 0;
static int dostat = 0;
static int traditional = 0;
static int noheader = 0;
static char hdrstr[] = "  Username   Sess Logs    OnLine       Input/Output/Total      AvgIO    AvgTM\n" 
                       "------------ ---- ----  ---------- ------------------------- -------- --------\n";


/*

	Next functions are used to report time, traffic and other 
	accounting data

*/

UINT4 
get_daily_online( user_entry *ue,int month,int day )
{
  return ue->day[month][day].on_line;
}

UINT4 
get_monthly_online( user_entry *ue,int month,int day )
{
  int i;
  UINT4 sum=0;

  for ( i=0; i<=day; i++ ) sum += ue->day[month][i].on_line;
  return sum;
}

UINT4 
get_yearly_online( user_entry *ue,int month,int day )
{
  int i, j;
  UINT4 sum=0;

  for ( i=0; i<=month; i++ )
    for ( j=0; j<=day; j++ ) sum += ue->day[i][j].on_line;
  return sum;
}

UINT4 
get_daily_itraffic( user_entry *ue,int month,int day )
{
  return ue->day[month][day].input_octets;
}

UINT4 
get_monthly_itraffic( user_entry *ue,int month,int day )
{
  int i;
  UINT4 sum=0;

  for ( i=0; i<=day; i++ ) sum += ue->day[month][i].input_octets;
  return sum;
}

UINT4 
get_yearly_itraffic( user_entry *ue,int month,int day )
{
  int i, j;
  UINT4 sum=0;

  for ( i=0; i<=month; i++ )
    for ( j=0; j<=day; j++ ) sum += ue->day[i][j].input_octets;
  return sum;
}



UINT4 
get_daily_otraffic( user_entry *ue,int month,int day )
{
  return ue->day[month][day].output_octets;
}

UINT4 
get_monthly_otraffic( user_entry *ue,int month,int day )
{
  int i;
  UINT4 sum=0;

  for ( i=0; i<=day; i++ ) sum += ue->day[month][i].output_octets;
  return sum;
}

UINT4 
get_yearly_otraffic( user_entry *ue,int month,int day )
{
  int i, j;
  UINT4 sum=0;

  for ( i=0; i<=month; i++ )
    for ( j=0; j<=day; j++ ) sum += ue->day[i][j].output_octets;
  return sum;
}



UINT4 
get_daily_nr_logins( user_entry *ue,int month,int day )
{
  return ue->day[month][day].nr_logins;
}

UINT4 
get_monthly_nr_logins( user_entry *ue,int month,int day )
{
  int i;
  UINT4 sum=0;

  for ( i=0; i<=day; i++ ) sum += ue->day[month][i].nr_logins;
  return sum;
}

UINT4 
get_yearly_nr_logins( user_entry *ue,int month,int day )
{
  int i, j;
  UINT4 sum=0;

  for ( i=0; i<=month; i++ )
    for ( j=0; j<=day; j++ ) sum += ue->day[i][j].nr_logins;
  return sum;
}


/*
	This structure is a lookup table to get accounting data 
	in short
*/


#define DAILY_STAT   0
#define MONTHLY_STAT 1
#define YEARLY_STAT  2

#define ON_LINE   0
#define ITRAFFIC  1
#define OTRAFFIC  2
#define NR_LOGINS 3

typedef UINT4 (*fptr)(user_entry*,int,int);
fptr get_stat[4][3] = {  
{ get_daily_online, get_monthly_online, get_yearly_online },
{ get_daily_itraffic, get_monthly_itraffic, get_yearly_itraffic },
{ get_daily_otraffic, get_monthly_otraffic, get_yearly_otraffic },
{ get_daily_nr_logins, get_monthly_nr_logins, get_yearly_nr_logins }
};


static void 
radlist_usage(void)
{
    printf("\nUsage: %s <option>\nValid options are:\n", progname);
    printf("\t-s\t\tlist stats\n");
    printf("\t-b\t\tbrief output format\n");
    printf("\t-t\t\ttraditional output format\n");
    printf("\t-n\t\tno header for traditional output\n");
    printf("\t-x\t\tprint port information\n");
    printf("\t-F <format>\t\tcustom output format\n");
    printf("\t-h\t\tthis help screen\n");
    printf("\t-m <month>\treport statistics for month <month>\n");
    printf("\t-d <day>\treport statistics for day <day>\n");
    printf("\t-y <year>\treport statistics for year <year>\n");
    printf("\t-u <username>\tget username database entry\n");
    printf("\t-Y\t\treport statistics per year\n");
    printf("\t-M\t\treport statistics per month\n");
    printf("\t-D\t\treport statistics per day\n\n");
    exit(-1);
}


static const char * 
proto_type_str(int proto)
{
    switch (proto) {
        case P_TELNET:
            return "TELNET";
        case P_RLOGIN:
            return "RLOGIN";
        case P_TCP_CLEAR:
            return "NETDATA";
        case P_PORTMASTER:
            return "PM";
        case P_PPP:
            return "PPP";
        case P_SLIP:
            return "SLIP";
        case P_CSLIP:
            return "CSLIP";
        default:
            return "UNK";
    }
    /* not reached */
    return "UNK";
}

static void 
print_error(char * fmt,va_list args) 
{
  vfprintf( stderr,fmt,args ); 
  return;
}

static void 
error(char *fmt,...)
{
  va_list arg;

  va_start(arg,fmt);
  fprintf( stderr,"%s: ",progname );
  print_error(fmt,arg);
  va_end(arg);
}

static int 
parse_width(char **format)
{
  int width=0;
  char *endstr;

  if ( isdigit(**format) || **format=='+' || **format=='-' )
    {
    width=(int)strtol(*format,&endstr,10);
    *format=endstr;
    }
  return width;
}

static void 
parse_format(char *format, char *entry, user_entry *tmp, int datasize, int mday,int month,int stat)
{
    UINT4 on_line;
    UINT4 itraffic,otraffic;
    UINT4 nr_logins;
    UINT4 timepersess;
    char  fstr[100];
    char *ptr;
    int   width;

    on_line         = get_stat[ON_LINE][stat](tmp,month,mday);
    nr_logins       = get_stat[NR_LOGINS][stat](tmp,month,mday); 
    itraffic        = get_stat[ITRAFFIC][stat](tmp,month,mday); 
    otraffic        = get_stat[OTRAFFIC][stat](tmp,month,mday); 

    while (*format) {
      switch (*format) {
        case '%':
	  format++;
	  width=parse_width(&format);
	  if (width) snprintf(fstr,sizeof(fstr),"%%%d",width);
	  else strcpy(fstr,"%");
	  switch(*format) {
	    case 'l':
	      strcat(fstr,"s"); printf(fstr,entry);
	      break;
	    case 's':
	      strcat(fstr,"d"); printf(fstr,tmp->logins);
	      break;
	    case 'n':
	      strcat(fstr,"d"); printf(fstr,nr_logins);
	      break;
	    case 't':
	      strcat(fstr,"d"); printf(fstr,on_line);
	      break;
	    case 'T':
	      ptr=fstr+50;
	      snprintf(ptr,sizeof(fstr)/2,"%d:%d:%d",
	               on_line/3600, (on_line%3600)/60,(on_line%3600)%60);
	      strcat(fstr,"s"); printf(fstr,ptr);
	      break;
	    case 'i':
	      strcat(fstr,"ld"); printf(fstr,itraffic);
	      break;
	    case 'I':
	      strcat(fstr,"ldKB"); printf(fstr,itraffic/1024);
	      break;
	    case 'o':
	      strcat(fstr,"ld"); printf(fstr,otraffic);
	      break;
	    case 'O':
	      strcat(fstr,"ldKB"); printf(fstr,otraffic/1024);
	      break;
	    case 'm':
	      strcat(fstr,"ld"); printf(fstr,itraffic+otraffic);
	      break;
	    case 'M':
	      strcat(fstr,"ldKB"); printf(fstr,(itraffic+otraffic)/1024);
	      break;
	    case 'g':
	      strcat(fstr,"ld"); printf(fstr,(itraffic+otraffic)/(nr_logins+1));
	      break;
	    case 'G':
	      strcat(fstr,"ldKB"); 
	      printf(fstr,(itraffic+otraffic)/(nr_logins?nr_logins:1)/1024);
	      break;
	    case 'k':
	      strcat(fstr,"d"); printf(fstr,on_line/(nr_logins?nr_logins:1));
	      break;
	    case 'K':
	      ptr=fstr+50;
	      timepersess = on_line/(nr_logins?nr_logins:1); 
	      snprintf(ptr,sizeof(fptr)/2,"%d:%d:%d",
	      	       timepersess/3600, (timepersess%3600)/60,
		       (timepersess%3600)%60);
	      strcat(fstr,"s"); printf(fstr,ptr);
	      break;
	    case '%':
              putchar('%');
	    default:
	      break;
	  }
	  break;

	case '\\':
          format++;
          switch(*format)
            {
            case 'n':
              printf("\n");
              break;
            case 't':
              printf("\t");
              break;
            case 'r':
              printf("\r");
              break;
            case '\\':
              printf("\\");
            default:
              break;
            }
	    break;

	default:
	  putchar(*format);
	  break;
      }
    format++;
    }
}

static void 
parse_pformat(char *format, char *entry, user_entry *tmp, int datasize, int mday,int month,int stat, port_entry *tpe, int number)
{
    static char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
		              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    int i,width;
    char str_time[512];
    char fstr[100];
    char *str_port_type;
    char client_ip[100];
    struct tm *time_info;
    char *fmt;

    for (i=0; i<number; i++,tpe++) {
	time_info = localtime(&(tpe->time));
	fmt = format;
	snprintf(str_time, sizeof(str_time),
		 "%02d/%s/%02d %02d:%02d:%02d",
		 time_info->tm_mday, months[time_info->tm_mon], 
		 time_info->tm_year, time_info->tm_hour, time_info->tm_min, 
		 time_info->tm_sec);
	memset(client_ip, 0, sizeof(client_ip));
	ipaddr2str(client_ip,sizeof(client_ip),tpe->client_ip);
	switch (tpe->port_type) {
	    case 0:
		str_port_type = "Async";
		break;
	    case 1:
		str_port_type = "Sync";
		break;
	    case 2:
		str_port_type = "ISDN";
		break;
	    case 3:
		str_port_type = "ISDN/V120";
		break;
	    case 4:
		str_port_type = "ISDN/V110";
		break;
	    default:
		str_port_type = "UNKNOWN";
		break;
	}

    while (*fmt) {
      switch (*fmt) {
        case '%':
	  fmt++;
	  width=parse_width(&fmt);
	  if (width) snprintf(fstr,sizeof(fstr),"%%%d",width);
	  else strcpy(fstr,"%");
	  switch (*fmt) {
	     case 'd':
	       strcat(fstr,"s"); printf(fstr,str_time);
	       break;
	     case 'P':
	       strcat(fstr,"s"); printf(fstr,str_port_type);
	       break;
	     case 'p':
	       strcat(fstr,"d"); printf(fstr,tpe->port_number);
	       break;
	     case 'a':
	       strcat(fstr,"s"); printf(fstr,ip_hostname(tpe->nas_ip));
	       break;
	     case 'y':
	       strcat(fstr,"s"); printf(fstr,proto_type_str(tpe->proto));
	       break;
	     case 'c':
	       strcat(fstr,"s"); printf(fstr,client_ip);
	       break;
	     default:
	       fstr[strlen(fstr)+1]='\0';
	       fstr[strlen(fstr)]=*fmt;
	       parse_format(fstr,entry,tmp,datasize,mday,month,stat);
	       break;
	  }
	  break;

        case '\\':
          fmt++;
          switch(*fmt)
            {
            case 'n':
              printf("\n");
              break;
            case 't':
              printf("\t");
              break;
            case 'r':
              printf("\r");
              break;
            case '\\':
              printf("\\");
            default:
              break;
          }
          break;

	default:
          putchar(*fmt);
	  break;
      }
      fmt++;
    }
    }
}

static void 
print_user_entry(char *format, char *entry, user_entry *tmp, int datasize, int mday,int month,int stat)
{
    if ((tmp->logins == 0) && !dostat ) {
      if ( username != NULL ) error("user '%s' not logged\n",username);
      return;
    }

    if ((tmp->logins != 0) && portinfo ) {

      int port_data_size, present_entries;

      port_data_size  = datasize - sizeof(user_entry);
      present_entries = port_data_size/sizeof(port_entry);
      if ( format!=NULL ) {
        parse_pformat(format,entry,tmp,datasize,mday,month,stat,
	              (port_entry*)((char*)tmp+sizeof(user_entry)),
		      present_entries);
        return;
      }
      if (traditional) {
         parse_pformat("%12l %4s %4n %10T %6I/%6O/%6M %6G %8k\n",
	      entry,tmp,datasize,mday,month,stat,
              (port_entry*)((char*)tmp+sizeof(user_entry)),
	      present_entries);
         return;
      }
      if (brief) { 
         parse_pformat( "%l/%ssess/%nlogs/%tsecs/%I/%O/%M/%G/%ksecs\n",
	      entry,tmp,datasize,mday,month,stat,
              (port_entry*)((char*)tmp+sizeof(user_entry)),
	      present_entries);
         return;
      }
      parse_pformat("%12l %d %y %Y%p %c\n",
	      entry,tmp,datasize,mday,month,stat,
              (port_entry*)((char*)tmp+sizeof(user_entry)),
	      present_entries);
      return;

/*
	printf("  [%s] %s-%d %s %s %s\n",
	       str_time,
	       str_port_type, tpe->port_number,
	       ip_hostname(tpe->nas_ip),
	       proto_type_str(tpe->proto),
	       client_ip);
*/
    }

    if ( format!=NULL ) {
      parse_format(format,entry,tmp,datasize,mday,month,stat);
      return;
    }
    if (traditional) {
      parse_format("%12l %4s %4n %10T %6I/%6O/%6M %6G %8k\n",
	           entry,tmp,datasize,mday,month,stat);
      return;
    }
    if (brief) { 
       parse_format( "%l/%ssess/%nlogs/%tsecs/%I/%O/%M/%G/%ksecs\n",
                     entry,tmp,datasize,mday,month,stat); 
       return;
    }
    parse_format( "\nUsername = %l\n"
      	      "Current-Sessions = %s\n"
	      "Logins = %n\n"
	      "Input-Traffic = %I\n"
	      "Output-Traffic = %O\n"
              "Total-Traffic = %M\n"
	      "Mean-Traffic = %gB\n"
	      "Mean-Session-Time = %ksecs\n",
              entry,tmp,datasize,mday,month,stat); 
}






int 
main(int argc, char ** argv)
{
    GDBM_FILE dbf;
    datum key, content, nextkey;
    int flag;
    int  stat=YEARLY_STAT;
    time_t crt_time;
    int month, mday, year;
    struct tm *time_info;
    char dbfile_name[PATH_MAX];
    char *cp;
    char *format = NULL;
    const char *radius_dir;
    
    extern char *optarg;
    extern int optind, opterr, optopt;

    progname = argv[0];
    crt_time = time(NULL);
    time_info = localtime(&crt_time);
    memset(dbfile_name, 0, PATH_MAX);

    month = time_info->tm_mon;
    mday  = time_info->tm_mday-1;
    year  = 1900+time_info->tm_year;
    radius_dir = RADACCT_DIR;

    while ((flag=getopt(argc,argv,"tDMYf:F:m:y:d:bu:psnh")) != EOF) {
	switch (flag) {
	    case 'D':
	       stat = DAILY_STAT;
	       break;

	    case 'M':
	       stat = MONTHLY_STAT;
	       break;

	    case 'Y':
	       stat = YEARLY_STAT;
	       break;
	    
	    case 'F':
	       format = optarg;
	       break;

	    case 'f':
		strncpy( dbfile_name,optarg,PATH_MAX-1 );
		break;

	    case 'm':
		month = strtol(optarg, &cp, 10);
		if (*cp) {
		    /* not a number ... */
		    error("month should be a number\n");
		    radlist_usage();
		}
		if ((month < 1) || (month > 12)) {
		    error("month should be between 1 and 12\n");
		    /* not a valid month */
		    radlist_usage();
		}
		month--;
		break;

	    case 'y':
		year = strtol(optarg, &cp, 10);
		if (*cp) {
		    /* not a number ... */
		    error("year should be a number greater than 1970\n");
		    radlist_usage();
		}
		if (year < 1970) {
		    error("year should be after 1970\n");
		    /* not a valid year */
		    radlist_usage();
		}
		break;

	    case 'd':
		mday = strtol(optarg, &cp, 10);
		if (*cp) {
		    /* not a number ... */
		    error("day should be a number\n");
		    radlist_usage();
		}
		if ((mday < 1) || (mday > 31)) {
		    error("day should be between 1 and 31\n");
		    /* not a valid day */
		    radlist_usage();
		}
		mday--;
		break;

	    case 't':
		traditional++;
		break;

	    case 'b':
		brief++;
		if (traditional) traditional=0;
		break;

	    case 'u':
		username = optarg;
		break;

	    case 'p':
		portinfo++;
		break;
	
	    case 's':
	    	dostat++; /* write statistics */
		break;
	    
	    case 'n':
	    	noheader++;
		break;

	    case 'h':
	    default:
		radlist_usage();
	}
    }
	
    if ( !strcmp(dbfile_name,"") )
       snprintf(dbfile_name, sizeof(dbfile_name),"%s/%d/%s",radius_dir,year,
                RADIUS_USER_STATS);
    dbf = gdbm_open(dbfile_name,0,GDBM_READER,0600,NULL);
    if (dbf == NULL) {
	error("cannot open '%s' database\n",dbfile_name);
	return -1;
    }

    if ( format != NULL ) {
    	traditional=0;
	brief=0;
	noheader=1;
    }

    if (traditional && !noheader) {
          printf(hdrstr);
    }

    if (username != NULL) {
	key.dptr=username;
	key.dsize=strlen(username);
		
	content = gdbm_fetch(dbf, key);
	if (content.dptr == NULL) {
	    error("info for user '%s' not found\n",username);
	    gdbm_close(dbf);
	    exit(-1);
        }
	print_user_entry(format,(char *)key.dptr, 
	                 (user_entry *)content.dptr, 
			 content.dsize, mday, month, stat);
    } else {
	static char str_user[1024];
	int cp_size;
	key = gdbm_firstkey(dbf);
	while (key.dptr != NULL) {
	    content = gdbm_fetch(dbf, key);
	    if (content.dptr == NULL) {
		error("cannot retrieve data in database\n");
		gdbm_close(dbf);
		free(key.dptr);
		return -1;
	    }
	    cp_size = key.dsize;
	    if (cp_size > sizeof(str_user)-1)
		cp_size = sizeof(str_user)-1;
	    memset(str_user, 0, sizeof(str_user));
	    strncpy(str_user, (char*)key.dptr, cp_size);
	    print_user_entry(format,str_user, (user_entry*)content.dptr, 
	                     content.dsize, mday, month,stat );
	    nextkey = gdbm_nextkey(dbf,key);
	    free(key.dptr);
	    key=nextkey;
	}
    }
    gdbm_close(dbf);
    return 0;
}

void 
rad_exit(int code)
{ exit(code); }
