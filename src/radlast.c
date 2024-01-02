/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

# define __MAIN__

#include	"yard.h"
#include	"global.h"

char *progname = NULL;
char username[USERNAME_MAX];

static int brief = 0;
static int extended = 0;

static const char *
port_type_str(int type)
{
    switch (type) {
	case 0:
	    return "ASYN";
	case 1:
	    return "SYNC";
	case 2:
	    return "ISDN";
	case 3:
	    return "V120";
	case 4:
	    return "V110";
	default:
	    return "UNKN";
    }
    /* not reached */
    return "Unknown";
}

static const char * 
proto_type_str(int proto)
{
    switch (proto) {
	case P_TELNET:
	    return "TELN";
	case P_RLOGIN:
	    return "RLOG";
	case P_TCP_CLEAR:
	    return "DATA";
	case P_PORTMASTER:
	    return "PM";
	case P_PPP:
	    return "PPP";
	case P_SLIP:
	    return "SLIP";
	case P_CSLIP:
	    return "CSLP";
	default:
	    return "UNK";
    }
    /* not reached */
    return "UNK";
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

/*
 *	Function: parse_formatstr()
 * 	Purpose: parse a -F format string and outputs as required all
 *		 radlast fields.
 *
 *	Format tokens are:
 *		%l	Username
 *		%p	Port ID
 *		%a	NAS ip address
 *		%k	Port type
 *		%c	Client ip address
 *		%d	Date in ctime format
 *		%t	Online time in secs
 *		%T	Online time in HH:MM:SS format
 *		%i	Input traffic in bytes
 *		%I	Input traffic in KBytes
 *		%o	Output traffic in bytes
 *		%O	Output traffic in KBytes
 *		%m	Total traffic in bytes
 *		%M	Total traffic in KBytes
 *		%s	Input speed in bps (or UNKNOWN)
 *		%S	Output speed in bps (or UNKNOWN)
 *		%A	NAS called id (or UNKNOWN)
 *		%#	Client calling id (or UNKNOWN)
 *		\n \t \\ \% %% As obvious :-)
 *
 *	Tokens can include an integer signed value for alignment with
 * 	the same sense of printf() format value.
 */

static void 
parse_formatstr( char *formatstr,radlast rl )
{
  char port_str[100];
  char nas_ip[100];
  char client_ip[100];
  char fstr[100];
  char *str_time;
  int  width;
  char *ptr;
  time_t login_time;


  if ( formatstr == NULL ) return;

  memset(port_str, 0, sizeof(port_str));
  memset(nas_ip, 0, sizeof(nas_ip));
  memset(client_ip, 0, sizeof(client_ip));
  login_time = rl.ut_time;
  str_time = ctime(&login_time); str_time[19] = '\0';

  snprintf(port_str, 
	   sizeof(port_str), 
           "%4.4s-%02d",
           port_type_str(rl.ent.port_type),
           rl.ent.port);
  ipaddr2str(nas_ip, sizeof(nas_ip), rl.nas_ip);
  ipaddr2str(client_ip, sizeof(client_ip), rl.client_ip);

  while ( *formatstr )
    {
    switch ( *formatstr )
      {
      case '%':
        formatstr++;
        width=parse_width(&formatstr);
        if (width) snprintf(fstr,sizeof(fstr),"%%%d",width);
        else strcpy(fstr,"%");
	switch (*formatstr)
	  {
	  case 'l':
	    strcat(fstr,"s"); printf(fstr,rl.login); 
	    break;
	  case 'p':
	    strcat(fstr,"s"); printf(fstr,port_str); 
	    break;
	  case 'a':
	    strcat(fstr,"s"); printf(fstr,nas_ip); 
	    break;
	  case 'k':
	    strcat(fstr,"s"); printf(fstr,proto_type_str(rl.ent.proto)); 
	    break;
	  case 'c':
	    strcat(fstr,"s"); printf(fstr,client_ip); 
	    break;
	  case 'd':
	    strcat(fstr,"s"); printf(fstr,str_time); 
	    break;
	  case 't':
	    strcat(fstr,"ld"); printf(fstr,rl.length); 
	    break;
	  case 'T':
	    ptr=fstr+50;
	    snprintf(ptr,sizeof(fstr)/2,"%dh:%dm:%ds",
		   (int)(rl.length/3600),
                   (int)((rl.length%3600)/60),
                   (int)((rl.length%3600)%60)); 
	    strcat(fstr,"s");
	    printf(fstr,ptr);
	    break;
	  case 'i':
	    strcat(fstr,"ld"); printf(fstr,rl.inb); 
	    break;
	  case 'I':
	    strcat(fstr,"ldKB"); printf(fstr,rl.inb/1024); 
	    break;
	  case 'o':
	    strcat(fstr,"ld"); printf(fstr,rl.outb); 
	    break;
	  case 'O':
	    strcat(fstr,"ldKB"); printf(fstr,rl.outb/1024); 
	    break;
	  case 'm':
	    strcat(fstr,"ld"); printf(fstr,rl.outb+rl.inb); 
	    break;
	  case 'M':
	    strcat(fstr,"ldKB"); printf(fstr,(rl.outb+rl.inb)/1024); 
	    break;
	  case 's':
	    if (rl.rxrate) {
	      strcat(fstr,"d"); printf(fstr,rl.rxrate); 
	    }
	    else {
	      strcat(fstr,"s"); printf(fstr,"NONE");
	    }
	    break;
	  case 'S':
	    if (rl.txrate) {
	      strcat(fstr,"d"); printf(fstr,rl.txrate); 
	    }
	    else {
	      strcat(fstr,"s"); printf(fstr,"NONE");
	    }
	    break;
	  case 'A':
	    strcat(fstr,"s"); 
	    printf(fstr,strlen(rl.calledid)?rl.calledid:"NONE"); 
	    break;
	  case '#':
	    strcat(fstr,"s"); 
	    printf(fstr,strlen(rl.callingid)?rl.callingid:"NONE"); 
	    break;
	  case '%':
	    putchar('%');
	  default:
	    break;
	  }
        break;
      case '\\':
        formatstr++;
        switch(*formatstr)
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
	  default:
	    printf("\\");
	    break;
	  }
        break;
      default:
	putchar(*formatstr);
	break;
      }
    formatstr++;
    }
}

/*
 *	Function: parse_header()
 * 	Purpose: parse a -H header string 
 *
 *	Format tokens are:
 *		\n \t \r \\ As obvious :-)
 */

static void 
parse_header( char *header )
{
   while (*header) {
      switch (*header) {
      case '\\':
        header++;
        switch(*header)
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
	  default:
	    printf("\\");
	    break;
	  }
        break;
      default:
	putchar(*header);
	break;
      }
    header++;
    }
}

static void 
print_entry(radlast rad_last)
{
  if (extended)
    if (brief) parse_formatstr("%l/%p/%a/%k/%c/%d/%T/%I/%O/%M/%s/%S/%A/%#\n",
                          rad_last);
    else parse_formatstr( 
		    "\nUsername = %l\n"
	    	    "Port-Number = %p\n"
		    "NAS-IP = %a\n"
		    "Service-Type = %k\n"
		    "User-IP = %c\n"
		    "Date = %d\n"
		    "Session-Time = %T\n"
		    "Input-Traffic = %I\n"
		    "Output-Traffic = %O\n"
		    "Total-Traffic = %M\n"
		    "Rx-Speed = %s\n"
		    "Tx-Speed = %S\n"
		    "NAS-CLI = %A\n"
		    "User-CLI = %#\n",rad_last );
  else /* !extended */
	if (brief)
	    parse_formatstr("%l/%p/%a/%k/%c/%d/%T\n",rad_last);
	else
	    parse_formatstr( 
                    "\nUsername = %l\n"
                    "Port-Number = %p\n"
                    "NAS-IP = %a\n"
                    "Service-Type = %k\n"
                    "User-IP = %c\n"
                    "Date = %d\n"
                    "Session-Time = %T\n",rad_last);
}

static void 
radlast_usage(void)
{
    printf("\nUsage: %s <option>\n\nValid options are:\n", progname);
    printf("\t-a <acct_dir>\tthe radius accounting files directory\n");
    printf("\t-F <format>\tcustom output format\n");
    printf("\t-H <format>\tcustom header\n");
    printf("\t-c\t\tshow records in cronological order\n");
    printf("\t-u <username>\tget username database entry\n");
    printf("\t-f <filename>\tuse this radlast logfile instead\n");
    printf("\t-h\t\tthis help screen\n");
    printf("\t-m <month>\treport statistics for <month>\n");
    printf("\t-y <year>\treport statistics for <year>\n");
    printf("\t-b\t\tsingle row output\n");
    printf("\t-x\t\textended info (include traffic and CLIs)\n\n");
    exit(-1);
}

static void 
fatal_func(const char *msg) {
    fprintf(stderr, "FATAL ERROR: %s\n",msg);
    return;
}

int 
main(int argc, char **argv)
{
    radlast rad_last;
    int fd;
    static char filename[PATH_MAX];
    int flag;
    int month;
    int year;
    time_t crt_time;
    struct tm *time_info;
    int file_arg = 0;
    int month_arg = 0;
    int year_arg = 0;
    int user_arg = 0;
    const char *radacct_dir;
    int cronologic = 0;
    char *format=NULL;
    char *header=NULL;
    extern char *optarg;
    
    crt_time = time(NULL);
    time_info = localtime(&crt_time);
    month = time_info->tm_mon + 1;				    
    year = 1900+time_info->tm_year;
    memset(&rad_last, 0, sizeof(radlast));
    memset(filename, 0, sizeof(filename));
    memset(username, 0, sizeof(username));
    
    progname = argv[0];
    radacct_dir = RADACCT_DIR;
    
    while ((flag = getopt(argc, argv, "a:F:H:cu:f:by:m:xh")) != EOF) {
	char *cp;
	switch (flag) {
	    case 'a':
		radacct_dir = optarg;
		break;
	    case 'F':
		format = optarg;
		break;
	    case 'H':
		header = optarg;
		break;
	    case 'c':
		cronologic++;
		break;
	    case 'u':
		strncpy(username, optarg, USERNAME_MAX);
		user_arg++;
		break;
	    case 'f':
		if (month_arg || year_arg) {
		    fatal_func("you cannot specify a filename and a month number");
		    radlast_usage();
		}
		strncpy(filename, optarg, PATH_MAX);
		file_arg++;
		break;
            case 'b':
		brief++;
		break;
	    case 'y':
		if (file_arg) {
                    fatal_func("you can not specify a year and a filename");
		    radlast_usage();
		}
		year = strtol(optarg, &cp, 10);
		if (*cp) {
		    fatal_func("year should be a number\n");
		    radlast_usage();
		}
		if (year < 1970) {
		    fatal_func("year should be greater than 1970\n");
		    radlast_usage();
		}
		year_arg++;
		break;
	    case 'm':
		if (file_arg) {
                    fatal_func("you can not specify a month number and a filename");
		    radlast_usage();
		}
		month = strtol(optarg, &cp, 10);
		if (*cp) {
		    /* not a number ... */
		    fatal_func("month should be a number\n");
		    radlast_usage();
		}
		if ((month < 1) || (month > 12)) {
		    fatal_func("month should be between 1 and 12\n");
		    /* not a valid month */
		    radlast_usage();
		}
		month_arg++;
		break;
	    case 'x':
		extended++;
		break;
	    case 'h':
	    default:
		radlast_usage();
	}
    }

    if (!file_arg)
	snprintf(filename, sizeof(filename),"%s/%d/%s-%02d", 
	        radacct_dir, year, RADIUS_LAST, month);
    
    if ((fd = open(filename, O_RDONLY)) >= 0) {
	off_t seekpos = 0;
	
	if (!cronologic)
	    seekpos = lseek(fd, -sizeof(radlast), SEEK_END);
	if ( format != NULL && header != NULL ) parse_header(header); 
	while ((seekpos >= 0) &&
	       read(fd, &rad_last, sizeof(radlast)) == sizeof(radlast)) {
	    if (user_arg && strncmp(username, rad_last.login, USERNAME_MAX)) {
		memset(&rad_last, 0, sizeof(rad_last));
		if (!cronologic)
		    seekpos = lseek(fd, -2*sizeof(radlast), SEEK_CUR);
		continue;
	    }
	    if ( format != NULL ) parse_formatstr(format,rad_last);
	    else print_entry(rad_last);
	    memset(&rad_last, 0, sizeof(rad_last));
	    if (!cronologic)
		seekpos = lseek(fd, -2*sizeof(radlast), SEEK_CUR);
	}
    } else {
	fprintf(stderr, "Cannot open the radlast log file: %s\n",filename);
	exit(-1);
    }
    exit(0);
}

void 
rad_exit(int code)
{
 	exit(code);
}
