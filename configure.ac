dnl
dnl $Id: configure.ac 100 2007-06-28 14:49:29Z flovergine $
dnl
dnl Copyright (C) 1999-2004 Francesco P. Lovergine. All rights reserved.
dnl 
dnl Process this file with autoconf (>=2.59) to produce a configure script.
dnl Use bootstrap script or autoreconf to prepare the build system.
dnl That is not needed for final users and generally package maitainers.
dnl 
dnl * IMPORTANT * * IMPORTANT * * IMPORTANT * * IMPORTANT * * IMPORTANT *
dnl
dnl If you need to regenerate autools scripts use autoconf (>=2.59) and 
dnl automake (>=1.7) which are versions I used.
dnl Note that maintainer mode is disable by default to avoid trashing
dnl the autoconf stuff with wrong versions.
dnl

AC_INIT([Yard Radius],[1.1],[francesco@lovergine.com],[yardradius])
AC_PREREQ([2.71])
AC_CONFIG_SRCDIR(src/radiusd.c)
AC_CONFIG_AUX_DIR(autotools)
AC_CONFIG_MACRO_DIR(autotools)
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE
AC_PREFIX_DEFAULT(/usr/local/yardradius)

dnl
dnl This directive is deprecated by someone, but I prefer to avoid
dnl running autotools if not required explicitly. The reason is 
dnl the need to be in sync with autoconf/automake.
dnl
AM_MAINTAINER_MODE

dnl
dnl Automake 1.7 does not export PACKAGE and VERSION, which are needed
dnl in the 'dist' target. This hack forces the definition of both.
dnl Moreover, PACKAGE_VERSION can be only a literate. That sucks.
dnl Currently I'm not using PACKAGE_* defines, so here we go...
dnl
PACKAGE="yardradius"
VERSION=`cat VERSION`
AC_SUBST(PACKAGE)
AC_SUBST(VERSION)

INSTALL="$srcdir/scripts/shtool install -c"
ECHO="$srcdir/scripts/shtool echo -e"
MKDIR="$srcdir/scripts/shtool mkdir -p"
AC_SUBST(INSTALL)
AC_SUBST(ECHO)
AC_SUBST(MKDIR)

dnl
dnl These definitions were in acconfig.h with old autoconf 2.13.
dnl Now that file is obsolete.
dnl
AH_TEMPLATE([SHADOW_PASSWORD],[define if shadowing password support should be enclosed])
AH_TEMPLATE([SHADOW_EXPIRATION],[define if shadowing password expiration should be enclosed])
AH_TEMPLATE([ACTIVCARD],[define if ActiveCard support should be enclosed])
AH_TEMPLATE([SECUREID],[define if SecureID support should be enclosed])
AH_TEMPLATE([IPASS],[define if IPass support should be enclosed])
AH_TEMPLATE([VPORTS],[define if VPORTS support should be enclosed])
AH_TEMPLATE([USE_PORTABLE_SNPRINTF],[define to do not use local (v)snprintf])
AH_TEMPLATE([OLD_PAM],[define if pam_strerror() has just one arg])
AH_TEMPLATE([PAM],[define if you want to activate PAM support and your system support PAM])
AH_TEMPLATE([ASCEND_BINARY],[define if you want to activate Ascend Binary Data Filters])

AC_CONFIG_HEADERS(config.h)

dnl
dnl Checks for make program.
dnl
AC_PROG_MAKE_SET
AM_SANITY_CHECK

dnl Check for C support (allow override if needed)
dnl Note: actually, setting CC environment variable works just as well.
AC_ARG_WITH(CC,
    [  --with-CC=compiler      use specific C compiler],
    [
        case "$withval" in
        "" | y | ye | yes | n | no)
            AC_MSG_ERROR([*** You must supply an argument to the --with-CC option.])
          ;;
        esac
        CC="$withval"
    ])

AC_PROG_CC

dnl Find CPP, then check traditional.
dnl Caution: these macros must be called in this order...
AC_PROG_CPP
AC_PROG_GCC_TRADITIONAL

if test "$CC" = "gcc"
then
        CC_VERSION=`${CC} -dumpversion`
else
        CC_VERSION=""
fi
AC_SUBST(CC_VERSION)

datadir=$prefix
AC_SUBST(datadir)


AC_SEARCH_LIBS([strerror],[cposix])
AC_PROG_RANLIB
AC_PROG_LN_S

dnl
dnl Checks for libraries.
dnl
AC_CHECK_LIB(nsl,gethostbyname)
AC_CHECK_LIB(socket,connect)
AC_CHECK_LIB(crypt,crypt)
AC_CHECK_LIB(gen,getspnam)

dnl
dnl Checks for header files.
dnl
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.
AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP

AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(fcntl.h limits.h strings.h string.h sys/file.h sys/time.h syslog.h unistd.h shadow.h machine/inline.h machine/endian.h sys/select.h sys/cdefs.h memory.h sys/stat.h sys/param.h sys/types.h) 

dnl
dnl Checks for typedefs, structures, and compiler characteristics.
dnl
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_GETGROUPS
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_HEADERS_ONCE([sys/time.h])

AC_STRUCT_TM
AC_STRUCT_TIMEZONE

dnl
dnl Checks for common library functions.
dnl
AC_FUNC_MEMCMP
AC_DEFINE_UNQUOTED([RETSIGTYPE],[$ac_cv_type_signal],[Define as the return type of signal handlers (`int' or `void').])

AC_FUNC_STRFTIME
AC_FUNC_VPRINTF

AC_CHECK_FUNCS(memcpy)
AC_CHECK_FUNCS(strchr)
AC_CHECK_FUNCS(strerror)
AC_CHECK_FUNCS(gethostname gettimeofday mkdir timelocal mktime select socket strtol)
AC_CHECK_FUNCS(snprintf __snprintf)
AC_CHECK_FUNCS(vsnprintf __vsnprintf)
AC_CHECK_FUNCS(getspnam)
AC_CHECK_FUNCS(syslog)
AC_CHECK_FUNCS(vsyslog)
AC_CHECK_FUNCS(getopt_long)

dnl 
dnl Optional features enabling.
dnl 
AC_ARG_ENABLE(
        pam,
	[  --enable-pam               to support PAM],
	[
	AC_CHECK_HEADERS(security/pam_appl.h security/pam_misc.h) 
dnl
dnl In order to compile a PAM version libpam.a is required.
dnl This is checked here along with other libs
dnl  
	AC_CHECK_LIB(pam,pam_start)
dnl
dnl  Some systems also have a PAM tool lib
dnl
	if test "$ac_cv_lib_pam_pam_start" = "yes"; then
		AC_CHECK_LIB(pam_misc,pam_misc_copy_env)
dnl
dnl Controls if pam_strerror() has one or two args.
dnl Old version of PAM has only one arg.
dnl

		AC_CHECK_FUNC(pam_strerror,
			[
			AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <security/pam_appl.h>]], [[
				char *val=pam_strerror(1);
				]])],[AC_DEFINE(OLD_PAM)],[])
			]
		)
	fi

	if test "$ac_cv_lib_pam_pam_start" = "yes"; then
		AC_DEFINE(PAM) AC_MSG_RESULT([PAM support enabled])
	else
                AC_MSG_ERROR([
	
	PAM development library libpam.a is missing. 
        You need to install it in order to build a PAM version 
	of these programs. Verify your configuration, if you are
	sure that this system supports PAM. Well-known PAM 
	supporting platforms are: Solaris, Linux, FreeBSD and 
	HP-UX. As well known, some distributions of Linux do not
	install PAM development libs/headers as default. So it's 
	up to you installing them.
	
		])
	fi
	],
	AC_MSG_RESULT([PAM support disabled]),
)

dnl
dnl The following libraries need more investigation
dnl
AC_ARG_ENABLE(
        secureid,
	[  --enable-secureid          to support SecurID library],
	[
	YARD_SID_LIBS=" sdiclient.a"
	AC_DEFINE(SECUREID) AC_MSG_RESULT([SecureID enabled])
	],
	AC_MSG_RESULT([SecureID disabled]),
)

AC_ARG_ENABLE(
        activcard,
	[  --enable-activcard         to support ActivCard library],
	[
	YARD_ACARD_LIBS=" aegcli.a"
	AC_DEFINE(ACTIVCARD) AC_MSG_RESULT([ActivCard enabled])
	],
	AC_MSG_RESULT([ActivCard disabled]),
)

AC_ARG_ENABLE(
        ipass,
	[  --enable-ipass             to support IPass library],
	[
	AC_DEFINE(IPASS) 
	AC_MSG_RESULT([IPass enabled])
	AC_CHECK_LIB(crypto,crypt)
	YARD_IPASS_LIBS=" -lip -lssl -lcrypto" 
	],
	AC_MSG_RESULT([IPass disabled]),
)

AC_ARG_ENABLE(
        shadow,
	[  --enable-shadow            to support shadow passwords],
	AC_DEFINE(SHADOW_PASSWORD) AC_MSG_RESULT([shadow passwd enabled]),
	AC_MSG_RESULT([shadow passwd disabled]),
)

AC_ARG_ENABLE(
        shadowexp,
	[  --enable-shadowexp         to support shadow expirations],
	AC_DEFINE(SHADOW_EXPIRATION) AC_DEFINE(SHADOW_PASSWORD) AC_MSG_RESULT([shadow passwd expiration enabled]),
	AC_MSG_RESULT([shadow passwd expiration disabled]),
)

AC_ARG_ENABLE(
        psnprintf,
	[  --enable-psnprintf         to force a portable snprintf],
	AC_DEFINE(USE_PORTABLE_SNPRINTF) AC_MSG_RESULT([portable (v)snprintf() forced]),
	AC_MSG_RESULT([portable (v)snprintf() not forced]),
)

AC_ARG_ENABLE(
        vports,
	[  --disable-vports           to disable vports],
	[
	if test "$enable_val" = "yes"; then
		AC_DEFINE(VPORTS) 
		AC_MSG_RESULT([Vports enabled])
	else
		AC_MSG_RESULT([Vports disabled])
	fi
	], 
	AC_DEFINE(VPORTS) AC_MSG_RESULT([Vports enabled])
)

AC_ARG_ENABLE(
        abinary,
	[  --disable-abinary          to disable abinary],
	[
	if test "$enable_val" = "yes"; then
		AC_DEFINE(ASCEND_BINARY) 
		AC_MSG_RESULT([abinary enabled])
	else
		AC_MSG_RESULT([abinary disabled])
	fi
	], 
	AC_DEFINE(ASCEND_BINARY) AC_MSG_RESULT([abinary enabled])
)

dnl
dnl This option enable specific settings for Debian GNU/Linux
dnl

AC_ARG_ENABLE(
	debian,
	[  --enable-debian            to force Debian GNU/Linux settings],
	[ 
	DEBIAN=yes
	AC_MSG_RESULT([Debianization enabled])
	if test -f "/etc/shadow"; then 
		AC_DEFINE(SHADOW_EXPIRATION) 
		AC_DEFINE(SHADOW_PASSWORD) 
		AC_MSG_RESULT([ - shadow passwd enabled])
		AC_MSG_RESULT([ - shadow passwd expiration enabled])
	fi
	],
	[
	DEBIAN=no
	AC_MSG_RESULT([Debianization disabled])
	]
)

if test "$DEBIAN" = "yes"; then
	YARDCONF="/etc/yardradius"
	YARDLOG="/var/log/yardradius"
	YARDDOC="/usr/share/doc/yardradius"
else
	if test "$prefix" != "NONE"; then
		YARDCONF=$prefix/conf
		YARDLOG=$prefix/logs
		YARDDOC=$prefix/doc
	else
		YARDCONF=/usr/local/yardradius/conf
		YARDLOG=/usr/local/yardradius/logs
		YARDDOC=/usr/local/yardradius/doc
	fi
fi
AC_SUBST(YARDCONF)
AC_SUBST(YARDLOG)
AC_SUBST(YARDDOC)


dnl
dnl Add include dirs, mainly for GDBM library, but also for other
dnl non standard headers
dnl 

AC_ARG_WITH(includes,
    [  --with-includes=DIR            site header files for GDBM, etc in DIR],
    [
        case "$withval" in
        "" | y | ye | yes | n | no)
           AC_MSG_ERROR([*** You must supply an argument to the --with-includes option.])
          ;;
        esac
        INCLUDE_DIRS="$withval"
    ])

if test "$INCLUDE_DIRS"; then
        for dir in $INCLUDE_DIRS; do
                if test -d "$dir"; then
                   YARD_CPPFLAGS="$YARD_CPPFLAGS -I$dir"
                else
                   AC_MSG_WARN([*** Include directory $dir does not exist.])
                fi
        done
else
	EXTRADIRS="/usr/local/include /opt/include /opt/gnu/include"
	for dir in $EXTRADIRS; do
                if test -d "$dir"; then
                   YARD_CPPFLAGS="$YARD_CPPFLAGS -I$dir"
                fi
	done
fi

AC_ARG_WITH(libs,
    [  --with-libdir=DIR              also search for libraries in DIR],
    [
        case "$withval" in
        "" | y | ye | yes | n | no)
            AC_MSG_ERROR([*** You must supply an argument to the --with-libdir option.])
          ;;
        esac
        LIBRARY_DIRS="$withval"
    ])

AC_ARG_WITH(libraries,
    [  --with-libraries='-lxxx -lyyy' also link libraries libxxx.a and libyyy.a],
    [
        case "$withval" in
        "" | y | ye | yes | n | no)
            AC_MSG_ERROR([*** You must supply an argument to the --with-libraries option.])
          ;;
        esac
        MORELIBRARIES="$withval"
    ])

dnl
dnl Test for linker shared libraries search options.
dnl These are non standard option. Configurator knows three well-known
dnl options, i.e.
dnl 
dnl -R (Solaris)
dnl -rpath (SunOS, FreeBSD, Compaq Tru64)
dnl -Xlinker -rpath (GCC)
dnl -Wl,-rpath (GCC)
dnl
dnl If all these options fail you should use some other exotic
dnl feature, such as an environment variable (eg LD_LIBRARY_PATH or
dnl LD_RUN_PATH) or a configuraton file (eg /etc/ld.so.conf with 
dnl 'ldconfig' a la Linux). At this moment all this is up to you. 
dnl 
dnl This is skipped for Debian GNU/Linux as required by Policy Manual.
dnl

if test "$DEBIAN" = "no"; then

TEMPLDFLAGS="$LDFLAGS" 
LDFLAGS="-R /usr/lib"
AC_RUN_IFELSE([AC_LANG_SOURCE([[
	main()
	{ exit(0); }
	]])],[
	    AC_MSG_RESULT([Linker -R flag supported])
	    LINKSHRDFLAGS="-R"
	],[
	    AC_MSG_RESULT([Linker -R flag not supported])
	],[
	    AC_MSG_RESULT([Cross compiling not supported])
	
])
LDFLAGS="$TEMPLDFLAGS"

if test ! "$LINKSHRDFLAGS"; then
LDFLAGS="-rpath /usr/lib"
AC_RUN_IFELSE([AC_LANG_SOURCE([[
	main()
	{ exit(0); }
	]])],[
	    AC_MSG_RESULT([Linker -rpath flag supported])
	    LINKSHRDFLAGS="-rpath "
	],[
	    AC_MSG_RESULT([Linker -rpath flag not supported])
	],[
	    AC_MSG_RESULT([Cross compiling not supported])
	
])
LDFLAGS="$TEMPLDFLAGS"
fi

if test ! "$LINKSHRDFLAGS"; then
LDFLAGS="-Xlinker -rpath -Xlinker /usr/lib"
AC_RUN_IFELSE([AC_LANG_SOURCE([[
	main()
	{ exit(0); }
	]])],[
	    AC_MSG_RESULT([Linker -Xlinker -rpath flag supported])
	    LINKSHRDFLAGS="-Xlinker -rpath -Xlinker "
	],[
	    AC_MSG_RESULT([Linker -Xlinker -rpath flag not supported])
	],[
	    AC_MSG_RESULT([Cross compiling not supported])
	
])
LDFLAGS="$TEMPLDFLAGS"
fi

if test ! "$LINKSHRDFLAGS"; then
LDFLAGS="-Xlinker -R -Xlinker /usr/lib"
AC_RUN_IFELSE([AC_LANG_SOURCE([[
	main()
	{ exit(0); }
	]])],[
	    AC_MSG_RESULT([Linker -Xlinker -R flag supported])
	    LINKSHRDFLAGS="-Xlinker -R -Xlinker "
	],[
	    AC_MSG_RESULT([Linker -Xlinker -R flag not supported])
	],[
	    AC_MSG_RESULT([Cross compiling not supported])
	
])
LDFLAGS="$TEMPLDFLAGS"
fi

if test ! "$LINKSHRDFLAGS"; then
LDFLAGS="-Wl,-R -Wl,/usr/lib"
AC_RUN_IFELSE([AC_LANG_SOURCE([[
	main()
	{ exit(0); }
	]])],[
	    AC_MSG_RESULT([Linker -Wl,-R flag supported])
	    LINKSHRDFLAGS="-Wl,-R -Wl,"
	],[
	    AC_MSG_RESULT([Linker -Wl,-R flag not supported])
	],[
	    AC_MSG_RESULT([Cross compiling not supported])
	
])
LDFLAGS="$TEMPLDFLAGS"
fi

if test ! "$LINKSHRDFLAGS"; then
LDFLAGS="-Wl,-rpath -Wl,/usr/lib"
AC_RUN_IFELSE([AC_LANG_SOURCE([[
	main()
	{ exit(0); }
	]])],[
	    AC_MSG_RESULT([Linker -Wl,-rpath flag supported])
	    LINKSHRDFLAGS="-Wl,-rpath -Wl,"
	],[
	    AC_MSG_RESULT([Linker -Wl,-rpath flag not supported])
	],[
	    AC_MSG_RESULT([Cross compiling not supported])
	
])
LDFLAGS="$TEMPLDFLAGS"
fi

if test ! "$LINKSHRDFLAGS"; then
	$ECHO "%BNo local support of additional shlib linking found%b"
fi

fi

dnl
dnl Add additional library path to check
dnl

if test "$LIBRARY_DIRS"; then
        for dir in $LIBRARY_DIRS; do
                if test -d "$dir"; then
		  if test "$LINKSHRDFLAGS"; then
                    YARD_LDFLAGS="$YARD_LDFLAGS $LINKSHRDFLAGS$dir -L$dir "
		  else
                    YARD_LDFLAGS="$YARD_LDFLAGS -L$dir "
		  fi
                else
                   AC_MSG_WARN([*** Library directory $dir does not exist.])
                fi
        done
else
	EXTRADIRS="/usr/local/lib /opt/lib /opt/gnu/lib "
	for dir in $EXTRADIRS; do
                if test -d "$dir"; then
		  if test "$LINKSHRDFLAGS"; then
                    YARD_LDFLAGS="$YARD_LDFLAGS $LINKSHRDFLAGS$dir -L$dir "
		  else
                    YARD_LDFLAGS="$YARD_LDFLAGS -L$dir "
		  fi
		fi
        done
fi

CPPFLAGS="$CPPFLAGS $YARD_CPPFLAGS"
$ECHO "Setting %BCPPFLAGS%b = $CPPFLAGS"
AC_SUBST(CPPFLAGS)

LDFLAGS="$LDFLAGS $YARD_LDFLAGS"
$ECHO "Setting %BLDFLAGS%b = $LDFLAGS"
AC_SUBST(LDFLAGS)

LIBS="$YARD_SID_LIBS$YARD_ACARD_LIBS $LIBS$YARD_IPASS_LIBS $MORELIBRARIES"
$ECHO "Setting %BLIBS%b = $LIBS"

dnl
dnl Now it's time to search the GDBM library. Sometimes its name is 
dnl not the standard one. That's true in very old system such as some
dnl old RH systems AFAIK.
dnl
AC_SEARCH_LIBS(gdbm_open,gdbm dbm db ndbm)
if test "$ac_cv_search_gdbm_open" = "no"; then
	 AC_MSG_ERROR([
	 
	GDBM library not found. Please install it or give the library
	name at configuration time with a --with-libraries="-lname"
	argument
	 
	 ])
fi

AC_CONFIG_FILES([
Makefile
conf/menus/Makefile
conf/Makefile
doc/txt/Makefile
doc/Makefile
include/Makefile
pam/Makefile
src/Makefile
logs/Makefile
man/Makefile
])

AC_CONFIG_COMMANDS([misc],[[
if test "$DEBIAN" = "yes"; then
cat > default-paths.h <<EOF
/*
** This file is produced by the configure script automagically.
** Do not edit it manually, please
*/

#define RADIUS_DIR              "$YARDCONF"
#define RADACCT_DIR             "$YARDLOG"

EOF

else

cat > default-paths.h <<EOF
/*
** This file is produced by the configure script automagically.
** Do not edit it manually, please
*/

#define RADIUS_DIR              "$prefix/conf"
#define RADACCT_DIR             "$prefix/logs"

EOF


fi
cat > hostinfo.h <<EOF
/*
** This file is produced by the configure script automagically.
** Do not edit it manually, please.
*/

#define HOSTINFO	"$host"

EOF

$srcdir/scripts/changeprefix man "$prefix"

]],[[prefix=$prefix host=$host]])

dnl
dnl This macro must be the very last one.
dnl
AC_OUTPUT
