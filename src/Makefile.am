AUTOMAKE_OPTIONS = no-dependencies no-installinfo no-installman \
		   no-texinfo.tex foreign 

INSTALL=@INSTALL@
CPPFLAGS+=-I$(top_srcdir)/include

bin_PROGRAMS = radlist radlast \
	       radwatch \
	       md5test radtest

sbin_PROGRAMS = radiusd builddbm

radiusd_SOURCES = acct.c dict.c ipass.c log.c \
		md5.c menu.c pass.c \
		proxy.c users.c util.c \
		version.c radiusd.c \
		vports.c extens.c snprintf.c filters.c


builddbm_SOURCES = builddbm.c version.c log.c snprintf.c

radlast_SOURCES = radlast.c util.c dict.c log.c snprintf.c

radlist_SOURCES = radlist.c util.c log.c dict.c snprintf.c

radwatch_SOURCES = radwatch.c log.c dict.c util.c snprintf.c

md5test_SOURCES = md5test.c md5.c

radtest_SOURCES = radtest.c md5.c dict.c util.c log.c snprintf.c

