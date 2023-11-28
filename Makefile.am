## $Id: Makefile.am 100 2007-06-28 14:49:29Z flovergine $
##
## Submit this file to automake with --force --add-missing --copy
## See AC_CONFIG_AUX_DIR to know where it adds his own files.
##
## You should also set AUTOCONF to autoconf2.50 or whatever is
## your autoconf program, if you have more than one version available.
##

AUTOMAKE_OPTIONS=foreign

INSTALL=@INSTALL@
PACKAGE=@PACKAGE@
VERSION=@VERSION@

SUBDIRS=src conf pam doc logs man include

DIST_CONF = conf/clients.example conf/config.aeg.example conf/dictionary \
	    conf/proxy.example conf/radwatch.conf.example conf/users.example \
            conf/menus/menu1 conf/menus/menu2 conf/denyuser.example \
	    conf/allowuser.example \
	    conf/Makefile.am conf/menus/Makefile.am 

DIST_PAM = pam/Makefile.am pam/Makefile-linux pam/pam.conf pam/pam_radius_session.c pam/README pam/current-draft.txt

DIST_DOC = doc/txt/PAM-INFO \
	   doc/Makefile.am doc/txt/Makefile.am 

DIST_LOGS = logs/README logs/Makefile.am

DIST_INCLUDE = include/activcard.h include/aegapi.h include/global.h \
	       include/md5.h include/prototypes.h include/radius.h \
	       include/users.h include/vports.h include/yard.h

DIST_MAN = man/radiusd.8.man man/builddbm.8.man man/md5test.1.man man/radlast.1.man \
	    man/radlist.1.man man/radtest.1.man man/radwatch.8.man \
	    man/radiusd_attributes.5.man man/radiusd_pam.7.man

EXTRA_DIST = ChangeLog-1.0 ChangeLog-1.1 CREDITS INSTALL \
	     LICENSE.LUCENT LICENSE \
	     README README.LUCENT ROADMAP VERSION \
	     GPG-KEY \
	     autotools/README \
	     scripts/bootstrap scripts/changeprefix scripts/shtool \
	     $(DIST_CONF) $(DIST_PAM) $(DIST_DOC) $(DIST_INCLUDE) $(DIST_MAN)


distclean-local:
	-rm -f $(srcdir)/default-paths.h $(srcdir)/hostinfo.h
	-rm -f $(srcdir)/man/*.[12345678]
	-rm -rf $(srcdir)/autom4te.cache
