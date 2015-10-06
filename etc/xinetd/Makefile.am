##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

if !HAVE_SYSTEMD
XINETDDIR = $(sysconfdir)/xinetd.d

XINETDFILES = mrlogind mrshd
EXTRA_DIST = $(XINETDFILES)

XINETDFILESdir = $(XINETDDIR)
XINETDFILES_DATA = $(XINETDFILES)
endif

install-data-hook:
	if [ -a $(DESTDIR)/$(XINETDFILESdir)/mrlogind ] ; \
	then \
		chmod 755 $(DESTDIR)/$(XINETDFILESdir)/mrlogind ; \
	fi;
	if [ -a $(DESTDIR)/$(XINETDFILESdir)/mrshd ] ; \
	then \
		chmod 755 $(DESTDIR)/$(XINETDFILESdir)/mrshd ; \
	fi;
