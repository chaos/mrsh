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
	chmod 755 $(DESTDIR)/$(XINETDFILESdir)/mrlogind
	chmod 755 $(DESTDIR)/$(XINETDFILESdir)/mrshd
