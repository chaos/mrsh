##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

XINETDDIR = $(sysconfdir)/xinetd.d

XINETDFILES = mrlogind mrshd
EXTRA_DIST = $(XINETDFILES)

XINETDFILESdir = $(XINETDDIR)
XINETDFILES_DATA = $(XINETDFILES)

install-data-hook:
	chmod 755 $(XINETDFILESdir)/mrlogind
	chmod 755 $(XINETDFILESdir)/mrshd
