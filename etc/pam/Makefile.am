##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

PAMDIR = $(sysconfdir)/pam.d

PAMFILES = mrlogin mrsh
EXTRA_DIST = $(PAMFILES)
 
if WITH_PAM 
PAMFILESdir = $(PAMDIR)
PAMFILES_DATA = $(PAMFILES)
endif
 
install-data-hook:
if WITH_PAM
	chmod 444 $(PAMFILESdir)/mrlogin
	chmod 444 $(PAMFILESdir)/mrsh
endif

