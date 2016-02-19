##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

if HAVE_SYSTEMD
systemdsystemunit_SCRIPTS = mrlogind.socket mrlogind@.service mrshd.socket mrshd@.service
endif

EXTRA_DIST = mrlogind.socket mrlogind@.service mrshd.socket mrshd@.service

install-data-hook:
	if [ -a $(DESTDIR)/$(systemdsystemunitdir)/mrlogind.socket ] ; \
	then \
		chmod 644 $(DESTDIR)/$(systemdsystemunitdir)/mrlogind.socket ; \
	fi;
	if [ -a $(DESTDIR)/$(systemdsystemunitdir)/mrlogind@.service ] ; \
	then \
		chmod 644 $(DESTDIR)/$(systemdsystemunitdir)/mrlogind@.service ; \
	fi;
	if [ -a $(DESTDIR)/$(systemdsystemunitdir)/mrshd.socket ] ; \
	then \
		chmod 644 $(DESTDIR)/$(systemdsystemunitdir)/mrshd.socket ; \
	fi;
	if [ -a $(DESTDIR)/$(systemdsystemunitdir)/mrshd@.service ] ; \
	then \
		chmod 644 $(DESTDIR)/$(systemdsystemunitdir)/mrshd@.service ; \
	fi;
