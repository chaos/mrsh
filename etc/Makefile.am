##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

XINETDDIR = /etc/xinetd.d
PAMDDIR = /etc/pam.d

install-exec-hook:
	mkdir -p -m 755 $(DESTDIR)$(XINETDDIR)
	mkdir -p -m 755 $(DESTDIR)$(PAMDDIR)
	install -m644 mrshd-xinetd $(DESTDIR)$(XINETDDIR)/mrshd
	install -m644 mrlogind-xinetd $(DESTDIR)$(XINETDDIR)/mrlogind
	install -m444 mrsh.pam $(DESTDIR)$(PAMDDIR)/mrsh
	install -m444 mrlogin.pam $(DESTDIR)$(PAMDDIR)/mrlogin
