##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

XINETDDIR = /etc/xinetd.d

install-exec-hook:
	mkdir -p -m 755 $(DESTDIR)$(XINETDDIR)
	install -m644 mrshd-xinetd $(DESTDIR)$(XINETDDIR)/mrshd
	install -m644 mrlogind-xinetd $(DESTDIR)$(XINETDDIR)/mrlogind
	install -m644 mrexecd-xinetd $(DESTDIR)$(XINETDDIR)/mrexecd
