##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

man1_MANS = rsh.1 rcp.1 rlogin.1
man8_MANS = rshd.8 in.rshd.8 rlogind.8 in.rlogind.8

all:
	rm -f rsh
	ln -s $(bindir)/mrsh rsh
	rm -f rcp
	ln -s $(bindir)/mrcp rcp
	rm -f rlogin
	ln -s $(bindir)/mrlogin rlogin

EXTRA_DIST = rsh.1 rcp.1 rlogin.1 \
	     rshd.8 in.rshd.8 rlogind.8 in.rlogind.8 

install-exec-hook:
	$(top_srcdir)/config/mkinstalldirs -m 755 $(DESTDIR)/$(bindir)
	cp -d ./rsh $(DESTDIR)/$(bindir)
	cp -d ./rcp $(DESTDIR)/$(bindir)
	cp -d ./rlogin $(DESTDIR)/$(bindir)

