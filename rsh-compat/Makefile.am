##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

man1_MANS = rsh.1 rcp.1 rlogin.1

all:
	rm -f rsh
	rm -f rcp
	rm -f rlogin
	ln -s $(bindir)/mrsh rsh
	ln -s $(bindir)/mrcp rcp
	ln -s $(bindir)/mrlogin rlogin

install-exec-hook:
	mkdir -m 755 -p $(DESTDIR)$(bindir)
	cp -d rsh $(DESTDIR)$(bindir)
	cp -d rcp $(DESTDIR)$(bindir)
	cp -d rlogin $(DESTDIR)$(bindir)

clean:
	rm -f rsh
	rm -f rcp
	rm -f rlogin
