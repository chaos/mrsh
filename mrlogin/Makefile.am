##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

bin_PROGRAMS = mrlogin

mrlogin_SOURCES = mrlogin.c des_rw.c
mrlogin_CFLAGS = -I$(srcdir)/../common -I../config -I$(srcdir)/../mcmd 
mrlogin_LDADD = ../mcmd/libmcmd.la

mrlogin_LDFLAGS = $(MCMD_CFLAGS)

../mcmd/libmcmd.la : force-dependency-check
	@cd `dirname $@` && make `basename $@`

force-dependency-check:
