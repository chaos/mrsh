##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

CPPFLAGS = -I../common -I../config -I../mcmd 

bin_PROGRAMS = mrlogin

mrlogin_SOURCES = mrlogin.c des_rw.c

mrlogin_LDADD = ../mcmd/libmcmd.la

mrlogin_LDFLAGS = $(MCMD_CFLAGS)

../mcmd/libmcmd.la : force-dependency-check
	@cd `dirname $@` && make `basename $@`

force-dependency-check:
