##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

noinst_HEADERS = pathnames.h

bin_PROGRAMS = mrsh

mrsh_SOURCES = mrsh.c

mrsh_CFLAGS = -I$(srcdir)/../common -I../config -I$(srcdir)/../mcmd

mrsh_LDADD = ../mcmd/libmcmd.la

mrsh_LDFLAGS = $(MCMD_CFLAGS)

../mcmd/libmcmd.la : force-dependency-check
	@cd `dirname $@` && make `basename $@`

force-dependency-check:
