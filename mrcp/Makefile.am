##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

noinst_HEADERS = pathnames.h

bin_PROGRAMS = mrcp

mrcp_SOURCES = mrcp.c
mrcp_CFLAGS = -I$(srcdir)/../common -I../config -I$(srcdir)/../mcmd
mrcp_LDADD = ../mcmd/libmcmd.la

mrcp_LDFLAGS = $(MCMD_CFLAGS)

../mcmd/libmcmd.la : force-dependency-check
	@cd `dirname $@` && make `basename $@`

force-dependency-check:
