##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

CPPFLAGS = -I../common -I../config -I../mcmd

noinst_HEADERS = pathnames.h

bin_PROGRAMS = mrcp

mrcp_SOURCES = mrcp.c

mrcp_LDADD = ../mcmd/libmcmd.la

mrcp_LDFLAGS = $(MCMD_CFLAGS)

../mcmd/libmcmd.la : force-dependency-check
	@cd `dirname $@` && make `basename $@`

force-dependency-check:
