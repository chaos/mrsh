##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

CPPFLAGS = -I../common -I../config $(MCMD_CFLAGS) 

noinst_HEADERS = mcmd.h

noinst_LTLIBRARIES = libmcmd.la

libmcmd_la_SOURCES = mcmd.c

libmcmd_la_LIBADD = ../common/libfd.la

libmcmd_la_LDFLAGS = $(MCMD_LIBS) 

../common/libfd.la : force-dependency-check
	@cd `dirname $@` && make `basename $@`

force-dependency-check:
