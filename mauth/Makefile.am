##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

CPPFLAGS = -I../common -I../config

noinst_HEADERS = mauth.h

noinst_LTLIBRARIES = libmauth.la

libmauth_la_SOURCES = mauth.c mauth.h

libmauth_la_LIBADD = ../common/libfd.la

libmauth_la_LDFLAGS = $(MAUTH_LIBS)

../common/libfd.la : force-dependency-check
	@cd `dirname $@` && make `basename $@`

force-dependency-check:
