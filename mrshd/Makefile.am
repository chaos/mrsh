##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

CPPFLAGS = -I../common -I../config

sbin_PROGRAMS = in.mrshd

in_mrshd_SOURCES = mrshd.c

if WITH_PAM
in_mrshd_LDFLAGS = $(LIBPAM)
endif 
