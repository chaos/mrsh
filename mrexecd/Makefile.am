##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

CPPFLAGS = -I../common -I../config

sbin_PROGRAMS = in.mrexecd

in_mrexecd_SOURCES = mrexecd.c

if WITH_PAM
in_mrexecd_LDFLAGS = $(LIBPAM)
else 
in_mrexecd_LDFLAGS = $(LIBSHADOW)
endif 
