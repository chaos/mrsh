##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

noinst_HEADERS = logwtmp.h pathnames.h mrlogind.h

sbin_PROGRAMS = in.mrlogind

EXTRA_in_mrlogind_SOURCES = auth.c network.c mrlogind.c sockconv.c

in_mrlogind_LDADD = ../mauth/libmauth.la

if WITH_PAM
in_mrlogind_SOURCES = auth.c network.c mrlogind.c sockconv.c
in_mrlogind_LDFLAGS = $(LIBPAM)
else 
in_mrlogind_SOURCES = auth.c network.c mrlogind.c
endif 

in_mrlogind_CFLAGS = -I../common -I../config -I../mauth

../mauth/libmauth.la : force-dependency-check
	@cd `dirname $@` && make `basename $@`

force-dependency-check:
