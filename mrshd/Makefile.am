##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with automake to produce Makefile.in.
##*****************************************************************************

noinst_HEADERS = list.h 

sbin_PROGRAMS = in.mrshd

in_mrshd_SOURCES = mrshd.c mrshconv.c list.c

if WITH_PAM
in_mrshd_LDFLAGS = $(LIBPAM)
endif 

in_mrshd_LDADD = ../mauth/libmauth.la

in_mrshd_CFLAGS = -I../common -I../config -I../mauth

../mauth/libmauth.la : force-dependency-check
	@cd `dirname $@` && make `basename $@`

force-dependency-check:
