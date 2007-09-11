##*****************************************************************************
## $Id$
##*****************************************************************************
## Process this file with autoconf to produce a configure script.
##*****************************************************************************

##
# Prologue.
##
AC_INIT([mrsh])
AC_META
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_SRCDIR([README])
AC_CANONICAL_SYSTEM

##
# Automake support.
##
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)
AM_CONFIG_HEADER([config/config.h])
AM_MAINTAINER_MODE

##
# Checks for programs.
##
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET
AC_PROG_LN_S

##
# Checks for header files.
##
AC_HEADER_STDC
AC_CHECK_HEADERS( \
  stdio.h \
  stdlib.h \
  string.h \
  unistd.h \
  getopt.h \
  types.h \
)

##
# Checks for typedefs, structures, and compiler characteristics.
##
AC_C_BIGENDIAN
AC_C_CONST
AC_TYPE_UID_T
AC_SYS_LARGEFILE

##
# Checks for library functions.
##
AC_FUNC_MALLOC
AC_CHECK_FUNCS( \
  strcmp \
  strlen \
  strcpy \
  strchr \
)

##
# Program checks
##
AC_SIGNALS
AC_NCURSES
AC_CRYPT
AC_FORKPTY
AC_LOGWTMP
AC_TYPE_SOCKLEN_T
AC_SNPRINTF
LIBS="$LIBS $LIBTERMCAP $LIBCRYPT $LIBFORKPTY $LIBLOGWTMP"

AC_PAM
AM_CONDITIONAL(WITH_PAM, test "$ac_have_pam" = "yes")

AC_SHADOW
AM_CONDITIONAL(WITH_SHADOW, test "$ac_have_shadow" = "yes")

AC_MUNGE
AC_MCMD
AC_MAUTH

##
# Epilogue.
##
AC_CONFIG_FILES( \
  mrsh.spec \
  Makefile \
  common/Makefile \
  doc/Makefile \
  etc/Makefile \
  etc/pam/Makefile \
  etc/xinetd/Makefile \
  mauth/Makefile \
  mcmd/Makefile \
  mrcp/Makefile \
  mrlogin/Makefile \
  mrlogind/Makefile \
  mrsh/Makefile \
  mrshd/Makefile \
  rsh-compat/Makefile \
)
AC_OUTPUT

