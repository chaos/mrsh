##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Albert Chu  <chu11@llnl.gov>
#
#  SYNOPSIS:
#    AC_CRYPT
#
#  DESCRIPTION:
#    Check for crypt
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
##*****************************************************************************

AC_DEFUN([AC_CRYPT],
[
  AC_CHECK_FUNC([crypt], [ac_have_crypt=yes], [ac_have_crypt=no])
  if test "$ac_have_crypt" = "no"; then
    AC_CHECK_LIB([crypt], [crypt], [ac_have_crypt=yes], [ac_have_crypt=no])
    LIBCRYPT=-lcrypt
  fi

  if test "$ac_have_crypt" = "no"; then
    AC_MSG_ERROR([crypt function required!])    
  fi
])
