##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Albert Chu  <chu11@llnl.gov>
#
#  SYNOPSIS:
#    AC_MUNGE
#
#  DESCRIPTION:
#    Check for munge
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
##*****************************************************************************

AC_DEFUN([AC_MUNGE],
[
  AC_CHECK_LIB([munge], [munge_encode], [ac_have_munge=yes], [ac_have_munge=no])
 
  if test "$ac_have_munge" = "no"; then
    AC_MSG_ERROR([munge library is required!])    
  fi

  # Libmunge requirers GPL_LICENSED
  AC_DEFINE([GPL_LICENSED], 1, [Define that we agree to the GPL License])

  LIBMUNGE=-lmunge
  AC_SUBST(LIBMUNGE)
])
