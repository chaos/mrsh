##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Albert Chu  <chu11@llnl.gov>
#
#  SYNOPSIS:
#    AC_SOCKLEN
#
#  DESCRIPTION:
#    Check for socklen_t type
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
##*****************************************************************************

# Mostly by Lars Brinkhoff <lars@nocrew.org>, from the gnu
# autoconf m4 archive
AC_DEFUN([AC_TYPE_SOCKLEN_T],
[AC_CACHE_CHECK([for socklen_t], ac_cv_type_socklen_t,
[
  AC_TRY_COMPILE(
  [#include <sys/types.h>
   #include <sys/socket.h>],
  [socklen_t len = 42; return 0;],
  ac_cv_type_socklen_t=yes,
  ac_cv_type_socklen_t=no)
])
  if test "$ac_cv_type_socklen_t" = "no"; then
    AC_MSG_ERROR([socklen_t type required!])    
  fi
])
