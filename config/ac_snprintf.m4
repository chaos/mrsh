##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Albert Chu  <chu11@llnl.gov>
#
#  SYNOPSIS:
#    AC_SNPRINTF
#
#  DESCRIPTION:
#    Check for snprintf
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
##*****************************************************************************

AC_DEFUN([AC_SNPRINTF],
[AC_CACHE_CHECK([for snprintf], ac_cv_snprintf,
[
  AC_TRY_COMPILE(
  [#include <stdio.h>],
  [void *x = (void *)snprintf; printf("%lx", (long)x); return 0;],
  ac_cv_snprintf=yes,
  ac_cv_snprintf=no)
])
  if test "$ac_cv_snprintf" = "no"; then
    AC_MSG_ERROR([snprintf function required!])    
  fi
])
