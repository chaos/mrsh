##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Albert Chu  <chu11@llnl.gov>
#
#  SYNOPSIS:
#    AC_STRUCT_SA_LEN
#
#  DESCRIPTION:
#    Check for sa_len variable in struct sockaddr_in 
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
##*****************************************************************************

# Found online, original author not known
AC_DEFUN([AC_STRUCT_SA_LEN],
[
  AC_CACHE_CHECK([for sa_len in struct sockaddr], ac_cv_struct_sa_len,
        AC_TRY_COMPILE([#include <sys/types.h> #include <sys/socket.h>], 
                        [struct sockaddr s; s.sa_len;],
                        ac_cv_struct_sa_len=yes, 
                        ac_cv_struct_sa_len=no))

  if test $ac_cv_struct_sa_len = yes; then
     AC_DEFINE(HAVE_SA_LEN, [1], [do we have sa_len in struct sockaddr])  
  fi
])
