##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Albert Chu  <chu11@llnl.gov>
#
#  SYNOPSIS:
#    AC_IPV6
#
#  DESCRIPTION:
#    Check for IPv6
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
##*****************************************************************************

AC_DEFUN([AC_IPV6],
[
   # IEEE standard says it should be in sys/socket.h
   AC_CHECK_DECL([AF_INET6], 
                 AC_DEFINE(HAVE_IPV6,1,[have IPv6]),,
                 [#include <sys/socket.h>])  
])
