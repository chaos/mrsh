##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Albert Chu  <chu11@llnl.gov>
#
#  SYNOPSIS:
#    AC_MAUTH
#
#  DESCRIPTION:
#    Check for things required by mauth
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
#    Must be called after AC_MUNGE.
##*****************************************************************************

AC_DEFUN([AC_MAUTH],
[
  AC_STRUCT_SA_LEN
  AC_IPV6

  MAUTH_LIBS="$LIBMUNGE"
  AC_SUBST(MAUTH_LIBS)
])
