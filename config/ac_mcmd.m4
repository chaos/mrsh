##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Albert Chu  <chu11@llnl.gov>
#
#  SYNOPSIS:
#    AC_MCMD
#
#  DESCRIPTION:
#    Check for things required by mcmd
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
#    Must be called after AC_MUNGE.
##*****************************************************************************

AC_DEFUN([AC_MCMD],
[
  AC_caolan_FUNC_WHICH_GETHOSTBYNAME_R
  ACX_PTHREAD

  MCMD_LIBS="$LIBMUNGE $PTHREAD_LIBS"
  MCMD_CFLAGS="$PTHREAD_CFLAGS"  

  AC_SUBST(MCMD_LIBS)
  AC_SUBST(MCMD_CFLAGS)
])
