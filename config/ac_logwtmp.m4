##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Albert Chu  <chu11@llnl.gov>
#
#  SYNOPSIS:
#    AC_LOGWTMP
#
#  DESCRIPTION:
#    Check for logwtmp
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
##*****************************************************************************

AC_DEFUN([AC_LOGWTMP],
[
  AC_CHECK_FUNC([logwtmp], [ac_have_logwtmp=yes], [ac_have_logwtmp=no])
  if test "$ac_have_logwtmp" = "no"; then
    AC_CHECK_LIB([util], [logwtmp], [LIBLOGWTMP=-lutil],
        AC_CHECK_LIB([bsd], [logwtmp], [LIBLOGWTMP=-lbsd]))
    if test -n "$LIBLOGWTMP"; then
       ac_have_logwtmp=yes
    else
       ac_have_logwtmp=no
    fi
  fi

  if test "$ac_have_logwtmp" = "no"; then
    AC_MSG_ERROR([logwtmp function required!])    
  fi
])
