##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Albert Chu  <chu11@llnl.gov>
#
#  SYNOPSIS:
#    AC_NCURSES
#
#  DESCRIPTION:
#    Check for ncurses or termcap library
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
##*****************************************************************************

AC_DEFUN([AC_NCURSES],
[
  AC_CHECK_LIB([ncurses], [endwin], [ac_have_ncurses=yes], [ac_have_ncurses=no])

  if test "$ac_have_ncurses" = "yes"; then
    LIBTERMCAP=-lncurses
  else
    AC_CHECK_LIB([termcap], [tgetent], [ac_have_termcap=yes], [ac_have_termcap=no])
    if test "$ac_have_termcap" = "yes"; then
      LIBTERMCAP=-ltermcap
    else
      AC_MSG_ERROR([libncurses or libtermcap required for this package])
    fi     
  fi        
])
