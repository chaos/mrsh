##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Albert Chu  <chu11@llnl.gov>
#
#  SYNOPSIS:
#    AC_SHADOW
#
#  DESCRIPTION:
#    Check for shadow library
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
##*****************************************************************************

AC_DEFUN([AC_SHADOW],
[
  AC_MSG_CHECKING([for whether to build with shadow file])
  AC_ARG_WITH([shadow],
    AC_HELP_STRING([--without-shadow],
      [Do not build with shadow file support]),
    [ case "$withval" in
        no)  ac_with_shadow=no ;;
        yes) ac_with_shadow=yes ;;
        *)   AC_MSG_RESULT([doh!])
             AC_MSG_ERROR([bad value "$withval" for --with-shadow]) ;;
      esac
    ]
  )
  AC_MSG_RESULT([${ac_with_shadow=yes}])

  if test "$ac_with_pam" = "no" && test "$ac_with_shadow" = "yes"; then 
     AC_CHECK_FUNC([getspnam], [ac_have_shadow=yes], [ac_have_shadow=no])
     if test "$ac_have_shadow" = "no"; then
       AC_CHECK_LIB([shadow], [getspnam], [ac_have_shadow=yes], [ac_have_shadow=no])
       LIBSHADOW=-lshadow
     fi

     if test "$ac_have_shadow" = "yes"; then
        AC_DEFINE([USE_SHADOW], [1], [Define use of shadow file])
     else
        AC_MSG_ERROR([cannot find getspnam!])
     fi
  fi        

  AC_SUBST(LIBSHADOW)
])
