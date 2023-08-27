##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Albert Chu  <chu11@llnl.gov>
#
#  SYNOPSIS:
#    AC_PAM
#
#  DESCRIPTION:
#    Check for pam
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
##*****************************************************************************

AC_DEFUN([AC_PAM],
[

  AC_MSG_CHECKING([for whether to build with pam])
  AC_ARG_WITH([pam],
    AS_HELP_STRING([--without-pam],
      [Do not build with pam support]),
    [ case "$withval" in
        no)  ac_with_pam=no ;;
        yes) ac_with_pam=yes ;;
        *)   AC_MSG_RESULT([doh!])
             AC_MSG_ERROR([bad value "$withval" for --with-pam]) ;;
      esac
    ]
  )
  AC_MSG_RESULT([${ac_with_pam=yes}])

  if test "$ac_with_pam" = "yes"; then
    AC_CHECK_LIB([pam], [pam_start], 
                 AC_CHECK_LIB([dl],  [dlopen], [ac_have_pam=yes]))
    if test "$ac_have_pam" = "yes"; then 
      AC_DEFINE([USE_PAM], [1], [define use of pam])
      LIBPAM="-ldl -lpam -lpam_misc"
    else
      AC_MSG_ERROR([Cannot find pam libraries!])
    fi
  fi    

  AC_SUBST(LIBPAM)
])
