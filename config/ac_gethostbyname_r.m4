##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Caolan McNamara <caolan@skynet.ie>
#
#  SYNOPSIS:
#    AC_caolan_FUNC_WHICH_GETHOSTBYNAME_R
#
#  DESCRIPTION:
#    Check for type of gethostbyname_r function
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
##*****************************************************************************

# Provides a test to determine the correct way to call gethostbyname_r:
#
#  - defines HAVE_FUNC_GETHOSTBYNAME_R_6 if it needs 6 arguments (e.g linux)
#  - defines HAVE_FUNC_GETHOSTBYNAME_R_5 if it needs 5 arguments (e.g. solaris)
#  - defines HAVE_FUNC_GETHOSTBYNAME_R_3 if it needs 3 arguments (e.g. osf/1)
#
# If used in conjunction in gethostname.c the api demonstrated in
# test.c can be used regardless of which gethostbyname_r exists. These
# example files found at
# <http://www.csn.ul.ie/~caolan/publink/gethostbyname_r>.
#
#
# Based on David Arnold's autoconf suggestion in the threads faq.

AC_DEFUN(AC_caolan_FUNC_WHICH_GETHOSTBYNAME_R,
[AC_CACHE_CHECK(for which type of gethostbyname_r, ac_cv_func_which_gethostname_r, [
AC_CHECK_FUNC(gethostbyname_r, [
        AC_TRY_COMPILE([
#               include <netdb.h>
        ],      [

        char *name;
        struct hostent *he;
        struct hostent_data data;
        (void) gethostbyname_r(name, he, &data);

                ],ac_cv_func_which_gethostname_r=three,
                        [
dnl                     ac_cv_func_which_gethostname_r=no
  AC_TRY_COMPILE([
#   include <netdb.h>
  ], [
        char *name;
        struct hostent *he, *res;
        char buffer[2048];
        int buflen = 2048;
        int h_errnop;
        (void) gethostbyname_r(name, he, buffer, buflen, &res, &h_errnop)
  ],ac_cv_func_which_gethostname_r=six,

  [
dnl  ac_cv_func_which_gethostname_r=no
  AC_TRY_COMPILE([
#   include <netdb.h>
  ], [
                        char *name;
                        struct hostent *he;
                        char buffer[2048];
                        int buflen = 2048;
                        int h_errnop;
                        (void) gethostbyname_r(name, he, buffer, buflen, &h_errnop)
  ],ac_cv_func_which_gethostname_r=five,ac_cv_func_which_gethostname_r=no)

  ]

  )
                        ]
                )]
        ,ac_cv_func_which_gethostname_r=no)])

if test $ac_cv_func_which_gethostname_r = six; then
  AC_DEFINE(HAVE_FUNC_GETHOSTBYNAME_R_6, 1, [gethostbyname with 6 arguments])
elif test $ac_cv_func_which_gethostname_r = five; then
  AC_DEFINE(HAVE_FUNC_GETHOSTBYNAME_R_5, 1, [gethostbyname with 5 arguments])
elif test $ac_cv_func_which_gethostname_r = three; then
  AC_DEFINE(HAVE_FUNC_GETHOSTBYNAME_R_3, 1, [gethostbyname with 3 arguments])

fi

])
