##*****************************************************************************
## $Id$
##*****************************************************************************
#  AUTHOR:
#    Albert Chu  <chu11@llnl.gov>
#
#  SYNOPSIS:
#    AC_SIGNALS
#
#  DESCRIPTION:
#    Check for signal and kill
#
#  WARNINGS:
#    This macro must be placed after AC_PROG_CC or equivalent.
##*****************************************************************************

AC_DEFUN([AC_SIGNALS],
[
  AC_MSG_CHECKING([for signals])
  AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM(
                [#include <unistd.h> 
                 #include <signal.h>
                 void handle(int foo) {}
                ], 
                [int pid=getpid(); 
                 signal(SIGINT, handle); 
                 kill(pid,SIGINT); 
                 return 0;])
        ]
        ac_cv_signals=yes,
        ac_cv_signals=no)

  AC_MSG_RESULT(${ac_cv_signal=yes})
 
  if test "$ac_cv_signals" = "no"; then
    AC_MSG_ERROR([signal and kill functions are required!])    
  fi
])
