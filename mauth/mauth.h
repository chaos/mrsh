/*
 * $Id$
 * $Source$
 */

#include <pwd.h>
#include <sys/types.h>
#include <sys/param.h>      /* MAXHOSTNAMELEN */
#include <netinet/in.h>     /* INETADDRSTRLEN */

#ifndef _MAUTH_H
#define _MAUTH_H

#define MAXUSERNAMELEN    32
#define MAXVERSIONLEN     16
#define MAXERRMSGLEN      256

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

struct mauth {
  uid_t uid;
  gid_t gid;
  unsigned int rand;
  unsigned short port;
  struct passwd *pwd;
  char username[MAXUSERNAMELEN+1];
  char version[MAXVERSIONLEN];
  char ip[INET_ADDRSTRLEN+1];
  char hostname[MAXHOSTNAMELEN+1];
  char cmd[ARG_MAX+1];
  char errmsg[MAXERRMSGLEN+1];
};

/* mauth
 * - Reads the munge blob from the specified file descriptor and
 *   performs the munge authentication check.  
 * - Returns 0 on success, -1 on error.  Error message stored in
 *   struct's errmsg buffer.
 */
int mauth(struct mauth *ma, int fd, int cport);

#endif /* _MAUTH_H */
