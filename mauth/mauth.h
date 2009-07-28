/*****************************************************************************\
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2007 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2003-2007 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Mike Haskell <haskell5@llnl.gov> and Albert Chu 
 *  <chu11@llnl.gov>
 *  UCRL-CODE-155697
 *  
 *  This file is part of Mrsh, a collection of remote shell programs
 *  that use munge based authentication rather than reserved ports for
 *  security. For details, see http://www.llnl.gov/linux/.
 *  
 *  Mrsh is free software; you can redistribute it and/or modify 
 *  it under the terms of the GNU General Public License as published by the 
 *  Free Software Foundation; either version 2 of the License, or (at your 
 *  option) any later version.
 *  
 *  Mrsh is distributed in the hope that it will be useful, but 
 *  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 *  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License 
 *  for more details.
 *  
 *  You should have received a copy of the GNU General Public License along
 *  with Mrsh.  If not, see <http://www.gnu.org/licenses/>.
\*****************************************************************************/

#include <pwd.h>
#include <sys/types.h>
#include <sys/param.h>      /* MAXHOSTNAMELEN */

#ifndef ARG_MAX
#define ARG_MAX 131072
#endif

#ifndef _MAUTH_H
#define _MAUTH_H

#define MAXUSERNAMELEN    32
#define MAXVERSIONLEN     16
#define MAXERRMSGLEN      256

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

struct mauth {
  uid_t uid;
  gid_t gid;
  unsigned int rand;
  unsigned short port;
  struct passwd *pwd;
  struct passwd cred;
  char username[MAXUSERNAMELEN+1];
  char version[MAXVERSIONLEN];
  char cmd[ARG_MAX+1];
  char errmsg[MAXERRMSGLEN+1];
};

/* mauth
 * - Reads the munge blob from the specified file descriptor and
 *   performs the munge authentication check.  
 * - Returns 0 on success, -1 on error.  Error message stored in
 *   struct's errmsg buffer.
 */
int mauth(struct mauth *ma, int fd, int cport, char *munge_socket);

#endif /* _MAUTH_H */
