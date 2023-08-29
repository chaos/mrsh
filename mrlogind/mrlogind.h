/*****************************************************************************\
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2007-2015 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2003-2007 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Mike Haskell <haskell5@llnl.gov> and Albert Chu 
 *  <chu11@llnl.gov>
 *  UCRL-CODE-155697
 *  
 *  This file is part of Mrsh, a collection of remote shell programs
 *  that use munge based authentication rather than reserved ports for
 *  security. For details, see https://github.com/chaos/mrsh.
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


/* mrlogind.c */
void fatal(int f, const char *msg, int syserr);

/* network.c */
char *network_init(int fd, int *hostokp);
void network_confirm(void);
void network_anticonfirm(void);
void network_close(void);

/* auth.c */
void auth_checkoptions(void);
void auth_finish(void);
int auth_checkauth(const char *remoteuser, const char *host,
		   char *localuser, size_t localusermaxsize);
char ** auth_env(char **extra_env, unsigned int extra_env_len);

/* 
 * Global flag variables 
 */

/* Do paranoid DNS confirmation on all hosts? */
extern int check_all;

/* Use TCP keepalive messages on connection? */
extern int keepalive;

/* Check ~/.rhosts? */
extern int use_rhosts;

/* Check ~root/.rhosts? */
extern int allow_root_rhosts;

/* Ignore all ~/.rhosts and /etc/hosts_equiv? */
extern int deny_all_rhosts_hequiv;
