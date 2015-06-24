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

#ifndef _MCMD_H
#define _MCMD_H

/* mcmd
 * - Modified version of rcmd(3) that uses munge authentication rather
 *   than reserved ports for security.
 */
int mcmd(char **ahost, int port, char *remuser, char *cmd, int *fd2p, char *munge_socket);

#endif /* _MCMD_H */
