/*
 * $Id$
 * $Source$
 */

#ifndef _MCMD_H
#define _MCMD_H

/* mcmd
 * - Modified version of rcmd(3) that uses munge authentication rather
 *   than reserved ports for security.
 */
int mcmd(char **ahost, int port, char *remuser, char *cmd, int *fd2p);

#endif /* _MCMD_H */
