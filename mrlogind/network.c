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
 *  The code in this file began with the code in the rsh project.  See
 *  below for original copyright information.
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

/*-
 * Copyright (c) 1983, 1988, 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Advertising clause removed per the following letter:
 *    ftp://ftp.cs.berkeley.edu/pub/4bsd/README.Impt.License.Change
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>       /* for MAXHOSTNAMELEN */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>           /* for snprintf(), BUFSIZ */
#include <syslog.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "mrlogind.h"

static int confirmed=0;
static int netf;

static const char *
topdomain(const char *h)
{
	const char *p;
	const char *maybe = NULL;
	int dots = 0;

	for (p = h + strlen(h); p >= h; p--) {
		if (*p == '.') {
			if (++dots == 2)
				return (p);
			maybe = p;
		}
	}
	return (maybe);
}

/*
 * Check whether host h is in our local domain,
 * defined as sharing the last two components of the domain part,
 * or the entire domain part if the local domain has only one component.
 * If either name is unqualified (contains no '.'),
 * assume that the host is local, as it will be
 * interpreted as such.
 */
static int
local_domain(const char *h)
{
	char localhost[MAXHOSTNAMELEN];
	const char *p1, *p2;

	localhost[0] = 0;
	(void) gethostname(localhost, sizeof(localhost));
	p1 = topdomain(localhost);
	p2 = topdomain(h);
	if (p1 == NULL || p2 == NULL || !strcasecmp(p1, p2))
		return(1);
	return(0);
}


static char *
find_hostname(const struct sockaddr_in *fromp, int *hostokp)
{
	struct hostent *hop;
	char *hname;
	int hostok = 0;

	hop = gethostbyaddr((const char *)&fromp->sin_addr, 
			    sizeof(struct in_addr), fromp->sin_family);
	if (hop == NULL) {
		hname = strdup(inet_ntoa(fromp->sin_addr));
		hostok = 1;
	} 
	else if (check_all || local_domain(hop->h_name)) {
		/*
		 * If name returned by gethostbyaddr is in our domain,
		 * attempt to verify that we haven't been fooled by someone
		 * in a remote net; look up the name and check that this
		 * address corresponds to the name.
		 */
		hname = strdup(hop->h_name);
		hop = gethostbyname(hname);
		if (hop) {
		    for (; hop->h_addr_list[0]; hop->h_addr_list++) {
			if (!memcmp(hop->h_addr_list[0], &fromp->sin_addr,
				    sizeof(fromp->sin_addr))) {
				hostok = 1;
				break;
			}
		    }
		    /* not clear if this is worthwhile */
		    free(hname);
		    hname = strdup(hop->h_name);
		}
	} 
	else {
		hname = strdup(hop->h_name);
		hostok = 1;
	}

        /* 
         * Actually it might be null if we're out of memory, but
         * where do we go then? We'd have to bail anyhow.
         */
        if (hname == NULL) {
                syslog(LOG_ERR, "find_hostname: Out of memory");
                fatal(STDERR_FILENO, "Out of Memory", 0);
        }

	*hostokp = hostok;

	return hname;
}



char * 
network_init(int f, int *hostokp)
{
	struct sockaddr_in from, *fromp;
	socklen_t fromlen;
	int on = 1;
	char c;
	char *hname;
	int port;

	from.sin_family = AF_INET;
	fromlen = sizeof (from);
	if (getpeername(f, (struct sockaddr *)&from, &fromlen) < 0) {
		syslog(LOG_ERR,"Can't get peer name of remote host: %m");
		fatal(STDERR_FILENO, "Can't get peer name of remote host", 1);
	}
	if (keepalive &&
	    setsockopt(f, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0)
		syslog(LOG_WARNING, "setsockopt (SO_KEEPALIVE): %m");
#ifdef IP_TOS
	#define IPTOS_LOWDELAY          0x10
	on = IPTOS_LOWDELAY;
	if (setsockopt(f, IPPROTO_IP, IP_TOS, &on, sizeof(on)) < 0)
		syslog(LOG_WARNING, "setsockopt (IP_TOS): %m");
#endif
	fromp = &from;

	alarm(60);
	read(f, &c, 1);

        if (c != 0) {
                syslog(LOG_ERR, "did not receive null from user");
                fatal(STDERR_FILENO, "Protocol Error", 0);
        }

	alarm(0);

	hname = find_hostname(fromp, hostokp);

	port = ntohs(fromp->sin_port);
	if (fromp->sin_family != AF_INET) {
	    syslog(LOG_NOTICE, "Illegal Connection");
	    fatal(f, "Illegal Connection", 0);
	}

#ifdef IP_OPTIONS
	{
	    u_char optbuf[BUFSIZ/3], *cp;
	    char lbuf[BUFSIZ];
	    int lboff;
	    socklen_t optsize = sizeof(optbuf);
	    int ipproto;
	    struct protoent *ip;

	    if ((ip = getprotobyname("ip")) != NULL)
		    ipproto = ip->p_proto;
	    else
		    ipproto = IPPROTO_IP;
	    if (getsockopt(0, ipproto, IP_OPTIONS, (char *)optbuf,
		&optsize) == 0 && optsize != 0) {
		    lboff=0;
		    for (cp = optbuf; optsize > 0; cp++, optsize--, lboff += 3)
			    snprintf(lbuf+lboff, sizeof(lbuf)-lboff, 
				     " %2.2x", *cp);
		    syslog(LOG_NOTICE,
			"Connection received using IP options (ignored):%s",
			lbuf);
		    if (setsockopt(0, ipproto, IP_OPTIONS,
				   NULL, optsize) != 0) {
			    syslog(LOG_ERR, "setsockopt IP_OPTIONS NULL: %m");
                            fatal(STDERR_FILENO, "Internal System Error", 0);
		    }
	    }
	}
#endif

	return hname;
}

void network_confirm(void) {
    assert(confirmed>=0);

    if (confirmed == 0) {		/* do_mrlogin may do this */
	write(netf, "", 1);
	confirmed = 1;		/* we sent the null! */
    }
}

void network_anticonfirm(void) {
    char x='\01';		/* error indicator */

    assert(confirmed>=0);

    if (!confirmed) {
	write(netf, &x, 1);
	/* 
	 * Still not confirmed, but we shouldn't ever get here again
	 * as we should be in the process of crashing.
	 */
	confirmed = -1;
    }
}

void network_close(void) {
    shutdown(netf, 2);
}
