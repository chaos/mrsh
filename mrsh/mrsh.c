/*****************************************************************************\
 *  $Id$
 *****************************************************************************
 *  Copyright (C) 2003 The Regents of the University of California.
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
 *  with Mrsh; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA.
\*****************************************************************************/

/*-
 * Copyright (c) 1983, 1990 The Regents of the University of California.
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

char copyright[] =
 "@(#) Copyright (c) 1983, 1990 The Regents of the University of California.\n"
 "All rights reserved.\n";

/*
 * From: @(#)mrsh.c	5.24 (Berkeley) 7/1/91
 */
char rcsid[] = "$Id$";
#include "version.h"

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <netdb.h>

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "pathnames.h"
#include "mcmd.h"

/*
 * mrsh - remote shell
 */
static int rfd2;
static char *copyargs(char **);
static void sendsig(int);
static void talk(int nflag, long omask, int pid, int rem);
static void usage(void);

int
main(int argc, char *argv[])
{
	struct passwd *pw;
	struct servent *sp;
	long omask;
	int argoff, asmrsh, ch, dflag, nflag, one, pid=0, rem, uid;
	char *p;
	char *args, *host, *user;
	char *null = NULL;
	char **saved_environ;

	saved_environ = __environ;
	__environ = &null;

	argoff = asmrsh = dflag = nflag = 0;
	one = 1;
	host = user = NULL;

	/* if called as something other than "mrsh", use it as the host name */
	p = strrchr(argv[0], '/');
	if (p) p++;
	else p = argv[0];

	if (!strcmp(p, "mrsh") || !strcmp(p, "rsh")) asmrsh = 1;
	else host = p;

	/* handle "mrsh host flags" */
	if (!host && argc > 2 && argv[1][0] != '-') {
		host = argv[1];
		argoff = 1;
	}

#define	OPTIONS	"+8KLdel:nwV"
	while ((ch = getopt(argc - argoff, argv + argoff, OPTIONS)) != EOF)
		switch(ch) {
		case 'K':
			break;
		case 'L':	/* -8Lew are ignored to allow mrlogin aliases */
		case 'e':
		case 'w':
		case '8':
			break;
		case 'd':
			dflag = 1;
			break;
		case 'l':
			user = optarg;
			break;
		case 'n':
			nflag = 1;
			break;
		case 'V':
			printf("%s %s-%s\n", PACKAGE, VERSION, RELEASE);
			printf("Protocol Level = %s\n", MRSH_PROTOCOL_VERSION);
			exit(0);
		case '?':
		default:
			usage();
		}
	optind += argoff;

	/* if haven't gotten a host yet, do so */
	if (!host && !(host = argv[optind++]))
		usage();

	/* if no further arguments, must have been called as mrlogin. */
	if (!argv[optind]) {
		if (setuid(getuid())) {
			fprintf(stderr, "mrsh: setuid: %s\n", strerror(errno));
			exit(1);
		}
		if (asmrsh) argv[0] = (char *)"mrlogin";
		execve(_PATH_MRLOGIN, argv, saved_environ);
		fprintf(stderr, "mrsh: can't exec %s.\n", _PATH_MRLOGIN);
		exit(1);
	}

	argc -= optind;
	argv += optind;

	if (!(pw = getpwuid(uid = getuid()))) {
		fprintf(stderr, "mrsh: unknown user id.\n");
		exit(1);
	}
	if (!user)
		user = pw->pw_name;


	args = copyargs(argv);

	sp = NULL;
	if (sp == NULL)
		sp = getservbyname("mshell", "tcp");
	if (sp == NULL) {
		fprintf(stderr, "mrsh: mshell/tcp: unknown service.\n");
		exit(1);
	}

	rem = mcmd(&host, sp->s_port, user, args, &rfd2);

	if (rem < 0)
		exit(1);

	if (rfd2 < 0) {
		fprintf(stderr, "mrsh: can't establish stderr.\n");
		exit(1);
	}

	if (setuid(uid)) {
		fprintf(stderr, "mrsh: setuid: %s\n", strerror(errno));
		exit(1);
	}

	if (dflag) {
		if (setsockopt(rem, SOL_SOCKET, SO_DEBUG, &one,
		    sizeof(one)) < 0)
			fprintf(stderr, "mrsh: setsockopt: %s.\n",
			    strerror(errno));
		if (setsockopt(rfd2, SOL_SOCKET, SO_DEBUG, &one,
		    sizeof(one)) < 0)
			fprintf(stderr, "mrsh: setsockopt: %s.\n",
			    strerror(errno));
	}

        /* set SO_KEEPALIVE to prevent mrsh from hanging indefinitely */
        if (setsockopt(rem, SOL_SOCKET, SO_KEEPALIVE, &one, 
            sizeof(one)) < 0)
                fprintf(stderr, "mrsh: setsockopt: %s.\n",
                    strerror(errno));

        if (setsockopt(rfd2, SOL_SOCKET, SO_KEEPALIVE, &one, 
            sizeof(one)) < 0)
                fprintf(stderr, "mrsh: setsockopt: %s.\n",
                    strerror(errno));
        
	omask = sigblock(sigmask(SIGINT)|sigmask(SIGQUIT)|sigmask(SIGTERM));
	if (signal(SIGINT, SIG_IGN) != SIG_IGN)
		signal(SIGINT, sendsig);
	if (signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		signal(SIGQUIT, sendsig);
	if (signal(SIGTERM, SIG_IGN) != SIG_IGN)
		signal(SIGTERM, sendsig);

	if (!nflag) {
		pid = fork();
		if (pid < 0) {
			fprintf(stderr,
			    "mrsh: fork: %s.\n", strerror(errno));
			exit(1);
		}
	}

	{
		ioctl(rfd2, FIONBIO, &one);
		ioctl(rem, FIONBIO, &one);
	}

	talk(nflag, omask, pid, rem);

	if (!nflag)
		kill(pid, SIGKILL);
	exit(0);
}

static void
talk(int nflag, long omask, int pid, int rem)
{
	register int cc, wc;
	register char *bp;
	fd_set readfrom, rembits;
	int rfd2_ok, rem_ok;
	char buf[BUFSIZ];

	FD_ZERO(&rembits);

	if (!nflag && pid == 0) {
		close(rfd2);

reread:		errno = 0;
		if ((cc = read(0, buf, sizeof buf)) <= 0)
			goto done;
		bp = buf;

rewrite:	FD_ZERO(&rembits);
		FD_SET(rem, &rembits);
		if (select(rem+1, 0, &rembits, 0, 0) < 0) {
			if (errno != EINTR) {
				fprintf(stderr,
				    "mrsh: select: %s.\n", strerror(errno));
				exit(1);
			}
			goto rewrite;
		}
		if (! FD_ISSET(rem, &rembits))
			goto rewrite;
			wc = write(rem, bp, cc);
		if (wc < 0) {
			if (errno == EWOULDBLOCK)
				goto rewrite;
			goto done;
		}
		bp += wc;
		cc -= wc;
		if (cc == 0)
			goto reread;
		goto rewrite;
done:
		shutdown(rem, 1);
		exit(0);
	}

	rfd2_ok = rem_ok = 1;
	sigsetmask(omask);
	while (rfd2_ok || rem_ok) {
		FD_ZERO(&readfrom);
		if (rfd2_ok)
			FD_SET(rfd2, &readfrom);
		if (rem_ok)
			FD_SET(rem, &readfrom);
		if (select(rfd2 > rem ? rfd2+1 : rem+1, 
			   &readfrom, 0, 0, 0) < 0) {
			if (errno != EINTR) {
				fprintf(stderr,
				    "mrsh: select: %s.\n", strerror(errno));
				exit(1);
			}
			continue;
		}
		if (FD_ISSET(rfd2, &readfrom)) {
			errno = 0;
				cc = read(rfd2, buf, sizeof buf);
			if (cc > 0)
				write(2, buf, cc);
			else if (cc == 0 || errno != EWOULDBLOCK)
				rfd2_ok = 0;
		}
		if (FD_ISSET(rem, &readfrom)) {
			errno = 0;
				cc = read(rem, buf, sizeof buf);
			if (cc > 0)
				write(1, buf, cc);
			else if (cc == 0 || errno != EWOULDBLOCK)
				rem_ok = 0;
		}
	}
}

void
sendsig(int signo)
{
	char x = (char) signo;
		write(rfd2, &x, 1);
}

char *
copyargs(char **argv)
{
	int cc;
	char **ap, *p;
	char *args;

	cc = 0;
	for (ap = argv; *ap; ++ap)
		cc += strlen(*ap) + 1;
	args = malloc(cc);
	if (!args) {
		fprintf(stderr, "mrsh: %s.\n", strerror(ENOMEM));
		exit(1);
	}
	for (p = args, ap = argv; *ap; ++ap) {
		/*strcpy(p, *ap);*/
		for (p = strcpy(p, *ap); *p; ++p);
		if (ap[1])
			*p++ = ' ';
	}
	return(args);
}

void
usage(void)
{
	fprintf(stderr,
	    "usage: mrsh [-nd%s]%s[-l login] host [command]\n",
	    "", " ");
	exit(1);
}
