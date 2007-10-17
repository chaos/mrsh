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

/*
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
 * From: @(#)mrcp.c	5.32 (Berkeley) 2/25/91
 */
char rcsid[] = "$Id$";
#include "version.h"

#if HAVE_CONFIG_H
#include "config.h"
#endif

/*
 * mrcp
 */
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "pathnames.h"
#include "mcmd.h"

#define	OPTIONS "dfprtV"

struct passwd *pwd;
u_short	port;
uid_t	userid;
int errs, rem;
int pflag, iamremote, iamrecursive, targetshouldbedirectory;
static char **saved_environ;

#define	CMDNEEDS	64
char cmd[CMDNEEDS];		/* must hold "mrcp -r -p -d\0" */

typedef struct _buf {
	int	cnt;
	char	*buf;
} BUF;

static void lostconn(int);
static char *colon(char *);
static int response(void);
static void verifydir(const char *cp);
static int okname(const char *cp0);
static int susystem(const char *s);
static void source(int argc, char *argv[]);
static void rsource(char *name, struct stat *statp);
static void sink(int argc, char *argv[]);
static BUF *allocbuf(BUF *bp, int fd, int blksize);
static void nospace(void);
static void usage(void);
static void toremote(const char *targ, int argc, char *argv[]);
static void tolocal(int argc, char *argv[]);
static void error(const char *fmt, ...);

int
main(int argc, char *argv[])
{
	struct servent *sp;
	int ch, fflag, tflag;
	char *targ;
	const char *shell;
	char *null = NULL;

	saved_environ = __environ;
	__environ = &null;

	fflag = tflag = 0;
	while ((ch = getopt(argc, argv, OPTIONS)) != EOF)
		switch(ch) {
		/* user-visible flags */
		case 'p':			/* preserve access/mod times */
			++pflag;
			break;
		case 'r':
			++iamrecursive;
			break;
		/* mrshd-invoked options (server) */
		case 'd':
			targetshouldbedirectory = 1;
			break;
		case 'f':			/* "from" */
			iamremote = 1;
			fflag = 1;
			break;
		case 't':			/* "to" */
			iamremote = 1;
			tflag = 1;
			break;
		case 'V':
			printf("%s %s-%s\n", PACKAGE, VERSION, RELEASE);
			printf("Protocol Level = %s\n", MRSH_PROTOCOL_VERSION);
			exit(0);

		case '?':
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	sp = getservbyname(shell = "mshell", "tcp");
	if (sp == NULL) {
		(void)fprintf(stderr, "mrcp: %s/tcp: unknown service\n", shell);
		exit(1);
	}
	port = sp->s_port;

	if (!(pwd = getpwuid(userid = getuid()))) {
		(void)fprintf(stderr, "mrcp: unknown user %d.\n", (int)userid);
		exit(1);
	}

	if (fflag) {
		/* follow "protocol", send data */
		(void)response();
		if (setuid(userid)) {
			fprintf(stderr, "mrcp: setuid: %s\n", strerror(errno));
			exit(1);
		}
		source(argc, argv);
		exit(errs);
	}

	if (tflag) {
		/* receive data */
		if (setuid(userid)) {
			fprintf(stderr, "mrcp: setuid: %s\n", strerror(errno));
			exit(1);
		}
		sink(argc, argv);
		exit(errs);
	}

	if (argc < 2)
		usage();
	if (argc > 2)
		targetshouldbedirectory = 1;

	rem = -1;
	/* command to be executed on remote system using "mrsh" */
	(void)snprintf(cmd, sizeof(cmd), "mrcp%s%s%s",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(void)signal(SIGPIPE, lostconn);

	if ((targ = colon(argv[argc - 1]))!=NULL) {
		/* destination is remote host */
		*targ++ = 0;
		toremote(targ, argc, argv);
	}
	else {
		tolocal(argc, argv);		/* destination is local host */
		if (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
	}
	exit(errs);
}

static void
toremote(const char *targ, int argc, char *argv[])
{
	int i, len, tos;
	char *bp, *host, *src, *suser, *thost, *tuser;

	if (*targ == 0)
		targ = ".";

	if ((thost = strchr(argv[argc - 1], '@'))!=NULL) {
		/* user@host */
		*thost++ = 0;
		tuser = argv[argc - 1];
		if (*tuser == '\0')
			tuser = NULL;
		else if (!okname(tuser))
			exit(1);
	} else {
		thost = argv[argc - 1];
		tuser = NULL;
	}

	for (i = 0; i < argc - 1; i++) {
		src = colon(argv[i]);
		if (src) {			/* remote to remote */
			static char dot[] = ".";
			*src++ = 0;
			if (*src == 0)
				src = dot;
			host = strchr(argv[i], '@');
			len = strlen(_PATH_MRSH) + strlen(argv[i]) +
			    strlen(src) + (tuser ? strlen(tuser) : 0) +
			    strlen(thost) + strlen(targ) + CMDNEEDS + 20;
			if (!(bp = malloc(len)))
				nospace();
			if (host) {
				*host++ = 0;
				suser = argv[i];
				if (*suser == '\0')
					suser = pwd->pw_name;
				else if (!okname(suser))
					continue;
				(void)snprintf(bp, len,
				    "%s %s -l %s -n %s %s '%s%s%s:%s'",
				    _PATH_MRSH, host, suser, cmd, src,
				    tuser ? tuser : "", tuser ? "@" : "",
				    thost, targ);
			} else
				(void)snprintf(bp, len,
				    "%s %s -n %s %s '%s%s%s:%s'",
				    _PATH_MRSH, argv[i], cmd, src,
				    tuser ? tuser : "", tuser ? "@" : "",
				    thost, targ);
			(void)susystem(bp);
			(void)free(bp);
		} else {			/* local to remote */
			if (rem == -1) {
				len = strlen(targ) + CMDNEEDS + 20;
				if (!(bp = malloc(len)))
					nospace();
				(void)snprintf(bp, len, "%s -t %s", cmd, targ);
				host = thost;
					rem = mcmd(&host, port, 
					    tuser ? tuser : pwd->pw_name,
					    bp, 0);
				if (rem < 0)
					exit(1);
#ifdef IP_TOS
				tos = IPTOS_THROUGHPUT;
				if (setsockopt(rem, IPPROTO_IP, IP_TOS,
				    (char *)&tos, sizeof(int)) < 0)
					perror("mrcp: setsockopt TOS (ignored)");
#endif
				if (response() < 0)
					exit(1);
				(void)free(bp);
				if (setuid(userid)) {
					fprintf(stderr, "mrcp: setuid: %s\n",
						strerror(errno));
				}
			}
			source(1, argv+i);
		}
	}
}

static void
tolocal(int argc, char *argv[])
{
 	static char dot[] = ".";
	int i, len, tos;
	char *bp, *host, *src, *suser;

	for (i = 0; i < argc - 1; i++) {
		if (!(src = colon(argv[i]))) {	/* local to local */
			len = strlen(_PATH_CP) + strlen(argv[i]) +
			    strlen(argv[argc - 1]) + 20;
			if (!(bp = malloc(len)))
				nospace();
			(void)snprintf(bp, len, "%s%s%s %s %s", _PATH_CP,
			    iamrecursive ? " -r" : "", pflag ? " -p" : "",
			    argv[i], argv[argc - 1]);
			(void)susystem(bp);
			(void)free(bp);
			continue;
		}
		*src++ = 0;
		if (*src == 0)
			src = dot;
		host = strchr(argv[i], '@');
		if (host) {
			*host++ = 0;
			suser = argv[i];
			if (*suser == '\0')
				suser = pwd->pw_name;
			else if (!okname(suser))
				continue;
		} else {
			host = argv[i];
			suser = pwd->pw_name;
		}
		len = strlen(src) + CMDNEEDS + 20;
		if (!(bp = malloc(len)))
			nospace();
		(void)snprintf(bp, len, "%s -f %s", cmd, src);
			rem = mcmd(&host, port, suser, bp, 0);
		(void)free(bp);
		if (rem < 0) {
			++errs;
			continue;
		}
		(void)seteuid(userid);
#ifdef IP_TOS
		tos = IPTOS_THROUGHPUT;
		if (setsockopt(rem, IPPROTO_IP, IP_TOS,
		    (char *)&tos, sizeof(int)) < 0)
			perror("mrcp: setsockopt TOS (ignored)");
#endif
		sink(1, argv + argc - 1);
		(void)seteuid(0);
		(void)close(rem);
		rem = -1;
	}
}

static void
verifydir(const char *cp)
{
	struct stat stb;

	if (stat(cp, &stb) >= 0) {
		if ((stb.st_mode & S_IFMT) == S_IFDIR)
			return;
		errno = ENOTDIR;
	}
	error("mrcp: %s: %s.\n", cp, strerror(errno));
	exit(1);
}

static char *
colon(char *cp)
{
	for (; *cp; ++cp) {
		if (*cp == ':')
			return(cp);
		if (*cp == '/')
			return NULL;
	}
	return NULL;
}

static int
okname(const char *cp0)
{
	const char *cp = cp0;
	int c;

	do {
		c = *cp;
		if (c & 0200)
			goto bad;
		if (!isalpha(c) && !isdigit(c) && c != '_' && c != '-')
			goto bad;
	} while (*++cp);
	return(1);
bad:
	(void)fprintf(stderr, "mrcp: invalid user name %s\n", cp0);
	return 0;
}

typedef void (*sighandler)(int);

static int
susystem(const char *s)
{
	int status, pid, w;
	sighandler istat, qstat;

	if ((pid = vfork()) == 0) {
		const char *args[4];
		const char **argsfoo;
		char **argsbar;
		if (setuid(userid)) {
			fprintf(stderr, "mrcp: child: setuid: %s\n", 
				strerror(errno));
			_exit(1);
		}
		args[0] = "sh";
		args[1] = "-c";
		args[2] = s;
		args[3] = NULL;
		/* Defeat C type system to permit passing char ** to execve */
		argsfoo = args;
		memcpy(&argsbar, &argsfoo, sizeof(argsfoo));
		execve(_PATH_BSHELL, argsbar, saved_environ);
		_exit(127);
	}
	istat = signal(SIGINT, SIG_IGN);
	qstat = signal(SIGQUIT, SIG_IGN);
	while ((w = wait(&status)) != pid && w != -1)
		;
	if (w == -1)
		status = -1;
	(void)signal(SIGINT, istat);
	(void)signal(SIGQUIT, qstat);
	return(status);
}

static void
source(int argc, char *argv[])
{
	struct stat stb;
	static BUF buffer;
	BUF *bp;
	off_t i;
	int x, readerr, f, amt;
	char *last, *name, buf[BUFSIZ];

	for (x = 0; x < argc; x++) {
		name = argv[x];
		if ((f = open(name, O_RDONLY, 0)) < 0) {
			error("mrcp: %s: %s\n", name, strerror(errno));
			continue;
		}
		if (fstat(f, &stb) < 0)
			goto notreg;
		switch (stb.st_mode&S_IFMT) {

		case S_IFREG:
			break;

		case S_IFDIR:
			if (iamrecursive) {
				(void)close(f);
				rsource(name, &stb);
				continue;
			}
			/* FALLTHROUGH */
		default:
notreg:			(void)close(f);
			error("mrcp: %s: not a plain file\n", name);
			continue;
		}
		last = strrchr(name, '/');
		if (last == 0)
			last = name;
		else
			last++;
		if (pflag) {
			/*
			 * Make it compatible with possible future
			 * versions expecting microseconds.
			 */
			(void)snprintf(buf, sizeof(buf),
			    "T%ld 0 %ld 0\n", stb.st_mtime, stb.st_atime);
			(void)write(rem, buf, (int)strlen(buf));
			if (response() < 0) {
				(void)close(f);
				continue;
			}
		}
		if (sizeof(stb.st_size) > sizeof(long))
			(void)snprintf(buf, sizeof(buf),
		    		"C%04o %lld %s\n", 
				stb.st_mode&07777, stb.st_size, last);
		else
			(void)snprintf(buf, sizeof(buf),
		    		"C%04o %ld %s\n", 
				stb.st_mode&07777, stb.st_size, last);
		(void)write(rem, buf, (int)strlen(buf));
		if (response() < 0) {
			(void)close(f);
			continue;
		}
		if ((bp = allocbuf(&buffer, f, BUFSIZ)) == 0) {
			(void)close(f);
			continue;
		}
		readerr = 0;
		for (i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			if (i + amt > stb.st_size)
				amt = stb.st_size - i;
			if (readerr == 0 && read(f, bp->buf, amt) != amt)
				readerr = errno;
			(void)write(rem, bp->buf, amt);
		}
		(void)close(f);
		if (readerr == 0)
			(void)write(rem, "", 1);
		else
			error("mrcp: %s: %s\n", name, strerror(readerr));
		(void)response();
	}
}

static void
rsource(char *name, struct stat *statp)
{
	DIR *dirp;
	struct dirent *dp;
	char *last, *vect[1], path[MAXPATHLEN];

	if (!(dirp = opendir(name))) {
		error("mrcp: %s: %s\n", name, strerror(errno));
		return;
	}
	last = strrchr(name, '/');
	if (last == 0)
		last = name;
	else
		last++;
	if (pflag) {
		(void)snprintf(path, sizeof(path),
		    "T%ld 0 %ld 0\n", statp->st_mtime, statp->st_atime);
		(void)write(rem, path, (int)strlen(path));
		if (response() < 0) {
			closedir(dirp);
			return;
		}
	}
	(void)snprintf(path, sizeof(path),
	    "D%04o %d %s\n", statp->st_mode&07777, 0, last);
	(void)write(rem, path, (int)strlen(path));
	if (response() < 0) {
		closedir(dirp);
		return;
	}
	while ((dp = readdir(dirp))!=NULL) {
		if (dp->d_ino == 0)
			continue;
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;
		if (strlen(name) + 1 + strlen(dp->d_name) >= MAXPATHLEN - 1) {
			error("%s/%s: name too long.\n", name, dp->d_name);
			continue;
		}
		(void)snprintf(path, sizeof(path), "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	closedir(dirp);
	(void)write(rem, "E\n", 2);
	(void)response();
}

static int
response(void)
{
	register char *cp;
	char ch, resp, rbuf[BUFSIZ];

	if (read(rem, &resp, sizeof(resp)) != sizeof(resp))
		lostconn(0);

	cp = rbuf;
	switch(resp) {
	  case 0:			/* ok */
		return 0;
	  default:
		*cp++ = resp;
		/* FALLTHROUGH */
	  case 1:			/* error, followed by err msg */
	  case 2:			/* fatal error, "" */
		do {
			if (read(rem, &ch, sizeof(ch)) != sizeof(ch))
				lostconn(0);
			*cp++ = ch;
		} while (cp < &rbuf[BUFSIZ] && ch != '\n');

		if (!iamremote)
			write(2, rbuf, cp - rbuf);
		++errs;
		if (resp == 1)
			return -1;
		exit(1);
	}
	/*NOTREACHED*/
	return 0;
}

static void
lostconn(int ignore)
{
	(void)ignore;

	if (!iamremote)
		(void)fprintf(stderr, "mrcp: lost connection\n");
	exit(1);
}

static void
sink(int argc, char *argv[])
{
	register char *cp;
	static BUF buffer;
	struct stat stb;
	struct timeval tv[2];
	enum { YES, NO, DISPLAYED } wrerr;
	BUF *bp;
	off_t i, j, size;
	char ch, *targ;
	const char *why;
	int amt, count, exists, first, mask, mode;
	int ofd, setimes, targisdir, cursize = 0;
	char *np, *vect[1], buf[BUFSIZ], *namebuf = NULL;

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; goto screwup; }

	setimes = targisdir = 0;
	mask = umask(0);
	if (!pflag)
		(void)umask(mask);
	if (argc != 1) {
		error("mrcp: ambiguous target\n");
		exit(1);
	}
	targ = *argv;
	if (targetshouldbedirectory)
		verifydir(targ);
	(void)write(rem, "", 1);
	if (stat(targ, &stb) == 0 && (stb.st_mode & S_IFMT) == S_IFDIR)
		targisdir = 1;
	for (first = 1;; first = 0) {
		cp = buf;
		if (read(rem, cp, 1) <= 0) {
			if (namebuf)
				free(namebuf);
			return;
		}

		if (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		do {
			if (read(rem, &ch, sizeof(ch)) != sizeof(ch))
				SCREWUP("lost connection");
			*cp++ = ch;
		} while (cp < &buf[BUFSIZ - 1] && ch != '\n');
		*cp = 0;

		if (buf[0] == '\01' || buf[0] == '\02') {
			if (iamremote == 0)
				(void)write(2, buf + 1, (int)strlen(buf + 1));
			if (buf[0] == '\02')
				exit(1);
			errs++;
			continue;
		}
		if (buf[0] == 'E') {
			if (namebuf)
				free(namebuf);
			(void)write(rem, "", 1);
			return;
		}

		if (ch == '\n')
			*--cp = 0;

#define getnum(t) (t) = 0; while (isdigit(*cp)) (t) = (t) * 10 + (*cp++ - '0');
		cp = buf;
		if (*cp == 'T') {
			setimes++;
			cp++;
			getnum(mtime.tv_sec);
			if (*cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			getnum(mtime.tv_usec);
			if (*cp++ != ' ')
				SCREWUP("mtime.usec not delimited");
			getnum(atime.tv_sec);
			if (*cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			getnum(atime.tv_usec);
			if (*cp++ != '\0')
				SCREWUP("atime.usec not delimited");
			(void)write(rem, "", 1);
			continue;
		}
		if (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "mrcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the mrcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			if (first) {
				error("%s\n", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		for (++cp; cp < buf + 5; cp++) {
			if (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		if (*cp++ != ' ')
			SCREWUP("mode not delimited");
		size = 0;
		while (isdigit(*cp))
			size = size * 10 + (*cp++ - '0');
		if (*cp++ != ' ')
			SCREWUP("size not delimited");
		if (targisdir) {
			int need;

			/* achu: Original rcp code had mem-leak here */
			need = strlen(targ) + strlen(cp) + 250;
			if (need > cursize) {
				if (namebuf)
					free(namebuf);
				if (!(namebuf = malloc(need))) {
					error("out of memory\n");
					exit(1);
				}
				cursize = need;
			}
			(void)snprintf(namebuf, need, "%s%s%s", targ,
			    *targ ? "/" : "", cp);
			np = namebuf;
		}
		else
			np = targ;
		exists = stat(np, &stb) == 0;
		if (buf[0] == 'D') {
			if (exists) {
				if ((stb.st_mode&S_IFMT) != S_IFDIR) {
					errno = ENOTDIR;
					goto bad;
				}
				if (pflag)
					(void)chmod(np, mode);
			} else if (mkdir(np, mode) < 0)
				goto bad;
			vect[0] = np;
			sink(1, vect);
			if (setimes) {
				setimes = 0;
				if (utimes(np, tv) < 0)
				    error("mrcp: can't set times on %s: %s\n",
					np, strerror(errno));
			}
			continue;
		}
		if ((ofd = open(np, O_WRONLY|O_CREAT, mode)) < 0) {
bad:			error("mrcp: %s: %s\n", np, strerror(errno));
			continue;
		}
		if (exists && pflag)
			(void)fchmod(ofd, mode);
		(void)write(rem, "", 1);
		if ((bp = allocbuf(&buffer, ofd, BUFSIZ)) == 0) {
			(void)close(ofd);
			continue;
		}
		cp = bp->buf;
		count = 0;
		wrerr = NO;
		for (i = 0; i < size; i += BUFSIZ) {
			amt = BUFSIZ;
			if (i + amt > size)
				amt = size - i;
			count += amt;
			do {
				j = read(rem, cp, amt);
				if (j <= 0) {
					error("mrcp: %s\n",
					    j ? strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} while (amt > 0);
			if (count == bp->cnt) {
				if (wrerr == NO &&
				    write(ofd, bp->buf, count) != count)
					wrerr = YES;
				count = 0;
				cp = bp->buf;
			}
		}
		if (count != 0 && wrerr == NO &&
		    write(ofd, bp->buf, count) != count)
			wrerr = YES;
		if (ftruncate(ofd, size)) {
			error("mrcp: can't truncate %s: %s\n", np,
			    strerror(errno));
			wrerr = DISPLAYED;
		}
		(void)close(ofd);
		(void)response();
		if (setimes && wrerr == NO) {
			setimes = 0;
			if (utimes(np, tv) < 0) {
				error("mrcp: can't set times on %s: %s\n",
				    np, strerror(errno));
				wrerr = DISPLAYED;
			}
		}
		switch(wrerr) {
		case YES:
			error("mrcp: %s: %s\n", np, strerror(errno));
			break;
		case NO:
			(void)write(rem, "", 1);
			break;
		case DISPLAYED:
			break;
		}
	}
screwup:
	error("mrcp: protocol screwup: %s\n", why);
	exit(1);
}

static BUF *
allocbuf(BUF *bp, int fd, int blksize)
{
	struct stat stb;
	int size;

	if (fstat(fd, &stb) < 0) {
		error("mrcp: fstat: %s\n", strerror(errno));
		return(0);
	}
	size = roundup(stb.st_blksize, blksize);
	if (size == 0)
		size = blksize;
	if (bp->cnt < size) {
		if (bp->buf != 0)
			free(bp->buf);
		bp->buf = malloc(size);
		if (!bp->buf) {
			error("mrcp: malloc: out of memory\n");
			return NULL;
		}
	}
	bp->cnt = size;
	return(bp);
}

void
error(const char *fmt, ...)
{
	static FILE *fp;
	va_list ap;
        va_list apcpy;

	va_start(ap, fmt);

	++errs;
	if (!fp && !(fp = fdopen(rem, "w")))
		return;
	fprintf(fp, "%c", 0x01);
        
        va_copy(apcpy, ap);
	vfprintf(fp, fmt, apcpy);
	fflush(fp);
	if (!iamremote)	{
                va_copy(apcpy, ap);
                vfprintf(stderr, fmt, ap);
                va_end(apcpy);
        }

	va_end(ap);
}

static void 
nospace(void)
{
	(void)fprintf(stderr, "mrcp: out of memory.\n");
	exit(1);
}

static void
usage(void)
{
	(void)fprintf(stderr,
	    "usage: mrcp [-p] f1 f2; or: mrcp [-rp] f1 ... fn directory\n");
	exit(1);
}
