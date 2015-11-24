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
 * Copyright (c) 1988, 1989 The Regents of the University of California.
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

/*
 * PAM modifications by Michael K. Johnson <johnsonm@redhat.com>
 */

char copyright[] =
 "@(#) Copyright (c) 1988, 1989 The Regents of the University of California.\n"
 "All rights reserved.\n";

/*
 * From: @(#)mrshd.c	5.38 (Berkeley) 3/2/91
 */
char rcsid[] = 
  "$Id$";
#include "version.h"

#if HAVE_CONFIG_H
#include "config.h"
#endif

/*
 * remote shell server:
 *	[port]\0
 *	remuser\0
 *	locuser\0
 *	command\0
 *	data
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <resolv.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>  /* for vsnprintf */
#include <stdlib.h>
#include <string.h>
#include <paths.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>

#include "fd.h"
#include "mauth.h"

#if defined(__GLIBC__) && (__GLIBC__ >= 2)
#define _check_rhosts_file  __check_rhosts_file
#endif

#ifdef USE_PAM
#include <security/pam_appl.h>
#include <security/pam_misc.h>
static pam_handle_t *pamh;

#include "list.h"
extern char *last_pam_msg;
extern int mrsh_conv(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *appdata_ptr);
#endif /* USE_PAM */

#define	OPTIONS	"ahlLnM:V"

static int keepalive = 1;
static int check_all = 0;
static int paranoid = 0;
static int sent_null;
static int allow_root_rhosts=1;
static char *munge_socket = NULL;

char	username[20] = "USER=";
char	homedir[64] = "HOME=";
char	shell[64] = "SHELL=";
char	path[256] = "PATH=";
char	*envinit[] =
	    {homedir, shell, path, username, 0};
extern	char	**environ;

static void error(const char *fmt, ...);
static void doit(struct sockaddr_in *fromp);

#define ERRMSGLEN           4096
static char errmsgbuf[ERRMSGLEN];
static const char *errmsg = NULL;
static struct mauth ma;

extern int _check_rhosts_file;

/*
 * Report error to client.
 * Note: can't be used until second socket has connected
 * to client, or older clients will hang waiting
 * for that connection first.
 */
static void
error(const char *fmt, ...) {
    va_list ap;
    char buf[BUFSIZ], *bp = buf;
    
    if (sent_null == 0)	*bp++ = 1;
    va_start(ap, fmt);
    vsnprintf(bp, sizeof(buf)-1, fmt, ap);
    va_end(ap);
    write(2, buf, strlen(buf));
}

static void fail(const char *errorstr, 
		 const char *remuser, const char *hostname, 
		 const char *locuser,
		 const char *cmdbuf) 
{
	/* log the (failed) mrsh request */
	syslog(LOG_INFO|LOG_AUTH, "mrsh denied to %s@%s as %s: %s",
	       remuser, hostname, locuser, errorstr);
	if (paranoid) {
	    syslog(LOG_INFO|LOG_AUTH, "mrsh command was '%s'", cmdbuf);
	}
	memset(errmsgbuf, '\0', ERRMSGLEN);
	sprintf(errmsgbuf, errorstr, hostname);
	errmsg = errmsgbuf;
}

static int getint(void) {
    int port = 0;
    char c;
    do {
	if (read(0, &c, 1) != 1) exit(1);
	if (isascii(c) && isdigit(c)) port = port*10 + c-'0';
    } while (c != 0);
    return port;
}

static void stderr_parent(int sock, int pype, int pid) {
    fd_set ready, readfrom;
    char buf[BUFSIZ], sig;
    int one = 1;
    int nfd, cc, guys=2;
    
    ioctl(pype, FIONBIO, (char *)&one);
    /* should set s nbio! */
    
    FD_ZERO(&readfrom);
    FD_SET(sock, &readfrom);
    FD_SET(pype, &readfrom);
    if (pype > sock) nfd = pype+1;
    else nfd = sock+1;
    
    while (guys > 0) {
	ready = readfrom;
	if (select(nfd, &ready, NULL, NULL, NULL) < 0) {
	   if (errno != EINTR) {
	      break;
	   }
	   continue;
	}
	if (FD_ISSET(sock, &ready)) {
	    cc = read(sock, &sig, 1);
	    if (cc <= 0) {
	       FD_CLR(sock, &readfrom);
	       guys--;
	    }
	    else killpg(pid, sig);
	}
	if (FD_ISSET(pype, &ready)) {
	    cc = read(pype, buf, sizeof(buf));
	    if (cc <= 0) {
		shutdown(sock, 2);
		FD_CLR(pype, &readfrom);
		guys--;
	    } 
	    else write(sock, buf, cc);
	}
    }
    
#ifdef USE_PAM
    /*
     * This does not strike me as the right place for this; this is
     * in a child process... what does this need to accomplish?
     *
     * No, it's not the child process, the code is just confusing.
     */
    pam_close_session(pamh, 0);
    pam_end(pamh, PAM_SUCCESS);
#endif
    exit(0);
}

static struct passwd *doauth(const char *remuser, 
			     const char *hostname, 
			     const char *locuser,
                             const char *cmdbuf)
{
#ifdef USE_PAM
    static struct pam_conv conv;
    int retcode;
    List pam_msgs = NULL;
#endif
    struct passwd *pwd = ma.pwd;
    if (pwd == NULL) goto error;
    if (pwd->pw_uid==0) paranoid = 1;

#ifdef USE_PAM
    if ((pam_msgs = list_create((ListDelF)free)) == NULL) {
        syslog(LOG_ERR, "list_create() failed\n");
        errmsg = "Internal System Error";
        return NULL;
    }

    conv.conv = mrsh_conv;
    conv.appdata_ptr = (void *)&pam_msgs;

    retcode = pam_start("mrsh", locuser, &conv, &pamh);
    if (retcode != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_start: %s\n", pam_strerror(pamh, retcode));
        goto error;
    }
    pam_set_item (pamh, PAM_RUSER, remuser);
    pam_set_item (pamh, PAM_RHOST, hostname);
    pam_set_item (pamh, PAM_TTY, "mrsh");
    
    retcode = pam_authenticate(pamh, 0);
    if (retcode == PAM_SUCCESS) {
        last_pam_msg = NULL;
	retcode = pam_acct_mgmt(pamh, 0);
    }
    if (retcode == PAM_SUCCESS) {
	/*
	 * Why do we need to set groups here?
	 * Also, this stuff should be moved down near where the setuid() is.
	 */
        if (setgid(pwd->pw_gid) != 0) {
            pam_end(pamh, PAM_SYSTEM_ERR);
            goto error;
        }
        if (initgroups(locuser, pwd->pw_gid) != 0) {
            pam_end(pamh, PAM_SYSTEM_ERR);
            goto error;
        }
        last_pam_msg = NULL;
        retcode = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    }
    
    if (retcode == PAM_SUCCESS) {
        last_pam_msg = NULL;
        retcode = pam_open_session(pamh,0);
    }
    if (retcode != PAM_SUCCESS) {
        pam_end(pamh, retcode);
        if (last_pam_msg != NULL) {
            /* Dump all pam messages to syslog, Send only the
             * last message to the user
             */
            ListIterator itr = list_iterator_create(pam_msgs);
            char *msg;
            while (msg = (char *)list_next(itr)) 
                syslog(LOG_ERR, "pam_msg: %s\n", msg);
            list_iterator_destroy(itr);
	    memset(errmsgbuf, '\0', ERRMSGLEN);
            snprintf(errmsgbuf, ERRMSGLEN, "%s", last_pam_msg);
            errmsg = errmsgbuf;
            list_destroy(pam_msgs);
            return NULL;
        }
        goto error;
    }
    list_destroy(pam_msgs);
    return pwd;
#else
    if (pwd->pw_uid==0 && !allow_root_rhosts) goto error;
    if (ruserok(hostname, pwd->pw_uid==0, remuser, locuser) < 0) {
	goto error;
    }
    return pwd;
#endif

 error:
#ifdef USE_PAM
    if (pam_msgs)
        list_destroy(pam_msgs);
    syslog(LOG_ERR, "PAM AUthentication Failure\n");
#else
    syslog(LOG_ERR, "Authentication Failure\n");
#endif
    fail("Permission Denied", 
         remuser, hostname, locuser, cmdbuf);
    return NULL;
}

static const char *findhostname(struct sockaddr_in *fromp,
				const char *remuser, const char *locuser,
				const char *cmdbuf) 
{
	struct hostent *hp;
	const char *hostname;

	hp = gethostbyaddr((char *)&fromp->sin_addr, sizeof (struct in_addr),
			   fromp->sin_family);

	errno = ENOMEM; /* malloc (thus strdup) may not set it */
	if (hp) hostname = strdup(hp->h_name);
	else hostname = strdup(inet_ntoa(fromp->sin_addr));

	if (hostname==NULL) {
	    /* out of memory? */
            syslog(LOG_ERR, "Out of Memory\n");
	    errmsg = "Out of Memory";
	    return NULL;
	}

	/*
	 * Attempt to confirm the DNS. 
	 */
#ifdef	RES_DNSRCH
	_res.options &= ~RES_DNSRCH;
#endif
	hp = gethostbyname(hostname);
	if (hp == NULL) {
	    syslog(LOG_INFO, "Couldn't look up address for %s", hostname);
	    fail("Couldn't get address for your host (%s)", 
		 remuser, inet_ntoa(fromp->sin_addr), locuser, cmdbuf);
	    return NULL;
	} 
	while (hp->h_addr_list[0] != NULL) {
	    if (!memcmp(hp->h_addr_list[0], &fromp->sin_addr,
			sizeof(fromp->sin_addr))) {
		return hostname;
	    }
	    hp->h_addr_list++;
	}
	syslog(LOG_NOTICE, "Host addr %s not listed for host %s",
	       inet_ntoa(fromp->sin_addr), hp->h_name);
	fail("Host address mismatch for %s", 
	     remuser, inet_ntoa(fromp->sin_addr), locuser, cmdbuf);
	return NULL;
}

static void
doit(struct sockaddr_in *fromp)
{
	char cmdbuf[ARG_MAX+1];
	const char *theshell, *shellname;
	char locuser[16], remuser[16];
	struct passwd *pwd;
	int sock = -1;
	const char *hostname;
	u_short port;
	int pv[2], pid, ifd;
#ifdef USE_PAM
	char **env;
#endif

	signal(SIGINT, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

	alarm(60);
	port = getint();
	alarm(0);


#if 0
	/* We're running from inetd; socket is already on 0, 1, 2 */
	dup2(f, 0);
	dup2(f, 1);
	dup2(f, 2);
#endif

	if (mauth(&ma, 0, port, munge_socket) < 0) {
                errmsg = ma.errmsg;
		goto error_out;
	}

	strncpy(remuser, &(ma.username[0]), sizeof(remuser));
	remuser[sizeof(remuser)-1] = '\0';
	strcpy(locuser, remuser);
	strncpy(cmdbuf, &(ma.cmd[0]), sizeof(cmdbuf));
	cmdbuf[sizeof(cmdbuf)-1] = '\0';
	if (!strcmp(locuser, "root")) paranoid = 1;

	hostname = findhostname(fromp, remuser, locuser, cmdbuf);
	if (hostname == NULL)
		goto error_out;

	setpwent();

	pwd = doauth(remuser, hostname, locuser, cmdbuf);
	if (pwd == NULL) {
            /* doauth() syslogs and sets errmsg pointer */
            goto error_out;
	}

	if (chdir(pwd->pw_dir) < 0) {
		chdir("/");
		/*
		 * error("No remote directory\n");
		 * exit(1);
		 */
	}

	if (pwd->pw_uid != 0 && !access(_PATH_NOLOGIN, F_OK)) {
                syslog(LOG_ERR, "Logins currently disabled\n");
		errmsg = "Logins currently disabled";
		goto error_out;
	}

error_out:
	/* Set up the socket for the client. */
	sock = 0;
	if (port != 0) {
		int rv;
		char c;

		if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			syslog(LOG_ERR,"create socket: %m");
			exit(1);
		}
		fromp->sin_port = htons(port);
		if (connect(sock, (struct sockaddr *)fromp, sizeof(*fromp)) < 0) {
			syslog(LOG_ERR,"connect second port: %m");
			exit(1);
		}

		/* Sync with client to avoid race condition */
		rv = read(1,&c,1);
		if (rv != 1 || c != '\0') {
			syslog (LOG_ERR, "%s: %m", "mrshd: Client not ready.");
			exit(1);
		}
	}

	if (errmsg != NULL) {
		char buf[BUFSIZ], *bp = buf;
		snprintf(bp, sizeof(buf)-1, "%c%s\n", '\01', errmsg);
		fd_write_n(sock, buf, strlen(buf));
		exit(1);
	}

	/* Send random number back on stderr */
	if (port != 0) {
		unsigned int rand = htonl(ma.rand);
		if (fd_write_n(sock,&rand,sizeof(unsigned int)) < 0) {
			syslog(LOG_ERR,"%s: %m","write to stderr port: ");
			error("Write error, %s\n", strerror(errno));
			exit(1);
		}
	}
					
	(void) write(2, "\0", 1);
	sent_null = 1;

	if (port) {
		if (pipe(pv) < 0) {
			error("Can't make pipe\n");
			exit(1);
		}
		pid = fork();
		if (pid == -1)  {
			error("Can't fork; try again\n");
			exit(1);
		}
		if (pid) {
			close(0); 
			close(1);
			close(2); 
			close(pv[1]);
			stderr_parent(sock, pv[0], pid);
			/* NOTREACHED */
		}
		setpgrp();
		close(sock); 
		close(pv[0]);
		dup2(pv[1], 2);
		close(pv[1]);
	}
	theshell = pwd->pw_shell;
	if (!theshell || !*theshell) {
	    /* shouldn't we deny access? */
	    theshell = _PATH_BSHELL;
	}

#if BSD > 43
	if (setlogin(pwd->pw_name) < 0) {
	    syslog(LOG_ERR, "setlogin() failed: %m");
	}
#endif
#ifndef USE_PAM
	/* if PAM, already done */
	if (setgid(pwd->pw_gid)) {
		syslog(LOG_ERR, "setgid: %m");
		exit(1);
	}
	if (initgroups(pwd->pw_name, pwd->pw_gid)) {
		syslog(LOG_ERR, "initgroups: %m");
		exit(1);
	}
#endif
	if (setuid(pwd->pw_uid)) {
		syslog(LOG_ERR, "setuid: %m");
		exit(1);
	}
	environ = envinit;

	strncat(homedir, pwd->pw_dir, sizeof(homedir)-6);
	homedir[sizeof(homedir)-1] = 0;

	strcat(path, _PATH_DEFPATH);

	strncat(shell, theshell, sizeof(shell)-7);
	shell[sizeof(shell)-1] = 0;

	strncat(username, pwd->pw_name, sizeof(username)-6);
	username[sizeof(username)-1] = 0;

	shellname = strrchr(theshell, '/');
	if (shellname) shellname++;
	else shellname = theshell;

#ifdef USE_PAM
	if ((env = (char **)pam_getenvlist(pamh))) {
	    /* On some systems, putenv() requires that the string be
	     * in its own malloced buffer.  So we will not free the
	     * string buffers (i.e. env[i]), but we can free the array
	     * of pointers (i.e. env).
	     */
	    int i;

	    for (i = 0; env[i]; i++)
		putenv(env[i]);

	    free(env);
	}
#endif

	endpwent();
	if (paranoid) {
	    syslog(LOG_INFO|LOG_AUTH, "%s@%s as %s: cmd='%s'",
		   remuser, hostname, locuser, cmdbuf);
	}

	/*
	 * Close all fds, in case libc has left fun stuff like 
	 * /etc/shadow open.
	 */
	for (ifd = getdtablesize()-1; ifd > 2; ifd--) close(ifd);

	execl(theshell, shellname, "-c", cmdbuf, (char *)NULL);
	perror(theshell);
	exit(1);
}

static void network_init(int fd, struct sockaddr_in *fromp)
{
	struct linger linger;
	socklen_t fromlen;
	int on=1;

	fromlen = sizeof(*fromp);
	if (getpeername(fd, (struct sockaddr *) fromp, &fromlen) < 0) {
		syslog(LOG_ERR, "getpeername: %m");
		_exit(1);
	}
	if (keepalive &&
	    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&on,
	    sizeof(on)) < 0)
		syslog(LOG_WARNING, "setsockopt (SO_KEEPALIVE): %m");
	linger.l_onoff = 1;
	linger.l_linger = 60;			/* XXX */
	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *)&linger,
	    sizeof (linger)) < 0)
		syslog(LOG_WARNING, "setsockopt (SO_LINGER): %m");

	if (fromp->sin_family != AF_INET) {
	    syslog(LOG_ERR, "malformed \"from\" address (af %d)\n",
		   fromp->sin_family);
	    exit(1);
	}
#ifdef IP_OPTIONS
      {
	u_char optbuf[BUFSIZ/3], *cp;
	char lbuf[BUFSIZ+1], *lp;
	socklen_t optsize = sizeof(optbuf);
	int  ipproto;
	struct protoent *ip;

	if ((ip = getprotobyname("ip")) != NULL)
		ipproto = ip->p_proto;
	else
		ipproto = IPPROTO_IP;
	if (!getsockopt(0, ipproto, IP_OPTIONS, (char *)optbuf, &optsize) &&
	    optsize != 0) {
		lp = lbuf;

		/*
		 * If these are true, this will not run off the end of lbuf[].
		 */
		assert(optsize <= BUFSIZ/3);
		assert(3*optsize <= BUFSIZ);
		for (cp = optbuf; optsize > 0; cp++, optsize--, lp += 3)
			snprintf(lp, 4, " %2.2x", *cp);

		syslog(LOG_NOTICE,
		       "Connection received from %s using IP options"
		       " (ignored): %s",
		       inet_ntoa(fromp->sin_addr), lbuf);

		if (setsockopt(0, ipproto, IP_OPTIONS, NULL, optsize) != 0) {
			syslog(LOG_ERR, "setsockopt IP_OPTIONS NULL: %m");
			exit(1);
		}
	}
      }
#endif

}

int
main(int argc, char *argv[])
{
	int ch;
	struct sockaddr_in from;
	_check_rhosts_file=1;

	openlog("mrshd", LOG_PID | LOG_ODELAY, LOG_DAEMON);

	opterr = 0;
	while ((ch = getopt(argc, argv, OPTIONS)) != EOF) {
		switch (ch) {
		case 'a':
			check_all = 1;
			break;

		case 'h':
			allow_root_rhosts = 1;
			break;

		case 'l':
			_check_rhosts_file = 0;
			break;

		case 'n':
			keepalive = 0;
			break;

		case 'L':
			paranoid = 1;
			break;

		case 'M':
			munge_socket = optarg;
			break;

		case 'V':
			printf("%s %s-%s\n", PACKAGE, VERSION, RELEASE);
			printf("Protocol Level = %s\n", MRSH_PROTOCOL_VERSION);
			exit(0);

		case '?':
		default:
			syslog(LOG_ERR, "usage: mrshd [-%s]", OPTIONS);
			exit(2);
		}
	}
	argc -= optind;
	argv += optind;

#ifdef USE_PAM
#if 0
       if (_check_rhosts_file == 0 || allow_root_rhosts)
               syslog(LOG_ERR, "-l and -h functionality has been moved to "
                               "pam_rhosts_auth in /etc/pam.conf");
#endif
#endif /* USE_PAM */

	network_init(0, &from);
	doit(&from);
	return 0;
}
