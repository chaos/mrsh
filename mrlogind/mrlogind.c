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

char copyright[] =
  "@(#) Copyright (c) 1983, 1988, 1989 "
  "The Regents of the University of California.\n"
  "All rights reserved.\n";

/* 
 * From: @(#)mrlogind.c	5.53 (Berkeley) 4/20/91
 */
char rcsid[] = 
  "$Id$";
#include "version.h"

#if HAVE_CONFIG_H
#include "config.h"
#endif

/*
 * remote login server:
 *	\0
 *	remuser\0
 *	locuser\0
 *	terminal_type/speed\0
 *	data
 */

#include <sys/types.h>   /* for size_t */
#include <sys/param.h>   /* for MAXPATHLEN */
#include <sys/stat.h>    /* for chmod() */
#include <sys/ioctl.h>   /* for TIOCPKT */
#include <sys/time.h>    /* for FD_SET() et al. */
#include <signal.h>      /* for SIGCHLD */
#include <termios.h>     /* for tcsetattr() */
#include <sys/socket.h>  /* for shutdown() */
#include <arpa/inet.h>   /* for ntohs() */
#include <stdio.h>       /* for EOF, BUFSIZ, snprintf() */
#include <syslog.h>      /* for syslog() */
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pty.h>
#include <utmp.h>

#include "pathnames.h"
#include "logwtmp.h"
#include "mrlogind.h"
#include "mauth.h"

int logout(const char *);

#ifndef TIOCPKT_WINDOW
#define TIOCPKT_WINDOW 0x80
#endif

int keepalive = 1;
int check_all = 0;
int use_rhosts = 1;
int allow_root_rhosts = 1;
int deny_all_rhosts_hequiv = 0;
char *munge_socket = NULL;

static char oobdata[] = {(char)TIOCPKT_WINDOW};
static char line[MAXPATHLEN];
struct winsize win = { 0, 0, 0, 0 };


void fatal(int f, const char *msg, int syserr) {
    char buf[BUFSIZ];

    /*
     * Send out a binary one if we haven't sent the magic null as confirmation.
     */
    network_anticonfirm();

    if (!syserr) {
	snprintf(buf, sizeof(buf), "mrlogind: %s.\r\n", msg);
    }
    else {
	snprintf(buf, sizeof(buf), "mrlogind: %s: %s.\r\n", 
		 msg, strerror(errno));
    }
    write(f, buf, strlen(buf));
    auth_finish();
    exit(1);
}


////////////////////////////////////////////////// parent ////////////////////

/*
 * Handle a "control" request (signaled by magic being present)
 * in the data stream.  For now, we are only willing to handle
 * window size changes.
 */
static int control(int pty, char *cp, int n) {
	struct winsize w;

	if (n < 4+(int)sizeof(w) || cp[2] != 's' || cp[3] != 's') {
		return 0;
	}
	oobdata[0] &= ~TIOCPKT_WINDOW;	/* we know he heard */
	memcpy(&w, cp+4, sizeof(w));
	w.ws_row = ntohs(w.ws_row);
	w.ws_col = ntohs(w.ws_col);
	w.ws_xpixel = ntohs(w.ws_xpixel);
	w.ws_ypixel = ntohs(w.ws_ypixel);
	ioctl(pty, TIOCSWINSZ, &w);
	return 4+sizeof(w);
}

/*
 * mrlogin "protocol" machine.
 */
static void protocol(int f, int p) {
	static char magic[2] = { (char)0377, (char)0377 };

	char pibuf[1024+1], fibuf[1024], *pbp = NULL, *fbp = NULL;
	int pcc = 0, fcc = 0;
	int cc, nfd, m;
	char cntl;

	/*
	 * Must ignore SIGTTOU, otherwise we'll stop
	 * when we try and set slave pty's window shape
	 * (our controlling tty is the master pty).
	 */
	(void) signal(SIGTTOU, SIG_IGN);
	send(f, oobdata, 1, MSG_OOB);	/* indicate new mrlogin */
	if (f > p)
		nfd = f + 1;
	else
		nfd = p + 1;
	if (nfd > FD_SETSIZE) {
		syslog(LOG_ERR, "select mask too small, increase FD_SETSIZE");
		fatal(f, "internal error (select mask too small)", 0);
	}
	for (;;) {
		fd_set ibits, obits, ebits, *omask;

		FD_ZERO(&ebits);
		FD_ZERO(&ibits);
		FD_ZERO(&obits);
		omask = (fd_set *)NULL;
		if (fcc) {
			FD_SET(p, &obits);
			omask = &obits;
		} else
			FD_SET(f, &ibits);
		if (pcc >= 0) {
			if (pcc) {
				FD_SET(f, &obits);
				omask = &obits;
			} else {
				FD_SET(p, &ibits);
			}
		}
		FD_SET(p, &ebits);
		if ((m = select(nfd, &ibits, omask, &ebits, 0)) < 0) {
			if (errno == EINTR)
				continue;
			fatal(f, "select", 1);
		}
		if (m == 0) {
			/* shouldn't happen... */
			sleep(5);
			continue;
		}
#define	pkcontrol(c)	((c)&(TIOCPKT_FLUSHWRITE|TIOCPKT_NOSTOP|TIOCPKT_DOSTOP))
		if (FD_ISSET(p, &ebits)) {
			cc = read(p, &cntl, 1);
			if (cc == 1 && pkcontrol(cntl)) {
				cntl |= oobdata[0];
				send(f, &cntl, 1, MSG_OOB);
				if (cntl & TIOCPKT_FLUSHWRITE) {
					pcc = 0;
					FD_CLR(p, &ibits);
				}
			}
		}
		if (FD_ISSET(f, &ibits)) {
				fcc = read(f, fibuf, sizeof(fibuf));
			if (fcc < 0 && errno == EWOULDBLOCK)
				fcc = 0;
			else {
				register char *cp;
				int left, nn;

				if (fcc <= 0)
					break;
				fbp = fibuf;

			top:
				for (cp = fibuf; cp < fibuf+fcc-1; cp++)
					if (cp[0] == magic[0] &&
					    cp[1] == magic[1]) {
						left = fcc - (cp-fibuf);
						nn = control(p, cp, left);
						if (nn) {
							left -= nn;
							if (left > 0)
								bcopy(cp+nn, cp, left);
							fcc -= nn;
							goto top; /* n^2 */
						}
					}
				FD_SET(p, &obits);		/* try write */
			}
		}

		if (FD_ISSET(p, &obits) && fcc > 0) {
			cc = write(p, fbp, fcc);
			if (cc > 0) {
				fcc -= cc;
				fbp += cc;
			}
		}

		if (FD_ISSET(p, &ibits)) {
			pcc = read(p, pibuf, sizeof (pibuf));
			pbp = pibuf;
			if (pcc < 0 && errno == EWOULDBLOCK)
				pcc = 0;
			else if (pcc <= 0)
				break;
			else if (pibuf[0] == 0) {
				pbp++, pcc--;
					FD_SET(f, &obits);	/* try write */
			} else {
				if (pkcontrol(pibuf[0])) {
					pibuf[0] |= oobdata[0];
					send(f, &pibuf[0], 1, MSG_OOB);
				}
				pcc = 0;
			}
		}
		if ((FD_ISSET(f, &obits)) && pcc > 0) {
				cc = write(f, pbp, pcc);
			if (cc < 0 && errno == EWOULDBLOCK) {
				/*
				 * This happens when we try write after read
				 * from p, but some old kernels balk at large
				 * writes even when select returns true.
				 */
				if (!FD_ISSET(p, &ibits))
					sleep(5);
				continue;
			}
			if (cc > 0) {
				pcc -= cc;
				pbp += cc;
			}
		}
	}
}

static void cleanup(int sig) {
    char *p;
    (void)sig;

    p = line + sizeof(_PATH_DEV) - 1;
    if (logout(p)) logwtmp(p, "", "");

    auth_finish();
    network_close();

    /* tty end to root.system mode 600 */
    chmod(line, 0600);
    chown(line, 0, 0);

    /* pty end to root.system mode 666 */
    *p = 'p';
    chmod(line, 0666);
    chown(line, 0, 0);

    /* all done */
    exit(0);
}


////////////////////////////////////////////////// child ////////////////////

static void setup_term(int fd, const char *termtype) {
    char *x;
    struct termios tt;

    tcgetattr(fd, &tt);
    if ((x=strchr(termtype, '/')) != NULL) {
	*x++ = '\0';
	cfsetispeed(&tt, atoi(x));
	cfsetospeed(&tt, atoi(x));
    }
#if 0  /* notyet */
    tt.c_iflag = TTYDEF_IFLAG;
    tt.c_oflag = TTYDEF_OFLAG;
    tt.c_lflag = TTYDEF_LFLAG;
#endif
    tcsetattr(fd, TCSAFLUSH, &tt);
}

/*
 * Close all fds, in case libc has left fun stuff like /etc/shadow open.
 */
static void closeall(void) {
    int i;
    for (i = getdtablesize()-1; i > 2; i--) close(i);
}


static void child(const char *hname, const char *termtype,
		  const char *localuser, int authenticated)
{
    char *termenv[2];
    char **env;

    setup_term(0, termtype);

    termenv[0] = malloc(strlen(termtype)+6);
    if (termenv[0]) {   /* shouldn't ever fail, mind you */
	strcpy(termenv[0], "TERM=");
	strcat(termenv[0], termtype);
    }
    termenv[1] = NULL;

#ifdef USE_PAM
    if (!(env = auth_env(&termenv[0], 1)))
        env = &termenv[0];
#else
    env = &termenv[0];
#endif

    if (authenticated) {
	auth_finish();
	closeall();
	execle(_PATH_LOGIN, "login", "-p",
	       "-h", hname, "-f", localuser, NULL, env);
    } 
    else {
	if (localuser[0] == '-') {
	    syslog(LOG_AUTH|LOG_INFO, "mrlogin with an option as a name!");
	    exit(1);
	}
	auth_finish();
	closeall();
	execle(_PATH_LOGIN, "login", "-p",
	       "-h", hname, localuser, NULL, env);
    }
    /* Can't exec login, croak */
    fatal(STDERR_FILENO, _PATH_LOGIN, 1);
}


////////////////////////////////////////////////// main ////////////////////



static void doit(int netfd) {
    int master, slave, r, pid, on = 1;
    int authenticated = 0;
    char *hname;
    int hostok;
    char lusername[32], rusername[32], termtype[256];
    struct mauth ma;

    hname = network_init(netfd, &hostok);

    if (mauth(&ma, 0, 0, munge_socket) < 0)
        fatal(netfd, &(ma.errmsg[0]), 0);

    /* achu: Necessary b/c of internals of auth_checkauth. */
    strncpy(lusername, &(ma.username[0]), sizeof(lusername));
    lusername[sizeof(lusername) - 1] = '\0';
    strcpy(rusername, lusername);
    
    /*
     * This function will either die, return -1 if authentication failed,
     * or return 0 if authentication succeeded.
     * 
     * dholland 6/13/97 I've changed this so it doesn't even call 
     * auth_checkauth if the hostname was bogus. I don't *think* 
     * this will break anything or give away state secrets.
     */
    if (hostok) {
	if (auth_checkauth(rusername, hname, 
			   lusername, sizeof(lusername)) == 0) {
	   authenticated=1;
	}
    }
    network_confirm();

    /* achu: It is possible to disclose information by fatally
     * exitting here.  We will accept this for now.
     */
    
    if (!hostok) {
        syslog(LOG_ERR, "Host address mismatch.");
        fatal(netfd, "Host address mismatch", 0);
    }

    if (!authenticated) {
        syslog(LOG_ERR, "Authentication Failed.");
        fatal(netfd, "Permission Denied", 0);
    }

    strncpy(termtype, &(ma.cmd[0]), sizeof(termtype));
    termtype[sizeof(termtype) - 1] = '\0';

    /*  We can no longer call forkpty here (a convenience routine that combines
        openpty, fork, and login_tty) because, with forkpty, the slave end of
        the pty is open only in the child process. The child process execs
        /bin/login which now closes all open file descriptors before doing a
        vhangup (see lkml.org/lkml/2012/6/5/145), and this resets packet mode
        on the pty, undoing the effect of the ioctl(master, TIOCPKT, &on) call
        made by the parent.

        Instead, we call openpty, fork, and login_tty individually, so that we
        can keep a file descriptor to the slave open in the parent process,
        thereby retaining packet mode even when the child closes file descriptors
        to call vhangup. */
    r = openpty(&master, &slave, line, NULL, &win);
    if (r < 0) {
	if (errno == ENOENT) fatal(netfd, "Out of ptys", 0);
	fatal(netfd, "Openpty", 1);
    }

    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0) {
        fatal(netfd, "Fork", 1);
    }

    if (pid == 0) {
	close(master);
	login_tty(slave);
	/* netfd should always be 0, but... */ 
	if (netfd > 2) close(netfd);
	child(hname, termtype, lusername, authenticated);
    }
    on = 1;
    ioctl(netfd, FIONBIO, &on);
    ioctl(master, FIONBIO, &on);
    ioctl(master, TIOCPKT, &on);
    signal(SIGCHLD, cleanup);
    protocol(netfd, master);
    signal(SIGCHLD, SIG_DFL);
    cleanup(0);
}

int main(int argc, char **argv) {
    int ch;
    use_rhosts = 1;     /* default */

    openlog("mrlogind", LOG_PID | LOG_CONS, LOG_AUTH);

    opterr = 0;
    while ((ch = getopt(argc, argv, "ahLlnM:V")) != EOF) {
	switch (ch) {
	    case 'a': check_all = 1; break;
	    case 'h': allow_root_rhosts = 1; break;
	    case 'L': deny_all_rhosts_hequiv = 1; break;
	    case 'l': use_rhosts = 0; break;
	    case 'n': keepalive = 0; break;
	    case 'M': munge_socket = optarg; break;
	    case 'V': printf("%s %s-%s\n", PACKAGE, VERSION, RELEASE);
		      printf("Protocol Level = %s\n", MRSH_PROTOCOL_VERSION);
		      exit(0);
	    case '?': default:
		syslog(LOG_ERR, "usage: mrlogind [-ahLln]");
		break;
	}
    }
    argc -= optind;
    argv += optind;

    auth_checkoptions();
    
    doit(0);
    return 0;
}
