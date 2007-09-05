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
 * From: @(#)mrlogin.c	5.33 (Berkeley) 3/1/91
 * Header: mit/mrlogin/RCS/mrlogin.c,v 5.2 89/07/26 12:11:21 kfall 
 *     Exp Locker: kfall
 */
char rcsid[] = 
  "$Id$";
#include "version.h"

#if HAVE_CONFIG_H
#include "config.h"
#endif

/*
 * mrlogin - remote login
 */
#include <stdio.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <termios.h>
#include <setjmp.h>
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "mcmd.h"

/*
 * mrlogin has problems with urgent data when logging into suns which
 * results in the connection being closed with an IO error. SUN_KLUDGE
 * is a work around - the actual bug is probably in tcp.c in the kernel, but
 * I haven't managed to find it yet.
 * Andrew.Tridgell@anu.edu.au (12th March 1993)
 * 
 * This should all be ancient history now. 
 * dholland@hcs.harvard.edu (15-Jul-1996)
 */
#if 0
#define SUN_KLUDGE
#endif

#ifndef TIOCPKT_WINDOW
#define	TIOCPKT_WINDOW	0x80
#endif

#ifndef TIOCPKT_FLUSHWRITE
#define TIOCPKT_FLUSHWRITE 0x02
#define TIOCPKT_NOSTOP 0x10
#define TIOCPKT_DOSTOP 0x20
#endif

/* concession to Sun */
#ifndef SIGUSR1
#define	SIGUSR1	30
#endif

struct termios defmodes;
struct termios ixon_state;
static int eight, litout, rem;

static int noescape;
static u_char escapechar = '~';

static int childpid;

static char defkill, defquit, defstart, defstop, defeol, defeof, defintr;
static char defsusp, defdsusp, defreprint, defdiscard, defwerase, deflnext;



#ifdef sun
struct winsize {
	unsigned short ws_row, ws_col;
	unsigned short ws_xpixel, ws_ypixel;
};
#endif
struct	winsize winsize;

#ifndef sun
#define	get_window_size(fd, wp)	ioctl(fd, TIOCGWINSZ, wp)
#endif

static void mode(int f);
static void stop(char cmdc);
static void usage(void);
static void doit(long omask);
static void done(int status);
static void writer(void);
static int reader(int omask);
static void msg(const char *str);
static void setsignal(int sig, void (*act)(int));
static void sendwindow(void);
static void echo(char c);
static void stop(char cmdc);
static void catch_child(int);
static void copytochild(int);
static void writeroob(int);
static void lostpeer(int);
static u_char getescape(const char *p);

/*
 * It is beyond me why code of this nature should be necessary.
 * Why can't termios hand back an integer?
 */
static const char *getspeedstr(speed_t speed) 
{
	switch(speed) {
	  case B0: return "0";
	  case B50: return "50";
	  case B75: return "75";
	  case B110: return "110";
	  case B134: return "134";
	  case B150: return "150";
	  case B200: return "200";
	  case B300: return "300";
	  case B600: return "600";
	  case B1200: return "1200";
	  case B1800: return "1800";
	  case B2400: return "2400";
	  case B4800: return "4800";
	  case B9600: return "9600";
	  case B19200: return "19200";
	  case B38400: return "38400";
	  case B57600: return "57600";
	  case B115200: return "115200";
	  case B230400: return "230400";
	  case B460800: return "460800";
	}
	return "9600";
}

int
main(int argc, char **argv)
{
	struct passwd *pw;
	struct servent *sp;
	struct termios tios;

	long omask;
	int argoff, ch, dflag, one, uid;
	char *host, *p, *user, term[1024];
	const char *t;
	char *null = NULL;

	argoff = dflag = 0;
	one = 1;
	host = user = NULL;

	if ((p = strrchr(argv[0], '/'))!=NULL)
		++p;
	else
		p = argv[0];

	if (strcmp(p, "mrlogin") && strcmp(p, "rlogin"))
		host = p;

	/* handle "mrlogin host flags" */
	if (!host && argc > 2 && argv[1][0] != '-') {
		host = argv[1];
		argoff = 1;
	}

#define	OPTIONS	"8EKLde:l:V"
	while ((ch = getopt(argc - argoff, argv + argoff, OPTIONS)) != EOF)
		switch(ch) {
		case '8':
			eight = 1;
			break;
		case 'E':
			noescape = 1;
			break;
		case 'K':
			break;
		case 'L':
			litout = 1;
			break;
		case 'd':
			dflag = 1;
			break;
		case 'e':
			escapechar = getescape(optarg);
			break;
		case 'l':
			user = optarg;
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
	argc -= optind;
	argv += optind;

	/* if haven't gotten a host yet, do so */
	if (!host && !(host = *argv++))
		usage();

	if (*argv)
		usage();

	if (!(pw = getpwuid(uid = getuid()))) {
		fprintf(stderr, "mrlogin: unknown user id.\n");
		exit(1);
	}
	if (!user)
		user = pw->pw_name;

	sp = NULL;
	if (sp == NULL)
		sp = getservbyname("mlogin", "tcp");
	if (sp == NULL) {
		fprintf(stderr, "mrlogin: mlogin/tcp: unknown service.\n");
		exit(1);
	}

	t = getenv("TERM");
	if (!t) t = "network";
  	if (tcgetattr(0, &tios) == 0) {
		speed_t speed = cfgetispeed(&tios);
		const char *speedstr = getspeedstr(speed);
		snprintf(term, sizeof(term), "%.256s/%s", t, speedstr);
  	}
	else snprintf(term, sizeof(term), "%.256s", t);

	__environ = &null;

	get_window_size(0, &winsize);

	/*
	 * Moved before mcmd call so that if get a SIGPIPE in mcmd
	 * we will have the defmodes set already. 
	 */
	tcgetattr(0, &defmodes);
	tcgetattr(0, &ixon_state);

	signal(SIGPIPE, lostpeer);
	/* will use SIGUSR1 for window size hack, so hold it off */
	omask = sigblock(sigmask(SIGURG) | sigmask(SIGUSR1));

	rem = mcmd(&host, sp->s_port, user, term, 0);

	if (rem < 0) exit(1);

	if (dflag) {
	    if (setsockopt(rem, SOL_SOCKET, SO_DEBUG, &one, sizeof(one)) < 0)
	    	fprintf(stderr, "mrlogin: setsockopt(SO_DEBUG): %s.\n", 
			strerror(errno));
	}
#ifdef IP_TOS
	one = IPTOS_LOWDELAY;
	if (setsockopt(rem, IPPROTO_IP, IP_TOS, (char *)&one, sizeof(one)) < 0)
	    	fprintf(stderr, "mrlogin: setsockopt(TOS): %s.\n", 
			strerror(errno));
#endif
	if (setuid(uid)) {
		fprintf(stderr, "mrlogin: setuid: %s\n", strerror(errno));
		exit(1);
	}

	doit(omask);
	/*NOTREACHED*/
	return 0;
}

static void
doit(long omask)
{
	struct termios tios;

	tcgetattr(0, &tios);

	tios.c_cc[VMIN] = 1;
	tios.c_cc[VTIME] = 1;

	defkill = tios.c_cc[VKILL];
	defquit = tios.c_cc[VQUIT];
	defstart = tios.c_cc[VSTART];
	defstop = tios.c_cc[VSTOP];
	defeol = tios.c_cc[VEOL];
	defeof = tios.c_cc[VEOF];
	defintr = tios.c_cc[VINTR];
	defsusp = tios.c_cc[VSUSP];        /* stop process */
#ifdef VDSUSP
	defdsusp = tios.c_cc[VDSUSP];        /* delayed stop process */
#else
	defdsusp = (char)0xFF; /* cast 0xFF for 32/64 bit platforms */
#endif
	defreprint = tios.c_cc[VREPRINT];       /* rprint line */
	defdiscard = tios.c_cc[VDISCARD];        /* flush output */
	defwerase = tios.c_cc[VWERASE];         /* word erase */
	deflnext = tios.c_cc[VLNEXT];         /* literal next char */

	signal(SIGINT, SIG_IGN);
	setsignal(SIGHUP, exit);
	setsignal(SIGQUIT, exit);
	/*
	 * Do this *before* forking...
	 */
	signal(SIGCHLD, catch_child);

	childpid = fork();
	if (childpid == -1) {
		fprintf(stderr, "mrlogin: fork: %s.\n", strerror(errno));
		done(1);
	}
	if (childpid == 0) {
		mode(1);
		if (reader(omask) == 0) {
			msg("connection closed.");
			exit(0);
		}
		sleep(1);
		msg("\007connection closed.");
		exit(1);
	}

	/*
	 * We may still own the socket, and may have a pending SIGURG (or might
	 * receive one soon) that we really want to send to the reader.  Set a
	 * trap that simply copies such signals to the child.
	 */
	signal(SIGURG, copytochild);
	signal(SIGUSR1, writeroob);
	sigsetmask(omask);
#ifdef	__linux__
	/*sleep(1);*/    /*  why?!? */
#endif
	writer();
	msg("closed connection.");
	done(0);
}

/* trap a signal, unless it is being ignored. */
static void
setsignal(int sig, void (*act)(int))
{
	int omask = sigblock(sigmask(sig));

	if (signal(sig, act) == SIG_IGN)
		signal(sig, SIG_IGN);
	sigsetmask(omask);
}

static void
done(int status)
{
	int w, wstatus;

	mode(0);
	if (childpid > 0) {
		/* make sure catch_child does not snap it up */
		signal(SIGCHLD, SIG_DFL);
		if (kill(childpid, SIGKILL) >= 0)
			while ((w = wait(&wstatus)) > 0 && w != childpid);
	}
	exit(status);
}

int dosigwinch;
void sigwinch(int);

/*
 * This is called when the reader process gets the out-of-band (urgent)
 * request to turn on the window-changing protocol.
 */
static void
writeroob(int ignore)
{
	(void)ignore;

	if (dosigwinch == 0) {
		sendwindow();
		signal(SIGWINCH, sigwinch);
	}
	dosigwinch = 1;
}

void
catch_child(int ignore)
{
	union wait status;
	int pid;

	(void)ignore;
	for (;;) {
		pid = wait3(&status,
		    WNOHANG|WUNTRACED, (struct rusage *)0);
		if (pid == 0)
			return;
		/* if the child (reader) dies, just quit */
		if (pid < 0 || (pid == childpid && !WIFSTOPPED(status)))
			done((int)(status.w_termsig | status.w_retcode));
	}
	/* NOTREACHED */
}

/*
 * writer: write to remote: 0 -> line.
 * ~.				terminate
 * ~^Z				suspend mrlogin process.
 * ~<delayed-suspend char>	suspend mrlogin process, but leave reader alone.
 */
static void
writer(void)
{
	register int bol, local, n;
	char c;

	bol = 1;			/* beginning of line */
	local = 0;
	for (;;) {
		n = read(STDIN_FILENO, &c, 1);
		if (n <= 0) {
			if (n < 0 && errno == EINTR)
				continue;
			break;
		}
		/*
		 * If we're at the beginning of the line and recognize a
		 * command character, then we echo locally.  Otherwise,
		 * characters are echo'd remotely.  If the command character
		 * is doubled, this acts as a force and local echo is
		 * suppressed.
		 */
		if (bol) {
			bol = 0;
			if (!noescape && c == escapechar) {
				local = 1;
				continue;
			}
		} else if (local) {
			local = 0;
			if (c == '.' || c == defeof) {
				echo(c);
				break;
			}
			if (c == defsusp || c == defdsusp) {
				bol = 1;
				echo(c);
				stop(c);
				continue;
			}
			if (c != escapechar)
					write(rem, &escapechar, 1);
		}

			if (write(rem, &c, 1) == 0) {
				msg("line gone");
				break;
			}
		bol = c == defkill || c == defeof ||
		    c == defintr || c == defsusp ||
		    c == '\r' || c == '\n';
	}
}

static void
echo(char c)
{
	register char *p;
	char buf[8];

	p = buf;
	c &= 0177;
	*p++ = escapechar;
	if (c < ' ') {
		*p++ = '^';
		*p++ = c + '@';
	} else if (c == 0177) {
		*p++ = '^';
		*p++ = '?';
	} else
		*p++ = c;
	*p++ = '\r';
	*p++ = '\n';
	write(STDOUT_FILENO, buf, p - buf);
}

static void
stop(char cmdc)
{
	mode(0);
	signal(SIGCHLD, SIG_IGN);
	kill(cmdc == defsusp ? 0 : getpid(), SIGTSTP);
	signal(SIGCHLD, catch_child);
	mode(1);
	sigwinch(SIGWINCH);		/* check for size changes */
}

void
sigwinch(int signum)
{
	struct winsize ws;

	(void)signum;
	if (dosigwinch && get_window_size(0, &ws) == 0 &&
	    bcmp(&ws, &winsize, sizeof(ws))) {
		winsize = ws;
		sendwindow();
	}
#ifdef SUN_KLUDGE
       signal(SIGWINCH,sigwinch);
#endif
}

/*
 * Send the window size to the server via the magic escape
 */
static void
sendwindow(void)
{
	struct winsize *wp;
	char obuf[4 + sizeof (struct winsize)];

	wp = (struct winsize *)(obuf+4);
	obuf[0] = (char)0377; /* (char) casts added for 32/64 bit machines */
	obuf[1] = (char)0377;
	obuf[2] = (char)'s';
	obuf[3] = (char)'s';
	wp->ws_row = htons(winsize.ws_row);
	wp->ws_col = htons(winsize.ws_col);
	wp->ws_xpixel = htons(winsize.ws_xpixel);
	wp->ws_ypixel = htons(winsize.ws_ypixel);

		write(rem, obuf, sizeof(obuf));
}

/*
 * reader: read from remote: line -> 1
 */
#define	READING	1
#define	WRITING	2

static sigjmp_buf rcvtop;
static int ppid, rcvcnt, rcvstate;
static char rcvbuf[8 * 1024];

static void
oob_real(void)
{
	struct termios tios;

	int atmark, n, rcvd;
	unsigned char waste[BUFSIZ], mark;

	rcvd = 0;
	while (recv(rem, &mark, 1, MSG_OOB) < 0) {
		sleep(1);
		switch (errno) {
		case EWOULDBLOCK:
			/*
			 * Urgent data not here yet.  It may not be possible
			 * to send it yet if we are blocked for output and
			 * our input buffer is full.
			 */
			if (rcvcnt < (int)sizeof(rcvbuf)) {
				n = read(rem, rcvbuf + rcvcnt,
					 sizeof(rcvbuf) - rcvcnt);
				if (n <= 0)
					return;
				rcvd += n;
			} else {
				n = read(rem, waste, sizeof(waste));
				if (n <= 0)
					return;
			}
			continue;
		default:
			return;
	}
	}
	if (mark & TIOCPKT_WINDOW) {
		/* Let server know about window size changes */
		kill(ppid, SIGUSR1);
	}
	if (!eight && (mark & TIOCPKT_NOSTOP)) {
		tcgetattr(0, &tios);
		tios.c_iflag &= ~IXON;
/*		tios.c_lflag &= ~ICANON;	*/
		tcsetattr(0, TCSADRAIN, &tios);
	}
	if (!eight && (mark & TIOCPKT_DOSTOP)) {
		tcgetattr(0, &tios);
/*		tios.c_lflag  |= ICANON;*/
		tios.c_iflag |= IXON;
		tcsetattr(0, TCSADRAIN, &tios);
	}
	if (mark & TIOCPKT_FLUSHWRITE) {
		tcflush(1, TCOFLUSH);

		for (;;) {
			if (ioctl(rem, SIOCATMARK, &atmark) < 0) {
				fprintf(stderr, "mrlogin: ioctl: %s.\n",
					strerror(errno));
				break;
			}
			if (atmark)
				break;
			n = read(rem, waste, sizeof (waste));
			if (n <= 0)
				break;
		}
		/*
		 * Don't want any pending data to be output, so clear the recv
		 * buffer.  If we were hanging on a write when interrupted,
		 * don't want it to restart.  If we were reading, restart
		 * anyway.
		 */
		rcvcnt = 0;
		siglongjmp(rcvtop, 1);
	}

	/* oob does not do FLUSHREAD (alas!) */

	/*
	 * If we filled the receive buffer while a read was pending, longjmp
	 * to the top to restart appropriately.  Don't abort a pending write,
	 * however, or we won't know how much was written.
	 */
	if (rcvd && rcvstate == READING) {
		siglongjmp(rcvtop, 1);
	}
}

static void oob(int ignore)
{
	(void)ignore;

	oob_real();
#ifdef SUN_KLUDGE
	signal(SIGURG,oob);
#endif
}



/* reader: read from remote: line -> 1 */
static int
reader(int omask)
{
	int pid = getpid();
	int n, remaining;
	char *volatile bufp = rcvbuf;

	signal(SIGTTOU, SIG_IGN);
	signal(SIGURG, oob);
	ppid = getppid();
/*	fcntl(rem, F_SETOWN, pid); */
	ioctl(rem, SIOCSPGRP, &pid); /* @@@ */
	sigsetjmp(rcvtop, 1);
	sigsetmask(omask);
	for (;;) {
		while ((remaining = rcvcnt - (bufp - rcvbuf)) > 0) {
			rcvstate = WRITING;
			n = write(STDOUT_FILENO, bufp, remaining);
			if (n < 0) {
				if (errno != EINTR)
					return -1;
				continue;
			}
			bufp += n;
		}
		bufp = rcvbuf;
		rcvcnt = 0;
		rcvstate = READING;

			rcvcnt = read(rem, rcvbuf, sizeof (rcvbuf));

/*
* If we get a EIO from a read then it may mean that we have unread ungent data
* waiting that is getting in the way. We probably have got more then one lot of
* urgent data but we only got one SIGURG due to a problem in the kernel tcp.
* We can try and fix this by sending ourself a SIGURG and pretending the error
* never occurred. This might be a problem if we really _should_ be getting
* a EIO for some unrelated reason. (AJT 3/93)
*
* Hmm, I just checked this with the current (NET-2e BETA-1) kernel, and
* it seems that this patch isn't needed anymore.  FvK 09/20/93
*/
#ifdef XX_SUN_KLUDGE
		if (rcvcnt < 0 && errno == EIO)
		  {
		    errno = 0;		    
		    kill(getpid(),SIGURG);
		    continue;
		  }		
#endif    
		if (rcvcnt == 0)
			return (0);
		if (rcvcnt < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "mrlogin: read: %s.\n",
				strerror(errno));
			return -1;
		}
	}
}

static void
mode(int f)
{
	struct termios tios;
	tcgetattr(0, &tios);

	switch(f) {
	  case 0:
		/*
		 * remember whether IXON was set, so it can be restored
		 * when mode(1) is next done
		 */
	        tcgetattr(0, &ixon_state);
		/*
		 * copy the initial modes we saved into sb; this is
		 * for restoring to the initial state
		 */
		memcpy(&tios, &defmodes, sizeof(defmodes));
		break;
	  case 1:
                /* turn off output mappings */
                tios.c_oflag &= ~(ONLCR|OCRNL);
                /*
                 * turn off canonical processing and character echo;
                 * also turn off signal checking -- ICANON might be
                 * enough to do this, but we're being careful
                 */
                tios.c_lflag &= ~(ECHO|ICANON|ISIG);
                tios.c_iflag &= ~(ICRNL);
                tios.c_cc[VTIME] = 1;
                tios.c_cc[VMIN] = 1;
                if (eight) tios.c_iflag &= ~(ISTRIP);
                /* preserve tab delays, but turn off tab-to-space expansion */
                if ((tios.c_oflag & TABDLY) == TAB3)
                        tios.c_oflag &= ~TAB3;
                /*
                 *  restore current flow control state
                 */
                if ((ixon_state.c_iflag & IXON) && ! eight) {
                    tios.c_iflag |= IXON;
                } 
		else {
                    tios.c_iflag &= ~IXON;
                }
		tios.c_cc[VSUSP] = 255;
		tios.c_cc[VEOL] = 255;
		tios.c_cc[VREPRINT] = 255;
		tios.c_cc[VDISCARD] = 255;
		tios.c_cc[VWERASE] = 255;
		tios.c_cc[VLNEXT] = 255;
		tios.c_cc[VEOL2] = 255;
		break;
	  default:
		return;
	}
	tcsetattr(0, TCSADRAIN, &tios);
}

static void
lostpeer(int ignore)
{
	(void)ignore;

	signal(SIGPIPE, SIG_IGN);
	msg("\007connection closed.");
	done(1);
}

/* copy SIGURGs to the child process. */
void
copytochild(int ignore)
{
	(void)ignore;

	kill(childpid, SIGURG);
#ifdef SUN_KLUDGE
	signal(SIGCHLD,copytochild);
#endif
}

static void
msg(const char *str)
{
	fprintf(stderr, "mrlogin: %s\r\n", str);
}


static void
usage(void)
{
	fprintf(stderr,
	    "usage: mrlogin [ -%s]%s[-e char] [ -l username ] host\n",
	    "8EL", " ");
	exit(1);
}

/*
 * The following routine provides compatibility (such as it is) between 4.2BSD
 * Suns and others.  Suns have only a `ttysize', so we convert it to a winsize.
 */
#ifdef sun
get_window_size(fd, wp)
	int fd;
	struct winsize *wp;
{
	struct ttysize ts;
	int error;

	error = ioctl(0, TIOCGSIZE, &ts);
	if (error != 0)	return error;

	wp->ws_row = ts.ts_lines;
	wp->ws_col = ts.ts_cols;
	wp->ws_xpixel = 0;
	wp->ws_ypixel = 0;
	return 0;
}
#endif

static u_char
getescape(const char *p)
{
	long val;
	int len;

	if ((len = strlen(p)) == 1)    /* use any single char, including '\' */
		return (u_char)*p;
					/* otherwise, \nnn */
	if (*p == '\\' && len >= 2 && len <= 4) {
		val = strtol(++p, NULL, 8);
		for (;;) {
			if (!*++p)
				return (u_char)val;
			if (*p < '0' || *p > '8')
				break;
		}
	}
	msg("illegal option value -- e");
	usage();
	/* NOTREACHED */
	return 0;
}
