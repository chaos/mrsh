/*
 * Copyright (c) 1983 The Regents of the University of California.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
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
 *
 *
 * 1-14-99 Karl R. Hakimian <hakimian@eecs.wsu.edu>
 * 
 * While the headers in this file claim only the purest decent from
 * their BSD roots, this program has had unspeakable things done to it
 * over the years. I have tried to clean things up and get them working
 * again.
 *
 * Put the port connect back to the client back where it belongs.
 * Replaced fork and coping data from stderr to error socket with a
 *  dup2 of the error socket onto stderr. This code was in the BSD code,
 *  but does not seem to be necessary and is broken under Linux
 * removed file descriptor from doit call. Not needed. f = 0 assumed
 *  throughout
 * Removed unused variables.
 *
 * 3-31-99 Karl R. Hakimian <hakimian@eecs.wsu.edu>
 *
 * Fixed problem where stderr socket can be left open if a daemon is
 * called from rexecd.
 *
 * KRH
 */

char copyright[] =
  "@(#) Copyright (c) 1983 The Regents of the University of California.\n"
  "All rights reserved.\n";

/*
 * From: @(#)rexecd.c	5.12 (Berkeley) 2/25/91
 */
char rcsid[] = 
  "$Id$";
#include "version.h"

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <signal.h>
#include <netdb.h>
#include <pwd.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <crypt.h>    /* apparently necessary in some glibcs */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <paths.h>
#include <grp.h>

#ifdef USE_SHADOW
#include <shadow.h>
#endif

#ifdef USE_PAM
#include <security/pam_appl.h>
#endif

#define _PATH_FTPUSERS	      "/etc/ftpusers"

#ifdef TCP_WRAPPER
#include <syslog.h>
#include "log_tcp.h"
struct from_host from_host;
#endif

int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;


/*
 * remote execute server:
 *	username\0
 *	password\0
 *	command\0
 *	data
 */

static void fatal(const char *);
static void doit(struct sockaddr_in *fromp);
static void getstr(char *buf, int cnt, const char *err);

static const char *remote = NULL;

int
main(int argc, char **argv)
{
	struct sockaddr_in from;
	socklen_t fromlen;

	(void)argc;

	fromlen = sizeof(from);
 
	if (getpeername(0, (struct sockaddr *)&from, &fromlen) < 0) {
		fprintf(stderr, "rexecd: getpeername: %s\n", strerror(errno));
		return 1;
	}

	openlog(argv[0], LOG_PID, LOG_DAEMON);

#ifdef	TCP_WRAPPER
	/* Find out and report the remote host name. */
	/* I don't think this works. -- dholland */
	if (fromhost(&from_host) < 0 || !hosts_access(argv[0], &from_host))
		refuse(&from_host);
	remote = hosts_info(&from_host);
#else
	{
	struct hostent *h = gethostbyaddr((const char *)&from.sin_addr,
					  sizeof(struct in_addr),
					  AF_INET);
	if (!h || !h->h_name) {
		write(0, "\1Where are you?\n", 16);
		return 1;
	}
	/* Be advised that this may be utter nonsense. */
	remote = strdup(h->h_name);
	}
#endif
	syslog(allow_severity, "connect from %.128s", remote);
	doit(&from);
	return 0;
}

char	username[20] = "USER=";
char	homedir[64] = "HOME=";
char	shell[64] = "SHELL=";
char	path[sizeof(_PATH_DEFPATH) + sizeof("PATH=")] = "PATH=";
char	*envinit[] =
	    {homedir, shell, path, username, 0};
char	**myenviron;

#ifdef USE_PAM
static char *PAM_username;
static char *PAM_password;

static int PAM_conv (int num_msg,
		     const struct pam_message **msg,
		     struct pam_response **resp,
		     void *appdata_ptr) {
  int count = 0, replies = 0;
  struct pam_response *reply = NULL;
  int size = sizeof(struct pam_response);

  #define GET_MEM if (reply) realloc(reply, size); else reply = malloc(size); \
  if (!reply) return PAM_CONV_ERR; \
  size += sizeof(struct pam_response)
  #define COPY_STRING(s) (s) ? strdup(s) : NULL

  for (count = 0; count < num_msg; count++) {
    GET_MEM;
    switch (msg[count]->msg_style) {
      case PAM_PROMPT_ECHO_ON:
	reply[replies].resp_retcode = PAM_SUCCESS;
	reply[replies++].resp = COPY_STRING(PAM_username);
	  /* PAM frees resp */
	break;
      case PAM_PROMPT_ECHO_OFF:
	reply[replies].resp_retcode = PAM_SUCCESS;
	reply[replies++].resp = COPY_STRING(PAM_password);
	  /* PAM frees resp */
	break;
      case PAM_TEXT_INFO:
	reply[replies].resp_retcode = PAM_SUCCESS;
	reply[replies++].resp = NULL;
	/* ignore it... */
	break;
      case PAM_ERROR_MSG:
	reply[replies].resp_retcode = PAM_SUCCESS;
	reply[replies++].resp = NULL;
	/* Must be an error of some sort... */
      default:
	return PAM_CONV_ERR;
    }
  }
  if (reply) *resp = reply;
  return PAM_SUCCESS;
}

static struct pam_conv PAM_conversation = {
    &PAM_conv,
    NULL
};
#endif /* USE_PAM */


static void
doit(struct sockaddr_in *fromp)
{
	char cmdbuf[ARG_MAX+1];
	char user[16], pass[16];
	struct passwd *pwd;
	int s = -1;
	u_short port;
	const char *theshell;
	const char *cp2;
	int ifd;
#ifdef USE_PAM
	pam_handle_t *pamh;
	int pam_error;
#else /* !USE_PAM */
	char *namep, *cp;
#ifdef RESTRICT_FTP
	char buf[BUFSIZ];
	FILE *fp;
#endif
#endif /* USE_PAM */

	signal(SIGINT, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
#ifdef DEBUG
	{ int t = open(_PATH_TTY, 2);
	  if (t >= 0) {
		ioctl(t, TIOCNOTTY, NULL);
		close(t);
	  }
	}
#endif

/* copy socket to stdout and stderr KRH */
	dup2(0, 1);
	dup2(0, 2);
	alarm(60);
	port = 0;
	for (;;) {
		char c;
		if (read(0, &c, 1) != 1)
			exit(1);
		if (c == 0)
			break;
		port = port * 10 + c - '0';
	}
	alarm(0);

/*
 We must connect back to the client here if a port was provided. KRH
*/
	if (port != 0) {
		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0)
			exit(1);

#if 0 /* this shouldn't be necessary */
		struct	sockaddr_in asin = { AF_INET };
		if (bind(s, (struct sockaddr *)&asin, sizeof (asin)) < 0)
			exit(1);
#endif
		alarm(60);
		fromp->sin_port = htons(port);
		if (connect(s, (struct sockaddr *)fromp, sizeof (*fromp)) < 0)
			exit(1);
		alarm(0);
	}

	getstr(user, sizeof(user), "username too long\n");
	getstr(pass, sizeof(pass), "password too long\n");
	getstr(cmdbuf, sizeof(cmdbuf), "command too long\n");
#ifdef USE_PAM
       #define PAM_BAIL if (pam_error != PAM_SUCCESS) { \
	       pam_end(pamh, pam_error); exit(1); \
       }
       PAM_username = user;
       PAM_password = pass;
       pam_error = pam_start("rexec", PAM_username, &PAM_conversation,&pamh);
       PAM_BAIL;
       pam_error = pam_authenticate(pamh, 0);
       PAM_BAIL;
       pam_error = pam_acct_mgmt(pamh, 0);
       PAM_BAIL;
       pam_error = pam_setcred(pamh, PAM_ESTABLISH_CRED);
       PAM_BAIL;
       pam_end(pamh, PAM_SUCCESS);
       /* If this point is reached, the user has been authenticated. */
       setpwent();
       pwd = getpwnam(user);
       endpwent();
#else /* !USE_PAM */
       /* All of the following issues are dealt with in the PAM configuration
	  file, so put all authentication/priviledge checks before the
	  corresponding #endif below. */

	setpwent();
	pwd = getpwnam(user);
	if (pwd == NULL) {
		/* Log failed attempts. */
		syslog(LOG_ERR, "LOGIN FAILURE from %.128s, %s", remote, user);
		fatal("Login incorrect.\n");
	}
	endpwent();
#ifdef USE_SHADOW
	{
		struct spwd *sp = getspnam(pwd->pw_name);
		endspent();
		if (sp) {
			pwd->pw_passwd = sp->sp_pwdp;
		}
	}
#endif
	if (*pwd->pw_passwd != '\0') {
		namep = crypt(pass, pwd->pw_passwd);
		if (strcmp(namep, pwd->pw_passwd)) {
			/* Log failed attempts. */
			syslog(LOG_ERR, "LOGIN FAILURE from %.128s, %s",
			       remote, user);
			fatal("Login incorrect.\n");
		}
	}

	/* Erase the cleartext password from memory. */
	memset(pass, 0, sizeof(pass));
	/* Clear out crypt()'s internal state, too. */
	crypt("flurgle", pwd->pw_passwd);

	/* Disallow access to root account. */
	if (pwd->pw_uid == 0) {
		syslog(LOG_ERR, "%s LOGIN REFUSED from %.128s", user, remote);
		fatal("Login incorrect.\n");
	}
#ifdef RESTRICT_FTP
	/* Disallow access to accounts in /etc/ftpusers. */
	fp = fopen(_PATH_FTPUSERS, "r");
	if (fp != NULL) {
	    while (fgets(buf, sizeof(buf), fp) != NULL) {
		if ((cp = strchr(buf, '\n')) != NULL)
			*cp = '\0';
		if (strcmp(buf, pwd->pw_name) == 0) {
			syslog(LOG_ERR, "%s LOGIN REFUSED from %.128s",
			       user, remote);
			fatal("Login incorrect.\n");
		}
	    }
	    fclose(fp);
	}
	else syslog(LOG_ERR, "cannot open /etc/ftpusers");
#endif
#endif /* !USE_PAM */

	/* Log successful attempts. */
	syslog(LOG_INFO, "login from %.128s as %s", remote, user);

	if (chdir(pwd->pw_dir) < 0) {
		fatal("No remote directory.\n");
	}

	write(2, "\0", 1);
	if (port) {
		/* If we have a port, dup STDERR on that port KRH */
		close(2);
		dup2(s, 2);
		/*
		 * We no longer need s, close it so we don't leave it 
		 * behind for a daemon.
		 */
		close (s);
	}
	if (*pwd->pw_shell == 0) {
		/* Shouldn't we deny access? (Can be done by PAM KRH) */
		theshell = _PATH_BSHELL;
	}
	else theshell = pwd->pw_shell;
	/* shouldn't we check /etc/shells? (Can be done by PAM KRH) */

	if (setgid(pwd->pw_gid)) {
		perror("setgid");
		exit(1);
	}
	if (initgroups(pwd->pw_name, pwd->pw_gid)) {
		perror("initgroups");
		exit(1);
	}
	if (setuid(pwd->pw_uid)) {
		perror("setuid");
		exit(1);
	}

	strcat(path, _PATH_DEFPATH);
	myenviron = envinit;
	strncat(homedir, pwd->pw_dir, sizeof(homedir)-6);
	strncat(shell, theshell, sizeof(shell)-7);
	strncat(username, pwd->pw_name, sizeof(username)-6);
	cp2 = strrchr(theshell, '/');
	if (cp2) cp2++;
	else cp2 = theshell;

	/*
	 * Close all fds, in case libc has left fun stuff like 
	 * /etc/shadow open.
	 */
	for (ifd = getdtablesize()-1; ifd > 2; ifd--) close(ifd);

	execle(theshell, cp2, "-c", cmdbuf, 0, myenviron);
	perror(theshell);
	exit(1);
}

static void
fatal(const char *msg)
{
	char x = 1;
	write(2, &x, 1);
	write(2, msg, strlen(msg));
	exit(1);
}

static void
getstr(char *buf, int cnt, const char *err)
{
	char c;

	do {
		if (read(0, &c, 1) != 1)
			exit(1);
		*buf++ = c;
		if (--cnt <= 0) {
			fatal(err);
		}
	} while (c != 0);
}

