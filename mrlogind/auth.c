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
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <pwd.h>

#include "rlogind.h"

#ifdef USE_PAM

/*
 * Modifications for Linux-PAM: Al Longyear <longyear@netcom.com>
 *   General code clean up: Andrew Morgan <morgan@physics.ucla.edu>
 *   Re-built with #ifdef USE_PAM: Michael K. Johnson <johnsonm@redhat.com>,
 *   Red Hat Software
 *
 *   The Linux-PAM mailing list (25JUN96) <pam-list@redhat.com>
 */

#include <syslog.h>
#include <unistd.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

/* in sockconv.c */
int sock_conv(int num_msg, const struct pam_message **msgm, 
	      struct pam_response **response, void *appdata_ptr);

static pam_handle_t *pamh;

void auth_checkoptions(void) {
    if (use_rhosts==0 || deny_all_rhosts_hequiv || allow_root_rhosts) {
	syslog(LOG_ERR, "-l, -L, and -h functionality has been moved to "
	       "pam_rhosts_auth in /etc/pam.conf");
    }
}

void auth_finish(void) {
    if (pamh) {
       pam_end(pamh, PAM_SUCCESS);
       pamh = NULL;
    }
}

static int attempt_auth(void) {
    int retval;

    retval = pam_authenticate(pamh, 0);
    if (retval == PAM_SUCCESS) {
	retval = pam_acct_mgmt(pamh, 0);
    }
    if (retval == PAM_NEW_AUTHTOK_REQD) {
	retval = pam_chauthtok(pamh, PAM_CHANGE_EXPIRED_AUTHTOK);
	if (retval == PAM_SUCCESS) {
	    /* 
	     * Try authentication again if passwd change
	     * succeeded.  Don't try again if it didn't;
	     * sysadmin might not want passwords changed
	     * over the net, and might have set password
	     * to pam_deny.so to disable it... 
	     *
	     * Hmm. Is it possible for the sysadmin to configure this
	     * for infinite recursion? (That is, will the second attempt
	     * also ever try to change the password?)
	     */
	    retval = attempt_auth();
	}
    }
    return retval;
}

/*
 * This function must either die, return -1 on authentication failure,
 * or return 0 on authentication success. Dying is discouraged.
 */
int auth_checkauth(const char *remoteuser, const char *host,
		   char *localuser, size_t localusersize) 
{
    static struct pam_conv conv = { sock_conv, NULL };
    struct passwd *pwd;
    char *ln;
    int retval;

    retval = pam_start("rlogin", localuser, &conv, &pamh);
    if (retval != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_start: %s\n", pam_strerror(pamh, retval));
	fatal(STDERR_FILENO, "initialization failed", 0);
    }
	
    pam_set_item(pamh, PAM_USER, localuser);
    pam_set_item(pamh, PAM_RUSER, remoteuser);
    pam_set_item(pamh, PAM_RHOST, host);
    pam_set_item(pamh, PAM_TTY, "tty");   /* ? */
	
    network_confirm();
    retval = attempt_auth();
    if (retval != PAM_SUCCESS) {
	syslog(LOG_ERR, "PAM authentication failed for in.rlogind");
	return -1;
    }

    pam_get_item(pamh, PAM_USER, &ln);
    if (!ln || !*ln) {
	/*
	 * Authentication wasn't adequate for requirements.
	 * Fall through to login quietly; don't let the
	 * remote user tell if he's found a valid username 
	 * or not.
	 */
	return -1;
    }

    /*
     * PAM is apparently willing to change the username on us. (!?)
     */
    strncpy(localuser, ln, localusersize-1);
    localuser[localusersize-1] = 0;

    /*
     * And, as far as I can tell, this shouldn't be here at all.
     * /bin/login is supposed to handle this, isn't it? Certainly
     * the gids. But, allegedly, it's needed.
     *
     * I thought PAM was supposed to make this sort of thing _easier_.
     */
    pwd = getpwnam(localuser);
    if (pwd==NULL) {
        syslog(LOG_ERR, "user returned by PAM does not exist\n");
	/* don't print this - it tells people which accounts exist */
	/*fprintf(stderr, "rlogind: internal error\n");*/
	return -1;
    }
    if (setgid(pwd->pw_gid) != 0) {
        syslog(LOG_ERR, "cannot assume gid for user returned by PAM\n");
	fprintf(stderr, "rlogind: internal error\n");
	return -1;
    }
    if (initgroups(localuser, pwd->pw_gid) != 0) {
        syslog(LOG_ERR, "initgroups failed for user returned by PAM\n");
	fprintf(stderr, "rlogind: internal error\n");
	return -1;
    }
    retval = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    if (retval != PAM_SUCCESS) {
	syslog(LOG_ERR,"PAM authentication failed for in.rlogind");
	return -1;
    }

    return 0;
}

#else /* not USE_PAM */

/*
 * Standard rlogin processing...
 */

#include <sys/socket.h>   /* for ruserok() in libc5 (!) */
#include <netdb.h>        /* for ruserok() in glibc (!) */

#if defined(__GLIBC__) && (__GLIBC__ >= 2)
#define _check_rhosts_file  __check_rhosts_file
#endif
extern int _check_rhosts_file;


void auth_checkoptions(void) {}
void auth_finish(void) {}

/*
 * This function must either die, return -1 on authentication failure,
 * or return 0 on authentication success. Dying is discouraged.
 */
int auth_checkauth(const char *remoteuser, const char *host,
		   char *localuser, size_t localusersize) 
{
    struct passwd *pwd;

    (void)localusersize;

    pwd = getpwnam(localuser);
    if (pwd == NULL) return -1;

    /*
     * The possibilities here are:
     *    user == root
     *          (1) .rhosts entry exists
     *          (2) hosts_equiv entry exists
     *		(3) neither .rhosts nor hosts_equiv entries exist
     *    user != root
     *          (4) .rhosts entry exists
     *          (5) hosts_equiv entry exists
     *		(6) neither .rhosts nor hosts_equiv entries exist
     *
     * ruserok() by itself will fail on (2), (3), and (6).
     * 
     * Turning off use_rhosts will (or should) prevent (1) and (4).
     * Leaving allow_root_rhosts off will prevent (1).
     * Setting deny_all_rhosts_hequiv prevents all cases from succeeding.
     */

    if (deny_all_rhosts_hequiv) return -1;
    if (!allow_root_rhosts && pwd->pw_uid == 0) return -1;

    _check_rhosts_file = use_rhosts;

    return ruserok(host, pwd->pw_uid==0, remoteuser, localuser);
}

#endif /* PAM */
