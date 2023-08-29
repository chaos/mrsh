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
 *  security. For details, see https://github.com/chaos/mrsh.
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

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include "version.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>     /* sockaddr_in, htonl */
#include <arpa/inet.h>
#include <net/if.h>         /* struct ifreq, struct ifconf */

#include <munge.h> 

#include "fd.h"
#include "common_defs.h"
#include "mauth.h"

#define MAX_MBUF_SIZE     4096

/* Static function prototypes */
static char *munge_parse(struct mauth *, char *, char *);
static int   getifrlen(struct ifreq *);
static int   check_interfaces(struct mauth *, void *, int h_length);
static int   check_munge_ip(struct mauth *, char *);

char *munge_parse(struct mauth *ma, char *buf, char *end) {
    int len = strlen(buf);

    buf += len + 1;
    if (buf >= end) {
        syslog(LOG_ERR, "parser went beyond valid data");
        snprintf(ma->errmsg, MAXERRMSGLEN, "Internal Error");
        return NULL;
    }
    return buf;
}

int getifrlen(struct ifreq *ifr) {
    int len;

    /* Calculations below are necessary b/c socket addresses can have
     * variable length
     */

#if HAVE_SA_LEN
    if (sizeof(struct sockaddr) > ifr->ifr_addr.sa_len)
        len = sizeof(struct sockaddr);
    else
        len = ifr->ifr_addr.sa_len;
#else /* !HAVE_SA_LEN */
    /* For now we only assume AF_INET and AF_INET6 */
    switch(ifr->ifr_addr.sa_family) {
#ifdef HAVE_IPV6
        case AF_INET6:
            len = sizeof(struct sockaddr_in6);
            break;
#endif /* HAVE_IPV6 */
        case AF_INET:
        default:
            len = sizeof(struct sockaddr_in);
            break;
    }
    
    /* On ia32 struct sockaddr_in6/sockaddr_in was the largest
     * structure in struct ifreq, but not on ia64.  This fixes things
     */
    if (len < (sizeof(struct ifreq) - IFNAMSIZ))
        len = sizeof(struct ifreq) - IFNAMSIZ;
#endif /* HAVE_SA_LEN */

    return len;
}

int check_interfaces(struct mauth *ma, void *munge_addr, int addr_len) {
    struct ifconf ifc;
    struct ifreq *ifr;
    int s, found = 0, lastlen = -1;
    int len = sizeof(struct ifreq) * 100;
    void *buf = NULL, *ptr = NULL;
    struct sockaddr_in *sin;
    char *addr;

    /* Significant amounts of this code are from Unix Network
     * Programming, by R. Stevens, Chapter 16
     */

    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        syslog(LOG_ERR, "socket call failed: %m");
        snprintf(ma->errmsg, MAXERRMSGLEN, "Internal System Error");
        goto bad;
    }

    /* get all active interfaces */
    while(1) {
        if ((buf = (char *)malloc(len)) == NULL) {
            syslog(LOG_ERR, "malloc failed: %m");
            snprintf(ma->errmsg, MAXERRMSGLEN, "Out of Memory");
            goto bad;
        }

        ifc.ifc_len = len;
        ifc.ifc_buf = buf;

        if (ioctl(s, SIOCGIFCONF, &ifc) < 0) {
            syslog(LOG_ERR, "ioctl SIOCGIFCONF failed: %m");
            snprintf(ma->errmsg, MAXERRMSGLEN, "Internal System Error");
            goto bad;
        }
        else {
            if (ifc.ifc_len == lastlen)
                break;
            lastlen = ifc.ifc_len;
        }

        /* Run ioctl() twice for portability reasons.  See Unix Network
         * Programming, section 16.6
         */

        len += 10 * sizeof(struct ifreq);
        free(buf);
    }
    
    /* get IP addresses for all interfaces */
    for (ptr = buf; ptr < buf + ifc.ifc_len; ) {

        ifr = (struct ifreq *)ptr;

        len = getifrlen(ifr);

        ptr += sizeof(ifr->ifr_name) + len;

        /* Currently, we only care about IPv4 (i.e. AF_INET) */
        if (ifr->ifr_addr.sa_family != AF_INET)
            continue;

        sin = (struct sockaddr_in *)&ifr->ifr_addr;

        /* Skip 127.0.0.1 */
        addr = inet_ntoa(sin->sin_addr);
        if (strcmp(addr,"127.0.0.1") == 0)
            continue;

        if (memcmp(munge_addr, (void *)&sin->sin_addr.s_addr, addr_len) == 0) {
            found++;
            break;
        }
    }

    free(buf);
    return found;

 bad:
    free(buf);
    return -1;
}

int check_munge_ip(struct mauth *ma, char *ip) {
    struct in_addr in;
    int ret;

    if ((ret = inet_pton(AF_INET, ip, &in)) <= 0) {
        /* Possibly localhost special case */
        if (ret == 0 
            && strncmp(ip, 
                       MRSH_LOCALHOST_KEY, 
                       MRSH_LOCALHOST_KEYLEN) == 0) {
            char hostname[MAXHOSTNAMELEN+1];

            memset(hostname, '\0', MAXHOSTNAMELEN+1);
            if (gethostname(hostname, MAXHOSTNAMELEN) < 0) {
                syslog(LOG_ERR, "failed gethostname: %m");
                snprintf(ma->errmsg, MAXERRMSGLEN, "Internal System Error");
                return -1;
            }
            return (strcmp(ip + MRSH_LOCALHOST_KEYLEN, hostname) ? 0 : 1);
        }

        syslog(LOG_ERR, "failed inet_pton: %m");
        snprintf(ma->errmsg, MAXERRMSGLEN, "Internal System Error");
        return -1;
    }

    return check_interfaces(ma, &in, sizeof(struct in_addr));
} 

static void _copy_passwd_struct(struct passwd *to, struct passwd *from) {
    to->pw_uid    = from->pw_uid;  
    to->pw_gid    = from->pw_gid;
    to->pw_name   = strdup(from->pw_name);
    to->pw_passwd = strdup(from->pw_passwd);
    to->pw_gecos  = strdup(from->pw_gecos);
    to->pw_dir    = strdup(from->pw_dir);
    to->pw_shell  = strdup(from->pw_shell);

    return;
}

int mauth(struct mauth *ma, int fd, int cport, char *munge_socket) {
    int rv, buf_length;
    char mbuf[MAX_MBUF_SIZE];
    char *mptr = NULL;
    char *m_head = NULL;
    char *m_end = NULL;
    munge_ctx_t ctx = NULL;

    if (ma == NULL)
        return -1;

    memset(&mbuf[0], '\0', MAX_MBUF_SIZE);
    if ((buf_length = fd_null_read_n(fd, &mbuf[0], MAX_MBUF_SIZE)) < 0) {
        syslog(LOG_ERR, "%s: %m", "bad read error.");
        snprintf(ma->errmsg, MAXERRMSGLEN, "Internal System Error");
        return -1;
    }

    if (buf_length == 0) {
        syslog(LOG_ERR, "%s", "null munge credential.");
        snprintf(ma->errmsg, MAXERRMSGLEN, "Protocol Error");
        return -1;
    }

    if ((ctx = munge_ctx_create()) == NULL) {
        syslog(LOG_ERR, "%s", "unable to create munge ctx.");
        snprintf(ma->errmsg, MAXERRMSGLEN, "Internal System Error");
        return -1;
    }

    if (munge_socket) {
        if ((rv = munge_ctx_set (ctx,
                                 MUNGE_OPT_SOCKET,
                                 munge_socket)) != EMUNGE_SUCCESS) {
            syslog(LOG_ERR, "%s: %s", "munge_ctx_set error", munge_strerror(rv));
            snprintf(ma->errmsg, MAXERRMSGLEN, "Internal System Error");
            goto bad2;
        }
    }

    /*
     * The format of our munge buffer is as follows (each a string terminated
     * with a '\0' (null):
     *
     * No stderr wanted if stderr_port_number & random number are 0
     *
     *                                         SIZE            EXAMPLE
     *                                         ==========      =============
     * remote_user_name                        variable        "mhaskell"
     * '\0'
     * version number                          < 12 bytes      "1.2"
     * '\0'
     * dotted_decimal_addr_of_this_server [1]  7-15 bytes      "134.9.11.155"
     * '\0'
     * stderr_port_number                      4-8 bytes       "50111"
     * '\0'
     * random_number                           1-8 bytes       "1f79ca0e"
     * '\0'
     * users_command                           variable        "ls -al"
     * '\0' '\0'
     *
     * [1] - With the exception when 127.0.0.1 or "localhost" are
     * input by the user. In that situation, the MRSH_LOCALHOST_KEY
     * and hostname are concatenated and the size may be much larger
     * than 7-15 bytes.
     */
  
    mptr = &mbuf[0];
    if ((rv = munge_decode(mbuf, ctx, (void **)&mptr, &buf_length, 
                           &ma->uid, &ma->gid)) != EMUNGE_SUCCESS) {
        syslog(LOG_ERR, "%s: %s", "munge_decode error", munge_strerror(rv));
        snprintf(ma->errmsg, MAXERRMSGLEN, "Authentication Failure: %s",
                 munge_strerror(rv));
        goto bad2;
    }
  
    if ((mptr == NULL) || (buf_length <= 0)) {
        syslog(LOG_ERR, "Null munge buffer");
        snprintf(ma->errmsg, MAXERRMSGLEN, "Protocol Error");
        goto bad2;
    }

    m_head = mptr;
    m_end = mptr + buf_length;
  
    /* Verify User Id */

    strncpy(ma->username, m_head, MAXUSERNAMELEN);
    if ((ma->pwd = getpwnam(ma->username)) == NULL) {
        syslog(LOG_ERR, "bad getpwnam(): %m"); 
        snprintf(ma->errmsg, MAXERRMSGLEN, "Permission Denied");
        goto bad;
    }

    /*  Copy struct passwd from this machine into local password
     *  structure, and point "pwd" to it
     */
    _copy_passwd_struct(&(ma->cred), ma->pwd);
    ma->pwd = &(ma->cred);

    if (ma->pwd->pw_uid != ma->uid) {
        if (ma->uid != 0) {
            syslog(LOG_ERR, "failed credential check: %m");
            snprintf(ma->errmsg, MAXERRMSGLEN, "Permission Denied");
            goto bad;
        }
    }

    /* Verify version number */

    if ((m_head = munge_parse(ma, m_head, m_end)) == NULL)
        goto bad;
    
    strncpy(ma->version, m_head, MAXVERSIONLEN);
  
    if (strcmp(ma->version, MRSH_PROTOCOL_VERSION) != 0) {
        syslog(LOG_ERR, 
               "Client protocol version (%s) does not match server version (%s)",
               ma->version, MRSH_PROTOCOL_VERSION);
        snprintf(ma->errmsg, MAXERRMSGLEN, 
                 "Client protocol version (%s) does not match server version (%s)",
                 ma->version, MRSH_PROTOCOL_VERSION);
        goto bad;
    }

    /* Verify IP address */
    
    if ((m_head = munge_parse(ma, m_head, m_end)) == NULL)
        goto bad;

    if ((rv = check_munge_ip(ma, m_head)) < 0)
        goto bad;

    if (rv == 0) {
        syslog(LOG_ERR, "%s: %s","Munge IP address doesn't match", m_head);
        snprintf(ma->errmsg, MAXERRMSGLEN, "Permission Denied");
        goto bad;
    }

    /* Verify Port */

    if ((m_head = munge_parse(ma, m_head, m_end)) == NULL)
        goto bad;

    errno = 0;
    ma->port = strtol(m_head, (char **)NULL, 10);
    if (errno != 0) {
        syslog(LOG_ERR, "%s: %s", "Bad port number from client.", m_head);
        snprintf(ma->errmsg, MAXERRMSGLEN, "Internal Error");
        goto bad;
    }

    if (ma->port != cport) {
        syslog(LOG_ERR, "%s: %d, %d", "Port mismatch", cport, ma->port);
        snprintf(ma->errmsg, MAXERRMSGLEN, "Protocol Error");
        return -1;
    }

    /* Get Random Number */
    
    if ((m_head = munge_parse(ma, m_head, m_end)) == NULL)
        goto bad;

    errno = 0;
    ma->rand = strtol(m_head,(char **)NULL,10);
    if (errno != 0) {
        syslog(LOG_ERR, "%s: %d", "Bad random number from client.", ma->rand);
        snprintf(ma->errmsg, MAXERRMSGLEN, "Internal Error");
        goto bad;
    }
  
    if (cport == 0 && ma->rand != 0) { 
        syslog(LOG_ERR,"protocol error, rand should be 0, %d", ma->rand);
        snprintf(ma->errmsg, MAXERRMSGLEN, "Protocol Error");
        goto bad;
    }

    /* Get Command */

    if ((m_head = munge_parse(ma, m_head, m_end)) == NULL)
        goto bad;
    
    if ((int)strlen(m_head) < ARG_MAX) {
        strncpy(ma->cmd, m_head, ARG_MAX);
        ma->cmd[ARG_MAX - 1] = '\0';
    } else {
        syslog(LOG_ERR, "Not enough space for command: %s", m_head);
        snprintf(ma->errmsg, MAXERRMSGLEN, "Command too long");
        goto bad;
    }

    free(mptr);
    
    snprintf(ma->errmsg, MAXERRMSGLEN, "Success");
    return 0;

 bad:
    free(mptr);
 bad2:
    munge_ctx_destroy(ctx);
    return -1;
}
