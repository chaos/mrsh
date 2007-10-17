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
 * $Id$
 * $Source$
 * 
 * Started with BSD mcmd.c which is:
 * 
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

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include "version.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/param.h>      /* MAXHOSTNAMELEN */

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#include <munge.h>
#include "fd.h"
#include "common_defs.h"
#include "mcmd.h"

#ifdef HAVE_GETHOSTBYNAME_R
#define HBUF_LEN     1024
#else
extern int h_errno;
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#define LINEBUFSIZE  2048

#ifdef HAVE_PTHREAD
#define SET_PTHREAD()		pthread_sigmask(SIG_BLOCK, &blockme, &oldset)
#define RESTORE_PTHREAD()	pthread_sigmask(SIG_SETMASK, &oldset, NULL)
#else
#define SET_PTHREAD()
#define RESTORE_PTHREAD()	
#endif

/*
 * Derived from the rcmd() libc call, with modified interface.
 * Is MT-safe if gethostbyname_r is defined.  
 * Connection can time out.
 *
 *	ahost (IN)		target hostname
 *      port (IN)               port to connect to
 *	remuser (IN)		remote username
 *	cmd (IN)		remote command to execute under shell
 *	fd2p (IN)		if non NULL, return stderr file descriptor here
 *	int (RETURN)		socket for I/O on success
 */
int 
mcmd(char **ahost, int port, char *remuser, char *cmd, int *fd2p)
{
    struct sockaddr m_socket;
    struct sockaddr_in *getp;
    struct sockaddr_in sin, from;
    struct sockaddr_storage ss;
    struct hostent *h_ent = NULL;
    struct in_addr m_in;
    unsigned int rand, randl;
    unsigned int randy = 0; 
    int s, s2, rv, mcount, lport;
    char c;
    char num[6] = {0};
    char *mptr;
    char *mbuf;
    char *tmbuf;
    char *m;
    char *mpvers;
    char num_seq[12] = {0};
    socklen_t len;
    sigset_t blockme;
    sigset_t oldset;
#ifdef HAVE_GETHOSTBYNAME_R_6
    struct hostent h_entry;
    int h_ent_bsize = HBUF_LEN;
    char h_ent_buf[HBUF_LEN] = {0};
#endif
    int h_ent_err = 0;
    unsigned char *hptr;
    char haddrdot[MAXHOSTNAMELEN + MRSH_LOCALHOST_KEYLEN + 1] = {0};
    munge_ctx_t ctx;

    sigemptyset(&blockme);
    sigaddset(&blockme, SIGURG);
    sigaddset(&blockme, SIGPIPE);
    SET_PTHREAD();

    if (fd2p != NULL) { 
        /*
         * Generate a random number to send in our package to the 
         * server.  We will see it again and compare it when the
         * server sets up the stderr socket and sends it to us.
         * We need to loop for the tiny possibility we read 0 :P
         */
        int rand_fd;
          
        if ((rand_fd = open ("/dev/urandom", O_RDONLY | O_NONBLOCK)) < 0) {
            perror("mcmd: Open of /dev/urandom failed");
            exit(1);
        }
	  
        do {
            if ((rv = read (rand_fd, &randy, sizeof(uint32_t))) < 0) {
                perror("mcmd: Read of /dev/urandom failed");
                close(rand_fd);
                exit(1);
            }
            if (rv < (int) (sizeof(uint32_t))) {
                perror("mcmd: Read returned too few bytes");
                close(rand_fd);
                exit(1);
            }
        } while (randy == 0);
        
        close(rand_fd);
    }

    /* Convert to decimal string, is 0 if we don't want stderr. */
    snprintf(num_seq, sizeof(num_seq),"%d",randy);

    /*
     * Start setup of the stdin/stdout socket...
     */
    lport = 0;
    len = sizeof(struct sockaddr_in);

    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("mcmd: socket call stdout failed");
        exit(1);
    }

    memset (&ss, '\0', sizeof(ss));
    ss.ss_family = AF_INET;

    if (bind(s, (struct sockaddr *)&ss, len) < 0) { 
        perror("mcmd: bind failed");
        goto bad;
    }

    sin.sin_family = AF_INET;

#ifdef HAVE_GETHOSTBYNAME_R_6
    (void) gethostbyname_r(*ahost, &h_entry, &h_ent_buf[0], 
                           h_ent_bsize, &h_ent, &h_ent_err);
#else
    h_ent = gethostbyname(*ahost);
    h_ent_err = h_errno; 
#endif
    if (h_ent == NULL) {
        switch (h_ent_err) {
            case HOST_NOT_FOUND:
                fprintf(stderr,"mcmd: Hostname not found.\n");
                goto bad;
            case NO_ADDRESS:
                fprintf(stderr,"mcmd: Can't find IP address.\n");
                goto bad;
            case NO_RECOVERY:
                fprintf(stderr,"mcmd: A non-recoverable error.\n");
                goto bad;
            case TRY_AGAIN:
                fprintf(stderr,"mcmd: Error on name server.\n");
                goto bad;
            default:
                fprintf(stderr,"mcmd: Unknown error.\n");
                goto bad;
        }
    }

    memcpy(&sin.sin_addr.s_addr, *h_ent->h_addr_list, h_ent->h_length);
    sin.sin_port = port;
    if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("mcmd: connect failed");
        goto bad;
    }

    /* save address in buffer */
    if ((strcmp(*ahost, "localhost") == 0)
        || (strcmp(*ahost, "127.0.0.1") == 0)) {
        /* Special case for localhost  */

        char hostname[MAXHOSTNAMELEN+1];

        memset(hostname, '\0', MAXHOSTNAMELEN+1);
        if (gethostname(hostname, MAXHOSTNAMELEN) < 0) {
            perror("mcmd: gethostname call failed");
            exit(1);
        }

        strncpy(haddrdot, MRSH_LOCALHOST_KEY, MRSH_LOCALHOST_KEYLEN);
        strncat(haddrdot, hostname, MAXHOSTNAMELEN);
    }
    else {
        memcpy(&m_in.s_addr, *h_ent->h_addr_list, h_ent->h_length);
        hptr = (unsigned char *) &m_in;
        sprintf(haddrdot, "%u.%u.%u.%u", hptr[0], hptr[1], hptr[2], hptr[3]);
    }

    lport = 0;
    s2 = -1;
    if (fd2p != NULL) {
        /*
         * Start the socket setup for the stderr.
         */
        struct sockaddr_in sin2;

        if ((s2 = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("mcmd: socket call for stderr failed");
            goto bad;
        }

        memset (&sin2, 0, sizeof(sin2));
        sin2.sin_family = AF_INET;
        sin2.sin_addr.s_addr = htonl(INADDR_ANY);
        sin2.sin_port = 0;
        if (bind(s2, (struct sockaddr *)&sin2, sizeof(sin2)) < 0) {
            perror("mcmd: bind failed");
            close(s2);
            goto bad;
        }
		
        len = sizeof(struct sockaddr);

        /*
         * Retrieve our port number so we can hand it to the server
         * for the return (stderr) connection...
         */
        if (getsockname(s2,&m_socket,&len) < 0) {
            perror("mcmd: getsockname failed");
            close(s2);
            goto bad;
        }

        getp = (struct sockaddr_in *)&m_socket;
        lport = ntohs(getp->sin_port);

        if (listen(s2, 5) < 0) {
            perror("mcmd: listen() failed");
            close(s2);
            goto bad;
        }
    }

    /* put port in buffer. will be 0 if user didn't want stderr */
    snprintf(num,sizeof(num),"%d",lport);

    /*
     * We call munge_encode which will take what we write in and
     * return a pointer to an munged buffer.  What we get back is
     * a null terminated string of encrypted characters.
     * 
     * The format of the unmunged buffer is as follows (each a
     * string terminated with a '\0' (null):
     *
     * stderr_port_number & random_number are 0 if user did not
     * request stderr socket
     *
     *                                     SIZE            EXAMPLE
     *                                     ==========      =============
     * remote_user_name                    variable        "mhaskell"
     * '\0'
     * protocol version                    < 12 bytes      "1.2"
     * '\0'
     * IP address of requestor [1]         7-15 bytes      "134.9.11.155" 
     * '\0'
     * stderr_port_number                  4-8 bytes       "50111"
     * '\0'
     * random_number                       1-8 bytes       "1f79ca0e"
     * '\0'
     * users_command                       variable        "ls -al"
     * '\0' '\0'
     *
     * (The last extra null is accounted for in the following
     * line's last strlen() call.)
     *
     * [1] - With the exception when 127.0.0.1 or "localhost" are
     * input by the user. In that situation, the MRSH_LOCALHOST_KEY
     * and hostname are concatenated and the size may be much larger
     * than 7-15 bytes.
     */

    mpvers = MRSH_PROTOCOL_VERSION;
    
    mcount = ((strlen(remuser)+1) + (strlen(mpvers)+1) + 
              (strlen(haddrdot)+1) + (strlen(num)+1) + 
              (strlen(num_seq)+1) + strlen(cmd)+2);
    tmbuf = mbuf = malloc(mcount);
    if (tmbuf == NULL) {
        perror("mcmd: Error from malloc");
        close(s2);
        goto bad;
    }

    /*
     * The following memset() call takes the extra trailing null
     * as part of its count as well.
     */
    memset(mbuf,0,mcount);

    mptr = strcpy(mbuf, remuser);
    mptr += strlen(remuser)+1;
    mptr = strcpy(mptr, mpvers);
    mptr += strlen(mpvers)+1;
    mptr = strcpy(mptr, haddrdot);
    mptr += strlen(haddrdot)+1;
    mptr = strcpy(mptr, num);
    mptr += strlen(num)+1;
    mptr = strcpy(mptr, num_seq);
    mptr += strlen(num_seq)+1;
    mptr = strcpy(mptr, cmd);

    ctx = munge_ctx_create();
    if ((rv = munge_encode(&m,ctx,mbuf,mcount)) != EMUNGE_SUCCESS) {
        fprintf(stderr,"munge_encode: %s\n", munge_ctx_strerror(ctx));
        munge_ctx_destroy(ctx);
        close(s2);
        free(tmbuf);
        goto bad;
    }
    
    munge_ctx_destroy(ctx);

    mcount = (strlen(m)+1);

    /*
     * Write stderr port in the clear in case we can't decode for
     * some reason (i.e. bad credentials).  May be 0 if user
     * doesn't want stderr.
     */
    if (fd2p != NULL) {
        rv = fd_write_n(s, num, strlen(num)+1);
        if (rv != (ssize_t)(strlen(num)+1)) {
            free(m);
            free(tmbuf);
            if (rv == -1) {
                if (errno == EPIPE)
                    perror("mcmd: Lost connection (EPIPE)");
                else
                    perror("mcmd: Write of stderr port");
            }
            else
                fprintf(stderr, "mcmd: write incorrect number of bytes.\n");
            close(s2);
            goto bad;
        }
    }
    else {
        write(s, "", 1);
        lport = 0;
    }
    
    /*
     * Write the munge_encoded blob to the socket.
     */
    if ((rv = fd_write_n(s, m, mcount)) != mcount) {
        free(m);
        free(tmbuf);
        if (rv == -1) {
            if (errno == EPIPE)
                perror("mcmd: Lost connection (EPIPE)");
            else
                perror("mcmd: Write of munge data");
        }
        else
            fprintf(stderr, "mcmd: write incorrect number of bytes.\n");
        close(s2);
        goto bad;
    }

    free(m);
    free(tmbuf);

    if (fd2p != NULL) {
        /* 
         * Wait for stderr connection from daemon.  
         */
        int maxfd, s3; 
        fd_set reads;
        
        errno = 0;
        FD_ZERO(&reads);
        FD_SET(s, &reads);
        FD_SET(s2, &reads);
        maxfd = (s > s2) ? s : s2;
        if (select(maxfd + 1, &reads, 0, 0, 0) < 1 || !FD_ISSET(s2, &reads)) {
            if (errno != 0)
                perror("mcmd: Select failed (setting up stderr)");
            else {
                char buf[100];
                int rv = read(s, buf, 100);
                if (rv == 0)
                    fprintf(stderr, "mcmd: Connection closed by remote host.\n");
                else if (rv > 0) 
                    fprintf(stderr, "mcmd: Protocol failure in circuit setup.\n");
                else /* rv < 0 */
                    fprintf(stderr, "mcmd: %s\n", strerror(errno));
            }
            close(s2);
            goto bad;
        }

        errno = 0;
        len = sizeof(from); /* arg to accept */
        
        if ((s3 = accept(s2, (struct sockaddr *)&from, &len)) < 0) {
            perror("mcmd: accept (stderr) failed");
            close(s2);
            goto bad;
        }

        if (from.sin_family != AF_INET) {
            fprintf(stderr, "mcmd: bad family type: %d\n", from.sin_family);
            goto bad2;      
        }

        close(s2);

        /*
         * The following fixes a race condition between the daemon
         * and the client.  The daemon is waiting for a null to
         * proceed.  We do this to make sure that we have our
         * socket is up prior to the daemon running the command.
         */
        if (write(s,"",1) != 1) { 
            perror("mcmd: Could not communicate to daemon to proceed");
            close(s3);
            goto bad;
        }

        /*
         * Read from our stderr.  The server should have placed
         * our random number we generated onto this socket.
         */
        rv = fd_read_n(s3, &rand, sizeof(rand));
        if (rv <= 0) {
            if (rv == 0)
                perror("mcmd: Connection closed by remote host");
            else
                perror("mcmd: Bad read of verification number");
            close(s3);
            goto bad;
        }

        randl = ntohl(rand);
        if (randl != randy) {
            char tmpbuf[LINEBUFSIZE] = {0};
            char *tptr = &tmpbuf[0];

            memcpy(tptr,(char *) &rand,sizeof(rand));
            tptr += sizeof(rand);
            if ((fd_read_line (s3, tptr, LINEBUFSIZE - sizeof(rand))) < 0) {
                perror("mcmd: Read error from remote host");
                close(s3);
                goto bad;
            }
            /* Legacy rsh may consider the first byte an error code,
             * so don't output this byte.
             */
            if (tmpbuf[0] == '\01')
              tptr = &tmpbuf[1];
            else
              tptr = &tmpbuf[0];
            fprintf(stderr,"mcmd error returned: %s\n", tptr);
            close(s3);
            goto bad;
        }

        /*
         * Set the stderr file descriptor for the user...
         */
        *fd2p = s3;
    }

    if ((rv = read(s, &c, 1)) < 0) {
        perror("mcmd: read: protocol failure"); 
        goto bad2;
    }

    if (rv != 1) {
        fprintf(stderr, "mcmd: read: protocol failure: invalid response.\n");
        goto bad2;
    }

    if (c != '\0') {
        /* retrieve error string from remote server */
        char tmpbuf[LINEBUFSIZE];
      
        if (fd_read_line (s, &tmpbuf[0], LINEBUFSIZE ) < 0) {
            perror("mcmd: Error from remote host");
            goto bad2;
        }
        fprintf(stderr,"mcmd error returned: %s\n",&tmpbuf[0]);
        goto bad2;
    }
    RESTORE_PTHREAD();
    return (s);

 bad2:
    if (lport)
        close(*fd2p);
 bad:
    close(s);
    RESTORE_PTHREAD();
    exit(1);
}
