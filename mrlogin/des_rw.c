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
 * Copyright (c) 1989 The Regents of the University of California.
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

#ifndef lint
static char sccsid[] = "@(#)des_rw.c	5.8 (Berkeley) 2/25/91";
#endif /* not lint */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef CRYPT
#ifdef KERBEROS
#include <sys/param.h>
#include <kerberosIV/des.h>
#include <kerberosIV/krb.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

extern long		random();
static unsigned char	des_inbuf[10240], storage[10240], *store_ptr;
static bit_64		*key;
static u_char		*key_schedule;

/*
 * NB: These routines will not function properly if NBIO
 * 	is set
 */

/*
 * des_set_key
 *
 * Set des encryption/decryption key for use by the des_read and
 * des_write routines
 *
 * The inkey parameter is actually the DES initial vector,
 * and the insched is the DES Key unwrapped for faster decryption
 */

void
des_set_key(inkey, insched)
	bit_64		*inkey;
	u_char		*insched;
{
	key = inkey;
	key_schedule = insched;
}

void
des_clear_key()
{
	bzero((char *) key, sizeof(C_Block));
	bzero((char *) key_schedule, sizeof(Key_schedule));
}
	

int
des_read(fd, buf, len)
	int fd;
	register char *buf;
	int len;
{
	int nreturned = 0;
	long net_len, rd_len;
	int nstored = 0;

	if (nstored >= len) {
		(void) bcopy(store_ptr, buf, len);
		store_ptr += len;
		nstored -= len;
		return(len);
	} else if (nstored) {
		(void) bcopy(store_ptr, buf, nstored);
		nreturned += nstored;
		buf += nstored;
		len -= nstored;
		nstored = 0;
	}
	
	if (krb_net_read(fd, &net_len, sizeof(net_len)) != sizeof(net_len)) {
		/* XXX can't read enough, pipe
		   must have closed */
		return(0);
	}
	net_len = ntohl(net_len);
	if (net_len <= 0 || net_len > sizeof(des_inbuf)) {
		/* preposterous length; assume out-of-sync; only
		   recourse is to close connection, so return 0 */
		return(0);
	}
	/* the writer tells us how much real data we are getting, but
	   we need to read the pad bytes (8-byte boundary) */
	rd_len = roundup(net_len, 8);
	if (krb_net_read(fd, des_inbuf, rd_len) != rd_len) {
		/* pipe must have closed, return 0 */
		return(0);
	}
	(void) des_pcbc_encrypt(des_inbuf,	/* inbuf */
			    storage,		/* outbuf */
			    net_len,		/* length */
			    key_schedule,	/* DES key */
			    key,		/* IV */
			    DECRYPT);		/* direction */

	if(net_len < 8)
		store_ptr = storage + 8 - net_len;
	else
		store_ptr = storage;

	nstored = net_len;
	if (nstored > len) {
		(void) bcopy(store_ptr, buf, len);
		nreturned += len;
		store_ptr += len;
		nstored -= len;
	} else {
		(void) bcopy(store_ptr, buf, nstored);
		nreturned += nstored;
		nstored = 0;
	}
	
	return(nreturned);
}

static	unsigned char des_outbuf[10240];	/* > longest write */

int
des_write(fd, buf, len)
	int fd;
	char *buf;
	int len;
{
	static	int	seeded = 0;
	static	char	garbage_buf[8];
	long net_len, garbage;

	if(len < 8) {
		if(!seeded) {
			seeded = 1;
			srandom((int) time((long *)0));
		}
		garbage = random();
		/* insert random garbage */
		(void) bcopy(&garbage, garbage_buf, MIN(sizeof(long),8));
		/* this "right-justifies" the data in the buffer */
		(void) bcopy(buf, garbage_buf + 8 - len, len);
	}
	/* pcbc_encrypt outputs in 8-byte (64 bit) increments */

	(void) des_pcbc_encrypt((len < 8) ? garbage_buf : buf,
			    des_outbuf,
			    (len < 8) ? 8 : len,
			    key_schedule,	/* DES key */
			    key,		/* IV */
			    ENCRYPT);

	/* tell the other end the real amount, but send an 8-byte padded
	   packet */
	net_len = htonl(len);
	(void) write(fd, &net_len, sizeof(net_len));
	(void) write(fd, des_outbuf, roundup(len,8));
	return(len);
}
#endif /* KERBEROS */
#endif /* CRYPT */
