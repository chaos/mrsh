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
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
\*****************************************************************************/

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef USE_PAM
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include "list.h"

char *last_pam_msg = NULL;

int mrsh_conv(int num_msg, const struct pam_message **msg,
              struct pam_response **resp, void *appdata_ptr) {

    /* rcmd/mcmd requires that no data come over the stdout connection
     * before a separate stderr connection has been made.  Therefore,
     * we cannot send PAM_ERROR_MSG or PAM_TEXT_INFO over stdout.
     * Instead, we will store all messages in a list until we are
     * assured of a PAM_FAILURE or PAM_SUCCESS.
     */

    int i = 0;
    struct pam_response *reply;
    
    if (num_msg <= 0)
        return PAM_CONV_ERR;

    reply = (struct pam_response *)malloc(num_msg*sizeof(struct pam_response));
    if (!reply)
        return PAM_CONV_ERR;

    for (i = 0; i < num_msg; i++) {
        char *string = NULL;

        switch (msg[i]->msg_style) {
        case PAM_ERROR_MSG: 
        case PAM_TEXT_INFO:
        {
            char *str = NULL;
            List pam_msgs = *((List *)appdata_ptr);

            if (!(msg[i]->msg))
                return -1;

            if ((str = strdup(msg[i]->msg)) == NULL)
                return -1;

            if (list_append(pam_msgs, (void *)str) == NULL) {
                syslog(LOG_ERR, "list_append failed: %s\n", str);
                free(str);
                return -1;
            }

            last_pam_msg = str;
            break;
        }
        case PAM_BINARY_PROMPT:
        {
            /* More or less ripped from PAM's misc_conv.c */

            /* As of this revision, PAM 0.77 functionality of
             * PAM_BINARY_PROMPT was still under development.  This
             * code is placed here to hopefully be compatible with any
             * existing pam modules that may use PAM_BINARY_PROMPT.
             */

            pamc_bp_t binary_prompt = NULL;

            if (!msg[i]->msg || !pam_binary_handler_fn)
                goto error;

            PAM_BP_RENEW(&binary_prompt,
                         PAM_BP_RCONTROL(msg[i]->msg),
                         PAM_BP_LENGTH(msg[i]->msg));
            PAM_BP_FILL(binary_prompt, 0, PAM_BP_LENGTH(msg[i]->msg),
                        PAM_BP_RDATA(msg[i]->msg));

            if (pam_binary_handler_fn(appdata_ptr,
                                      &binary_prompt) != PAM_SUCCESS
                || (binary_prompt == NULL))
                goto error;

            string = (char *) binary_prompt;
            binary_prompt = NULL;
            
            break;
        }
        case PAM_PROMPT_ECHO_OFF:
        case PAM_PROMPT_ECHO_ON:
            /* Giving the user a prompt for input defeats the purpose
             * of not sending the data over stdout.  A pam module
             * under mrsh should never ask the user for data.  So fall
             * through.
             */
        default:
            syslog(LOG_ERR, "bad conversation: %d", msg[i]->msg_style);
            goto error;
            break;
        }

        /* Must set values, or _pam_drop_reply in pam modules will fail */
        reply[i].resp_retcode = 0;
        if (string != NULL) {
            reply[i].resp = string;
            string = NULL;
        }
        else
            reply[i].resp = NULL;
    }

    *resp = reply;
    reply = NULL;
 
    return PAM_SUCCESS;

 error:
    if (reply) {   
        for (i = 0; i < num_msg; i++) {
            if (reply[i].resp == NULL)
                continue;
            if (msg[i]->msg_style == PAM_BINARY_PROMPT)
                pam_binary_handler_free(appdata_ptr,
                                        (pamc_bp_t *) &reply[i].resp);
            else
                /* Uhh, we shouldn't be able to get here */
                free(reply[i].resp);
            reply[i].resp = NULL;
        }
        free(reply);
        reply = NULL;
    }
    return PAM_CONV_ERR;
}
#endif /* USE_PAM */
