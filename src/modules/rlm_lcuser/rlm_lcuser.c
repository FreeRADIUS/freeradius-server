/*
 * rlm_lcuser.c
 *
 * Version:     $Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2009  Gabriel Blanchard <gabe@teksavvy.com>
 *
 * Very simple module to lowercase the Username (PW_USER_NAME) valuepair
 * Can be used to make authentication case-insensitive for users that don't know any better...
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <ctype.h>

static void lowercase(char string[])
{
        int i;

        for (i=0; string[i]; i++) {
                string[i] = tolower(string[i]);
        }
        return;
}


static int lcuser_instantiate(UNUSED CONF_SECTION *conf, UNUSED void **instance)
{
        *instance = NULL;

        return 0;
}

static int lcuser_detach(void *instance)
{
        return 0;
}


static int lcuser_authorize(UNUSED void *instance, REQUEST *request)
{
        VALUE_PAIR *vp;

        vp = pairfind(request->packet->vps, PW_USER_NAME);
        if (vp == NULL) {
                return RLM_MODULE_NOOP;
        }

        lowercase(vp->vp_strvalue);

        return RLM_MODULE_OK;
}


module_t rlm_lcuser = {
        RLM_MODULE_INIT,
        "lcuser",
        RLM_TYPE_THREAD_SAFE,           /* type */
        lcuser_instantiate,             /* instantiation */
        lcuser_detach,                  /* detach */
        {
                NULL,                   /* authentication */
                lcuser_authorize,       /* authorization */
                lcuser_authorize,       /* preaccounting */
                NULL,                   /* accounting */
                NULL,                   /* checksimul */
                NULL,                   /* pre-proxy */
                NULL,                   /* post-proxy */
                NULL                    /* post-auth */
        },
};
