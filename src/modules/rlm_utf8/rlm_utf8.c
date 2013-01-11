/*
 * rlm_utf8.c
 *
 * Version:	$Id$
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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  your name <your address>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

/*
 *	Reject any non-UTF8 data.
 */
static rlm_rcode_t utf8_clean(void *instance, REQUEST *request)
{
	size_t i, len;
	VALUE_PAIR *vp, *next;

	/* quiet the compiler */
	instance = instance;

	for (vp = request->packet->vps; vp != NULL; vp = next) {
		next = vp->next;

		if (vp->type != PW_TYPE_STRING) continue;

		for (i = 0; i < vp->length; i += len) {
			len = fr_utf8_char(&vp->vp_octets[i]);
			if (len == 0) return RLM_MODULE_FAIL;
		}
	}

	return RLM_MODULE_NOOP;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_utf8 = {
	RLM_MODULE_INIT,
	"utf8",
	RLM_TYPE_THREAD_SAFE,		/* type */
	NULL,				/* instantiation */
	NULL,				/* detach */
	{
		NULL,		 	/* authentication */
		utf8_clean,		/* authorization */
		utf8_clean,		/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
#ifdef WITH_COA
		, utf8_clean,
		NULL
#endif
	},
};
