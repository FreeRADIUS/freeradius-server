/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 of the
 *   License as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Functions to deal with Linux capabilities
 *
 * @file src/lib/util/cap.c
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2020 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

#ifdef HAVE_CAPABILITY_H
#include <freeradius-devel/util/cap.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>

/** Set CAP_NET_* if possible.
 *
 * A negative return from this function should NOT always
 * be interpreted as an error.  The server MAY already be running as
 * root, OR the system may not support CAP_NET_RAW.  It is almost
 * always better to use a negative return value to print a warning
 * message as to why CAP_NET_RAW was not set.
 *
 * @return
 *	- <0 on "cannot set it"
 *	- 0 on "can set it"
 */
int fr_cap_set(cap_value_t cap)
{
	int			rcode = -1;
	cap_t			caps;
	cap_flag_value_t	state;

	caps = cap_get_proc();
	if (!caps) {
		fr_strerror_printf("Failed getting process capabilities: %s", fr_syserror(errno));
		goto done;
	}

	if (cap_get_flag(caps, cap, CAP_PERMITTED, &state) < 0) {
		char *cap_name = cap_to_name(cap);
		fr_strerror_printf("Failed getting %s permitted state: %s", cap_name, fr_syserror(errno));
		cap_free(cap_name);
		goto done;
	}

	/*
	 *	We're not permitted to set the capability
	 */
	if (state == CAP_CLEAR) {
		char *cap_name = cap_to_name(cap);
		fr_strerror_printf("This program may not function correctly it lacks the %s capability", cap_name);
		fr_strerror_printf_push("Use the following command to allow this capability "
					"setcap %s+ep <path_to_binary>", cap_name);
		cap_free(cap_name);
		goto done;
	}

	if (cap_get_flag(caps, cap, CAP_EFFECTIVE, &state) < 0) {
		char *cap_name = cap_to_name(cap);
		fr_strerror_printf("Failed getting %s effective state: %s", cap_name, fr_syserror(errno));
		cap_free(cap_name);
		goto done;
	}

	/*
	 *	Permitted bit is high effective bit is low, see
	 *	if we can fix that.
	 */
	if (state == CAP_CLEAR) {
		cap_value_t const to_set[] = {
			cap
		};

		if (cap_set_flag(caps, CAP_EFFECTIVE, NUM_ELEMENTS(to_set), to_set, CAP_SET) < 0) {
			char *cap_name = cap_to_name(cap);
			fr_strerror_printf("Failed setting %s effective state: %s", cap_name, fr_syserror(errno));
			cap_free(cap_name);
			goto done;
		}

		rcode = 0;
	/*
	 *	It's already in the effective set
	 */
	} else if (state == CAP_SET) {
		rcode = 0;
	}

done:
	if (caps) cap_free(caps);

	return rcode;
}
#endif	/* HAVE_CAPABILITY_H */
