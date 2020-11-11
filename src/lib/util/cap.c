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
#include <freeradius-devel/util/table.h>

#include <pthread.h>

static fr_table_num_sorted_t const cap_set_table[] = {
	{ L("effective"),	CAP_EFFECTIVE	},
	{ L("inherited"),	CAP_INHERITABLE	},
	{ L("permitted"),	CAP_PERMITTED	}
};
size_t cap_set_table_len = NUM_ELEMENTS(cap_set_table);

/** Ensure we don't loose updates, and the threads have a consistent view of the capability set
 *
 * This is needed because capabilities are process wide, but may be modified by multiple threads.
 */
static pthread_mutex_t	cap_mutex = PTHREAD_MUTEX_INITIALIZER;

/** Return whether a given capability is in a capabilities set
 *
 * @param[in] cap	to query.
 * @param[in] set	One of the following sets of capabilities:
 *			- CAP_EFFECTIVE		capabilities we currently have.
 *			- CAP_INHERITABLE	capabilities inherited across exec.
 *			- CAP_PERMITTED		capabilities we can request.
 * @return
 *	- true if CAP_SET (enabled) in the specified set.
 *	- false if CAP_CLEAR (disabled) in the specified set.
 */
bool fr_cap_is_enabled(cap_value_t cap, cap_flag_t set)
{
	cap_t			caps;
	cap_flag_value_t	state = CAP_CLEAR;

	pthread_mutex_lock(&cap_mutex);

	caps = cap_get_proc();
	if (!caps) {
		fr_strerror_printf("Failed getting process capabilities: %s", fr_syserror(errno));
		goto done;
	}

	if (cap_get_flag(caps, cap, CAP_EFFECTIVE, &state) < 0) {
		char *cap_name = cap_to_name(cap);
		fr_strerror_printf("Failed getting %s %s state from working set: %s",
				   cap_name,
				   fr_table_str_by_value(cap_set_table, set, "<INVALID>"),
				   fr_syserror(errno));
		cap_free(cap_name);
		goto done;
	}

done:
	pthread_mutex_unlock(&cap_mutex);

	if (caps) cap_free(caps);

	return (state == CAP_SET);
}

/** Add a CAP_* to the effective or inheritable set
 *
 * A negative return from this function should NOT always
 * be interpreted as an error.  The server MAY already be running as
 * root, OR the system may not support CAP_*.  It is almost
 * always better to use a negative return value to print a warning
 * message as to why CAP_* was not set.
 *
 * @param[in] cap	to enable.
 * @param[in] set	One of the following sets of capabilities:
 *			- CAP_EFFECTIVE		capabilities we currently have.
 *			- CAP_INHERITABLE	capabilities inherited across exec.
 * @return
 *	- <0 on "cannot set it"
 *	- 0 on "can set it (or it was already set)"
 */
int fr_cap_enable(cap_value_t cap, cap_flag_t set)
{
	int			ret = -1;
	cap_t			caps = NULL;
	cap_flag_value_t	state;

	/*
	 *	This function may be called by multiple
	 *      threads each binding to their own network
	 *	sockets.  There's no guarantee that those
	 *	threads will be requesting the same
	 *	capabilities at the same time, so we could
	 *	suffer from a lost update problem.
	 */
	pthread_mutex_lock(&cap_mutex);

	if (set == CAP_PERMITTED) {
		fr_strerror_printf("Can't modify permitted capabilities");
		goto done;
	}

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
		/*
		 *	Messages printed in the inverse order
		 *	to the order they're printed.
		 */
		fr_strerror_printf("Use \"setcap %s+ep <path_to_binary>\" to grant the %s capability",
				   cap_name, cap_name);
		cap_free(cap_name);
		goto done;
	}

	if (cap_get_flag(caps, cap, set, &state) < 0) {
		char *cap_name = cap_to_name(cap);
		fr_strerror_printf("Failed getting %s %s state from working set: %s",
				   cap_name,
				   fr_table_str_by_value(cap_set_table, set, "<INVALID>"),
				   fr_syserror(errno));
		cap_free(cap_name);
		goto done;
	}

	/*
	 *	Permitted bit is high but the capability
	 *      isn't in the specified set, see if we can
	 *	fix that.
	 */
	if (state == CAP_CLEAR) {
		cap_value_t const to_set[] = {
			cap
		};

		if (cap_set_flag(caps, set, NUM_ELEMENTS(to_set), to_set, CAP_SET) < 0) {
			char *cap_name = cap_to_name(cap);
			fr_strerror_printf("Failed setting %s %s state in working set: %s",
					   cap_name,
					   fr_table_str_by_value(cap_set_table, set, "<INVALID>"),
					   fr_syserror(errno));
			cap_free(cap_name);
			goto done;
		}

		if (cap_set_proc(caps) < 0) {
			char *cap_name = cap_to_name(cap);
			fr_strerror_printf("Failed setting %s %s state: %s",
					   cap_name,
					   fr_table_str_by_value(cap_set_table, set, "<INVALID>"),
					   fr_syserror(errno));
			cap_free(cap_name);
			goto done;
		}

		ret = 0;
	/*
	 *	It's already in the effective set
	 */
	} else if (state == CAP_SET) {
		ret = 0;
	}

done:
	pthread_mutex_unlock(&cap_mutex);

	if (caps) cap_free(caps);

	return ret;
}

/** Remove a CAP_* from the permitted, effective or inheritable set
 *
 * @param[in] cap	to disable.
 * @param[in] set	One of the following sets of capabilities:
 *			- CAP_EFFECTIVE		capabilities we currently have.
 *			- CAP_INHERITABLE	capabilities inherited across exec.
 *			- CAP_PERMITTED		capabilities we can request.
 * @return
 *	- <0 on "cannot unset it"
 *	- 0 on "unset it (or it was already set)"
 */
int fr_cap_disable(cap_value_t cap, cap_flag_t set)
{
	int			ret = -1;
	cap_t			caps;
	cap_flag_value_t	state;

	/*
	 *	This function may be called by multiple
	 *      threads each binding to their own network
	 *	sockets.  There's no guarantee that those
	 *	threads will be requesting the same
	 *	capabilities at the same time, so we could
	 *	suffer from a lost update problem.
	 */
	pthread_mutex_lock(&cap_mutex);

	caps = cap_get_proc();
	if (!caps) {
		fr_strerror_printf("Failed getting process capabilities: %s", fr_syserror(errno));
		goto done;
	}

	if (cap_get_flag(caps, cap, set, &state) < 0) {
		char *cap_name = cap_to_name(cap);
		fr_strerror_printf("Failed getting %s %s state from working set: %s",
				   cap_name,
				   fr_table_str_by_value(cap_set_table, set, "<INVALID>"),
				   fr_syserror(errno));
		cap_free(cap_name);
		goto done;
	}

	if (state == CAP_SET) {
		if (cap_clear_flag(caps, set) < 0) {
			char *cap_name = cap_to_name(cap);
			fr_strerror_printf("Failed clearing %s %s state in working set: %s",
					   cap_name,
					   fr_table_str_by_value(cap_set_table, set, "<INVALID>"),
					   fr_syserror(errno));
			cap_free(cap_name);
			goto done;
		}

		if (cap_set_proc(caps) < 0) {
			char *cap_name = cap_to_name(cap);
			fr_strerror_printf("Failed setting %s %s state: %s",
					   cap_name,
					   fr_table_str_by_value(cap_set_table, set, "<INVALID>"),
					   fr_syserror(errno));
			cap_free(cap_name);
			goto done;
		}

		ret = 0;
	} else {
		ret = 0;
	}

done:
	pthread_mutex_unlock(&cap_mutex);

	if (caps) cap_free(caps);

	return ret;
}
#endif	/* HAVE_CAPABILITY_H */
