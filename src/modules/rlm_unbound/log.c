/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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

/**
 * $Id$
 * @file rlm_unbound/log.c
 * @brief Provides interface between libunbound and the FreeRADIUS event loop
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_unbound - "

#include <freeradius-devel/util/syserror.h>
#include "log.h"

/** Write libunbound output to the server or request log
 *
 * @param[in] cookie	The current thread.
 * @param[in] buf	Log message from unbound.
 * @param[in] size	Length of log message.
 */
static ssize_t _unbound_log_write(void *cookie, char const *buf, size_t size)
{
	unbound_log_t	*u_log = talloc_get_type_abort(cookie, unbound_log_t);
	REQUEST		*request = u_log->request;
	size_t		len = size;

	if (len == 0) return len;
	if (buf[len - 1] == '\n') len--;	/* Trim trailing new line */

	ROPTIONAL(RDEBUG, DEBUG, "%pV", fr_box_strvalue_len(buf, len));

	return size;
}

/** Set the debug level for a ub_ctx from the request or global debug level
 *
 * @param[in] ub	Unbound context to set log level for.
 * @param[in] lvl 	To set.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int unbound_log_lvl_set(struct ub_ctx *ub, fr_log_lvl_t lvl)
{
	int ret;
	int level;

	switch (lvl) {
	case L_DBG_LVL_DISABLE:
	case L_DBG_LVL_OFF:
	case L_DBG_LVL_1:
		level = 0;
		break;

	case L_DBG_LVL_2:
		level = 1;
		break;

	case L_DBG_LVL_3:
		level = 2;	/* Mid-to-heavy levels of output */
		break;

	case L_DBG_LVL_4:
		level = 3;	/* Pretty crazy amounts of output */
		break;

	case L_DBG_LVL_MAX:
	default:
		level = 4;	/* Insane amounts of output including crypts */
		break;
	}

	ret = ub_ctx_debuglevel(ub, level);
	if (ret != 0) {
	        ERROR("Failed setting unbound log level to %i", level);
	        return -1;
	}

	return 0;
}

/** Switch thread-specific libunbound output to the request log destination(s)
 *
 */
int unbound_log_to_request(unbound_log_t *u_log, struct ub_ctx *ub, REQUEST *request)
{
	u_log->request = request;
	return unbound_log_lvl_set(ub, request->log.lvl);
}

/** Switch thread-specific libunbound output to the global log
 *
 * Must be called before a function that previously called #unbound_log_to_request
 * yields, or can no longer be certain that the REQUEST * set in t->request
 * is still valid.
 */
int unbound_log_to_global(unbound_log_t *u_log, struct ub_ctx *ub)
{
	u_log->request = NULL;
	return unbound_log_lvl_set(ub, fr_debug_lvl);
}

static int _unbound_log_free(unbound_log_t *u_log)
{
	if (u_log->stream) fclose(u_log->stream);
	return 0;
}

/** Setup an unbound context for log, and initialise a u_log struct
 *
 */
int unbound_log_init(TALLOC_CTX *ctx, unbound_log_t **u_log_out, struct ub_ctx *ub)
{
	char		opt[64]; /* To silence const warns until newer unbound in distros */
	char		*val;
	unbound_log_t	*u_log;
	int		ret;

	/*
	 *	Check if the user tried to configure
	 *	a log destination, and disable it
	 *	if they did.
	 */
	strcpy(opt, "use-syslog");
	ret = ub_ctx_get_option(ub, opt, &val);
	if ((ret != 0) || !val) {
		ERROR("Failed retrieving unbound syslog settings: %s", ub_strerror(ret));
		return -1;
	}

	if (strcmp(val, "yes") == 0) {
		char vbuff[3];

		strcpy(opt, "use-syslog:");
		strcpy(vbuff, "no");

		WARN("Disabling unbound syslog output (%s %s) > (%s %s)", opt, val, opt, vbuff);

		ret = ub_ctx_set_option(ub, opt, vbuff);
		if (ret != 0) {
			ERROR("Failed disabling unbound syslog output: %s", ub_strerror(ret));
			free(val);
			return -1;
		}
	}
	free(val);

	strcpy(opt, "logfile");
	ret = ub_ctx_get_option(ub, opt, &val);
	if ((ret != 0) || !val) {
		ERROR("Failed retrieving unbound logfile settings: %s", ub_strerror(ret));
		return -1;
	}

	if (strcmp(val, "yes") == 0) {
		char vbuff[3];

		WARN("Disabling unbound logfile output (%s %s) > (%s %s)", opt, val, opt, vbuff);
		strcpy(opt, "logfile:");
		strcpy(vbuff, "no");

		ret = ub_ctx_set_option(ub, opt, vbuff);
		if (ret != 0) {
			ERROR("Failed disabling unbound logfile output: %s", ub_strerror(ret));
			free(val);
			return -1;
		}
	}
	free(val);

	MEM(u_log = talloc_zero(ctx, unbound_log_t));

	/*
	 *	Open a FILE stream, and associate a write
	 *      function with it, which then call's
	 *	FreeRADIUS' log functions.
	 */
	u_log->stream = fopencookie(u_log, "w", (cookie_io_functions_t){ .write = _unbound_log_write });
	if (!u_log->stream) {
		ERROR("Failed creating log stream for unbound: %s", fr_syserror(errno));
		talloc_free(u_log);
		return -1;
	}
	talloc_set_destructor(u_log, _unbound_log_free);	/* Close stream when log struct is freed */
	setlinebuf(u_log->stream);

	ret = ub_ctx_debugout(ub, u_log->stream);
	if (ret != 0) {
		ERROR("Failed setting log stream for unbound: %s", ub_strerror(ret));
		talloc_free(u_log);
		return -1;
	}

	/*
	 *	Set the initial log level and destination
	 */
	ret = unbound_log_to_global(u_log, ub);
	if (ret < 0) {
		talloc_free(u_log);
		return -1;
	}

	*u_log_out = u_log;

	return 0;
}
