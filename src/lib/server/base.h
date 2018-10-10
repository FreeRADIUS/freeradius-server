#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/server/base.h
 * @brief Structures, prototypes and global variables for the FreeRADIUS server.
 *
 * @copyright 1999-2000,2002-2008  The FreeRADIUS server project
 */
RCSIDH(radiusd_h, "$Id$")

#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/client.h>
#include <freeradius-devel/server/dependency.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/paircmp.h>
#include <freeradius-devel/server/process.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/server/realms.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/stats.h>
#include <freeradius-devel/server/trigger.h>
#include <freeradius-devel/server/util.h>

#include <freeradius-devel/util/base.h>

/*
 *  Let any external program building against the library know what
 *  features the library was built with.
 */
#include <freeradius-devel/features.h>

/*
 *	All POSIX systems should have these headers
 */
#include <pwd.h>
#include <grp.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WITH_TCP
#  include <freeradius-devel/server/tcp.h>
#endif

/*
 *	See util.c
 */
#define EXEC_TIMEOUT		10

/*
 *	Global variables.
 *
 *	We really shouldn't have this many.
 */
extern fr_log_lvl_t	rad_debug_lvl;
extern fr_log_lvl_t	req_debug_lvl;
extern char const	*radiusd_version;
extern char const	*radiusd_version_short;



/*
 *	Function prototypes.
 */


/* radiusd.c */
int		log_err (char *);

/* auth.c */
rlm_rcode_t    	rad_authenticate (REQUEST *);
rlm_rcode_t    	rad_postauth(REQUEST *);
rlm_rcode_t    	rad_virtual_server(REQUEST *);

/* exec.c */
extern pid_t	(*rad_fork)(void);
extern pid_t	(*rad_waitpid)(pid_t pid, int *status);

pid_t radius_start_program(char const *cmd, REQUEST *request, bool exec_wait,
			   int *input_fd, int *output_fd,
			   VALUE_PAIR *input_pairs, bool shell_escape);
int radius_readfrom_program(int fd, pid_t pid, int timeout,
			    char *answer, int left);
int radius_exec_program(TALLOC_CTX *ctx, char *out, size_t outlen, VALUE_PAIR **output_pairs,
			REQUEST *request, char const *cmd, VALUE_PAIR *input_pairs,
			bool exec_wait, bool shell_escape, int timeout) CC_HINT(nonnull (5, 6));

/** Allocate a VALUE_PAIR in the request list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_add_request(_attr, _da) fr_pair_add_by_da(request->packet, _attr, &request->packet->vps, _da)

/** Allocate a VALUE_PAIR in the reply list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_add_reply(_attr, _da) fr_pair_add_by_da(request->reply, _attr, &request->reply->vps, _da)

/** Allocate a VALUE_PAIR in the control list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_add_control(_attr, _da) fr_pair_add_by_da(request, _attr, &request->control, _da)

/** Return or allocate a VALUE_PAIR in the request list
 *
 * @param[in] _attr	allocated or found.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
#define pair_update_request(_attr, _da) fr_pair_update_by_da(request->packet, _attr, &request->packet->vps, _da)

/** Return or allocate a VALUE_PAIR in the reply list
 *
 * @param[in] _attr	allocated or found.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
#define pair_update_reply(_attr, _da) fr_pair_update_by_da(request->reply, _attr, &request->reply->vps, _da)

/** Return or allocate a VALUE_PAIR in the control list
 *
 * @param[in] _attr	allocated or found.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
#define pair_update_control(_attr, _da) fr_pair_update_by_da(request, _attr, &request->control, _da)

/** Return or allocate a VALUE_PAIR in the request list
 *
 * @param[in] _da	#fr_dict_attr_t of the pair(s) to be deleted.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
#define pair_delete_request(_da) fr_pair_delete_by_da(&request->packet->vps, _da)

/** Return or allocate a VALUE_PAIR in the reply list
 *
 * @param[in] _da	#fr_dict_attr_t of the pair(s) to be deleted.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
#define pair_delete_reply(_da) fr_pair_delete_by_da(&request->reply->vps, _da)

/** Return or allocate a VALUE_PAIR in the control list
 *
 * @param[in] _da	#fr_dict_attr_t of the pair(s) to be deleted.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
#define pair_delete_control(_da) fr_pair_delete_by_da(&request->control, _da)


#ifdef __cplusplus
}
#endif
