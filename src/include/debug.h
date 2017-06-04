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
#ifndef _FR_DEBUG_H
#define _FR_DEBUG_H
/*
 * $Id$
 *
 * @file include/debug.h
 * @brief Debugging function definitions and structures.
 *
 * @copyright 2015-2017 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <freeradius-devel/fring.h>

typedef enum {
	DEBUGGER_STATE_UNKNOWN_NO_PTRACE	= -3,	//!< We don't have ptrace so can't check.
	DEBUGGER_STATE_UNKNOWN_NO_PTRACE_CAP	= -2,	//!< CAP_SYS_PTRACE not set for the process.
	DEBUGGER_STATE_UNKNOWN			= -1,	//!< Unknown, likely fr_get_debug_state() not called yet.
	DEBUGGER_STATE_NOT_ATTACHED		= 0,	//!< We can attach, so a debugger must not be.
	DEBUGGER_STATE_ATTACHED			= 1	//!< We can't attach, it's likely a debugger is already tracing.
} fr_debug_state_t;

extern fr_debug_state_t fr_debug_state;

#define FR_FAULT_LOG(fmt, ...) fr_fault_log(fmt "\n", ## __VA_ARGS__)
typedef void (*fr_fault_log_t)(char const *msg, ...) CC_HINT(format (printf, 1, 2));

/** Optional callback passed to fr_fault_setup
 *
 * Allows optional logic to be run before calling the main fault handler.
 *
 * If the callback returns < 0, the main fault handler will not be called.
 *
 * @param signum signal raised.
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
typedef int (*fr_fault_cb_t)(int signum);
typedef struct fr_bt_marker fr_bt_marker_t;

void		fr_debug_state_store(void);
char const	*fr_debug_state_to_msg(fr_debug_state_t state);
void		fr_debug_break(bool always);
void		backtrace_print(fr_fring_t *fring, void *obj);
int		fr_backtrace_do(fr_bt_marker_t *marker);
fr_bt_marker_t	*fr_backtrace_attach(fr_fring_t **fring, TALLOC_CTX *obj);

void		fr_panic_on_free(TALLOC_CTX *ctx);
int		fr_set_dumpable_init(void);
int		fr_set_dumpable(bool allow_core_dumps);
int		fr_reset_dumpable(void);
int		fr_log_talloc_report(TALLOC_CTX *ctx);
void		fr_fault(int sig);
void		fr_talloc_fault_setup(void);
int		fr_fault_setup(char const *cmd, char const *program);
void		fr_fault_set_cb(fr_fault_cb_t func);
void		fr_fault_set_log_fd(int fd);
void		fr_fault_log(char const *msg, ...) CC_HINT(format (printf, 1, 2));
bool		fr_cond_assert_fail(char const *file, int line, char const *expr);

/** Calls panic_action ifndef NDEBUG, else logs error and evaluates to value of _x
 *
 * Should be wrapped in a condition, and if false, should cause function to return
 * an error code.  This allows control to return to the caller if a precondition is
 * not satisfied and we're not debugging.
 *
 * Example:
 @verbatim
   if (!fr_cond_assert(request)) return -1
 @endverbatim
 *
 * @param _x expression to test (should evaluate to true)
 */
#define		fr_cond_assert(_x) (bool)((_x) ? true : (fr_cond_assert_fail(__FILE__,  __LINE__, #_x) && false))

void		NEVER_RETURNS _fr_exit(char const *file, int line, int status);
#  define	fr_exit(_x) _fr_exit(__FILE__,  __LINE__, (_x))

void		NEVER_RETURNS _fr_exit_now(char const *file, int line, int status);
#  define	fr_exit_now(_x) _fr_exit_now(__FILE__,  __LINE__, (_x))
#endif /* _FR_DEBUG_H */
