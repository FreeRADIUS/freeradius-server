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

/** Debugging function definitions and structures
 *
 * @file src/lib/util/debug.h
 *
 * @copyright 2015-2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/fring.h>

#ifdef NO_ASSERT
# define MEM(x) error "Use of MEM() not allowed in this source file.  Deal with memory allocation failure gracefully"
#else
# define MEM(x) do { if (!(x)) { fr_cond_assert_msg((x), "OUT OF MEMORY"); _fr_exit(__FILE__, __LINE__, EXIT_FAILURE, true); } } while (0)
#endif

typedef enum {
	DEBUGGER_STATE_UNKNOWN_NO_PTRACE	= -3,	//!< We don't have ptrace so can't check.
	DEBUGGER_STATE_UNKNOWN_NO_PTRACE_CAP	= -2,	//!< CAP_SYS_PTRACE not set for the process.
	DEBUGGER_STATE_UNKNOWN			= -1,	//!< Unknown, likely fr_get_debug_state() not called yet.
	DEBUGGER_STATE_NOT_ATTACHED		= 0,	//!< We can attach, so a debugger must not be.
	DEBUGGER_STATE_ATTACHED			= 1	//!< We can't attach, it's likely a debugger is already tracing.
} fr_debug_state_t;

extern fr_debug_state_t fr_debug_state;

#define FR_FAULT_LOG(_fmt, ...)			fr_fault_log(_fmt "\n", ## __VA_ARGS__)
#define FR_FAULT_LOG_HEX(_data, _data_len)	fr_fault_log_hex(_data, _data_len)

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

int			fr_get_lsan_state(void);

int			fr_get_debug_state(void);

void			fr_debug_state_store(void);

char const		*fr_debug_state_to_msg(fr_debug_state_t state);

void			fr_debug_break(bool always);

void			backtrace_print(fr_fring_t *fring, void *obj);

int			fr_backtrace_do(fr_bt_marker_t *marker);

fr_bt_marker_t		*fr_backtrace_attach(fr_fring_t **fring, TALLOC_CTX *obj);

void			fr_panic_on_free(TALLOC_CTX *ctx);

int			fr_set_dumpable_init(void);

int			fr_set_dumpable(bool allow_core_dumps);

int			fr_reset_dumpable(void);

int			fr_log_talloc_report(TALLOC_CTX const *ctx);

void			fr_fault(int sig);

void			fr_talloc_fault_setup(void);

void			fr_disable_null_tracking_on_free(TALLOC_CTX *ctx);

int			fr_fault_setup(TALLOC_CTX *ctx, char const *cmd, char const *program);

void			fr_fault_set_cb(fr_fault_cb_t func);

void			fr_fault_set_log_fd(int fd);

void			fr_fault_log(char const *msg, ...) CC_HINT(format (printf, 1, 2));

void			fr_fault_log_hex(uint8_t const *data, size_t data_len);

/** @name Assertion support functions
 * @{
 */
bool			_fr_assert_fail(char const *file, int line, char const *expr, char const *msg, ...)
			CC_HINT(format (printf, 4, 5));

NEVER_RETURNS void	_fr_assert_fatal(char const *file, int line, char const *expr, char const *msg, ...)
			CC_HINT(format (printf, 4, 5));

NEVER_RETURNS void	_fr_exit(char const *file, int line, int status, bool now);
/** @} */

/** @name Assertion and exit macros
 * @{
 */

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
 * @param[in] _x expression to test (should evaluate to true)
 */
#define		fr_cond_assert(_x) likely((bool)((_x) ? true : (_fr_assert_fail(__FILE__, __LINE__, #_x, NULL) && false)))

/** Calls panic_action ifndef NDEBUG, else logs error and evaluates to value of _x
 *
 * Should be wrapped in a condition, and if false, should cause function to return
 * an error code.  This allows control to return to the caller if a precondition is
 * not satisfied and we're not debugging.
 *
 * Example:
 @verbatim
   if (!fr_cond_assert_msg(request, "Bad stuff happened: %s", fr_syserror(errno)))) return -1
 @endverbatim
 *
 * @param[in] _x	expression to test (should evaluate to true)
 * @param[in] _fmt	of message to log.
 * @param[in] ...	fmt arguments.
 */
#define		fr_cond_assert_msg(_x, _fmt, ...) likely((bool)((_x) ? true : (_fr_assert_fail(__FILE__, __LINE__, #_x, _fmt, ## __VA_ARGS__) && false)))

/** Calls panic_action ifndef NDEBUG, else logs error and causes the server to exit immediately with code 134
 *
 * Example:
 @verbatim
   fr_fatal_assert(<extremely_unlikely_and_fatal_condition>);
 @endverbatim
 *
 * @param _x expression to test (should evaluate to true)
 */
#define		fr_fatal_assert(_x) if (unlikely(!((bool)(_x)))) _fr_assert_exit(__FILE__, __LINE__, #_x, NULL))

/** Calls panic_action ifndef NDEBUG, else logs error and causes the server to exit immediately with code 134
 *
 * Should be wrapped in a condition, and if false, should cause function to return
 * an error code.  This allows control to return to the caller if a precondition is
 * not satisfied and we're not debugging.
 *
 * Example:
 @verbatim
   fr_fatal_assert(<extremely_unlikely_and_fatal_condition>);
 @endverbatim
 *
 * @param[in] _x	expression to test (should evaluate to true)
 * @param[in] _fmt	of message to log.
 * @param[in] ...	fmt arguments.
 */
#define		fr_fatal_assert_msg(_x, _fmt, ...) if (unlikely(!((bool)(_x)))) _fr_assert_fatal(__FILE__, __LINE__, #_x, _fmt, ## __VA_ARGS__)

/** Calls panic_action ifndef NDEBUG, else logs error and causes the server to exit immediately with code 134
 *
 * @param[in] _msg	to log.
 * @param[in] ...	args.
 */
#define		fr_fatal_assert_fail(_msg, ...) _fr_assert_fatal(__FILE__, __LINE__, "false", _msg,  ## __VA_ARGS__)

#ifdef NDEBUG
#  define fr_assert(_x)
#  define fr_assert_msg(_x, _msg, ...)
#  define fr_assert_fail(_msg, ...)
#elif !defined(__clang_analyzer__)
/** Calls panic_action ifndef NDEBUG, else logs error
 *
 * @param[in] _x	expression to test (should evaluate to true)
 */
#  define	fr_assert(_x) if (unlikely(!((bool)(_x)))) _fr_assert_fail(__FILE__, __LINE__, #_x, NULL)

/** Calls panic_action ifndef NDEBUG, else logs error and causes the server to exit immediately with code 134
 *
 * @param[in] _x	expression to test (should evaluate to true)
 * @param[in] _msg	to log.
 * @param[in] ...	args.
 */
#  define	fr_assert_msg(_x, _msg, ...) if (unlikely(!((bool)(_x)))) _fr_assert_fail(__FILE__, __LINE__, #_x, _msg, ## __VA_ARGS__)
/** Calls panic_action ifndef NDEBUG, else logs error
 *
 * @param[in] _msg	to log.
 * @param[in] ...	args.
 */
#define		fr_assert_fail(_msg, ...) _fr_assert_fail(__FILE__, __LINE__, "false", _msg,  ## __VA_ARGS__)
#else
#  include <assert.h>
#  define fr_assert(_x) assert(_x)
#  define fr_assert_msg(_x, _msg, ...) assert(_x)
#  define fr_assert_fail(_msg ...) assert(0)
#endif

/** Exit, producing a log message in debug builds
 *
 * @param[in] _x	code to exit with.
 */
#  define	fr_exit(_x) _fr_exit(__FILE__, __LINE__, (_x), false)

/** Exit without calling atexit() handlers, producing a log message in debug builds
 *
 * @param[in] _x	code to exit with.
 */
#  define	fr_exit_now(_x) _fr_exit(__FILE__, __LINE__, (_x), true)
/** @} */

void fr_sign_struct(void *ptr, size_t size, size_t offset);
void fr_verify_struct(void const *ptr, size_t size, size_t offset);
void fr_verify_struct_member(void const *ptr, size_t len, uint32_t *signature);

/** Manual validation of structures.
 *
 *	typedef struct {
 *		char *a;
 *		int b;
 *		FR_SIGNATURE		// no semicolon!
 *	} foo_t;
 *
 *  and then once the structure is initialized (and will never be changed)
 *
 *	foo_t *ptr;
 *	FR_STRUCT_SIGN(ptr);
 *
 *  and some time later...
 *
 *	foo_t *ptr;
 *	FR_STRUCT_VERIFY(ptr);
 *
 *  Note that the structure can't contain variable elements such as fr_dlist_t.
 *  And that we're not verifying the contents of the members which are pointers.
 */
#ifndef NDEBUG
#define FR_STRUCT_SIGN(_ptr)			fr_sign_struct(_ptr, sizeof(__typeof__(*_ptr)), offsetof(__typeof__(*_ptr), _signature));
#define FR_STRUCT_VERIFY(_ptr)			fr_verify_struct(_ptr, sizeof(__typeof__(*_ptr)), offsetof(__typeof__(*_ptr), _signature))
#define FR_STRUCT_SIGNATURE			uint32_t _signature;

#define FR_STRUCT_MEMBER_SIGN(_ptr, _member, _len) _ptr->_signature_##_member = fr_hash(_ptr->_member, _len)
#define FR_STRUCT_MEMBER_VERIFY(_ptr, _member, _len) fr_verify_struct_member(_ptr->_member, _len, &(_ptr->_signature_##_member))
#define FR_STRUCT_MEMBER_SIGNATURE(_member)	uint32_t _signature_##_member;
#else
#define FR_STRUCT_SIGN(_ptr)
#define FR_STRUCT_VERIFY(_ptr)
#define FR_STRUCT_SIGNATURE

#define FR_STRUCT_MEMBER_SIGN(_ptr, _member, _len)
#define FR_STRUCT_MEMBER_VERIFY(_ptr, _member, _len)
#define FR_STRUCT_MEMBER_SIGNATURE(_member)
#endif

#ifdef __cplusplus
}
#endif
