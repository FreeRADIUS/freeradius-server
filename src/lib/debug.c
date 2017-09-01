/*
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
 */

/**
 * @file debug.c
 * @brief Various functions to aid in debugging
 *
 * @copyright 2013  The FreeRADIUS server project
 * @copyright 2013  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <assert.h>
#include <freeradius-devel/libradius.h>
#include <sys/stat.h>
#include <sys/wait.h>

#if defined(HAVE_MALLOPT) && defined(HAVE_MALLOC_H)
#  include <malloc.h>
#endif

/*
 *	runtime backtrace functions are not POSIX but are included in
 *	glibc, OSX >= 10.5 and various BSDs
 */
#ifdef HAVE_EXECINFO
#  include <execinfo.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
#  include <sys/prctl.h>
#endif

#ifdef HAVE_SYS_PTRACE_H
#  include <sys/ptrace.h>
#  if !defined(PT_ATTACH) && defined(PTRACE_ATTACH)
#    define PT_ATTACH PTRACE_ATTACH
#  endif
#  if !defined(PT_DETACH) && defined(PTRACE_DETACH)
#    define PT_DETACH PTRACE_DETACH
#  endif
#endif

#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
#endif

#ifdef HAVE_PTHREAD_H
#  define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#  define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock
#else
#  define PTHREAD_MUTEX_LOCK(_x)
#  define PTHREAD_MUTEX_UNLOCK(_x)
#endif

#ifdef HAVE_EXECINFO
#  ifndef MAX_BT_FRAMES
#    define MAX_BT_FRAMES 128
#  endif
#  ifndef MAX_BT_CBUFF
#    define MAX_BT_CBUFF  1048576			//!< Should be a power of 2
#  endif

#  ifdef HAVE_PTHREAD_H
static pthread_mutex_t fr_debug_init = PTHREAD_MUTEX_INITIALIZER;
#  endif

typedef struct fr_bt_info {
	void 		*obj;				//!< Memory address of the block of allocated memory.
	void		*frames[MAX_BT_FRAMES];		//!< Backtrace frame data
	int		count;				//!< Number of frames stored
} fr_bt_info_t;

struct fr_bt_marker {
	void 		*obj;				//!< Pointer to the parent object, this is our needle
							//!< when we iterate over the contents of the circular buffer.
	fr_cbuff_t 	*cbuff;				//!< Where we temporarily store the backtraces
};
#endif

static char panic_action[512];				//!< The command to execute when panicking.
static fr_fault_cb_t panic_cb = NULL;			//!< Callback to execute whilst panicking, before the
							//!< panic_action.

static bool dump_core;					//!< Whether we should drop a core on fatal signals.

static int fr_fault_log_fd = STDERR_FILENO;		//!< Where to write debug output.

fr_debug_state_t fr_debug_state = DEBUG_STATE_UNKNOWN;	//!< Whether we're attached to by a debugger.

#ifdef HAVE_SYS_RESOURCE_H
static struct rlimit core_limits;
#endif

static TALLOC_CTX *talloc_null_ctx;
static TALLOC_CTX *talloc_autofree_ctx;

#ifdef HAVE_SYS_PTRACE_H
#  ifdef __linux__
#    define _PTRACE(_x, _y) ptrace(_x, _y, NULL, NULL)
#  else
#    define _PTRACE(_x, _y) ptrace(_x, _y, NULL, 0)
#  endif

#  ifdef HAVE_CAPABILITY_H
#    include <sys/capability.h>
#  endif

/** Determine if we're running under a debugger by attempting to attach using pattach
 *
 * @return 0 if we're not, 1 if we are, -1 if we can't tell because of an error,
 *	-2 if we can't tell because we don't have the CAP_SYS_PTRACE capability.
 */
static int fr_get_debug_state(void)
{
	int pid;

	int from_child[2] = {-1, -1};

#ifdef HAVE_CAPABILITY_H
	cap_flag_value_t value;
	cap_t current;

	/*
	 *  If we're running under linux, we first need to check if we have
	 *  permission to to ptrace. We do that using the capabilities
	 *  functions.
	 */
	current = cap_get_proc();
	if (!current) {
		fr_strerror_printf("Failed getting process capabilities: %s", fr_syserror(errno));
		return DEBUG_STATE_UNKNOWN;
	}

	if (cap_get_flag(current, CAP_SYS_PTRACE, CAP_PERMITTED, &value) < 0) {
		fr_strerror_printf("Failed getting permitted ptrace capability state: %s",
				   fr_syserror(errno));
		cap_free(current);
		return DEBUG_STATE_UNKNOWN;
	}

	if ((value == CAP_SET) && (cap_get_flag(current, CAP_SYS_PTRACE, CAP_EFFECTIVE, &value) < 0)) {
		fr_strerror_printf("Failed getting effective ptrace capability state: %s",
				   fr_syserror(errno));
		cap_free(current);
		return DEBUG_STATE_UNKNOWN;
	}

	/*
	 *  We don't have permission to ptrace, so this test will always fail.
	 */
	if (value == CAP_CLEAR) {
		fr_strerror_printf("ptrace capability not set.  If debugger detection is required run as root or: "
				   "setcap cap_sys_ptrace+ep <path_to_radiusd>");
		cap_free(current);
		return DEBUG_STATE_UNKNOWN_NO_PTRACE_CAP;
	}
	cap_free(current);
#endif

	if (pipe(from_child) < 0) {
		fr_strerror_printf("Error opening internal pipe: %s", fr_syserror(errno));
		return DEBUG_STATE_UNKNOWN;
	}

	pid = fork();
	if (pid == -1) {
		fr_strerror_printf("Error forking: %s", fr_syserror(errno));
		return DEBUG_STATE_UNKNOWN;
	}

	/* Child */
	if (pid == 0) {
		int8_t ret = DEBUG_STATE_NOT_ATTACHED;
		int ppid = getppid();

		/* Close parent's side */
		close(from_child[0]);

		/*
		 *	FreeBSD is extremely picky about the order of operations here
		 *	we need to attach, wait *then* write whilst the parent is still
		 *	suspended, then detach, continuing the process.
		 *
		 *	If we don't do it in that order the read in the parent triggers
		 *	a SIGKILL.
		 */
		if (_PTRACE(PT_ATTACH, ppid) == 0) {
			/* Wait for the parent to stop */
			waitpid(ppid, NULL, 0);

			/* Tell the parent what happened */
			if (write(from_child[1], &ret, sizeof(ret)) < 0) {
				fprintf(stderr, "Writing ptrace status to parent failed: %s", fr_syserror(errno));
			}

			/* Detach */
			_PTRACE(PT_DETACH, ppid);
			exit(0);
		}

		ret = DEBUG_STATE_ATTACHED;
		/* Tell the parent what happened */
		if (write(from_child[1], &ret, sizeof(ret)) < 0) {
			fprintf(stderr, "Writing ptrace status to parent failed: %s", fr_syserror(errno));
		}

		exit(0);
	/* Parent */
	} else {
		int8_t ret = DEBUG_STATE_UNKNOWN;

		/*
		 *	The child writes errno (reason) if pattach failed else 0.
		 *
		 *	This read may be interrupted by pattach,
		 *	which is why we need the loop.
		 */
		while ((read(from_child[0], &ret, sizeof(ret)) < 0) && (errno == EINTR));

		/* Close the pipes here (if we did it above, it might race with pattach) */
		close(from_child[1]);
		close(from_child[0]);

		/* Collect the status of the child */
		waitpid(pid, NULL, 0);

		return ret;
	}
}
#else
static int fr_get_debug_state(void)
{
	fr_strerror_printf("PTRACE not available");

	return DEBUG_STATE_UNKNOWN_NO_PTRACE;
}
#endif

/** Should be run before using setuid or setgid to get useful results
 *
 * @note sets the fr_debug_state global.
 */
void fr_store_debug_state(void)
{
	fr_debug_state = fr_get_debug_state();

#ifndef NDEBUG
	/*
	 *  There are many reasons why this might happen with
	 *  a vanilla install, so we don't want to spam users
	 *  with messages they won't understand and may not
	 *  want to resolve.
	 */
	if (fr_debug_state < 0) fprintf(stderr, "Getting debug state failed: %s\n", fr_strerror());
#endif
}

/** Return current value of debug_state
 *
 * @param state to translate into a humanly readable value.
 * @return humanly readable version of debug state.
 */
char const *fr_debug_state_to_msg(fr_debug_state_t state)
{
	switch (state) {
	case DEBUG_STATE_UNKNOWN_NO_PTRACE:
		return "Debug state unknown (ptrace functionality not available)";

	case DEBUG_STATE_UNKNOWN_NO_PTRACE_CAP:
		return "Debug state unknown (cap_sys_ptrace capability not set)";

	case DEBUG_STATE_UNKNOWN:
		return "Debug state unknown";

	case DEBUG_STATE_ATTACHED:
		return "Found debugger attached";

	case DEBUG_STATE_NOT_ATTACHED:
		return "Debugger not attached";
	}

	return "<INVALID>";
}

/** Break in debugger (if were running under a debugger)
 *
 * If the server is running under a debugger this will raise a
 * SIGTRAP which will pause the running process.
 *
 * If the server is not running under debugger then this will do nothing.
 */
void fr_debug_break(bool always)
{
	if (always) raise(SIGTRAP);

	if (fr_debug_state < 0) fr_debug_state = fr_get_debug_state();
	if (fr_debug_state == DEBUG_STATE_ATTACHED) {
		fprintf(stderr, "Debugger detected, raising SIGTRAP\n");
		fflush(stderr);

		raise(SIGTRAP);
	}
}

#ifdef HAVE_EXECINFO
/** Print backtrace entry for a given object
 *
 * @param cbuff to search in.
 * @param obj pointer to original object
 */
void backtrace_print(fr_cbuff_t *cbuff, void *obj)
{
	fr_bt_info_t *p;
	bool found = false;

	while ((p = fr_cbuff_rp_next(cbuff, NULL))) {
		if ((p->obj == obj) || !obj) {
			found = true;

			fprintf(stderr, "Stacktrace for: %p\n", p->obj);
			backtrace_symbols_fd(p->frames, p->count, STDERR_FILENO);
		}
	};

	if (!found) {
		fprintf(stderr, "No backtrace available for %p", obj);
	}
}

/** Generate a backtrace for an object
 *
 * If this is the first entry being inserted
 */
int fr_backtrace_do(fr_bt_marker_t *marker)
{
	fr_bt_info_t *bt;

	if (!fr_assert(marker->obj) || !fr_assert(marker->cbuff)) return -1;

	bt = talloc_zero(NULL, fr_bt_info_t);
	if (!bt) return -1;

	bt->obj = marker->obj;
	bt->count = backtrace(bt->frames, MAX_BT_FRAMES);

	fr_cbuff_rp_insert(marker->cbuff, bt);

	return 0;
}

/** Inserts a backtrace marker into the provided context
 *
 * Allows for maximum laziness and will initialise a circular buffer if one has not already been created.
 *
 * Code augmentation should look something like:
@verbatim
	// Create a static cbuffer pointer, the first call to backtrace_attach will initialise it
	static fr_cbuff_t *my_obj_bt;

	my_obj_t *alloc_my_obj(TALLOC_CTX *ctx) {
		my_obj_t *this;

		this = talloc(ctx, my_obj_t);

		// Attach backtrace marker to object
		backtrace_attach(&my_obj_bt, this);

		return this;
	}
@endverbatim
 *
 * Then, later when a double free occurs:
@verbatim
	(gdb) call backtrace_print(&my_obj_bt, <pointer to double freed memory>)
@endverbatim
 *
 * which should print a limited backtrace to stderr. Note, this backtrace will not include any argument
 * values, but should at least show the code path taken.
 *
 * @param cbuff this should be a pointer to a static *fr_cbuff.
 * @param obj we want to generate a backtrace for.
 */
fr_bt_marker_t *fr_backtrace_attach(fr_cbuff_t **cbuff, TALLOC_CTX *obj)
{
	fr_bt_marker_t *marker;

	if (*cbuff == NULL) {
		PTHREAD_MUTEX_LOCK(&fr_debug_init);
		/* Check again now we hold the mutex - eww*/
		if (*cbuff == NULL) *cbuff = fr_cbuff_alloc(NULL, MAX_BT_CBUFF, true);
		PTHREAD_MUTEX_UNLOCK(&fr_debug_init);
	}

	marker = talloc(obj, fr_bt_marker_t);
	if (!marker) {
		return NULL;
	}

	marker->obj = (void *) obj;
	marker->cbuff = *cbuff;

	fprintf(stderr, "Backtrace attached to %s %p\n", talloc_get_name(obj), obj);
	/*
	 *	Generate the backtrace for memory allocation
	 */
	fr_backtrace_do(marker);
	talloc_set_destructor(marker, fr_backtrace_do);

	return marker;
}
#else
void backtrace_print(UNUSED fr_cbuff_t *cbuff, UNUSED void *obj)
{
	fprintf(stderr, "Server built without fr_backtrace_* support, requires execinfo.h and possibly -lexecinfo\n");
}
fr_bt_marker_t *fr_backtrace_attach(UNUSED fr_cbuff_t **cbuff, UNUSED TALLOC_CTX *obj)
{
	fprintf(stderr, "Server built without fr_backtrace_* support, requires execinfo.h and possibly -lexecinfo\n");
	abort();
}
#endif /* ifdef HAVE_EXECINFO */

static int _panic_on_free(UNUSED char *foo)
{
	fr_fault(SIGABRT);
	return -1;	/* this should make the free fail */
}

/** Insert memory into the context of another talloc memory chunk which
 * causes a panic when freed.
 *
 * @param ctx TALLOC_CTX to monitor for frees.
 */
void fr_panic_on_free(TALLOC_CTX *ctx)
{
	char *ptr;

	ptr = talloc(ctx, char);
	talloc_set_destructor(ptr, _panic_on_free);
}

/** Set the dumpable flag, also controls whether processes can PATTACH
 *
 * @param dumpable whether we should allow core dumping
 */
#if defined(HAVE_SYS_PRCTL_H) && defined(PR_SET_DUMPABLE)
static int fr_set_dumpable_flag(bool dumpable)
{
	if (prctl(PR_SET_DUMPABLE, dumpable ? 1 : 0) < 0) {
		fr_strerror_printf("Cannot re-enable core dumps: prctl(PR_SET_DUMPABLE) failed: %s",
				   fr_syserror(errno));
		return -1;
	}

	return 0;
}
#else
static int fr_set_dumpable_flag(UNUSED bool dumpable)
{
	fr_strerror_printf("Changing value of PR_DUMPABLE not supported on this system");
	return -2;
}
#endif

/** Get the processes dumpable flag
 *
 */
#if defined(HAVE_SYS_PRCTL_H) && defined(PR_GET_DUMPABLE)
static int fr_get_dumpable_flag(void)
{
	int ret;

	ret = prctl(PR_GET_DUMPABLE);
	if (ret < 0) {
		fr_strerror_printf("Cannot get dumpable flag: %s", fr_syserror(errno));
		return -1;
	}

	/*
	 *  Linux is crazy and prctl sometimes returns 2 for disabled
	 */
	if (ret != 1) return 0;
	return 1;
}
#else
static int fr_get_dumpable_flag(void)
{
	fr_strerror_printf("Getting value of PR_DUMPABLE not supported on this system");
	return -2;
}
#endif


/** Get the current maximum for core files
 *
 * Do this before anything else so as to ensure it's properly initialized.
 */
int fr_set_dumpable_init(void)
{
#ifdef HAVE_SYS_RESOURCE_H
	if (getrlimit(RLIMIT_CORE, &core_limits) < 0) {
		fr_strerror_printf("Failed to get current core limit:  %s", fr_syserror(errno));
		return -1;
	}
#endif
	return 0;
}

/** Enable or disable core dumps
 *
 * @param allow_core_dumps whether to enable or disable core dumps.
 */
int fr_set_dumpable(bool allow_core_dumps)
{
	dump_core = allow_core_dumps;
	/*
	 *	If configured, turn core dumps off.
	 */
	if (!allow_core_dumps) {
#ifdef HAVE_SYS_RESOURCE_H
		struct rlimit no_core;

		no_core.rlim_cur = 0;
		no_core.rlim_max = 0;

		if (setrlimit(RLIMIT_CORE, &no_core) < 0) {
			fr_strerror_printf("Failed disabling core dumps: %s", fr_syserror(errno));

			return -1;
		}
#endif
		return 0;
	}

	if (fr_set_dumpable_flag(true) < 0) return -1;

	/*
	 *	Reset the core dump limits to their original value.
	 */
#ifdef HAVE_SYS_RESOURCE_H
	if (setrlimit(RLIMIT_CORE, &core_limits) < 0) {
		fr_strerror_printf("Cannot update core dump limit: %s", fr_syserror(errno));

		return -1;
	}
#endif
	return 0;
}

/** Reset dumpable state to previously configured value
 *
 * Needed after suid up/down
 *
 * @return 0 on success, else -1 on failure.
 */
int fr_reset_dumpable(void)
{
	return fr_set_dumpable(dump_core);
}

/** Check to see if panic_action file is world writeable
 *
 * @return 0 if file is OK, else -1.
 */
static int fr_fault_check_permissions(void)
{
	char const *p, *q;
	size_t len;
	char filename[256];
	struct stat statbuf;

	/*
	 *	Try and guess which part of the command is the binary, and check to see if
	 *	it's world writeable, to try and save the admin from their own stupidity.
	 *
	 *	@fixme we should do this properly and take into account single and double
	 *	quotes.
	 */
	if ((q = strchr(panic_action, ' '))) {
		/*
		 *	need to use a static buffer, because mallocing memory in a signal handler
		 *	is a bad idea and can result in deadlock.
		 */
		len = snprintf(filename, sizeof(filename), "%.*s", (int)(q - panic_action), panic_action);
		if (is_truncated(len, sizeof(filename))) {
			fr_strerror_printf("Failed writing panic_action to temporary buffer (truncated)");
			return -1;
		}
		p = filename;
	} else {
		p = panic_action;
	}

	if (stat(p, &statbuf) == 0) {
#ifdef S_IWOTH
		if ((statbuf.st_mode & S_IWOTH) != 0) {
			fr_strerror_printf("panic_action file \"%s\" is globally writable", p);
			return -1;
		}
#endif
	}

	return 0;
}

/** Prints a simple backtrace (if execinfo is available) and calls panic_action if set.
 *
 * @param sig caught
 */
NEVER_RETURNS void fr_fault(int sig)
{
	char cmd[sizeof(panic_action) + 20];
	char *out = cmd;
	size_t left = sizeof(cmd), ret;

	char const *p = panic_action;
	char const *q;

	int code;

	/*
	 *	If a debugger is attached, we don't want to run the panic action,
	 *	as it may interfere with the operation of the debugger.
	 *	If something calls us directly we just raise the signal and let
	 *	the debugger handle it how it wants.
	 */
	if (fr_debug_state == DEBUG_STATE_ATTACHED) {
		FR_FAULT_LOG("RAISING SIGNAL: %s", strsignal(sig));
		raise(sig);
		goto finish;
	}

	/*
	 *	Makes the backtraces slightly cleaner
	 */
	memset(cmd, 0, sizeof(cmd));

	FR_FAULT_LOG("CAUGHT SIGNAL: %s", strsignal(sig));

	/*
	 *	Check for administrator sanity.
	 */
	if (fr_fault_check_permissions() < 0) {
		FR_FAULT_LOG("Refusing to execute panic action: %s", fr_strerror());
		goto finish;
	}

	/*
	 *	Run the callback if one was registered
	 */
	if (panic_cb && (panic_cb(sig) < 0)) goto finish;

	/*
	 *	Produce a simple backtrace - They're very basic but at least give us an
	 *	idea of the area of the code we hit the issue in.
	 *
	 *	See below in fr_fault_setup() and
	 *	https://sourceware.org/bugzilla/show_bug.cgi?id=16159
	 *	for why we only print backtraces in debug builds if we're using GLIBC.
	 */
#if defined(HAVE_EXECINFO) && (!defined(NDEBUG) || !defined(__GNUC__))
	if (fr_fault_log_fd >= 0) {
		size_t frame_count;
		void *stack[MAX_BT_FRAMES];

		frame_count = backtrace(stack, MAX_BT_FRAMES);

		FR_FAULT_LOG("Backtrace of last %zu frames:", frame_count);

		backtrace_symbols_fd(stack, frame_count, fr_fault_log_fd);
	}
#endif

	/* No panic action set... */
	if (panic_action[0] == '\0') {
		FR_FAULT_LOG("No panic action set");
		goto finish;
	}

	/* Substitute %p for the current PID (useful for attaching a debugger) */
	while ((q = strstr(p, "%p"))) {
		out += ret = snprintf(out, left, "%.*s%d", (int) (q - p), p, (int) getpid());
		if (left <= ret) {
		oob:
			FR_FAULT_LOG("Panic action too long");
			fr_exit_now(1);
		}
		left -= ret;
		p = q + 2;
	}
	if (strlen(p) >= left) goto oob;
	strlcpy(out, p, left);

	{
		bool disable = false;

		FR_FAULT_LOG("Calling: %s", cmd);

		/*
		 *	Here we temporarily enable the dumpable flag so if GBD or LLDB
		 *	is called in the panic_action, they can pattach to the running
		 *	process.
		 */
		if (fr_get_dumpable_flag() == 0) {
			if ((fr_set_dumpable_flag(true) < 0) || !fr_get_dumpable_flag()) {
				FR_FAULT_LOG("Failed setting dumpable flag, pattach may not work: %s", fr_strerror());
			} else {
				disable = true;
			}
			FR_FAULT_LOG("Temporarily setting PR_DUMPABLE to 1");
		}

		code = system(cmd);

		/*
		 *	We only want to error out here, if dumpable was originally disabled
		 *	and we managed to change the value to enabled, but failed
		 *	setting it back to disabled.
		 */
		if (disable) {
			FR_FAULT_LOG("Resetting PR_DUMPABLE to 0");
			if (fr_set_dumpable_flag(false) < 0) {
				FR_FAULT_LOG("Failed reseting dumpable flag to off: %s", fr_strerror());
				FR_FAULT_LOG("Exiting due to insecure process state");
				fr_exit_now(1);
			}
		}

		FR_FAULT_LOG("Panic action exited with %i", code);

		fr_exit_now(code);
	}


finish:
	/*
	 *	(Re-)Raise the signal, so that if we're running under
	 *	a debugger, the debugger can break when it receives
	 *	the signal.
	 */
	fr_unset_signal(sig);	/* Make sure we don't get into a loop */

	raise(sig);

	fr_exit_now(1);		/* Function marked as noreturn */
}

/** Callback executed on fatal talloc error
 *
 * This is the simple version which mostly behaves the same way as the default
 * one, and will not call panic_action.
 *
 * @param reason string provided by talloc.
 */
static void _fr_talloc_fault_simple(char const *reason) CC_HINT(noreturn);
static void _fr_talloc_fault_simple(char const *reason)
{
	FR_FAULT_LOG("talloc abort: %s\n", reason);

#if defined(HAVE_EXECINFO) && (!defined(NDEBUG) || !defined(__GNUC__))
	if (fr_fault_log_fd >= 0) {
		size_t frame_count;
		void *stack[MAX_BT_FRAMES];

		frame_count = backtrace(stack, MAX_BT_FRAMES);
		FR_FAULT_LOG("Backtrace of last %zu frames:", frame_count);
		backtrace_symbols_fd(stack, frame_count, fr_fault_log_fd);
	}
#endif
	abort();
}

/** Callback executed on fatal talloc error
 *
 * Translates a talloc abort into a fr_fault call.
 * Mostly to work around issues with some debuggers not being able to
 * attach after a SIGABRT has been raised.
 *
 * @param reason string provided by talloc.
 */
static void _fr_talloc_fault(char const *reason) CC_HINT(noreturn);
static void _fr_talloc_fault(char const *reason)
{
	FR_FAULT_LOG("talloc abort: %s", reason);
#ifdef SIGABRT
	fr_fault(SIGABRT);
#endif
	fr_exit_now(1);
}

/** Wrapper to pass talloc log output to our fr_fault_log function
 *
 */
static void _fr_talloc_log(char const *msg)
{
	fr_fault_log("%s\n", msg);
}

/** Generate a talloc memory report for a context and print to stderr/stdout
 *
 * @param ctx to generate a report for, may be NULL in which case the root context is used.
 */
int fr_log_talloc_report(TALLOC_CTX *ctx)
{
#define TALLOC_REPORT_MAX_DEPTH 20

	FILE *log;
	int fd;

	fd = dup(fr_fault_log_fd);
	if (fd < 0) {
		fr_strerror_printf("Couldn't write memory report, failed to dup log fd: %s", fr_syserror(errno));
		return -1;
	}
	log = fdopen(fd, "w");
	if (!log) {
		close(fd);
		fr_strerror_printf("Couldn't write memory report, fdopen failed: %s", fr_syserror(errno));
		return -1;
	}

	if (!ctx) {
		fprintf(log, "Current state of talloced memory:\n");
		talloc_report_full(talloc_null_ctx, log);
	} else {
		int i;

		fprintf(log, "Talloc chunk lineage:\n");
		fprintf(log, "%p (%s)", ctx, talloc_get_name(ctx));

		i = 0;
		while ((i < TALLOC_REPORT_MAX_DEPTH) && (ctx = talloc_parent(ctx))) {
			fprintf(log, " < %p (%s)", ctx, talloc_get_name(ctx));
			i++;
		}
		fprintf(log, "\n");

		i = 0;
		do {
			fprintf(log, "Talloc context level %i:\n", i++);
			talloc_report_full(ctx, log);
		} while ((ctx = talloc_parent(ctx)) &&
			 (i < TALLOC_REPORT_MAX_DEPTH) &&
			 (talloc_parent(ctx) != talloc_autofree_ctx) &&	/* Stop before we hit the autofree ctx */
			 (talloc_parent(ctx) != talloc_null_ctx));  	/* Stop before we hit NULL ctx */
	}

	fclose(log);

	return 0;
}


static int _fr_disable_null_tracking(UNUSED bool *p)
{
	talloc_disable_null_tracking();
	return 0;
}

/** Register talloc fault handlers
 *
 * Just register the fault handlers we need to make talloc
 * produce useful debugging output.
 */
void fr_talloc_fault_setup(void)
{
	talloc_set_log_fn(_fr_talloc_log);
	talloc_set_abort_fn(_fr_talloc_fault_simple);
}

/** Registers signal handlers to execute panic_action on fatal signal
 *
 * May be called multiple time to change the panic_action/program.
 *
 * @param cmd to execute on fault. If present %p will be substituted
 *        for the parent PID before the command is executed, and %e
 *        will be substituted for the currently running program.
 * @param program Name of program currently executing (argv[0]).
 * @return 0 on success -1 on failure.
 */
int fr_fault_setup(char const *cmd, char const *program)
{
	static bool setup = false;

	char *out = panic_action;
	size_t left = sizeof(panic_action);

	char const *p = cmd;
	char const *q;

	if (cmd) {
		size_t ret;

		/* Substitute %e for the current program */
		while ((q = strstr(p, "%e"))) {
			out += ret = snprintf(out, left, "%.*s%s", (int) (q - p), p, program ? program : "");
			if (left <= ret) {
			oob:
				fr_strerror_printf("Panic action too long");
				return -1;
			}
			left -= ret;
			p = q + 2;
		}
		if (strlen(p) >= left) goto oob;
		strlcpy(out, p, left);
	} else {
		*panic_action = '\0';
	}

	/*
	 *	Check for administrator sanity.
	 */
	if (fr_fault_check_permissions() < 0) return -1;

	/* Unsure what the side effects of changing the signal handler mid execution might be */
	if (!setup) {
		char *env;
		fr_debug_state_t debug_state;

		/*
		 *  Installing signal handlers interferes with some debugging
		 *  operations.  Give the developer control over whether the
		 *  signal handlers are installed or not.
		 */
		env = getenv("DEBUG");
		if (!env || (strcmp(env, "no") == 0)) {
			debug_state = DEBUG_STATE_NOT_ATTACHED;
		} else if (!strcmp(env, "auto") || !strcmp(env, "yes")) {
			/*
			 *  Figure out if we were started under a debugger
			 */
			if (fr_debug_state < 0) fr_debug_state = fr_get_debug_state();
			debug_state = fr_debug_state;
		} else {
			debug_state = DEBUG_STATE_ATTACHED;
		}

		talloc_set_log_fn(_fr_talloc_log);

		/*
		 *  These signals can't be properly dealt with in the debugger
		 *  if we set our own signal handlers.
		 */
		switch (debug_state) {
		default:
#ifndef NDEBUG
			FR_FAULT_LOG("Debugger check failed: %s", fr_strerror());
			FR_FAULT_LOG("Signal processing in debuggers may not work as expected");
#endif
			/* FALL-THROUGH */

		case DEBUG_STATE_NOT_ATTACHED:
#ifdef SIGABRT
			if (fr_set_signal(SIGABRT, fr_fault) < 0) return -1;

			/*
			 *  Use this instead of abort so we get a
			 *  full backtrace with broken versions of LLDB
			 */
			talloc_set_abort_fn(_fr_talloc_fault);
#endif
#ifdef SIGILL
			if (fr_set_signal(SIGILL, fr_fault) < 0) return -1;
#endif
#ifdef SIGFPE
			if (fr_set_signal(SIGFPE, fr_fault) < 0) return -1;
#endif
#ifdef SIGSEGV
			if (fr_set_signal(SIGSEGV, fr_fault) < 0) return -1;
#endif
			break;

		case DEBUG_STATE_ATTACHED:
			break;
		}

		/*
		 *  Needed for memory reports
		 */
		{
			TALLOC_CTX *tmp;
			bool *marker;

			tmp = talloc(NULL, bool);
			talloc_null_ctx = talloc_parent(tmp);
			talloc_free(tmp);

			/*
			 *  Disable null tracking on exit, else valgrind complains
			 */
			talloc_autofree_ctx = talloc_autofree_context();
			marker = talloc(talloc_autofree_ctx, bool);
			talloc_set_destructor(marker, _fr_disable_null_tracking);
		}

#if defined(HAVE_MALLOPT) && !defined(NDEBUG)
		/*
		 *  If were using glibc malloc > 2.4 this scribbles over
		 *  uninitialised and freed memory, to make memory issues easier
		 *  to track down.
		 */
		if (!getenv("TALLOC_FREE_FILL")) mallopt(M_PERTURB, 0x42);
		mallopt(M_CHECK_ACTION, 3);
#endif

#if defined(HAVE_EXECINFO) && defined(__GNUC__) && !defined(NDEBUG)
	       /*
		*  We need to pre-load lgcc_s, else we can get into a deadlock
		*  in fr_fault, as backtrace() attempts to dlopen it.
		*
		*  Apparently there's a performance impact of loading lgcc_s,
		*  so only do it if this is a debug build.
		*
		*  See: https://sourceware.org/bugzilla/show_bug.cgi?id=16159
		*/
		{
			void *stack[10];

			backtrace(stack, 10);
		}
#endif
	}
	setup = true;

	return 0;
}

/** Set a callback to be called before fr_fault()
 *
 * @param func to execute. If callback returns < 0
 *	fr_fault will exit before running panic_action code.
 */
void fr_fault_set_cb(fr_fault_cb_t func)
{
	panic_cb = func;
}

/** Log output to the fr_fault_log_fd
 *
 * We used to support a user defined callback, which was set to a radlog
 * function. Unfortunately, when logging to syslog, syslog would malloc memory
 * which would result in a deadlock if fr_fault was triggered from within
 * a malloc call.
 *
 * Now we just write directly to the FD.
 */
void fr_fault_log(char const *msg, ...)
{
	va_list ap;

	if (fr_fault_log_fd < 0) return;

	va_start(ap, msg);
	vdprintf(fr_fault_log_fd, msg, ap);
	va_end(ap);
}

/** Set a file descriptor to log memory reports to.
 *
 * @param fd to write output to.
 */
void fr_fault_set_log_fd(int fd)
{
	fr_fault_log_fd = fd;
}

/** A soft assertion which triggers the fault handler in debug builds
 *
 * @param file the assertion failed in.
 * @param line of the assertion in the file.
 * @param expr that was evaluated.
 * @param cond Result of evaluating the expression.
 * @return the value of cond.
 */
bool fr_assert_cond(char const *file, int line, char const *expr, bool cond)
{
	if (!cond) {
		FR_FAULT_LOG("SOFT ASSERT FAILED %s[%u]: %s", file, line, expr);
#if !defined(NDEBUG)
		fr_fault(SIGABRT);
#endif
		return false;
	}

	return cond;
}

/** Exit possibly printing a message about why we're exiting.
 *
 * @note Use the fr_exit(status) macro instead of calling this function directly.
 *
 * @param file where fr_exit() was called.
 * @param line where fr_exit() was called.
 * @param status we're exiting with.
 */
void NEVER_RETURNS _fr_exit(char const *file, int line, int status)
{
#ifndef NDEBUG
	char const *error = fr_strerror();

	if (error && (status != 0)) {
		FR_FAULT_LOG("EXIT(%i) CALLED %s[%u].  Last error was: %s", status, file, line, error);
	} else {
		FR_FAULT_LOG("EXIT(%i) CALLED %s[%u]", status, file, line);
	}
#endif
	fr_debug_break(false);	/* If running under GDB we'll break here */

	exit(status);
}

/** Exit possibly printing a message about why we're exiting.
 *
 * @note Use the fr_exit_now(status) macro instead of calling this function directly.
 *
 * @param file where fr_exit_now() was called.
 * @param line where fr_exit_now() was called.
 * @param status we're exiting with.
 */
void NEVER_RETURNS _fr_exit_now(char const *file, int line, int status)
{
#ifndef NDEBUG
	char const *error = fr_strerror();

	if (error && (status != 0)) {
		FR_FAULT_LOG("_EXIT(%i) CALLED %s[%u].  Last error was: %s", status, file, line, error);
	} else {
		FR_FAULT_LOG("_EXIT(%i) CALLED %s[%u]", status, file, line);
	}
#endif
	fr_debug_break(false);	/* If running under GDB we'll break here */

	_exit(status);
}
