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
#  if !defined(PTRACE_ATTACH) && defined(PT_ATTACH)
#    define PTRACE_ATTACH PT_ATTACH
#  endif
#  if !defined(PTRACE_DETACH) && defined(PT_DETACH)
#    define PTRACE_DETACH PT_DETACH
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

static void CC_HINT(format (printf, 1, 2)) _fr_fault_log(char const *msg, ...);

static fr_fault_log_t fr_fault_log = _fr_fault_log;	//!< Function to use to process logging output.
static int fr_fault_log_fd = STDERR_FILENO;		//!< Where to write debug output.

static int debugger_attached = -1;			//!< Whether were attached to by a debugger.

#ifdef HAVE_SYS_RESOURCE_H
static struct rlimit core_limits;
#endif

static TALLOC_CTX *talloc_null_ctx;
static TALLOC_CTX *talloc_autofree_ctx;

#define FR_FAULT_LOG(fmt, ...) fr_fault_log(fmt "\n", ## __VA_ARGS__)

#ifdef HAVE_SYS_PTRACE_H
#  ifdef __linux__
#    define _PTRACE(_x, _y) ptrace(_x, _y, NULL, NULL)
#  else
#    define _PTRACE(_x, _y) ptrace(_x, _y, NULL, 0)
#  endif

/** Determine if we're running under a debugger by attempting to attach using pattach
 *
 * @return 0 if we're not, 1 if we are, -1 if we can't tell.
 */
static int fr_debugger_attached(void)
{
	int pid;

	int from_child[2] = {-1, -1};

	if (pipe(from_child) < 0) {
		fr_strerror_printf("Debugger check failed: Error opening internal pipe: %s", fr_syserror(errno));
		return -1;
	}

	pid = fork();
	if (pid == -1) {
		fr_strerror_printf("Debugger check failed: Error forking: %s", fr_syserror(errno));
		return -1;
	}

	/* Child */
	if (pid == 0) {
		int8_t ret = 0;
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
		if (_PTRACE(PTRACE_ATTACH, ppid) == 0) {
			/* Wait for the parent to stop */
			waitpid(ppid, NULL, 0);

			/* Tell the parent what happened */
			if (write(from_child[1], &ret, sizeof(ret)) < 0) {
				fprintf(stderr, "Writing ptrace status to parent failed: %s", fr_syserror(errno));
			}

			/* Detach */
			_PTRACE(PTRACE_DETACH, ppid);
			exit(0);
		}

		ret = 1;
		/* Tell the parent what happened */
		if (write(from_child[1], &ret, sizeof(ret)) < 0) {
			fprintf(stderr, "Writing ptrace status to parent failed: %s", fr_syserror(errno));
		}

		exit(0);
	/* Parent */
	} else {
		int8_t ret = -1;

		/*
		 *	The child writes a 1 if pattach failed else 0.
		 *
		 *	This read may be interrupted by pattach,
		 *	which is why we need the loop.
		 */
		while ((read(from_child[0], &ret, sizeof(ret)) < 0) && (errno == EINTR));

		/* Ret not updated */
		if (ret < 0) {
			fr_strerror_printf("Debugger check failed: Error getting status from child: %s",
			fr_syserror(errno));
		}

		/* Close the pipes here (if we did it above, it might race with pattach) */
		close(from_child[1]);
		close(from_child[0]);

		/* Collect the status of the child */
		waitpid(pid, NULL, 0);

		return ret;
	}
}
#else
static int fr_debugger_attached(void)
{
	fr_strerror_printf("Debugger check failed: PTRACE not available");

	return -1;
}
#endif

/** Break in debugger (if were running under a debugger)
 *
 * If the server is running under a debugger this will raise a
 * SIGTRAP which will pause the running process.
 *
 * If the server is not running under debugger then this will do nothing.
 */
void fr_debug_break(void)
{
	if (debugger_attached == -1) {
		debugger_attached = fr_debugger_attached();
	}

	if (debugger_attached == 1) {
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
	fr_fault(SIGUSR1);
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
void fr_fault(int sig)
{
	char cmd[sizeof(panic_action) + 20];
	char *out = cmd;
	size_t left = sizeof(cmd), ret;

	char const *p = panic_action;
	char const *q;

	int code;

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
	 *	Produce a simple backtrace - They've very basic but at least give us an
	 *	idea of the area of the code we hit the issue in.
	 *
	 *	See below in fr_fault_setup() and
	 *	https://sourceware.org/bugzilla/show_bug.cgi?id=16159
	 *	for why we only print backtraces in debug builds if we're using GLIBC.
	 */
#if defined(HAVE_EXECINFO) && (!defined(NDEBUG) || !defined(__GNUC__))
	{
		size_t frame_count, i;
		void *stack[MAX_BT_FRAMES];
		char **strings;

		frame_count = backtrace(stack, MAX_BT_FRAMES);

		FR_FAULT_LOG("Backtrace of last %zu frames:", frame_count);

		/*
		 *	Only use backtrace_symbols() if we don't have a logging fd.
		 *	If the server has experienced memory corruption, there's
		 *	a high probability that calling backtrace_symbols() which
		 *	mallocs more memory, will fail.
		 */
		if (fr_fault_log_fd < 0) {
			strings = backtrace_symbols(stack, frame_count);
			for (i = 0; i < frame_count; i++) {
				FR_FAULT_LOG("%s", strings[i]);
			}
			free(strings);
		} else {
			backtrace_symbols_fd(stack, frame_count, fr_fault_log_fd);
		}
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

	FR_FAULT_LOG("Calling: %s", cmd);

	{
		bool disable = false;

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
	}

	FR_FAULT_LOG("Panic action exited with %i", code);

finish:
#ifdef SIGUSR1
	if (sig == SIGUSR1) {
		return;
	}
#endif
	fr_exit_now(1);
}

#ifdef SIGABRT
/** Work around debuggers which can't backtrace past the signal handler
 *
 * At least this provides us some information when we get talloc errors.
 */
static void _fr_talloc_fault(char const *reason)
{
	fr_fault_log("talloc abort: %s\n", reason);
	fr_fault(SIGABRT);
}
#endif

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
	FILE *log;
	int i = 0;
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
		fprintf(log, "Talloc chunk lineage:\n");
		fprintf(log, "%p (%s)", ctx, talloc_get_name(ctx));
		while ((ctx = talloc_parent(ctx))) fprintf(log, " < %p (%s)", ctx, talloc_get_name(ctx));
		fprintf(log, "\n");

		do {
			fprintf(log, "Talloc context level %i:\n", i++);
			talloc_report_full(ctx, log);
		} while ((ctx = talloc_parent(ctx)) &&
			 (talloc_parent(ctx) != talloc_autofree_ctx) &&	/* Stop before we hit the autofree ctx */
			 (talloc_parent(ctx) != talloc_null_ctx));  	/* Stop before we hit NULL ctx */
	}

	fclose(log);

	return 0;
}

/** Signal handler to print out a talloc memory report
 *
 * @param sig caught
 */
static void _fr_fault_mem_report(int sig)
{
	FR_FAULT_LOG("CAUGHT SIGNAL: %s", strsignal(sig));

	if (fr_log_talloc_report(NULL) < 0) fr_perror("memreport");
}

static int _fr_disable_null_tracking(UNUSED bool *p)
{
	talloc_disable_null_tracking();
	return 0;
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
	size_t left = sizeof(panic_action), ret;

	char const *p = cmd;
	char const *q;

	if (cmd) {
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
		debugger_attached = fr_debugger_attached();

		/*
		 *  These signals can't be properly dealt with in the debugger
		 *  if we set our own signal handlers
		 */
		if (debugger_attached == 0) {
#ifdef SIGSEGV
			if (fr_set_signal(SIGSEGV, fr_fault) < 0) return -1;
#endif
#ifdef SIGBUS
			if (fr_set_signal(SIGBUS, fr_fault) < 0) return -1;
#endif
#ifdef SIGFPE
			if (fr_set_signal(SIGFPE, fr_fault) < 0) return -1;
#endif

#ifdef SIGABRT
			if (fr_set_signal(SIGABRT, fr_fault) < 0) return -1;

			/*
			 *  Use this instead of abort so we get a
			 *  full backtrace with broken versions of LLDB
			 */
			talloc_set_abort_fn(_fr_talloc_fault);
#endif
		}
#ifdef SIGUSR1
		if (fr_set_signal(SIGUSR1, fr_fault) < 0) return -1;
#endif

#ifdef SIGUSR2
		if (fr_set_signal(SIGUSR2, _fr_fault_mem_report) < 0) return -1;
#endif

		/*
		 *  Setup the default logger
		 */
		if (!fr_fault_log) fr_fault_set_log_fn(NULL);
		talloc_set_log_fn(_fr_talloc_log);

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
};

/** Default logger, logs output to stderr
 *
 */
static void CC_HINT(format (printf, 1, 2)) _fr_fault_log(char const *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
}

/** Set a file descriptor to log panic_action output to.
 *
 * @param func to call to output log messages.
 */
void fr_fault_set_log_fn(fr_fault_log_t func)
{
	fr_fault_log = func ? func : _fr_fault_log;
}

/** Set a file descriptor to log memory reports to.
 *
 * @param fd to write output to.
 */
void fr_fault_set_log_fd(int fd)
{
	fr_fault_log_fd = fd;
}

#ifdef WITH_VERIFY_PTR

/*
 *	Verify a VALUE_PAIR
 */
inline void fr_verify_vp(char const *file, int line, VALUE_PAIR const *vp)
{
	if (!vp) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR pointer was NULL", file, line);
		fr_assert(0);
		fr_exit_now(0);
	}

	(void) talloc_get_type_abort(vp, VALUE_PAIR);

	if (vp->data.ptr) switch (vp->da->type) {
	case PW_TYPE_OCTETS:
	case PW_TYPE_TLV:
	{
		size_t len;
		TALLOC_CTX *parent;

		if (!talloc_get_type(vp->data.ptr, uint8_t)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" data buffer type should be "
				     "uint8_t but is %s\n", file, line, vp->da->name, talloc_get_name(vp->data.ptr));
			(void) talloc_get_type_abort(vp->data.ptr, uint8_t);
		}

		len = talloc_array_length(vp->vp_octets);
		if (vp->length > len) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" length %zu is greater than "
				     "uint8_t data buffer length %zu\n", file, line, vp->da->name, vp->length, len);
			fr_assert(0);
			fr_exit_now(1);
		}

		parent = talloc_parent(vp->data.ptr);
		if (parent != vp) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" char buffer is not "
				     "parented by VALUE_PAIR %p, instead parented by %p (%s)\n",
				     file, line, vp->da->name,
				     vp, parent, parent ? talloc_get_name(parent) : "NULL");
			fr_assert(0);
			fr_exit_now(1);
		}
	}
		break;

	case PW_TYPE_STRING:
	{
		size_t len;
		TALLOC_CTX *parent;

		if (!talloc_get_type(vp->data.ptr, char)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" data buffer type should be "
				     "char but is %s\n", file, line, vp->da->name, talloc_get_name(vp->data.ptr));
			(void) talloc_get_type_abort(vp->data.ptr, char);
		}

		len = (talloc_array_length(vp->vp_strvalue) - 1);
		if (vp->length > len) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" length %zu is greater than "
				     "char buffer length %zu\n", file, line, vp->da->name, vp->length, len);
			fr_assert(0);
			fr_exit_now(1);
		}

		if (vp->vp_strvalue[vp->length] != '\0') {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" char buffer not \\0 "
				     "terminated\n", file, line, vp->da->name);
			fr_assert(0);
			fr_exit_now(1);
		}

		parent = talloc_parent(vp->data.ptr);
		if (parent != vp) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" uint8_t buffer is not "
				     "parented by VALUE_PAIR %p, instead parented by %p (%s)\n",
				     file, line, vp->da->name,
				     vp, parent, parent ? talloc_get_name(parent) : "NULL");
			fr_assert(0);
			fr_exit_now(1);
		}
	}
		break;

	default:
		break;
	}
}

/*
 *	Verify a pair list
 */
void fr_verify_list(char const *file, int line, TALLOC_CTX *expected, VALUE_PAIR *vps)
{
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	TALLOC_CTX *parent;

	for (vp = fr_cursor_init(&cursor, &vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		VERIFY_VP(vp);

		parent = talloc_parent(vp);
		if (expected && (parent != expected)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: Expected VALUE_PAIR \"%s\" to be parented "
				     "by %p (%s), instead parented by %p (%s)\n",
				     file, line, vp->da->name,
				     expected, talloc_get_name(expected),
				     parent, parent ? talloc_get_name(parent) : "NULL");

			fr_log_talloc_report(expected);
			if (parent) fr_log_talloc_report(parent);

			fr_assert(0);
			fr_exit_now(0);
		}

	}
}
#endif

bool fr_assert_cond(char const *file, int line, char const *expr, bool cond)
{
	if (!cond) {
		FR_FAULT_LOG("SOFT ASSERT FAILED %s[%u]: %s", file, line, expr);
#if !defined(NDEBUG) && defined(SIGUSR1)
		fr_fault(SIGUSR1);
#endif
		return false;
	}

	return cond;
}

/** Exit possibly printing a message about why we're exiting.
 *
 * Use the fr_exit(status) macro instead of calling this function
 * directly.
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
	fr_debug_break();	/* If running under GDB we'll break here */

	exit(status);
}

/** Exit possibly printing a message about why we're exiting.
 *
 * Use the fr_exit_now(status) macro instead of calling this function
 * directly.
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
	fr_debug_break();	/* If running under GDB we'll break here */

	_exit(status);
}
