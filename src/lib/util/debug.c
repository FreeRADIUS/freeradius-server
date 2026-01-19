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

/** Functions to help with debugging
 *
 * @file src/lib/util/debug.c
 *
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/util/backtrace.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/hash.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>

#if defined(HAVE_MALLOPT) && defined(HAVE_MALLOC_H)
#  include <malloc.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
#  include <sys/prctl.h>
#endif

#ifdef HAVE_SYS_PROCCTL_H
#  include <sys/procctl.h>
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

#ifdef __APPLE__
#include <sys/sysctl.h>
#endif

static char panic_action[512];				//!< The command to execute when panicking.
static fr_fault_cb_t panic_cb = NULL;			//!< Callback to execute whilst panicking, before the
							//!< panic_action.

static bool dump_core;					//!< Whether we should drop a core on fatal signals.

int fr_fault_log_fd = STDERR_FILENO;		//!< Where to write debug output.

fr_debug_state_t fr_debug_state = DEBUGGER_STATE_UNKNOWN;	//!< Whether we're attached to by a debugger.

#ifdef HAVE_SYS_RESOURCE_H
static struct rlimit init_core_limit;
#endif

static TALLOC_CTX *talloc_autofree_ctx;

/*
 * On BSD systems, ptrace(PT_DETACH) uses a third argument for
 * resume address, with the magic value (void *)1 to resume where
 * process stopped. Specifying NULL there leads to a crash because
 * process resumes at address 0.
 */
#if defined(HAVE_SYS_PTRACE_H)
#  ifdef __linux__
#    define _PTRACE(_x, _y) ptrace(_x, _y, NULL, NULL)
#    define _PTRACE_DETACH(_x) ptrace(PT_DETACH, _x, NULL, NULL)
#  elif !defined(__APPLE__) && !defined(__EMSCRIPTEN__) && !defined(HAVE_SYS_PROCCTL_H)
#    define _PTRACE(_x, _y) ptrace(_x, _y, NULL, 0)
#    define _PTRACE_DETACH(_x) ptrace(PT_DETACH, _x, (void *)1, 0)
#endif

#  ifdef HAVE_CAPABILITY_H
#    include <sys/capability.h>
#  endif
#endif

#ifdef HAVE_SANITIZER_LSAN_INTERFACE_H
#  include <sanitizer/lsan_interface.h>
#endif

#ifdef HAVE_SANITIZER_LSAN_INTERFACE_H
static int lsan_test_pipe[2] = {-1, -1};
static int lsan_test_pid = -1;
static int lsan_state = INT_MAX;
static bool lsan_disable = false;	//!< Explicitly disable LSAN

/*
 *	Some versions of lsan_interface.h are broken and don't declare
 *	the prototypes of the functions properly, omitting the zero argument
 *	specifier (void), so we need to disable the warning.
 *
 *	Observed with clang 5.
 */
DIAG_OFF(missing-prototypes)
/** Callback for LSAN - do not rename
 *
 */
char const CC_HINT(used) *__lsan_default_suppressions(void)
{
	return
		"leak:CRYPTO_THREAD_lock_new\n"		/* OpenSSL init leak - reported by heaptrack */
#if defined(__APPLE__)
		"leak:*gmtsub*\n"
		"leak:ImageLoaderMachO::doImageInit\n"
		"leak:initializeNonMetaClass\n"
		"leak:_st_tzset_basic\n"
		"leak:attachCategories\n"
		"leak:fork\n"
		"leak:getaddrinfo\n"
		"leak:getpwuid_r\n"
		"leak:libSystem_atfork_child\n"
		"leak:libsystem_notify\n"
		"leak:load_images\n"
		"leak:newlocale\n"
		/* Perl >= 5.32.0 - Upstream bug, tracked by https://github.com/Perl/perl5/issues/18108 */
		"leak:perl_construct\n"
		"leak:realizeClassWithoutSwift\n"
		"leak:tzset\n"
		"leak:tzsetwall_basic\n"
#elif defined(__linux__)
		"leak:*getpwnam_r*\n"			/* libc startup leak - reported by heaptrack */
		"leak:_dl_init\n"			/* dl startup leak - reported by heaptrack */
		"leak:initgroups\n"			/* libc startup leak - reported by heaptrack */
		"leak:kqueue\n"
#endif
		;
}

/** Callback for LSAN - do not rename
 *
 * Turn off suppressions by default as it interferes with interpreting
 * output from some of the test utilities.
 */
char const CC_HINT(used) *__lsan_default_options(void)
{
	return "print_suppressions=0";
}

/** Callback for LSAN - do not rename
 *
 */
int CC_HINT(used) __lsan_is_turned_off(void)
{
	uint8_t ret = 1;

	/* Disable LSAN explicitly - Used for tests involving fork() */
	if (lsan_disable) return 1;

	/* Parent */
	if (lsan_test_pid != 0) return 0;

	/* Child */
	if (write(lsan_test_pipe[1], &ret, sizeof(ret)) < 0) {
		fprintf(stderr, "Writing LSAN status failed: %s", fr_syserror(errno));
	}
	close(lsan_test_pipe[1]);
	return 0;
}
DIAG_ON(missing-prototypes)

/** Determine if we're running under LSAN (Leak Sanitizer)
 *
 * @return
 *	- 0 if we're not.
 *	- 1 if we are.
 *	- -1 if we can't tell because of an error.
 *	- -2 if we can't tell because we were compiled with support for the LSAN interface.
 */
int fr_get_lsan_state(void)
{
	uint8_t ret = 0;

	if (lsan_state != INT_MAX) return lsan_state;/* Use cached result */

	if (pipe(lsan_test_pipe) < 0) {
		fr_strerror_printf("Failed opening internal pipe: %s", fr_syserror(errno));
		return -1;
	}

	lsan_test_pid = fork();
	if (lsan_test_pid == -1) {
		fr_strerror_printf("Error forking: %s", fr_syserror(errno));
		return -1;
	}

	/* Child */
	if (lsan_test_pid == 0) {
		close(lsan_test_pipe[0]);	/* Close parent's side */
		exit(EXIT_SUCCESS);		/* Results in LSAN calling __lsan_is_turned_off via onexit handler */
	}

	/* Parent */
	close(lsan_test_pipe[1]);		/* Close child's side */

	while ((read(lsan_test_pipe[0], &ret, sizeof(ret)) < 0) && (errno == EINTR));

	close(lsan_test_pipe[0]);		/* Close our side (so we don't leak FDs) */

	/* Collect child */
	waitpid(lsan_test_pid, NULL, 0);

	lsan_state = ret;			/* Cache test results */

	return ret;
}
#else
int fr_get_lsan_state(void)
{
	fr_strerror_const("Not built with support for LSAN interface");
	return -2;
}
#endif

#if defined(HAVE_SYS_PROCCTL_H)
int fr_get_debug_state(void)
{
	int status;

	if (procctl(P_PID, getpid(), PROC_TRACE_STATUS, &status) == -1) {
		fr_strerror_printf("Cannot get dumpable flag: procctl(PROC_TRACE_STATUS) failed: %s", fr_syserror(errno));
		return DEBUGGER_STATE_UNKNOWN;
	}

	/*
	 *	As FreeBSD docs say about "PROC_TRACE_STATUS":
	 *
	 *	Returns the current tracing status for the specified process in the
	 *	integer variable pointed to by data.  If tracing is disabled, data
	 *	is set to -1.  If tracing is enabled, but no debugger is attached by
	 *	the ptrace(2) syscall, data is set to 0.  If a debugger is attached,
	 *	data is set to the pid of the debugger process.
	 */
	if (status <= 0) return DEBUGGER_STATE_NOT_ATTACHED;

	return DEBUGGER_STATE_ATTACHED;
}
#elif defined(__APPLE__)
/** The ptrace_attach() method no longer works as of macOS 11.4 (we always get eperm)
 *
 * Apple published this helpful article here which provides the
 * magical invocation: https://developer.apple.com/library/archive/qa/qa1361/_index.html
 *
 * @return
 *	- 0 if we're not.
 *	- 1 if we are.
 *      - -1
 */
int fr_get_debug_state(void)
{
	int                 ret;
	int                 mib[4];
	struct kinfo_proc   info;
	size_t              size;

	/*
	 *	Initialize the flags so that, if sysctl fails for some
	 *	reason, we get a predictable result.
	 */
	info.kp_proc.p_flag = 0;

	/*
	 *	Initialize mib, which tells sysctl the info we want, in this case
	 *	we're looking for information about a specific process ID.
	 */
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = getpid();

	/* Call sysctl */
	size = sizeof(info);
	ret = sysctl(mib, NUM_ELEMENTS(mib), &info, &size, NULL, 0);
	if (ret != 0) return -1;

	/* We're being debugged if the P_TRACED flag is set */
	return ((info.kp_proc.p_flag & P_TRACED) != 0);
}
#elif defined(HAVE_SYS_PTRACE_H) && !defined(__EMSCRIPTEN__)
/** Determine if we're running under a debugger by attempting to attach using pattach
 *
 * @return
 *	- 0 if we're not.
 *	- 1 if we are.
 *	- -1 if we can't tell because of an error.
 *	- -2 if we can't tell because we don't have the CAP_SYS_PTRACE capability.
 */
int fr_get_debug_state(void)
{
	int pid;

	int from_child[2] = {-1, -1};

#ifdef HAVE_CAPABILITY_H
	cap_flag_value_t	state;
	cap_t			caps;

	/*
	 *  If we're running under linux, we first need to check if we have
	 *  permission to to ptrace. We do that using the capabilities
	 *  functions.
	 */
	caps = cap_get_proc();
	if (!caps) {
		fr_strerror_printf("Failed getting process capabilities: %s", fr_syserror(errno));
		return DEBUGGER_STATE_UNKNOWN;
	}

	if (cap_get_flag(caps, CAP_SYS_PTRACE, CAP_PERMITTED, &state) < 0) {
		fr_strerror_printf("Failed getting CAP_SYS_PTRACE permitted state: %s",
				   fr_syserror(errno));
		cap_free(caps);
		return DEBUGGER_STATE_UNKNOWN;
	}

	if ((state == CAP_SET) && (cap_get_flag(caps, CAP_SYS_PTRACE, CAP_EFFECTIVE, &state) < 0)) {
		fr_strerror_printf("Failed getting CAP_SYS_PTRACE effective state: %s",
				   fr_syserror(errno));
		cap_free(caps);
		return DEBUGGER_STATE_UNKNOWN;
	}

	/*
	 *  We don't have permission to ptrace, so this test will always fail.
	 */
	if (state == CAP_CLEAR) {
		fr_strerror_printf("ptrace capability not set.  If debugger detection is required run as root or: "
				   "setcap cap_sys_ptrace+ep <path_to_binary>");
		cap_free(caps);
		return DEBUGGER_STATE_UNKNOWN_NO_PTRACE_CAP;
	}
	cap_free(caps);
#endif

	if (pipe(from_child) < 0) {
		fr_strerror_printf("Error opening internal pipe: %s", fr_syserror(errno));
		return DEBUGGER_STATE_UNKNOWN;
	}

	pid = fork();
	if (pid == -1) {
		fr_strerror_printf("Error forking: %s", fr_syserror(errno));
		return DEBUGGER_STATE_UNKNOWN;
	}

	/* Child */
	if (pid == 0) {
		int8_t	ret = DEBUGGER_STATE_NOT_ATTACHED;
		int	ppid = getppid();
		int	flags;

		/*
		 *	Disable the leak checker for this forked process
		 *	so we don't get spurious leaks reported.
		 */
#ifdef HAVE_SANITIZER_LSAN_INTERFACE_H
		lsan_disable = true;
#endif

DIAG_OFF(deprecated-declarations)
		flags = PT_ATTACH;
DIAG_ON(deprecated-declarations)

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
		errno = 0;
		_PTRACE(flags, ppid);
		if (errno == 0) {
			/* Wait for the parent to stop */
			waitpid(ppid, NULL, 0);

			/* Tell the parent what happened */
		send_status:
			if (write(from_child[1], &ret, sizeof(ret)) < 0) {
				fprintf(stderr, "Writing ptrace status to parent failed: %s\n", fr_syserror(errno));
			}

			/* Detach */
			_PTRACE_DETACH(ppid);


			/*
			*	We call _exit() instead of exit().  This means that we skip the atexit() handlers,
			*	which don't need to run in a temporary child process.  Skipping them means that we
			*	avoid dirtying those pages to "clean things up", which is then immediately followed by
			*	exiting.
			*
			*	Skipping the atexit() handlers also means that we're not worried about memory leaks
			*	because things "aren't cleaned up correctly".  We're not exiting cleanly here (and
			*	don't care to exit cleanly).  So just exiting with no cleanups is fine.
			*/
			_exit(0); /* don't run the atexit() handlers. */
		/*
		 *	man ptrace says the following:
		 *
		 *	EPERM  The specified process cannot be traced.  This could be
                 *	because the tracer has insufficient privileges (the
                 *	required capability is CAP_SYS_PTRACE); unprivileged
                 *	processes cannot trace processes that they cannot send
                 *	signals to or those running set-user-ID/set-group-ID
                 *	programs, for obvious reasons.  Alternatively, the process
		 *	may already be being traced, or (before Linux 2.6.26) be
        	 *	init(1) (PID 1).
		 *
		 *	In any case, we are very unlikely to be able to attach to
		 *	the process from the panic action.
		 *
		 *	We checked for CAP_SYS_PTRACE previously, so know that
		 *	we _should_ haven been ablle to attach, so if we can't, it's
		 *	likely that we're already being traced.
		 */
		} else if (errno == EPERM) {
			ret = DEBUGGER_STATE_ATTACHED;
			goto send_status;
		}

		/*
		 *	Unexpected error, we don't know whether we're already running
		 * 	under a debugger or not...
		 */
		ret = DEBUGGER_STATE_UNKNOWN;
		fprintf(stderr, "Debugger check failed to attach to parent with unexpected error: %s\n", fr_syserror(errno));
		goto send_status;
	/* Parent */
	} else {
		int8_t ret = DEBUGGER_STATE_UNKNOWN;

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
int fr_get_debug_state(void)
{
	fr_strerror_const("PTRACE not available");

	return DEBUGGER_STATE_UNKNOWN_NO_PTRACE;
}
#endif

/** Should be run before using setuid or setgid to get useful results
 *
 * @note sets the fr_debug_state global.
 */
void fr_debug_state_store(void)
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
	case DEBUGGER_STATE_UNKNOWN_NO_PTRACE:
		return "Debug state unknown (ptrace functionality not available)";

	case DEBUGGER_STATE_UNKNOWN_NO_PTRACE_CAP:
		return "Debug state unknown (cap_sys_ptrace capability not set)";

	case DEBUGGER_STATE_UNKNOWN:
		return "Debug state unknown";

	case DEBUGGER_STATE_ATTACHED:
		return "Found debugger attached";

	case DEBUGGER_STATE_NOT_ATTACHED:
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
	if (fr_debug_state == DEBUGGER_STATE_ATTACHED) {
		fprintf(stderr, "Debugger detected, raising SIGTRAP\n");
		fflush(stderr);

		raise(SIGTRAP);
	}
}

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
#if defined(HAVE_SYS_PRCTL_H) && defined(PR_SET_DUMPABLE) && !defined(__EMSCRIPTEN__)
static int fr_set_pr_dumpable_flag(bool dumpable)
{
	if (prctl(PR_SET_DUMPABLE, dumpable ? 1 : 0) < 0) {
		fr_strerror_printf("Cannot re-enable core dumps: prctl(PR_SET_DUMPABLE) failed: %s",
				   fr_syserror(errno));
		return -1;
	}

	return 0;
}
#elif defined(HAVE_SYS_PROCCTL_H)
static int fr_set_pr_dumpable_flag(bool dumpable)
{
	int mode = dumpable ? PROC_TRACE_CTL_ENABLE : PROC_TRACE_CTL_DISABLE;

	if (procctl(P_PID, getpid(), PROC_TRACE_CTL, &mode) == -1) {
		fr_strerror_printf("Cannot re-enable core dumps: procctl(PROC_TRACE_CTL) failed: %s",
				   fr_syserror(errno));
		return -1;
	}

	return 0;
}
#else
static int fr_set_pr_dumpable_flag(UNUSED bool dumpable)
{
	fr_strerror_const("Changing value of PR_DUMPABLE not supported on this system");
	return -2;
}
#endif

/** Get the processes dumpable flag
 *
 */
#if defined(HAVE_SYS_PRCTL_H) && defined(PR_GET_DUMPABLE) && !defined(__EMSCRIPTEN__)
static int fr_get_pr_dumpable_flag(void)
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
#elif defined(HAVE_SYS_PROCCTL_H)
static int fr_get_pr_dumpable_flag(void)
{
	int status;

	if (procctl(P_PID, getpid(), PROC_TRACE_CTL, &status) == -1) {
		fr_strerror_printf("Cannot get dumpable flag: procctl(PROC_TRACE_CTL) failed: %s", fr_syserror(errno));
		return -1;
	}

	/*
	 *	There are a few different kinds of disabled, but only
	 *	one ENABLE.
	 */
	if (status != PROC_TRACE_CTL_ENABLE) return 0;

	return 1;
}
#else
static int fr_get_pr_dumpable_flag(void)
{
	fr_strerror_const("Getting value of PR_DUMPABLE not supported on this system");
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
	if (getrlimit(RLIMIT_CORE, &init_core_limit) < 0) {
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

#ifdef HAVE_SYS_RESOURCE_H
	{
		struct rlimit current;

		/*
		 *	Reset the core limits (or disable them)
		 */
		if (getrlimit(RLIMIT_CORE, &current) < 0) {
			fr_strerror_printf("Failed to get current core limit:  %s", fr_syserror(errno));
			return -1;
		}

		if (allow_core_dumps) {
			if ((current.rlim_cur != init_core_limit.rlim_cur) ||
			    (current.rlim_max != init_core_limit.rlim_max)) {
				if (setrlimit(RLIMIT_CORE, &init_core_limit) < 0) {
					fr_strerror_printf("Cannot update core dump limit: %s", fr_syserror(errno));

					return -1;
				}
			}
		/*
		 *	We've been told to disable core dumping,
		 *	rlim_cur is not set to zero.
		 *
		 *	Set rlim_cur to zero, but leave rlim_max
		 *	set to whatever the current value is.
		 *
		 *	This is because, later, we may need to
		 *	re-enable core dumps to allow the debugger
		 *	to attach *sigh*.
		 */
		} else if (current.rlim_cur != 0) {
			struct rlimit no_core;

			no_core.rlim_cur = 0;
			no_core.rlim_max = current.rlim_max;

			if (setrlimit(RLIMIT_CORE, &no_core) < 0) {
				fr_strerror_printf("Failed disabling core dumps: %s", fr_syserror(errno));

				return -1;
			}
		}
	}
#endif
	/*
	 *	Macro needed so we don't emit spurious errors
	 */
#if defined(HAVE_SYS_PROCCTL_H) || (defined(HAVE_SYS_PRCTL_H) && defined(PR_SET_DUMPABLE))
	if (fr_set_pr_dumpable_flag(allow_core_dumps) < 0) return -1;
#endif

	return 0;
}

/** Reset dumpable state to previously configured value
 *
 * Needed after suid up/down
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_reset_dumpable(void)
{
	return fr_set_dumpable(dump_core);
}

/** Check to see if panic_action file is world writable
 *
 * @return
 *	- 0 if file is OK.
 *	- -1 if the file is world writable.
 */
static int fr_fault_check_permissions(void)
{
	char const *p, *q;
	size_t len;
	char filename[256];
	struct stat statbuf;

	/*
	 *	Try and guess which part of the command is the binary, and check to see if
	 *	it's world writable, to try and save the admin from their own stupidity.
	 *
	 *	@fixme we should do this properly and take into account single and double
	 *	quotes.
	 */
	if ((q = strchr(panic_action, ' '))) {
		/*
		 *	need to use a static buffer, because allocing memory in a signal handler
		 *	is a bad idea and can result in deadlock.
		 */
		len = snprintf(filename, sizeof(filename), "%.*s", (int)(q - panic_action), panic_action);
		if (is_truncated(len, sizeof(filename))) {
			fr_strerror_const("Failed writing panic_action to temporary buffer (truncated)");
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
	char		cmd[sizeof(panic_action) + 20];
	char		*out = cmd;
	size_t		left = sizeof(cmd), ret;

	char const	*p = panic_action;
	char const	*q;

	int		code;

	/*
	 *	If a debugger is attached, we don't want to run the panic action,
	 *	as it may interfere with the operation of the debugger.
	 *	If something calls us directly we just raise the signal and let
	 *	the debugger handle it how it wants.
	 */
	if (fr_debug_state == DEBUGGER_STATE_ATTACHED) {
		FR_FAULT_LOG("RAISING SIGNAL: %s", strsignal(sig));
		raise(sig);
	}

	/*
	 *	Makes the backtraces slightly cleaner
	 */
	memset(cmd, 0, sizeof(cmd));

	FR_FAULT_LOG("CAUGHT SIGNAL: %s", strsignal(sig));

	/*
	 *	Run the callback if one was registered
	 */
	if (panic_cb && (panic_cb(sig) < 0)) goto finish;

	fr_backtrace();

	/* No panic action set... */
	if (panic_action[0] == '\0') {
		FR_FAULT_LOG("No panic action set");
		goto finish;
	}

	/*
	 *	Check for administrator sanity.
	 */
	if (fr_fault_check_permissions() < 0) {
		FR_FAULT_LOG("Refusing to execute panic action: %s", fr_strerror());
		goto finish;
	}

	/* Substitute %p for the current PID (useful for attaching a debugger) */
	while ((q = strstr(p, "%p"))) {
		out += ret = snprintf(out, left, "%.*s%d", (int) (q - p), p, (int) getpid());
		if (left <= ret) {
		oob:
			FR_FAULT_LOG("Panic action too long");
			fr_exit_now(128 + sig);
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
		if (fr_get_pr_dumpable_flag() == 0) {
			if ((fr_set_pr_dumpable_flag(true) < 0) || !fr_get_pr_dumpable_flag()) {
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
			if (fr_set_pr_dumpable_flag(false) < 0) {
				FR_FAULT_LOG("Failed resetting dumpable flag to off: %s", fr_strerror());
				FR_FAULT_LOG("Exiting due to insecure process state");
				fr_exit_now(EXIT_FAILURE);
			}
		}

		FR_FAULT_LOG("Panic action exited with %i", code);

		fr_exit_now(128 + sig);
	}

finish:
	/*
	 *	(Re-)Raise the signal, so that if we're running under
	 *	a debugger.
	 *
	 *	This allows debuggers to function normally and catch
	 *	fatal signals.
	 */
	fr_unset_signal(sig);		/* Make sure we don't get into a loop */
	raise(sig);
	fr_exit_now(128 + sig);		/* Function marked as noreturn */
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

	fr_backtrace();
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
	fr_exit_now(128 + SIGABRT);
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
int fr_log_talloc_report(TALLOC_CTX const *ctx)
{
#define TALLOC_REPORT_MAX_DEPTH 20

	FILE	*log;
	int	fd;

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
		talloc_report_full(talloc_null_ctx(), log);
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
			 (talloc_parent(ctx) != talloc_null_ctx()));  	/* Stop before we hit NULL ctx */
	}

	fclose(log);

	return 0;
}

static int _disable_null_tracking(UNUSED bool *p)
{
	talloc_disable_null_tracking();
	return 0;
}

/** Disable the null tracking context when a talloc chunk is freed
 *
 */
void fr_disable_null_tracking_on_free(TALLOC_CTX *ctx)
{
	bool *marker;

	/*
	 *  Disable null tracking on exit, else valgrind complains
	 */
	marker = talloc(ctx, bool);
	talloc_set_destructor(marker, _disable_null_tracking);
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
 * @param[in] ctx	to allocate autofreeable resources in.
 * @param[in] cmd	to execute on fault. If present %p will be substituted
 *      		for the parent PID before the command is executed, and %e
 *      		will be substituted for the currently running program.
 * @param program Name of program currently executing (argv[0]).
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_fault_setup(TALLOC_CTX *ctx, char const *cmd, char const *program)
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
				fr_strerror_const("Panic action too long");
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
		char			*env;

		/*
		 *  Installing signal handlers interferes with some debugging
		 *  operations.  Give the developer control over whether the
		 *  signal handlers are installed or not.
		 */
		env = getenv("DEBUGGER_ATTACHED");
		if (env && (strcmp(env, "yes") == 0)) {
			fr_debug_state = DEBUGGER_STATE_ATTACHED;		/* i.e. disable signal handlers */

		} else if (env && (strcmp(env, "no") == 0)) {
			fr_debug_state = DEBUGGER_STATE_NOT_ATTACHED;	/* i.e. enable signal handlers */

			/*
			 *  Figure out if we were started under a debugger
			 */
		} else {
			if (fr_debug_state < 0) fr_debug_state = fr_get_debug_state();
		}

		talloc_set_log_fn(_fr_talloc_log);

		/*
		 *  These signals can't be properly dealt with in the debugger
		 *  if we set our own signal handlers.
		 */
		switch (fr_debug_state) {
		default:
		case DEBUGGER_STATE_NOT_ATTACHED:
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
#ifdef SIGALRM
			/*
			 *  This is used be jlibtool to terminate
			 *  processes which have been running too
			 *  long.
			 */
			if (fr_set_signal(SIGALRM, fr_fault) < 0) return -1;
#endif
			break;

		case DEBUGGER_STATE_ATTACHED:
			break;
		}

		/*
		 *  Needed for memory reports
		 */
		fr_disable_null_tracking_on_free(ctx);

#if defined(HAVE_MALLOPT) && !defined(NDEBUG)
		/*
		 *  If were using glibc malloc > 2.4 this scribbles over
		 *  uninitialised and freed memory, to make memory issues easier
		 *  to track down.
		 */
#  ifdef M_PERTURB
		if (!getenv("TALLOC_FREE_FILL")) mallopt(M_PERTURB, 0x42);
#  endif
#  ifdef M_CHECK_ACTION
		mallopt(M_CHECK_ACTION, 3);
#  endif
#endif
		fr_backtrace_init(program);
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
 * function. Unfortunately, when logging to syslog, syslog would alloc memory
 * which would result in a deadlock if fr_fault was triggered from within
 * a allocation call.
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

/** Print data as a hex block
 *
 */
void fr_fault_log_hex(uint8_t const *data, size_t data_len)
{
	size_t		i, j, len;
	char		buffer[(0x10 * 3) + 1];
	char		*p, *end = buffer + sizeof(buffer);

	for (i = 0; i < data_len; i += 0x10) {
		len = 0x10;
		if ((i + len) > data_len) len = data_len - i;

		for (p = buffer, j = 0; j < len; j++, p += 3) snprintf(p, end - p, "%02x ", data[i + j]);

		dprintf(fr_fault_log_fd, "%04x: %s\n", (unsigned int) i, buffer);
	}
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
 * @param[in] file	the assertion failed in.
 * @param[in] line	of the assertion in the file.
 * @param[in] expr	that was evaluated.
 * @param[in] msg	Message to print (may be NULL).
 * @param[in] ...	Arguments for msg string.
 * @return the value of cond.
 */
bool _fr_assert_fail(char const *file, int line, char const *expr, char const *msg, ...)
{
	if (msg) {
		char str[256];		/* Decent compilers won't allocate this unless fmt is !NULL... */
		va_list ap;

		va_start(ap, msg);
		(void)vsnprintf(str, sizeof(str), msg, ap);
		va_end(ap);

#ifndef NDEBUG
		FR_FAULT_LOG("ASSERT FAILED %s[%d]: %s: %s", file, line, expr, str);
		fr_fault(SIGABRT);
#else
		FR_FAULT_LOG("ASSERT WOULD FAIL %s[%d]: %s: %s", file, line, expr, str);
		return false;
#endif
	}

#ifndef NDEBUG
	FR_FAULT_LOG("ASSERT FAILED %s[%d]: %s", file, line, expr);
	fr_fault(SIGABRT);
#else
	FR_FAULT_LOG("ASSERT WOULD FAIL %s[%d]: %s", file, line, expr);
	return false;
#endif
}

/** A fatal assertion which triggers the fault handler in debug builds or exits
 *
 * @param[in] file	the assertion failed in.
 * @param[in] line	of the assertion in the file.
 * @param[in] expr	that was evaluated.
 * @param[in] msg	Message to print (may be NULL).
 * @param[in] ...	Arguments for msg string.
 */
void _fr_assert_fatal(char const *file, int line, char const *expr, char const *msg, ...)
{
	if (msg) {
		char str[256];		/* Decent compilers won't allocate this unless fmt is !NULL... */
		va_list ap;

		va_start(ap, msg);
		(void)vsnprintf(str, sizeof(str), msg, ap);
		va_end(ap);

		FR_FAULT_LOG("FATAL ASSERT %s[%d]: %s: %s", file, line, expr, str);
	} else {
		FR_FAULT_LOG("FATAL ASSERT %s[%d]: %s", file, line, expr);
	}

#ifdef NDEBUG
	_fr_exit(file, line, 128 + SIGABRT, true);
#else
	fr_fault(SIGABRT);
#endif
}

/** Exit possibly printing a message about why we're exiting.
 *
 * @note Use the fr_exit(status) macro instead of calling this function directly.
 *
 * @param[in] file	where fr_exit() was called.
 * @param[in] line	where fr_exit() was called.
 * @param[in] status	we're exiting with.
 * @param[in] now	Exit immediately.
 */
#ifndef NDEBUG
NEVER_RETURNS void _fr_exit(char const *file, int line, int status, bool now)
{
	if (status != EXIT_SUCCESS) {
		char const *error = fr_strerror();

		if (error && *error && (status != 0)) {
			FR_FAULT_LOG("%sEXIT(%i) CALLED %s[%d].  Last error was: %s", now ? "_" : "",
				     status, file, line, error);
		} else {
			FR_FAULT_LOG("%sEXIT(%i) CALLED %s[%d]", now ? "_" : "", status, file, line);
		}

		fr_debug_break(false);	/* If running under GDB we'll break here */
	}

	if (now) _Exit(status);
	exit(status);
}
#else
NEVER_RETURNS void _fr_exit(UNUSED char const *file, UNUSED int line, int status, bool now)
{
	if (status != EXIT_SUCCESS) fr_debug_break(false);	/* If running under GDB we'll break here */

	if (now) _Exit(status);
	exit(status);
}
#endif
