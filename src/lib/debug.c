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
#include <freeradius-devel/libradius.h>

/*
 *	runtime backtrace functions are not POSIX but are included in
 *	glibc, OSX >= 10.5 and various BSDs
 */
#ifdef HAVE_EXECINFO_H
#  include <execinfo.h>
#endif

#ifdef HAVE_PTHREAD_H
#define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock
#else
#define PTHREAD_MUTEX_LOCK(_x)
#define PTHREAD_MUTEX_UNLOCK(_x)
#endif

#ifdef HAVE_EXECINFO_H
#  define MAX_BT_FRAMES 128
#  define MAX_BT_CBUFF  65536			//!< Should be a power of 2

#  ifdef HAVE_PTHREAD_H
static pthread_mutex_t fr_debug_init = PTHREAD_MUTEX_INITIALIZER;
#  endif

typedef struct fr_bt_info {
	void 		*obj;				//!< Memory address of the block of allocated memory.
	void		*frames[MAX_BT_FRAMES];		//!< Backtrace frame data
	int		count;				//!< Number of frames stored
} fr_bt_info_t;

struct fr_bt_marker {
	void 		*obj;			//!< Pointer to the parent object, this is our needle
						//!< when we iterate over the contents of the circular buffer.
	fr_cbuff_t 	*cbuff;			//!< Where we temporarily store the backtraces
};
#endif

static char panic_action[512];
static int fr_debugger_present = -1;

/** Stub callback to see if the SIGTRAP handler is overriden
 *
 * @param signum signal raised.
 */
static void _sigtrap_handler(UNUSED int signum)
{
    fr_debugger_present = 0;
    signal(SIGTRAP, SIG_DFL);
}

/** Break in GDB (if were running under GDB)
 *
 * If the server is running under GDB this will raise a SIGTRAP which
 * will pause the running process.
 *
 * If the server is not running under GDB then this will do nothing.
 */
void fr_debug_break(void)
{
    if (fr_debugger_present == -1) {
    	fr_debugger_present = 0;
        signal(SIGTRAP, _sigtrap_handler);
        raise(SIGTRAP);
    } else if (fr_debugger_present == 1) {
    	raise(SIGTRAP);
    }
}

#ifdef HAVE_EXECINFO_H
/** Generate a backtrace for an object during destruction
 *
 * If this is the first entry being inserted
 */
static int _fr_do_bt(fr_bt_marker_t *marker)
{
	fr_bt_info_t *bt;

	if (!fr_assert(marker->obj) || !fr_assert(marker->cbuff)) {
		return -1;
	}

	bt = talloc_zero(marker->cbuff, fr_bt_info_t);
	if (!bt) {
		return -1;
	}
	bt->count = backtrace(bt->frames, MAX_BT_FRAMES);
	fr_cbuff_rp_insert(marker->cbuff, bt);

	return 0;
}

/** Print backtrace entry for a given object
 *
 * @param cbuff to search in.
 * @param obj pointer to original object
 */
void backtrace_print(fr_cbuff_t *cbuff, void *obj)
{
	fr_bt_info_t *p;
	bool found = false;
	int i = 0;
	char **frames;

	while ((p = fr_cbuff_rp_next(cbuff, NULL))) {
		if ((p == obj) || !obj) {
			found = true;
			frames = backtrace_symbols(p->frames, p->count);

			fprintf(stderr, "Stacktrace for: %p\n", p);
			for (i = 0; i < p->count; i++) {
				fprintf(stderr, "%s\n", frames[i]);
			}

			/* We were only asked to look for one */
			if (obj) {
				return;
			}
		}
	};

	if (!found) {
		fprintf(stderr, "No backtrace available for %p", obj);
	}
}

/** Inserts a backtrace marker into the provided context
 *
 * Allows for maximum laziness and will initialise a circular buffer if one has not already been created.
 *
 * Code augmentation should look something like:
@verbatim
	// Create a static cbuffer pointer, the first call to backtrace_attach will initialise it
	static fr_cbuff *my_obj_bt;

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
		if (*cbuff == NULL) {
			TALLOC_CTX *ctx;

			ctx = fr_autofree_ctx();
			*cbuff = fr_cbuff_alloc(ctx, MAX_BT_CBUFF, true);
		}
		PTHREAD_MUTEX_UNLOCK(&fr_debug_init);
	}

	marker = talloc(obj, fr_bt_marker_t);
	if (!marker) {
		return NULL;
	}

	marker->obj = (void *) obj;
	marker->cbuff = *cbuff;

	talloc_set_destructor(marker, _fr_do_bt);

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
#endif /* ifdef HAVE_EXECINFO_H */

/** Prints a simple backtrace (if execinfo is available) and calls panic_action if set.
 *
 * @param sig caught
 */
static void NEVER_RETURNS _fr_fault(int sig)
{
	char cmd[sizeof(panic_action) + 20];
	char *p;
	int ret;

	fprintf(stderr, "FATAL SIGNAL: %s\n", strsignal(sig));

	/*
	 *	Produce a simple backtrace - They've very basic but at least give us an
	 *	idea of the area of the code we hit the issue in.
	 */
#ifdef HAVE_EXECINFO_H
	size_t frame_count, i;
	void *stack[MAX_BT_FRAMES];
	char **frames;

	frame_count = backtrace(stack, MAX_BT_FRAMES);
	frames = backtrace_symbols(stack, frame_count);

	fprintf(stderr, "Backtrace of last %zu frames:\n", frame_count);
	for (i = 0; i < frame_count; i++) {
		fprintf(stderr, "%s\n", frames[i]);
		/* Leak the backtrace strings, freeing may lead to undefined behaviour... */
	}
#endif

	/* No panic action set... */
	if (panic_action[0] == '\0') {
		fprintf(stderr, "No panic action set\n");
		fr_exit_now(1);
	}

	/* Substitute %p for the current PID (useful for attaching a debugger) */
	p = strstr(panic_action, "%p");
	if (p) {
		snprintf(cmd, sizeof(cmd), "%.*s%i%s",
			 (int)(p - panic_action), panic_action, (int)getpid(), p + 2);
	} else {
		strlcpy(cmd, panic_action, sizeof(cmd));
	}

	fprintf(stderr, "Calling: %s\n", cmd);
	ret = system(cmd);
	fprintf(stderr, "Panic action exited with %i\n", ret);

	fr_exit_now(1);
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
	char *p;

	if (cmd) {
		/* Substitute %e for the current program */
		p = strstr(cmd, "%e");
		if (p) {
			snprintf(panic_action, sizeof(panic_action), "%.*s%s%s",
				 (int)(p - cmd), cmd, program ? program : "", p + 2);
		} else {
			strlcpy(panic_action, cmd, sizeof(panic_action));
		}
	} else {
		*panic_action = '\0';
	}

	/* Unsure what the side effects of changing the signal handler mid execution might be */
	if (!setup) {
#ifdef SIGSEGV
		if (fr_set_signal(SIGSEGV, _fr_fault) < 0) return -1;
#endif
#ifdef SIGBUS
		if (fr_set_signal(SIGBUS, _fr_fault) < 0) return -1;
#endif
#ifdef SIGABRT
		if (fr_set_signal(SIGABRT, _fr_fault) < 0) return -1;
#endif
#ifdef SIGFPE
		if (fr_set_signal(SIGFPE, _fr_fault) < 0) return -1;
#endif
	}
	setup = true;

	return 0;
}

