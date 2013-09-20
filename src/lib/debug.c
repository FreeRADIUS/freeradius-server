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
#include <signal.h>
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
#  define MAX_BT_ENTRIES 65536			//!< Should be a power of 2

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
				fprintf(stdout, "%s\n", frames[i]);
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
			*cbuff = fr_cbuff_alloc(ctx, MAX_BT_ENTRIES, true);
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
	fr_perror("Server built without fr_backtrace_* support, requires execinfo.h and possibly -lexecinfo");
}
fr_bt_marker_t *fr_backtrace_attach(UNUSED fr_cbuff_t **cbuff, UNUSED TALLOC_CTX *obj)
{
	fr_perror("Server built without fr_backtrace_* support, requires execinfo.h and possibly -lexecinfo");
	abort();
}
#endif /* ifdef HAVE_EXECINFO_H */
