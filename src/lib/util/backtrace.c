#include <dlfcn.h>

#include <freeradius-devel/util/backtrace.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/fring.h>
#include <freeradius-devel/util/misc.h>

#ifdef HAVE_BACKTRACE
#  include <freeradius-devel/backtrace/backtrace.h>

static struct backtrace_state *backtrace_state = NULL;	//!< Backtrace state for the backtrace functions
							///< This is initialised to be thread-safe, so we only need one.

/** Used when building without libbacktrace to record frame information
 */
typedef struct {
	char const	*library;			//!< Backtrace library name.
	char const 	*filename;			//!< Backtrace file.
	char const	*function;			//!< Backtrace function.
	bool		function_guess;			//!< Whether dladdr guessed the function.
							//!< This is true if the function name is not in the
							//!< symbol table, but was guessed from the program counter.
	unsigned int	lineno;				//!< Backtrace line number.
	unsigned int	frameno;			//!< Backtrace frame number.
	uintptr_t	pc;				//!< Backtrace program counter.
} fr_bt_info_frame_t;
#elif defined(HAVE_EXECINFO)
#  include <execinfo.h>
#endif

#  ifndef MAX_BT_FRAMES
#    define MAX_BT_FRAMES 128
#  endif
#  ifndef MAX_BT_CBUFF
#    define MAX_BT_CBUFF  1048576			//!< Should be a power of 2
#  endif

static pthread_mutex_t fr_backtrace_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
	void 			*obj;				//!< Memory address of the block of allocated memory.
#ifdef HAVE_BACKTRACE
	fr_bt_info_frame_t	*frames[MAX_BT_FRAMES];		//!< Backtrace frame data
#else
	void			*frames[MAX_BT_FRAMES];		//!< Backtrace frame data
#endif
	int			count;				//!< Number of frames stored
} fr_bt_info_t;

struct fr_bt_marker {
	void 		*obj;				//!< Pointer to the parent object, this is our needle
							//!< when we iterate over the contents of the circular buffer.
	fr_fring_t 	*fring;				//!< Where we temporarily store the backtraces
};

#ifdef HAVE_BACKTRACE
/** Log faults from libbacktrace
 *
 */
static void _backtrace_error(UNUSED void *data, const char *msg, int errnum)
{
	FR_FAULT_LOG("Backtrace error: %s (%d)", msg, errnum);
}

static void backtrace_info_sanitise(fr_bt_info_frame_t *info)
{
	Dl_info dl_info;

	if (dladdr((void *)info->pc, &dl_info) != 0) {
		info->library = dl_info.dli_fname;
		if (!info->function) {
			info->function = dl_info.dli_sname;
			info->function_guess = true;
		}
	}
}

static void backtrace_info_print(fr_bt_info_frame_t *frame, int fd, bool trim_path)
{
	if (!frame->library && !frame->filename) {
		dprintf(fd, "#%u: 0x%lx\n",
			frame->frameno,
			(unsigned long)frame->pc);
		return;
	}
	else if (!frame->filename) {
		dprintf(fd, "%u: 0x%lx %s in %s()\n",
			frame->frameno,
			(unsigned long)frame->pc,
			trim_path ? fr_filename(frame->library) : frame->library,
			frame->function);
		return;
	}
	dprintf(fd, "#%u: 0x%lx %s in %s() at %s:%d\n",
		frame->frameno,
		(unsigned long)frame->pc,
		trim_path ? fr_filename(frame->library) : frame->library,
		frame->function,
		trim_path ? fr_filename_common_trim(frame->filename, frame->library) : frame->filename,
		frame->lineno);

}

static int _backtrace_info_record(void *data, uintptr_t pc,
				  const char *filename, int lineno,
				  const char *function)
{
	fr_bt_info_t *info = talloc_get_type_abort(data, fr_bt_info_t);
	fr_bt_info_frame_t *frame;

	if (info->count >= (int)NUM_ELEMENTS(info->frames)) return 0;

	frame = talloc_zero(info, fr_bt_info_frame_t);
	if (!frame) return -1;

	frame->filename = talloc_strdup(frame, filename);
	frame->function = talloc_strdup(frame, function);
	frame->lineno = lineno;
	frame->frameno = info->count;
	frame->pc = pc;

	backtrace_info_sanitise(frame);

	info->frames[info->count++] = frame;

	return 0;
}

static void backtrace_record(fr_bt_info_t *info)
{
	backtrace_full(backtrace_state, 0, _backtrace_info_record, _backtrace_error, info);
}

static int _backtrace_print(void *data, uintptr_t pc,
			    const char *filename, int lineno,
			    const char *function)
{
	unsigned int *frame_no = ((unsigned int *)data);
	fr_bt_info_frame_t frame = {
		.filename = filename,
		.lineno = lineno,
		.function = function,
		.frameno = *frame_no,
		.pc = pc,
	};

	backtrace_info_sanitise(&frame);
	backtrace_info_print(&frame, fr_fault_log_fd, true);

	(*frame_no)++;
	return 0;
}

void fr_backtrace(void)
{
	unsigned int frame = 0;

	if (fr_fault_log_fd >= 0) {
		FR_FAULT_LOG("Backtrace:");
		backtrace_full(backtrace_state, 0, _backtrace_print, _backtrace_error, &frame);
	}
}
#elif defined(HAVE_EXECINFO)
void fr_backtrace(void)
{
	/*
	 *	Produce a simple backtrace - They're very basic but at least give us an
	 *	idea of the area of the code we hit the issue in.
	 *
	 *	See below in fr_fault_setup() and
	 *	https://sourceware.org/bugzilla/show_bug.cgi?id=16159
	 *	for why we only print backtraces in debug builds if we're using GLIBC.
	 */
#if (!defined(NDEBUG) || !defined(__GNUC__))
	if (fr_fault_log_fd >= 0) {
		size_t frame_count;
		void *stack[MAX_BT_FRAMES];

		frame_count = backtrace(stack, MAX_BT_FRAMES);

		FR_FAULT_LOG("Backtrace of last %zu frames:", frame_count);

		backtrace_symbols_fd(stack, frame_count, fr_fault_log_fd);
	}
#endif
	return;
}
#else
void fr_backtrace(void)
{
	return;
}
#endif

#if defined(HAVE_BACKTRACE) || defined(HAVE_EXECINFO)
/** Print backtrace entry for a given object
 *
 * @param fring to search in.
 * @param obj pointer to original object
 */
void fr_backtrace_print(fr_fring_t *fring, void *obj)
{
	fr_bt_info_t *p;
	bool found = false;

	while ((p = fr_fring_next(fring))) {
		if ((p->obj == obj) || !obj) {
			found = true;

			fprintf(stderr, "Stacktrace for: %p\n", p->obj);
#ifdef HAVE_BACKTRACE
			{
				int i;

				for (i = 0; i < p->count; i++) {
					backtrace_info_print(p->frames[i], fr_fault_log_fd, true);
				}
			}
#else
			backtrace_symbols_fd(p->frames, p->count, fr_fault_log_fd);
#endif
		}
	}

	if (!found) {
		fprintf(stderr, "No backtrace available for %p", obj);
	}
}

/** Generate a backtrace for an object
 *
 * If this is the first entry being inserted
 */
static int _backtrace_do(fr_bt_marker_t *marker)
{
	fr_bt_info_t *bt;

	if (!fr_cond_assert(marker->obj) || !fr_cond_assert(marker->fring)) return -1;

	bt = talloc_zero(NULL, fr_bt_info_t);
	if (!bt) return -1;

	bt->obj = marker->obj;
#ifdef HAVE_BACKTRACE

#else
	bt->count = backtrace(bt->frames, MAX_BT_FRAMES);
#endif
	fr_fring_overwrite(marker->fring, bt);

	return 0;
}

/** Inserts a backtrace marker into the provided context
 *
 * Allows for maximum laziness and will initialise a circular buffer if one has not already been created.
 *
 * Code augmentation should look something like:
@verbatim
	// Create a static fring pointer, the first call to backtrace_attach will initialise it
	static fr_fring_t *my_obj_bt;

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
 * @param fring this should be a pointer to a static *fr_fring_buffer.
 * @param obj we want to generate a backtrace for.
 */
fr_bt_marker_t *fr_backtrace_attach(fr_fring_t **fring, TALLOC_CTX *obj)
{
	fr_bt_marker_t *marker;

	if (*fring == NULL) {
		pthread_mutex_lock(&fr_backtrace_lock);
		if (*fring == NULL) *fring = fr_fring_alloc(NULL, MAX_BT_CBUFF, true);
		pthread_mutex_unlock(&fr_backtrace_lock);
	}

	marker = talloc(obj, fr_bt_marker_t);
	if (!marker) {
		return NULL;
	}

	marker->obj = (void *) obj;
	marker->fring = *fring;

	fprintf(stderr, "Backtrace attached to %s %p\n", talloc_get_name(obj), obj);
	/*
	 *	Generate the backtrace for memory allocation
	 */
	_backtrace_do(marker);
	talloc_set_destructor(marker, _backtrace_do);

	return marker;
}
#else
fr_bt_marker_t *fr_backtrace_attach(UNUSED fr_fring_t **fring, UNUSED TALLOC_CTX *obj)
{
	fprintf(stderr, "Server built without fr_backtrace_* support, requires execinfo.h and possibly -lexecinfo, or libbacktrace\n");
	abort();
}
#endif

void fr_backtrace_init(
#ifndef HAVE_BACKTRACE
			UNUSED
#endif
			char const *program)
{
#ifdef HAVE_BACKTRACE
		/*
		 *  Initialise the state for libbacktrace.  As per the docs
		 *  these resources can never be freed, and should be ignore
		 *  in any leak tracking code.
		 */
		backtrace_state = backtrace_create_state(program, 1, _backtrace_error, NULL);
#elif defined(HAVE_EXECINFO) && defined(__GNUC__) && !defined(NDEBUG)
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
