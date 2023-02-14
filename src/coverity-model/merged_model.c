/*
 * Below are modeling functions that use Coverity functions (the __coverity_*__())
 * to tell it the functions' intent.
 *
 * cov-make-library is the only model-related program that lets one specify compiler
 * options, notably -I to specify where header files live....but it is NOT in the
 * gzipped tar file of coverity programs one can run locally, so pending further
 * information, one must create a file with modelig functions that one can upload via
 * the web interfacet that does not #include header files not in the C standard.
 *
 * Speaking of -I, it would need to be cc -E -I <path to get to src>, since
 * src contains the freeradius-devel symlink.
 *
 * The most nearly sane way to do that is to preprocessthis file and upload the
 * output via the web. It would be good if this could be automated. One can do this
 * from the command line in the top-level directory of the reposiitory with the command
 *
 *	cc -E -I src -I/usr/include/kqueue -D HAVE_CLOCK_GETTIME src/coverity-model/merged_model.c
 *
 * and redirecting standard output to a file to then upload via Coverity's web interface as the
 * modeling file.
 *
 * (One may well ask what static functions are doing here. Coverity says that one
 * can model static functions, so here they are. This may require further change.)
 *
 * Since standard header files are guaranteed idempotent and FreeRADIUS header files
 * are idempotent, we group modeling functions according to the source file the
 * functions being modeled come from and keep the #include directives in that file
 * with them.
 */


#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/exfile.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/perm.h>
#include <freeradius-devel/util/syserror.h>

#include <sys/stat.h>
#include <fcntl.h>

int exfile_open(exfile_t *ef, char const *filename, mode_t permissions, off_t *offset)
{
    int result;

    if (ef->locking && result > 0) __coverity_exclusive_lock_acquire__(ef->mutex);
    return result;
}

int exfile_close(exfile_t *ef, int fd)
{
    int result;

    if (ef->locking) __coverity_exclusive_lock_release__(ef->mutex);
    return result;
}

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/util/heap.h>
#include <freeradius-devel/util/misc.h>

#include <time.h>

static fr_pool_connection_t *connection_spawn(fr_pool_t *pool, request_t *request, fr_time_t now, bool in_use, bool unlock)
{
	fr_pool_connection_t *result;

	if (result && !unlock)  __coverity_exclusive_lock_acquire__(pool->mutex);
	return result;
}

static fr_pool_connection_t *connection_find(fr_pool_t *pool, void *conn)
{
	fr_pool_connection_t *result;

	if (result)  __coverity_exclusive_lock_acquire__(pool->mutex);
	return result;
}

