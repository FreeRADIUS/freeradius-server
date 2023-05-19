/*
 * Below are modeling functions that use Coverity functions (the __coverity_*__())
 * to tell it the functions' intent.
 *
 * Summary: there doesn't appear to be any way we can run cov-make-library, which
 * leaves us with uploading it via the Coverity web page. We found out the hard
 * way that just preprocessing won't cut it. Coverity can't handle the expansions
 * of some of the macro usage in FreeRADIUS. In fact, one (open source) Coverity
 * modeling file says in comments that you *can't* include header files.
 *
 * That said... coverity models only describe the modeled functions' effects that
 * matter to coverity. There's an example in the Coverity docs modeling a function
 * that calls fopen(), and it actually typedefs FILE as an empty structure. It works..
 * because coverity is told what happens only in terms of the FILE * fopen() returns.
 *
 * We can't always get away with that. For example, initializing a value box, if
 * successful, writes sizeof(fr_value_box_t) bytes, so coverity has to know enough
 * to accurately determine that. We may find other issues as well... ah! If the models
 * keep things symbolic, maybe we CAN get away with only mentioning referenced fields.
 *
 * All this leads to possible coupling between the declarations and typedefs herein
 * and the real ones in FreeRADIUS header files, so that changes in the latter may
 * require changes to the former. So... We will declare ONLY what the modeling functions
 * need, mentioning their source, until we find out that more is necessary.
 *
 * NOTE: Any time this file changes, it must be reuploaded via the coverity scan web
 * interface.
 */

typedef unsigned char bool;

typedef unsigned int mode_t;
typedef long long int off_t;


typedef union {
} pthread_mutex_t;

/* from src/lib/server/exfile.[ch] */

typedef struct exfile_s {
	pthread_mutex_t		mutex;
	bool			locking;
} exfile_t;

static int exfile_open_lock(exfile_t *ef, char const *filename, mode_t permissions, off_t *offset)
{
    int result;

    if (result > 0) __coverity_exclusive_lock_acquire__((void *) &ef->mutex);
    return result;
}

static int exfile_close_lock(exfile_t *ef, int fd)
{
    int result;

    __coverity_exclusive_lock_release__((void *) &ef->mutex);
    return result;
}

/* from src/lib/server/pool.[ch] */

typedef struct {
} request_t;

typedef struct {
	pthread_mutex_t	mutex;
} fr_pool_t;

typedef struct {
} fr_pool_connection_t;

typedef struct {
} fr_time_t;

static fr_pool_connection_t *connection_spawn(fr_pool_t *pool, request_t *request, fr_time_t now, bool in_use, bool unlock)
{
	fr_pool_connection_t *result;

	if (result && !unlock)  __coverity_exclusive_lock_acquire__((void *) &pool->mutex);
	return result;
}

static fr_pool_connection_t *connection_find(fr_pool_t *pool, void *conn)
{
	fr_pool_connection_t *result;

	if (result)  __coverity_exclusive_lock_acquire__((void *) &pool->mutex);
	return result;
}

