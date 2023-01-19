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
