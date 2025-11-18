/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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

/** API for POSIX semaphores in mmapped memory.
 *
 * @file src/lib/util/semaphore.c
 *
 * @copyright 2025 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <sys/mman.h>
#include <freeradius-devel/util/semaphore.h>
#include <freeradius-devel/util/syserror.h>

fr_sem_t *fr_sem_alloc(void)
{
	fr_sem_t *sem;

	sem = mmap(NULL, sizeof(fr_sem_t), PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);

	if (sem == MAP_FAILED) {
		fr_strerror_printf("Failed allocating mmap memory: %s", fr_syserror(errno));
		return NULL;
	}

	if (sem_init(sem, 1, SEMAPHORE_LOCKED) != 0) {
		sem_destroy(sem);
		munmap(sem, sizeof(fr_sem_t));
		return NULL;
	}

	return sem;
}

void fr_sem_free(fr_sem_t *sem)
{
	if (!sem) return;

	sem_destroy(sem);
	munmap(sem, sizeof(fr_sem_t));
}
