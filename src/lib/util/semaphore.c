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

sem_t *fr_sem_alloc(void)
{
	sem_t *sem;

	sem = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);

	if (sem_init(sem, 0, SEMAPHORE_LOCKED) != 0) {
		sem_destroy(sem);
		munmap(sem, sizeof(sem_t));
		return NULL;
	}

	return sem;
}

void fr_sem_free(sem_t *sem)
{
	if (!sem) return;

	sem_destroy(sem);
	munmap(sem, sizeof(sem_t));
}
