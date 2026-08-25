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
 * $Id$
 *
 * @file build/make/port.c
 * @brief Hand out a block of ports that nothing else on the machine is using
 *
 * @copyright 2026 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

/*
 *  Every test server needs a port of its own, because a second server on the
 *  same port fails to start.  Counting upwards from a fixed number in the
 *  makefiles does not give that.  A second "make" counts from the same fixed
 *  number and lands on the same ports.
 *
 *  $(unique-port ...) hands out a block of ports against a name.  Asking twice
 *  for the same name gives the same block both times, which matters because a
 *  test recipe starts its server through a sub-make.  The sub-make reads the
 *  makefiles again, asks again, and has to be told the same port the parent
 *  told the client to connect to.
 *
 *  On every call:
 *
 *  1. Open the file named in the first argument, creating the file if it is
 *     not there.  The file holds one "name port" pair per line.
 *  2. Take a write lock on the file.  A second "make" asking at the same time
 *     waits here until the first one has finished, so the two never hand out
 *     the same block.
 *  3. Read the file.  A line already naming this caller ends the work, and the
 *     port on that line is the answer.
 *  4. Otherwise walk the range from the bottom, skipping any block already
 *     named in the file, and bind every port in the block over both UDP and
 *     TCP.  A bind that fails means something already holds the port, so the
 *     block is skipped and the next one is tried.
 *  5. Add a line for the caller, write the file back, then close the file,
 *     which drops the lock.
 *  6. Return the first port of the block.
 *
 *  Deleting the file, which "make clean" does along with the rest of the build
 *  directory, throws the names away and the next build allocates again.
 *
 *  Two build trees on one machine keep separate files, so the bind in step 4
 *  is the only thing that stops them choosing the same block.  A server that
 *  is running at the time is found and avoided.  Two trees that both allocate
 *  while neither is running can still choose the same block, and the fix for
 *  that is to point both at one file.
 *
 *  To use from a makefile:
 *
 *	PORT := $(unique-port $(BUILD_DIR)/ports,$(TEST),20)
 */
#include <gnumake.h>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"

/*
 *	The only exported symbol
 */
int port_gmk_setup(void);

/*
 * GNU make insists on this in a loadable object.
 */
extern int plugin_is_GPL_compatible;
int plugin_is_GPL_compatible;

/*
 *	Above the ephemeral range the platforms we build on hand out, and far
 *	enough below the top that a block near the end still fits.
 */
#define PORT_FIRST	20000
#define PORT_LAST	60000
#define PORT_COUNT	1

/*
 *	One test server per entry.  The tree has tens, so the ceiling only
 *	exists to keep the whole file on the stack.
 */
#define PORT_NAME_LEN	64
#define PORT_ENTRIES	512
#define PORT_FILE_LEN	(PORT_ENTRIES * (PORT_NAME_LEN + sizeof(" 65535\n")))

typedef struct {
	char	name[PORT_NAME_LEN];
	int	port;
} port_entry_t;

/** Is nothing holding this port?
 *
 * SO_REUSEADDR is deliberately not set.  A port held by a live server, or by a
 * TCP connection still in TIME_WAIT, has to read as taken.
 *
 * @param[in] port	to test.
 * @param[in] type	SOCK_DGRAM or SOCK_STREAM.
 * @param[in] protocol	IPPROTO_UDP or IPPROTO_TCP.
 * @return whether the port could be bound.
 */
static bool port_free(int port, int type, int protocol)
{
	struct sockaddr_in	addr;
	int			fd;
	bool			available;

	fd = socket(AF_INET, type, protocol);
	if (fd < 0) return false;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(port);

	available = bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0;
	close(fd);

	return available;
}

/** Is nothing holding any port in the block?
 *
 * @param[in] first	port of the block.
 * @param[in] count	ports in the block.
 * @return whether every port in the block could be bound.
 */
static bool block_free(int first, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (!port_free(first + i, SOCK_DGRAM, IPPROTO_UDP)) return false;
		if (!port_free(first + i, SOCK_STREAM, IPPROTO_TCP)) return false;
	}

	return true;
}

/** Read every "name port" line out of the serialisation file
 *
 * A line that does not parse is dropped, so a truncated write from a killed
 * build costs one allocation instead of failing the build.
 *
 * @param[out] out	entries read.
 * @param[in] outlen	entries that fit.
 * @param[in] fd	of the serialisation file, already locked.
 * @return the number of entries read, or -1 on error.
 */
static int entries_read(port_entry_t *out, int outlen, int fd)
{
	char	buff[PORT_FILE_LEN + 1];
	char	*p;
	ssize_t	slen;
	int	used = 0;

	slen = pread(fd, buff, sizeof(buff) - 1, 0);
	if (slen < 0) return -1;
	buff[slen] = '\0';

	for (p = strtok(buff, "\n"); p && (used < outlen); p = strtok(NULL, "\n")) {
		char	name[PORT_NAME_LEN];
		int	port;

		if (sscanf(p, "%63s %i", name, &port) != 2) continue;
		if ((port < 1) || (port > 65535)) continue;

		strcpy(out[used].name, name);
		out[used].port = port;
		used++;
	}

	return used;
}

/** Write every "name port" line back to the serialisation file
 *
 * @param[in] fd	of the serialisation file, already locked.
 * @param[in] entries	to write.
 * @param[in] used	entries to write.
 * @return whether the whole file reached the disk.
 */
static bool entries_write(int fd, port_entry_t const *entries, int used)
{
	char	buff[PORT_FILE_LEN + 1];
	char	*p = buff, *end = buff + sizeof(buff);
	int	i;

	for (i = 0; i < used; i++) {
		p += snprintf(p, end - p, "%s %i\n", entries[i].name, entries[i].port);
		if (p >= end) return false;
	}

	if (ftruncate(fd, 0) < 0) return false;

	return pwrite(fd, buff, p - buff, 0) == (p - buff);
}

/** Has some other caller already been given a port in this block?
 *
 * @param[in] entries	already handed out.
 * @param[in] used	entries already handed out.
 * @param[in] first	port of the block.
 * @param[in] count	ports in the block.
 * @return whether the block overlaps one already handed out.
 */
static bool block_taken(port_entry_t const *entries, int used, int first, int count)
{
	int i;

	for (i = 0; i < used; i++) {
		if ((entries[i].port < (first + count)) && (first < (entries[i].port + count))) return true;
	}

	return false;
}

/** $(unique-port <file>,<name>[,<count>[,<first>[,<last>]]])
 *
 * @param[in] argv	file and name, then optionally the ports per block, the
 *			bottom of the range and the top of the range.
 * @return the first port of the block belonging to name.
 */
static char *make_unique_port(__attribute__((unused)) char const *nm, unsigned int argc, char **argv)
{
	char const	*file = argv[0];
	char const	*name = argv[1];
	int		count = PORT_COUNT;
	int		first = PORT_FIRST;
	int		last = PORT_LAST;
	int		port = 0;
	int		used;
	int		fd;
	char		*out;
	struct flock	lock;
	port_entry_t	entries[PORT_ENTRIES];

	if ((argc > 2) && *argv[2]) count = atoi(argv[2]);
	if ((argc > 3) && *argv[3]) first = atoi(argv[3]);
	if ((argc > 4) && *argv[4]) last = atoi(argv[4]);

	if (!*name || (strlen(name) >= PORT_NAME_LEN) || strpbrk(name, " \t\n")) {
		ERROR("unique-port: \"%s\" is not a usable name, give up to %i characters and no spaces",
		      name, PORT_NAME_LEN - 1);
		return NULL;
	}

	if (count < 1) {
		ERROR("unique-port: ports per block must be at least 1, got %i", count);
		return NULL;
	}

	if ((first < 1) || (last > 65535) || ((last - first + 1) < count)) {
		ERROR("unique-port: the range %i-%i does not hold a block of %i ports", first, last, count);
		return NULL;
	}

	fd = open(file, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		ERROR("unique-port: failed opening %s - %s", file, strerror(errno));
		return NULL;
	}

	/*
	 *	F_SETLKW waits for a "make" that got here first, so the two never
	 *	hand out the same block.  Closing the file drops the lock.
	 */
	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;

	if (fcntl(fd, F_SETLKW, &lock) < 0) {
		ERROR("unique-port: failed locking %s - %s", file, strerror(errno));
		close(fd);
		return NULL;
	}

	used = entries_read(entries, PORT_ENTRIES, fd);
	if (used < 0) {
		ERROR("unique-port: failed reading %s - %s", file, strerror(errno));
		close(fd);
		return NULL;
	}

	/*
	 *	The sub-make that starts the server asks for the same name the
	 *	parent asked for, and has to be given the same answer.
	 */
	{
		int i;

		for (i = 0; i < used; i++) {
			if (strcmp(entries[i].name, name) != 0) continue;

			port = entries[i].port;
			break;
		}
	}

	if (!port) {
		int candidate;

		if (used == PORT_ENTRIES) {
			ERROR("unique-port: %s already names %i ports, which is all this build can track",
			      file, used);
			close(fd);
			return NULL;
		}

		for (candidate = first; (candidate + count - 1) <= last; candidate += count) {
			if (block_taken(entries, used, candidate, count)) continue;
			if (!block_free(candidate, count)) continue;

			port = candidate;
			break;
		}

		if (!port) {
			ERROR("unique-port: no block of %i ports is free in %i-%i", count, first, last);
			close(fd);
			return NULL;
		}

		strcpy(entries[used].name, name);
		entries[used].port = port;
		used++;

		if (!entries_write(fd, entries, used)) {
			ERROR("unique-port: failed writing %s - %s", file, strerror(errno));
			close(fd);
			return NULL;
		}
	}

	close(fd);

	out = gmk_alloc(sizeof("65535"));
	snprintf(out, sizeof("65535"), "%i", port);

	return out;
}

int port_gmk_setup(void)
{
	gmk_add_function("unique-port", &make_unique_port, 2, 5, 0); /* min 2, max 5, please expand the arguments */

	return 1;
}
