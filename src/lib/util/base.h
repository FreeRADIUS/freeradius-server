#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Structures and prototypes for this utility library
 *
 * @file src/lib/util/base.h
 *
 * @copyright 1999-2014 The FreeRADIUS server project
 */

#include <freeradius-devel/build.h>
RCSIDH(libradius_h, "$Id$")

/*
 *  Talloc'd memory must be used throughout the librarys and server.
 *  This allows us to track allocations in the NULL context and makes
 *  root causing memory leaks easier.
 */
#include <talloc.h>

/*
 *  Defines signatures for any missing functions.
 */
#include <freeradius-devel/missing.h>

/*
 *  Include system headers.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <signal.h>

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#include <freeradius-devel/autoconf.h>

#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/threads.h>
#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/token.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/pair_cursor.h>

#include <freeradius-devel/util/packet.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/hash.h>
#include <freeradius-devel/util/regex.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/conf.h>

#include <freeradius-devel/util/rbtree.h>
#include <freeradius-devel/util/log.h>
#include <freeradius-devel/util/version.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/fifo.h>

#include <freeradius-devel/radius/defs.h>
#include <freeradius-devel/radius/radius.h>

#ifdef SIZEOF_UNSIGNED_INT
#  if SIZEOF_UNSIGNED_INT != 4
#    error FATAL: sizeof(unsigned int) != 4
#  endif
#endif

/*
 *  Include for modules.
 */
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/util/md4.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_SIG_T
typedef void (*sig_t)(int);
#endif

#ifndef NDEBUG
#  define FREE_MAGIC (0xF4EEF4EE)
#endif

/*
 *	Several handy miscellaneous functions.
 */


/** Check whether the string is all whitespace
 *
 * @return
 *	- true if the entirety of the string is whitespace.
 *	- false if the string contains non whitespace.
 */
static inline bool is_whitespace(char const *value)
{
	do {
		if (!isspace(*value)) return false;
	} while (*++value);

	return true;
}

/** Check whether the string is made up of printable UTF8 chars
 *
 * @param value to check.
 * @param len of value.
 *
 * @return
 *	- true if the string is printable.
 *	- false if the string contains non printable chars
 */
 static inline bool is_printable(void const *value, size_t len)
 {
 	uint8_t	const *p = value;
 	int	clen;
 	size_t	i;

 	for (i = 0; i < len; i++) {
 		clen = fr_utf8_char(p, len - i);
 		if (clen == 0) return false;
 		i += (size_t)clen;
 		p += clen;
 	}
 	return true;
 }

/** Check whether the string is all numbers
 *
 * @return
 *	- true if the entirety of the string is number chars.
 *	- false if string contains no number chars.
 */
static inline bool is_integer(char const *value)
{
	do {
		if (!isdigit(*value)) return false;
	} while (*++value);

	return true;
}

/** Check whether the string is all zeros
 *
 * @return
 *	- true if the entirety of the string is all zeros.
 *	- false if string contains no zeros.
 */
static inline bool is_zero(char const *value)
{
	do {
		if (*value != '0') return false;
	} while (*++value);

	return true;
}

/*
 *	Define TALLOC_DEBUG to check overflows with talloc.
 *	we can't use valgrind, because the memory used by
 *	talloc is valid memory... just not for us.
 */
#ifdef TALLOC_DEBUG
void		fr_talloc_verify_cb(const void *ptr, int depth,
				    int max_depth, int is_ref,
				    void *private_data);
#define VERIFY_ALL_TALLOC talloc_report_depth_cb(NULL, 0, -1, fr_talloc_verify_cb, NULL)
#else
#define VERIFY_ALL_TALLOC
#endif

#ifdef WITH_ASCEND_BINARY
/* filters.c */
int		ascend_parse_filter(fr_value_box_t *out, char const *value, size_t len);
void		print_abinary(char *out, size_t outlen, uint8_t const *data, size_t len, int8_t quote);
#endif /*WITH_ASCEND_BINARY*/

/* random numbers in isaac.c */
/* context of random number generator */
typedef struct fr_randctx {
	uint32_t randcnt;
	uint32_t randrsl[256];
	uint32_t randmem[256];
	uint32_t randa;
	uint32_t randb;
	uint32_t randc;
} fr_randctx;

void		fr_isaac(fr_randctx *ctx);
void		fr_randinit(fr_randctx *ctx, int flag);
uint32_t	fr_rand(void);	/* like rand(), but better. */
void		fr_rand_buffer(void *start, size_t length) CC_HINT(nonnull);
void		fr_rand_seed(void const *, size_t ); /* seed the random pool */


/* crypt wrapper from crypt.c */
int		fr_crypt_check(char const *password, char const *reference_crypt);

/*
 *	socket.c
 */


bool		fr_socket_is_valid_proto(int proto);
int		fr_socket_client_unix(char const *path, bool async);
int		fr_socket_client_udp(fr_ipaddr_t *src_ipaddr, uint16_t *src_port, fr_ipaddr_t const *dst_ipaddr,
				     uint16_t dst_port, bool async);
int		fr_socket_client_tcp(fr_ipaddr_t const *src_ipaddr, fr_ipaddr_t const *dst_ipaddr,
				     uint16_t dst_port, bool async);
int		fr_socket_wait_for_connect(int sockfd, struct timeval const *timeout);

int		fr_socket_server_udp(fr_ipaddr_t const *ipaddr, uint16_t *port, char const *port_name, bool async);
int		fr_socket_server_tcp(fr_ipaddr_t const *ipaddr, uint16_t *port, char const *port_name, bool async);
int		fr_socket_bind(int sockfd, fr_ipaddr_t const *ipaddr, uint16_t *port, char const *interface);
#ifdef __cplusplus
}
#endif


#ifdef WITH_TCP
#  include <freeradius-devel/server/tcp.h>
#endif
