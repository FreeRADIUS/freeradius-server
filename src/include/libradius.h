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
#ifndef _FR_LIBRADIUS_H
#define _FR_LIBRADIUS_H
/*
 * $Id$
 *
 * @file include/libradius.h
 * @brief Structures and prototypes for the radius library.
 *
 * @copyright 1999-2014 The FreeRADIUS server project
 */

/*
 *  Compiler hinting macros.  Included here for 3rd party consumers
 *  of libradius.h.
 *
 *  @note Defines RCSIDH.
 */
#include <freeradius-devel/build.h>
RCSIDH(libradius_h, "$Id$")

/*
 *  Let any external program building against the library know what
 *  features the library was built with.
 */
#include <freeradius-devel/features.h>

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

#include <freeradius-devel/threads.h>
#include <freeradius-devel/inet.h>
#include <freeradius-devel/dict.h>
#include <freeradius-devel/token.h>
#include <freeradius-devel/pair.h>
#include <freeradius-devel/pair_cursor.h>

#include <freeradius-devel/packet.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/talloc.h>
#include <freeradius-devel/hash.h>
#include <freeradius-devel/regex.h>
#include <freeradius-devel/proto.h>
#include <freeradius-devel/conf.h>
#include <freeradius-devel/radpaths.h>
#include <freeradius-devel/rbtree.h>
#include <freeradius-devel/fr_log.h>
#include <freeradius-devel/version.h>
#include <freeradius-devel/value.h>
#include <freeradius-devel/debug.h>

#ifdef SIZEOF_UNSIGNED_INT
#  if SIZEOF_UNSIGNED_INT != 4
#    error FATAL: sizeof(unsigned int) != 4
#  endif
#endif

/*
 *  Include for modules.
 */
#include <freeradius-devel/sha1.h>
#include <freeradius-devel/md4.h>

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
 *	Printing functions.
 */
size_t		fr_utf8_char(uint8_t const *str, ssize_t inlen);
ssize_t		fr_utf8_str(uint8_t const *str, ssize_t inlen);
char const     	*fr_utf8_strchr(int *chr_len, char const *str, char const *chr);
size_t		fr_snprint(char *out, size_t outlen, char const *in, ssize_t inlen, char quote);
size_t		fr_snprint_len(char const *in, ssize_t inlen, char quote);
char		*fr_asprint(TALLOC_CTX *ctx, char const *in, ssize_t inlen, char quote);
char		*fr_vasprintf(TALLOC_CTX *ctx, char const *fmt, va_list ap);
char		*fr_asprintf(TALLOC_CTX *ctx, char const *fmt, ...) CC_HINT(format (printf, 2, 3));

#define		is_truncated(_ret, _max) ((_ret) >= (size_t)(_max))
#define		truncate_len(_ret, _max) (((_ret) >= (size_t)(_max)) ? (((size_t)(_max)) - 1) : _ret)

/** Boilerplate for checking truncation
 *
 * If truncation has occurred, advance _p as far as possible without
 * overrunning the output buffer, and \0 terminate.  Then return the length
 * of the buffer we would have needed to write the full value.
 *
 * If truncation has not occurred, advance _p by whatever the copy or print
 * function returned.
 */
#define RETURN_IF_TRUNCATED(_p, _ret, _max) \
do { \
	if (is_truncated(_ret, _max)) { \
		size_t _r = (_p - out) + _ret; \
		_p += truncate_len(_ret, _max); \
		*_p = '\0'; \
		return _r; \
	} \
	_p += _ret; \
} while (0)

/*
 *	Several handy miscellaneous functions.
 */
int		fr_set_signal(int sig, sig_t func);
int		fr_talloc_link_ctx(TALLOC_CTX *parent, TALLOC_CTX *child);
int		fr_unset_signal(int sig);
int		rad_lockfd(int fd, int lock_len);
int		rad_lockfd_nonblock(int fd, int lock_len);
int		rad_unlockfd(int fd, int lock_len);
char		*fr_abin2hex(TALLOC_CTX *ctx, uint8_t const *bin, size_t inlen);
size_t		fr_bin2hex(char *hex, uint8_t const *bin, size_t inlen);
size_t		fr_hex2bin(uint8_t *bin, size_t outlen, char const *hex, size_t inlen);
uint64_t	fr_strtoull(char const *value, char **end);
int64_t		fr_strtoll(char const *value, char **end);
bool		is_whitespace(char const *value);
bool		is_printable(void const *value, size_t len);
bool		is_integer(char const *value);
bool		is_zero(char const *value);

int		fr_nonblock(int fd);
int		fr_blocking(int fd);
ssize_t		fr_writev(int fd, struct iovec[], int iovcnt, struct timeval *timeout);

ssize_t		fr_utf8_to_ucs2(uint8_t *out, size_t outlen, char const *in, size_t inlen);
size_t		fr_snprint_uint128(char *out, size_t outlen, uint128_t const num);
int		fr_time_from_str(time_t *date, char const *date_str);
void		fr_timeval_from_ms(struct timeval *out, uint64_t ms);
void		fr_timeval_from_usec(struct timeval *out, uint64_t usec);
void		fr_timeval_subtract(struct timeval *out, struct timeval const *end, struct timeval const *start);
void		fr_timeval_add(struct timeval *out, struct timeval const *a, struct timeval const *b);
void		fr_timeval_divide(struct timeval *out, struct timeval const *in, int divisor);

int		fr_timeval_cmp(struct timeval const *a, struct timeval const *b);
int		fr_timeval_from_str(struct timeval *out, char const *in);
bool		fr_timeval_isset(struct timeval const *tv);

void		fr_timespec_subtract(struct timespec *out, struct timespec const *end, struct timespec const *start);

bool		fr_multiply(uint64_t *result, uint64_t lhs, uint64_t rhs);
int		fr_size_from_str(size_t *out, char const *str);
int8_t		fr_pointer_cmp(void const *a, void const *b);
void		fr_quick_sort(void const *to_sort[], int min_idx, int max_idx, fr_cmp_t cmp);
int		fr_digest_cmp(uint8_t const *a, uint8_t const *b, size_t length) CC_HINT(nonnull);

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
void		fr_rand_seed(void const *, size_t ); /* seed the random pool */


/* crypt wrapper from crypt.c */
int		fr_crypt_check(char const *password, char const *reference_crypt);

/*
 *	FIFOs
 */
typedef struct	fr_fifo_t fr_fifo_t;
typedef void (*fr_fifo_free_t)(void *);
fr_fifo_t	*fr_fifo_create(TALLOC_CTX *ctx, int max_entries, fr_fifo_free_t freeNode);
int		fr_fifo_push(fr_fifo_t *fi, void *data);
void		*fr_fifo_pop(fr_fifo_t *fi);
void		*fr_fifo_peek(fr_fifo_t *fi);
unsigned int	fr_fifo_num_elements(fr_fifo_t *fi);

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
#  include <freeradius-devel/tcp.h>
#endif

#endif /* _FR_LIBRADIUS_H */
