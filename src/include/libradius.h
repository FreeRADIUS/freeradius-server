#ifndef LIBRADIUS_H
#define LIBRADIUS_H

/*
 * libradius.h	Structures and prototypes
 *		for the radius library.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 1999,2000,2001,2002,2003,2004,2005,2006,2007,2008  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSIDH(libradius_h, "$Id$")

#include <freeradius-devel/missing.h>

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <freeradius-devel/radius.h>
#include <freeradius-devel/token.h>
#include <freeradius-devel/hash.h>

#ifdef SIZEOF_UNSIGNED_INT
#if SIZEOF_UNSIGNED_INT != 4
#error FATAL: sizeof(unsigned int) != 4
#endif
#endif

/*
 *  Include for modules.
 */
#include <freeradius-devel/sha1.h>
#include <freeradius-devel/md4.h>

#ifndef WITHOUT_TCP
#define WITH_TCP (1)
#endif

#define EAP_START               2

#define AUTH_VECTOR_LEN		16
#define CHAP_VALUE_LENGTH       16
#define MAX_STRING_LEN		254	/* RFC2138: string 0-253 octets */
#define FR_MAX_VENDOR		(1 << 24) /* RFC limitations */

#ifdef _LIBRADIUS
#  define AUTH_HDR_LEN		20
#  define VENDORPEC_USR		429
#define VENDORPEC_LUCENT	4846
#define VENDORPEC_STARENT	8164
#  define DEBUG			if (fr_debug_flag && fr_log_fp) fr_printf_log
#  define debug_pair(vp)	do { if (fr_debug_flag && fr_log_fp) { \
					fputc('\t', fr_log_fp); \
					vp_print(fr_log_fp, vp); \
					fputc('\n', fr_log_fp); \
				     } \
				} while(0)
#  define TAG_VALID(x)          ((x) > 0 && (x) < 0x20)
#  define TAG_VALID_ZERO(x)     ((x) < 0x20)
#  define TAG_ANY               -128   /* minimum signed char */
#endif

#if defined(__GNUC__)
# define PRINTF_LIKE(n) __attribute__ ((format(printf, n, n+1)))
# define NEVER_RETURNS __attribute__ ((noreturn))
# define UNUSED __attribute__ ((unused))
# define BLANK_FORMAT " "	/* GCC_LINT whines about empty formats */
#else
# define PRINTF_LIKE(n)	/* ignore */
# define NEVER_RETURNS /* ignore */
# define UNUSED /* ignore */
# define BLANK_FORMAT ""
#endif

typedef struct attr_flags {
	unsigned int		addport : 1;  /* add NAS-Port to IP address */
	unsigned int		has_tag : 1;  /* tagged attribute */
	unsigned int		do_xlat : 1;  /* strvalue is dynamic */
	unsigned int		unknown_attr : 1; /* not in dictionary */
	unsigned int		array : 1; /* pack multiples into 1 attr */
	unsigned int		has_value : 1; /* has a value */
	unsigned int		has_value_alias : 1; /* has a value alias */
	unsigned int		has_tlv : 1; /* has sub attributes */
	unsigned int		is_tlv : 1; /* is a sub attribute */
	unsigned int		encoded : 1; /* has been put into packet */
	unsigned int		extended : 1; /* extended attribute */
	unsigned int		extended_flags : 1; /* with flag */

	int8_t			tag;	      /* tag for tunneled attributes */
	uint8_t		        encrypt;      /* encryption method */
	uint8_t			length;
} ATTR_FLAGS;

/*
 *  Values of the encryption flags.
 */
#define FLAG_ENCRYPT_NONE            (0)
#define FLAG_ENCRYPT_USER_PASSWORD   (1)
#define FLAG_ENCRYPT_TUNNEL_PASSWORD (2)
#define FLAG_ENCRYPT_ASCEND_SECRET   (3)

typedef struct dict_attr {
	unsigned int		attr;
	int			type;
	int			vendor;
        ATTR_FLAGS              flags;
	char			name[1];
} DICT_ATTR;

typedef struct dict_value {
	unsigned int		attr;
	unsigned int		vendor;
	int			value;
	char			name[1];
} DICT_VALUE;

typedef struct dict_vendor {
	int			vendorpec;
	int			type; /* length of type data */
	int			length;	/* length of length data */
	int			flags;
	char			name[1];
} DICT_VENDOR;

typedef union value_pair_data {
	char			strvalue[MAX_STRING_LEN];
	uint8_t			octets[MAX_STRING_LEN];
	struct in_addr		ipaddr;
	struct in6_addr		ipv6addr;
	uint32_t		date;
	uint32_t		integer;
	int32_t			sinteger;
	uint8_t			filter[32];
	uint8_t			ifid[8]; /* struct? */
	uint8_t			ipv6prefix[18]; /* struct? */
     	uint8_t			ether[6];
	uint8_t			*tlv;
} VALUE_PAIR_DATA;

typedef struct value_pair {
	const char	        *name;
	unsigned int		attribute;
	int			vendor;
	int			type;
	size_t			length; /* of data */
	FR_TOKEN		operator;
        ATTR_FLAGS              flags;
	struct value_pair	*next;
	uint32_t		lvalue;
	VALUE_PAIR_DATA		data;
} VALUE_PAIR;
#define vp_strvalue   data.strvalue
#define vp_octets     data.octets
#define vp_ipv6addr   data.ipv6addr
#define vp_ifid       data.ifid
#define vp_ipv6prefix data.ipv6prefix
#define vp_filter     data.filter
#define vp_ether      data.ether
#define vp_signed     data.sinteger
#define vp_tlv	      data.tlv

#if 0
#define vp_ipaddr     data.ipaddr.s_addr
#define vp_date       data.date
#define vp_integer    data.integer
#else
/*
 *	These are left as lvalue until we audit the source for code
 *	that prints to vp_strvalue for integer/ipaddr/date types.
 */
#define vp_ipaddr     lvalue
#define vp_date       lvalue
#define vp_integer    lvalue
#endif


typedef struct fr_ipaddr_t {
	int		af;	/* address family */
	union {
		struct in_addr	ip4addr;
		struct in6_addr ip6addr; /* maybe defined in missing.h */
	} ipaddr;
	uint32_t	scope;	/* for IPv6 */
} fr_ipaddr_t;

/*
 *	vector:		Request authenticator from access-request packet
 *			Put in there by rad_decode, and must be put in the
 *			response RADIUS_PACKET as well before calling rad_send
 *
 *	verified:	Filled in by rad_decode for accounting-request packets
 *
 *	data,data_len:	Used between rad_recv and rad_decode.
 */
typedef struct radius_packet {
	int			sockfd;
	fr_ipaddr_t		src_ipaddr;
        fr_ipaddr_t		dst_ipaddr;
	uint16_t		src_port;
	uint16_t		dst_port;
	int			id;
	unsigned int		code;
	uint32_t		hash;
	uint8_t			vector[AUTH_VECTOR_LEN];
	time_t			timestamp;
	uint8_t			*data;
	ssize_t			data_len;
	VALUE_PAIR		*vps;
	ssize_t			offset;
#ifdef WITH_TCP
	ssize_t			partial;
#endif
} RADIUS_PACKET;

/*
 *	Printing functions.
 */
int		fr_utf8_char(const uint8_t *str);
void		fr_print_string(const char *in, size_t inlen,
				 char *out, size_t outlen);
int     	vp_prints_value(char *out, size_t outlen,
				VALUE_PAIR *vp, int delimitst);
const char	*vp_print_name(char *buffer, size_t bufsize, int attr, int vendor);
int     	vp_prints(char *out, size_t outlen, VALUE_PAIR *vp);
void		vp_print(FILE *, VALUE_PAIR *);
void		vp_printlist(FILE *, VALUE_PAIR *);
#define		fprint_attr_val vp_print

/*
 *	Dictionary functions.
 */
int		dict_addvendor(const char *name, int value);
int		dict_addattr(const char *name, int attr, int vendor, int type, ATTR_FLAGS flags);
int		dict_addvalue(const char *namestr, const char *attrstr, int value);
int		dict_init(const char *dir, const char *fn);
void		dict_free(void);
DICT_ATTR	*dict_attrbyvalue(unsigned int attr, unsigned int vendor);
DICT_ATTR	*dict_attrbyname(const char *attr);
DICT_VALUE	*dict_valbyattr(unsigned int attr, unsigned int vendor, int val);
DICT_VALUE	*dict_valbyname(unsigned int attr, unsigned int vendor, const char *val);
int		dict_vendorbyname(const char *name);
DICT_VENDOR	*dict_vendorbyvalue(int vendor);

#if 1 /* FIXME: compat */
#define dict_attrget	dict_attrbyvalue
#define dict_attrfind	dict_attrbyname
#define dict_valfind	dict_valbyname
/*#define dict_valget	dict_valbyattr almost but not quite*/
#endif

/* get around diffrent ctime_r styles */
#ifdef CTIMERSTYLE
#if CTIMERSTYLE == SOLARISSTYLE
#define CTIME_R(a,b,c) ctime_r(a,b,c)
#else
#define CTIME_R(a,b,c) ctime_r(a,b)
#endif
#else
#define CTIME_R(a,b,c) ctime_r(a,b)
#endif

/* md5.c */

void		fr_md5_calc(uint8_t *, const uint8_t *, unsigned int);

/* hmac.c */

void fr_hmac_md5(const uint8_t *text, int text_len,
		   const uint8_t *key, int key_len,
		   unsigned char *digest);

/* hmacsha1.c */

void fr_hmac_sha1(const uint8_t *text, int text_len,
		    const uint8_t *key, int key_len,
		    uint8_t *digest);

/* radius.c */
int		rad_send(RADIUS_PACKET *, const RADIUS_PACKET *, const char *secret);
int		rad_packet_ok(RADIUS_PACKET *packet, int flags);
RADIUS_PACKET	*rad_recv(int fd, int flags);
ssize_t rad_recv_header(int sockfd, fr_ipaddr_t *src_ipaddr, int *src_port,
			int *code);
void		rad_recv_discard(int sockfd);
int		rad_verify(RADIUS_PACKET *packet, RADIUS_PACKET *original,
			   const char *secret);
int		rad_decode(RADIUS_PACKET *packet, RADIUS_PACKET *original, const char *secret);
int		rad_encode(RADIUS_PACKET *packet, const RADIUS_PACKET *original,
			   const char *secret);
int		rad_sign(RADIUS_PACKET *packet, const RADIUS_PACKET *original,
			 const char *secret);

RADIUS_PACKET	*rad_alloc(int newvector);
RADIUS_PACKET	*rad_alloc_reply(RADIUS_PACKET *);
void		rad_free(RADIUS_PACKET **);
int		rad_pwencode(char *encpw, size_t *len, const char *secret,
			     const uint8_t *vector);
int		rad_pwdecode(char *encpw, size_t len, const char *secret,
			     const uint8_t *vector);
int		rad_tunnel_pwencode(char *encpw, size_t *len, const char *secret,
				    const uint8_t *vector);
int		rad_tunnel_pwdecode(uint8_t *encpw, size_t *len,
				    const char *secret, const uint8_t *vector);
int		rad_chap_encode(RADIUS_PACKET *packet, uint8_t *output,
				int id, VALUE_PAIR *password);
VALUE_PAIR	*rad_attr2vp(const RADIUS_PACKET *packet, const RADIUS_PACKET *original,
			     const char *secret, int attribute, int vendor,
			     int length, const uint8_t *data);
int		rad_vp2attr(const RADIUS_PACKET *packet,
			    const RADIUS_PACKET *original, const char *secret,
			    const VALUE_PAIR *vp, uint8_t *ptr, size_t room);

/* valuepair.c */
VALUE_PAIR	*pairalloc(DICT_ATTR *da);
VALUE_PAIR	*paircreate_raw(int attr, int vendor, int type, VALUE_PAIR *);
VALUE_PAIR	*paircreate(int attr, int vendor, int type);
void		pairfree(VALUE_PAIR **);
void            pairbasicfree(VALUE_PAIR *pair);
VALUE_PAIR	*pairfind(VALUE_PAIR *, int attr, int vendor);
void		pairdelete(VALUE_PAIR **, int attr, int vendor);
void		pairadd(VALUE_PAIR **, VALUE_PAIR *);
void            pairreplace(VALUE_PAIR **first, VALUE_PAIR *add);
int		paircmp(VALUE_PAIR *check, VALUE_PAIR *data);
VALUE_PAIR	*paircopyvp(const VALUE_PAIR *vp);
VALUE_PAIR	*paircopy(VALUE_PAIR *vp);
VALUE_PAIR	*paircopy2(VALUE_PAIR *vp, int attr, int vendor);
void		pairmove(VALUE_PAIR **to, VALUE_PAIR **from);
void		pairmove2(VALUE_PAIR **to, VALUE_PAIR **from, int attr, int vendor);
VALUE_PAIR	*pairparsevalue(VALUE_PAIR *vp, const char *value);
VALUE_PAIR	*pairmake(const char *attribute, const char *value, int operator);
VALUE_PAIR	*pairread(const char **ptr, FR_TOKEN *eol);
FR_TOKEN	userparse(const char *buffer, VALUE_PAIR **first_pair);
VALUE_PAIR     *readvp2(FILE *fp, int *pfiledone, const char *errprefix);

/*
 *	Error functions.
 */
#ifdef _LIBRADIUS
void		fr_strerror_printf(const char *, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 1, 2)))
#endif
;
#endif
void		fr_perror(const char *, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 1, 2)))
#endif
;
extern const char *fr_strerror(void);
extern int	fr_dns_lookups;	/* 0 = no dns lookups */
extern int	fr_debug_flag;	/* 0 = no debugging information */
extern int	fr_max_attributes; /* per incoming packet */
#define	FR_MAX_PACKET_CODE (52)
extern const char *fr_packet_codes[FR_MAX_PACKET_CODE];
extern FILE	*fr_log_fp;
void		fr_printf_log(const char *, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 1, 2)))
#endif
;

/*
 *	Several handy miscellaneous functions.
 */
const char *	ip_ntoa(char *, uint32_t);
char		*ifid_ntoa(char *buffer, size_t size, uint8_t *ifid);
uint8_t		*ifid_aton(const char *ifid_str, uint8_t *ifid);
int		rad_lockfd(int fd, int lock_len);
int		rad_lockfd_nonblock(int fd, int lock_len);
int		rad_unlockfd(int fd, int lock_len);
void		fr_bin2hex(const uint8_t *bin, char *hex, size_t len);
size_t		fr_hex2bin(const char *hex, uint8_t *bin, size_t len);
#ifndef HAVE_INET_PTON
int		inet_pton(int af, const char *src, void *dst);
#endif
#ifndef HAVE_INET_NTOP
const char	*inet_ntop(int af, const void *src, char *dst, size_t cnt);
#endif
#ifndef HAVE_CLOSEFROM
int		closefrom(int fd);
#endif
int fr_ipaddr_cmp(const fr_ipaddr_t *a, const fr_ipaddr_t *b);

int		ip_hton(const char *src, int af, fr_ipaddr_t *dst);
const char	*ip_ntoh(const fr_ipaddr_t *src, char *dst, size_t cnt);
int fr_ipaddr2sockaddr(const fr_ipaddr_t *ipaddr, int port,
		       struct sockaddr_storage *sa, socklen_t *salen);
int fr_sockaddr2ipaddr(const struct sockaddr_storage *sa, socklen_t salen,
		       fr_ipaddr_t *ipaddr, int * port);


#ifdef ASCEND_BINARY
/* filters.c */
int		ascend_parse_filter(VALUE_PAIR *pair);
void		print_abinary(VALUE_PAIR *vp, char *buffer, size_t len);
#endif /*ASCEND_BINARY*/

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

void fr_isaac(fr_randctx *ctx);
void fr_randinit(fr_randctx *ctx, int flag);
uint32_t fr_rand(void);	/* like rand(), but better. */
void fr_rand_seed(const void *, size_t ); /* seed the random pool */


/* crypt wrapper from crypt.c */
int fr_crypt_check(const char *key, const char *salt);

/* rbtree.c */
typedef struct rbtree_t rbtree_t;
typedef struct rbnode_t rbnode_t;

rbtree_t       *rbtree_create(int (*Compare)(const void *, const void *),
			       void (*freeNode)(void *),
			       int replace_flag);
void		rbtree_free(rbtree_t *tree);
int		rbtree_insert(rbtree_t *tree, void *Data);
rbnode_t	*rbtree_insertnode(rbtree_t *tree, void *Data);
void		rbtree_delete(rbtree_t *tree, rbnode_t *Z);
int		rbtree_deletebydata(rbtree_t *tree, const void *data);
rbnode_t       *rbtree_find(rbtree_t *tree, const void *Data);
void	       *rbtree_finddata(rbtree_t *tree, const void *Data);
int		rbtree_num_elements(rbtree_t *tree);
void	       *rbtree_min(rbtree_t *tree);
void	       *rbtree_node2data(rbtree_t *tree, rbnode_t *node);

/* callback order for walking  */
typedef enum { PreOrder, InOrder, PostOrder } RBTREE_ORDER;

/*
 *	The callback should be declared as:
 *	int callback(void *context, void *data)
 *
 *	The "context" is some user-defined context.
 *	The "data" is the pointer to the user data in the node,
 *	  NOT the node itself.
 *
 *	It should return 0 if all is OK, and !0 for any error.
 *	The walking will stop on any error.
 */
int rbtree_walk(rbtree_t *tree, RBTREE_ORDER order, int (*callback)(void *, void *), void *context);

/*
 *	FIFOs
 */
typedef struct fr_fifo_t fr_fifo_t;
typedef void (*fr_fifo_free_t)(void *);
fr_fifo_t *fr_fifo_create(int max_entries, fr_fifo_free_t freeNode);
void fr_fifo_free(fr_fifo_t *fi);
int fr_fifo_push(fr_fifo_t *fi, void *data);
void *fr_fifo_pop(fr_fifo_t *fi);
void *fr_fifo_peek(fr_fifo_t *fi);
int fr_fifo_num_elements(fr_fifo_t *fi);

#include <freeradius-devel/packet.h>

#ifdef WITH_TCP
#include <freeradius-devel/tcp.h>
#endif

#endif /*LIBRADIUS_H*/
