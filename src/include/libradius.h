/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifndef LIBRADIUS_H
#define LIBRADIUS_H
/*
 * $Id$
 *
 * @file libradius.h
 * @brief Structures and prototypes for the radius library.
 *
 * @copyright 1999-2008 The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSIDH(libradius_h, "$Id$")

#include <freeradius-devel/missing.h>

/*
 *  Let any external program building against the library know what
 *  features the library was built with.
 */
#include <freeradius-devel/features.h>

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

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
/*
 *	This definition of true as NOT false is definitive. :) Making
 *	it '1' can cause problems on stupid platforms.  See articles
 *	on C portability for more information.
 */
#define TRUE (!FALSE)
#endif

/*
 *  Include for modules.
 */
#include <freeradius-devel/sha1.h>
#include <freeradius-devel/md4.h>

#ifdef __cplusplus
extern "C" {
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
					vp_print(fr_log_fp, vp); \
				     } \
				} while(0)
#endif

#define TAG_VALID(x)		((x) > 0 && (x) < 0x20)
#define TAG_VALID_ZERO(x)	((x) < 0x20)
#define TAG_ANY			-128	/* minimum signed char */
#define TAG_UNUSED		0

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
	unsigned int 	is_unknown : 1;		//!< Attribute number or  
						//!< vendor is unknown.					
	unsigned int	is_tlv : 1;		//!< Is a sub attribute.
	unsigned int	vp_free : 1;		//!< Should be freed when 
						//!< VALUE_PAIR is freed.

	unsigned int	has_tag : 1;		//!< Tagged attribute.
	unsigned int	do_xlat : 1; 		//!< Strvalue is dynamic.
	unsigned int	array : 1; 		//!< Pack multiples into 1 attr.
	unsigned int	has_value : 1;		//!< Has a value.
	unsigned int	has_value_alias : 1; 	//!< Has a value alias.
	unsigned int	has_tlv : 1; 		//!< Has sub attributes.

	unsigned int	extended : 1; 		//!< Extended attribute.
	unsigned int	long_extended : 1; 	//!< Long format.
	unsigned int	evs : 1;		//!< Extended VSA.
	unsigned int	wimax: 1;		//!< WiMAX format=1,1,c.

	int8_t		tag;			//!< Tag for tunneled.
						//!< Attributes.
	uint8_t		encrypt;      		//!< Ecryption method.
	uint8_t		length;
} ATTR_FLAGS;

/*
 *  Values of the encryption flags.
 */
#define FLAG_ENCRYPT_NONE            (0)
#define FLAG_ENCRYPT_USER_PASSWORD   (1)
#define FLAG_ENCRYPT_TUNNEL_PASSWORD (2)
#define FLAG_ENCRYPT_ASCEND_SECRET   (3)

extern const FR_NAME_NUMBER dict_attr_types[];

typedef struct dict_attr {
	unsigned int		attr;
	PW_TYPE			type;
	unsigned int		vendor;
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
	unsigned int		vendorpec;
	size_t			type; /* length of type data */
	size_t			length;	/* length of length data */
	size_t			flags;
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
	uint64_t		integer64;
	uint8_t			filter[32];
	uint8_t			ifid[8]; /* struct? */
	uint8_t			ipv6prefix[18]; /* struct? */
	uint8_t			ipv4prefix[6]; /* struct? */
     	uint8_t			ether[6];
	uint8_t			*tlv;
} VALUE_PAIR_DATA;

typedef struct value_pair {
	const DICT_ATTR	        *da;		//!< Dictionary attribute
						//!< defines the attribute
						//!< number, vendor and type
						//!< of the attribute.
	const char	        *name;
	struct value_pair	*next;

	/*
	 *	Pack 4 32-bit fields together.  Saves ~8 bytes per struct
	 *	on 64-bit machines.
	 */
	unsigned int		attribute;
	unsigned int	       	vendor;
	PW_TYPE			type;

	FR_TOKEN		op;		//!< Operator to use when 
						//!< moving or inserting 
						//!< valuepair into a list.
						
        ATTR_FLAGS              flags;

	size_t			length; /* of data field */
	VALUE_PAIR_DATA		data;
} VALUE_PAIR;
#define vp_strvalue   data.strvalue
#define vp_octets     data.octets
#define vp_ipv6addr   data.ipv6addr
#define vp_ifid       data.ifid
#define vp_ipv6prefix data.ipv6prefix
#define vp_ipv4prefix data.ipv4prefix
#define vp_filter     data.filter
#define vp_ether      data.ether
#define vp_signed     data.sinteger
#define vp_tlv	      data.tlv
#define vp_integer64  data.integer64
#define vp_ipaddr     data.ipaddr.s_addr
#define vp_date       data.date
#define vp_integer    data.integer

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
	uint8_t			vector[AUTH_VECTOR_LEN];
	struct timeval		timestamp;
	uint8_t			*data;
	size_t			data_len;
	VALUE_PAIR		*vps;
	ssize_t			offset;
#ifdef WITH_TCP
	size_t			partial;
#endif
} RADIUS_PACKET;

/*
 *	Printing functions.
 */
int		fr_utf8_char(const uint8_t *str);
size_t		fr_print_string(const char *in, size_t inlen,
				 char *out, size_t outlen);
int     	vp_prints_value(char *out, size_t outlen,
				const VALUE_PAIR *vp, int delimitst);
int     	vp_prints_value_json(char *out, size_t outlen,
				     const VALUE_PAIR *vp);
size_t		vp_print_name(char *buffer, size_t bufsize,
			      unsigned int attr, unsigned int vendor);
int     	vp_prints(char *out, size_t outlen, const VALUE_PAIR *vp);
void		vp_print(FILE *, const VALUE_PAIR *);
void		vp_printlist(FILE *, const VALUE_PAIR *);
#define		fprint_attr_val vp_print

/*
 *	Dictionary functions.
 */
int		str2argv(char *str, char **argv, int max_argc);
int		dict_str2oid(const char *ptr, unsigned int *pattr,
			     unsigned int *pvendor, int tlv_depth);
int		dict_addvendor(const char *name, unsigned int value);
int		dict_addattr(const char *name, int attr, unsigned int vendor, int type, ATTR_FLAGS flags);
int		dict_addvalue(const char *namestr, const char *attrstr, int value);
int		dict_init(const char *dir, const char *fn);
void		dict_free(void);
void 		dict_attr_free(DICT_ATTR const **da);
const DICT_ATTR *dict_attr_copy(const DICT_ATTR *da, int vp_free);
const DICT_ATTR	*dict_attrunknown(unsigned int attr, unsigned int vendor, int vp_free);
const DICT_ATTR	*dict_attrunknownbyname(const char *attribute, int vp_free);
const DICT_ATTR	*dict_attrbyvalue(unsigned int attr, unsigned int vendor);
const DICT_ATTR	*dict_attrbyname(const char *attr);
const DICT_ATTR	*dict_attrbytype(unsigned int attr, unsigned int vendor,
				 PW_TYPE type);
const DICT_ATTR	*dict_attrbyparent(const DICT_ATTR *parent, unsigned int attr,
					   unsigned int vendor);
int		dict_attr_child(const DICT_ATTR *parent,
				unsigned int *pattr, unsigned int *pvendor);
DICT_VALUE	*dict_valbyattr(unsigned int attr, unsigned int vendor, int val);
DICT_VALUE	*dict_valbyname(unsigned int attr, unsigned int vendor, const char *val);
const char	*dict_valnamebyattr(unsigned int attr, unsigned int vendor, int value);
int		dict_vendorbyname(const char *name);
DICT_VENDOR	*dict_vendorbyvalue(int vendor);

#if 1 /* FIXME: compat */
#define dict_attrget	dict_attrbyvalue
#define dict_attrfind	dict_attrbyname
#define dict_valfind	dict_valbyname
/*#define dict_valget	dict_valbyattr almost but not quite*/
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

int rad_digest_cmp(const uint8_t *a, const uint8_t *b, size_t length);
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

int rad_attr_ok(const RADIUS_PACKET *packet, const RADIUS_PACKET *original,
		DICT_ATTR *da,
		const uint8_t *data, size_t length);
int rad_tlv_ok(const uint8_t *data, size_t length,
	       size_t dv_type, size_t dv_length);

ssize_t rad_attr2vp_raw(const RADIUS_PACKET *packet,
			const RADIUS_PACKET *original,
			const char *secret,
			const uint8_t *data, size_t length,
			VALUE_PAIR **pvp);
ssize_t rad_attr2vp_extended(const RADIUS_PACKET *packet,
			     const RADIUS_PACKET *original,
			     const char *secret,
			     const uint8_t *start, size_t length,
			     VALUE_PAIR **pvp);
ssize_t rad_attr2vp_wimax(const RADIUS_PACKET *packet,
			  const RADIUS_PACKET *original,
			  const char *secret,
			  const uint8_t *data, size_t length,
			  VALUE_PAIR **pvp);

ssize_t rad_attr2vp_vsa(const RADIUS_PACKET *packet,
			const RADIUS_PACKET *original,
			const char *secret,
			const uint8_t *data, size_t length,
			VALUE_PAIR **pvp);
ssize_t rad_attr2vp_rfc(const RADIUS_PACKET *packet,
			const RADIUS_PACKET *original,
			const char *secret,
			const uint8_t *data, size_t length,
			VALUE_PAIR **pvp);

ssize_t	rad_attr2vp(const RADIUS_PACKET *packet, const RADIUS_PACKET *original,
		    const char *secret,
		    const uint8_t *data, size_t length,
		    VALUE_PAIR **pvp);

ssize_t  rad_data2vp(unsigned int attribute, unsigned int vendor,
		     const uint8_t *data, size_t length,
		     VALUE_PAIR **pvp);

ssize_t rad_vp2data(const VALUE_PAIR *vp, uint8_t *out, size_t outlen);

int rad_vp2extended(const RADIUS_PACKET *packet,
		    const RADIUS_PACKET *original,
		    const char *secret, const VALUE_PAIR **pvp,
		    uint8_t *ptr, size_t room);
int rad_vp2wimax(const RADIUS_PACKET *packet,
		 const RADIUS_PACKET *original,
		 const char *secret, const VALUE_PAIR **pvp,
		 uint8_t *ptr, size_t room);
int rad_vp2vsa(const RADIUS_PACKET *packet, const RADIUS_PACKET *original,
	       const char *secret, const VALUE_PAIR **pvp, uint8_t *start,
	       size_t room);
int rad_vp2rfc(const RADIUS_PACKET *packet,
	       const RADIUS_PACKET *original,
	       const char *secret, const VALUE_PAIR **pvp,
	       uint8_t *ptr, size_t room);

int rad_vp2attr(const RADIUS_PACKET *packet,
		const RADIUS_PACKET *original, const char *secret,
		const VALUE_PAIR **pvp, uint8_t *ptr, size_t room);

/* valuepair.c */
VALUE_PAIR	*pairalloc(const DICT_ATTR *da);
VALUE_PAIR	*paircreate_raw(int attr, int vendor, int type, VALUE_PAIR *);
VALUE_PAIR	*paircreate(int attr, int vendor, int type);
void		pairfree(VALUE_PAIR **);
void            pairbasicfree(VALUE_PAIR *pair);
VALUE_PAIR	*pairfind(VALUE_PAIR *, unsigned int attr, unsigned int vendor, int8_t tag);
void		pairdelete(VALUE_PAIR **, unsigned int attr, unsigned int vendor, int8_t tag);
void		pairadd(VALUE_PAIR **, VALUE_PAIR *);
void            pairreplace(VALUE_PAIR **first, VALUE_PAIR *add);
int		paircmp(VALUE_PAIR *check, VALUE_PAIR *data);
VALUE_PAIR	*paircopyvp(const VALUE_PAIR *vp);
VALUE_PAIR	*paircopyvpdata(const DICT_ATTR *da, const VALUE_PAIR *vp);
VALUE_PAIR	*paircopy(VALUE_PAIR *vp);
VALUE_PAIR	*paircopy2(VALUE_PAIR *vp, unsigned int attr, unsigned int vendor, int8_t tag);
void		pairmove(VALUE_PAIR **to, VALUE_PAIR **from);
void		pairmove2(VALUE_PAIR **to, VALUE_PAIR **from, unsigned int attr, unsigned int vendor, int8_t tag);
VALUE_PAIR	*pairparsevalue(VALUE_PAIR *vp, const char *value);
VALUE_PAIR	*pairmake(const char *attribute, const char *value, FR_TOKEN op);
VALUE_PAIR	*pairmake_xlat(const char *attribute, const char *value, FR_TOKEN op);
VALUE_PAIR	*pairread(const char **ptr, FR_TOKEN *eol);
FR_TOKEN	userparse(const char *buffer, VALUE_PAIR **first_pair);
VALUE_PAIR	*readvp2(FILE *fp, int *pfiledone, const char *errprefix);

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
extern void rad_print_hex(RADIUS_PACKET *packet);
void		fr_printf_log(const char *, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 1, 2)))
#endif
;

/*
 *	Several handy miscellaneous functions.
 */
const char 	*ip_ntoa(char *, uint32_t);
char		*ifid_ntoa(char *buffer, size_t size, const uint8_t *ifid);
uint8_t		*ifid_aton(const char *ifid_str, uint8_t *ifid);
int		rad_lockfd(int fd, int lock_len);
int		rad_lockfd_nonblock(int fd, int lock_len);
int		rad_unlockfd(int fd, int lock_len);
size_t		fr_bin2hex(const uint8_t *bin, char *hex, size_t len);
size_t		fr_hex2bin(const char *hex, uint8_t *bin, size_t len);
int fr_ipaddr_cmp(const fr_ipaddr_t *a, const fr_ipaddr_t *b);

int		ip_hton(const char *src, int af, fr_ipaddr_t *dst);
const char	*ip_ntoh(const fr_ipaddr_t *src, char *dst, size_t cnt);
int fr_ipaddr2sockaddr(const fr_ipaddr_t *ipaddr, int port,
		       struct sockaddr_storage *sa, socklen_t *salen);
int fr_sockaddr2ipaddr(const struct sockaddr_storage *sa, socklen_t salen,
		       fr_ipaddr_t *ipaddr, int * port);


#ifdef WITH_ASCEND_BINARY
/* filters.c */
int		ascend_parse_filter(VALUE_PAIR *pair);
void		print_abinary(const VALUE_PAIR *vp, char *buffer, size_t len, int delimitst);
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

void fr_isaac(fr_randctx *ctx);
void fr_randinit(fr_randctx *ctx, int flag);
uint32_t fr_rand(void);	/* like rand(), but better. */
void fr_rand_seed(const void *, size_t ); /* seed the random pool */


/* crypt wrapper from crypt.c */
int fr_crypt_check(const char *key, const char *salt);

/* rbtree.c */
typedef struct rbtree_t rbtree_t;
typedef struct rbnode_t rbnode_t;

#define RBTREE_FLAG_NONE    (0)
#define RBTREE_FLAG_REPLACE (1 << 0)
#define RBTREE_FLAG_LOCK    (1 << 1)
rbtree_t       *rbtree_create(int (*Compare)(const void *, const void *),
			      void (*freeNode)(void *),
			      int flags);
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

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/packet.h>

#ifdef WITH_TCP
#include <freeradius-devel/tcp.h>
#endif

#endif /*LIBRADIUS_H*/
