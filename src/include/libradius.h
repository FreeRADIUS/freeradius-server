#ifndef LIBRADIUS_H
#define LIBRADIUS_H

/*
 * libradius.h	Structures and prototypes
 *		for the radius library.
 *
 * Version:	$Id$
 *
 */

#include "autoconf.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include <stdio.h>

/*
 *  Check for inclusion of <time.h>, versus <sys/time.h>
 *  Taken verbatim from the autoconf manual.
 */
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "radius.h"
#include "token.h"

#ifdef SIZEOF_UNSIGNED_INT
#if SIZEOF_UNSIGNED_INT != 4
#error FATAL: sizeof(unsigned int) != 4
#endif
#endif

/*
 *  Include for modules.
 */
#include <sha1.h>
#include <md4.h>

#define EAP_START               2

#define AUTH_VECTOR_LEN		16
#define CHAP_VALUE_LENGTH       16
#define MAX_STRING_LEN		254	/* RFC2138: string 0-253 octets */

#ifdef _LIBRADIUS
#  define AUTH_HDR_LEN		20
#  define VENDORPEC_USR		429
#  define VENDOR(x)		((x >> 16) & 0xffff)
#  define DEBUG			if (librad_debug) printf
#  define debug_pair(vp)	do { if (librad_debug) { \
					putchar('\t'); \
					vp_print(stdout, vp); \
					putchar('\n'); \
				     } \
				} while(0)
#  define TAG_VALID(x)          ((x) > 0 && (x) < 0x20)
#  define TAG_VALID_ZERO(x)     ((x) >= 0 && (x) < 0x20)
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
	unsigned int		caseless : 1; /* case insensitive compares */
	int8_t			tag;	      /* tag for tunneled attributes */
	uint8_t		        encrypt;      /* encryption method */
} ATTR_FLAGS;

/*
 *  Values of the encryption flags.
 */
#define FLAG_ENCRYPT_NONE            (0)
#define FLAG_ENCRYPT_USER_PASSWORD   (1)
#define FLAG_ENCRYPT_TUNNEL_PASSWORD (2)
#define FLAG_ENCRYPT_ASCEND_SECRET   (3)

typedef struct dict_attr {
	char			name[40];
	int			attr;
	int			type;
	int			vendor;
        ATTR_FLAGS              flags;
} DICT_ATTR;

typedef struct dict_value {
	char			name[40];
	int			attr;
	int			value;
} DICT_VALUE;

typedef struct dict_vendor {
	char			name[40];
	int			vendorpec;
	struct dict_vendor	*next;
} DICT_VENDOR;

typedef struct value_pair {
	char			name[40];
	int			attribute;
	int			type;
	int			length; /* of strvalue */
	uint32_t		lvalue;
	LRAD_TOKEN		operator;
	uint8_t			strvalue[MAX_STRING_LEN];
        ATTR_FLAGS              flags;
	struct value_pair	*next;
} VALUE_PAIR;

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
	uint32_t		src_ipaddr;
	uint32_t		dst_ipaddr;
	u_short			src_port;
	u_short			dst_port;
	int			id;
	unsigned int		code;
	uint8_t			vector[AUTH_VECTOR_LEN];
	time_t			timestamp;
	int			verified;
	uint8_t			*data;
	int			data_len;
	VALUE_PAIR		*vps;
} RADIUS_PACKET;

/*
 *	Printing functions.
 */
void		librad_safeprint(char *in, int inlen, char *out, int outlen);
int     vp_prints_value(char *out, int outlen, VALUE_PAIR *vp,int delimitst);
int     vp_prints(char *out, int outlen, VALUE_PAIR *vp);
void		vp_print(FILE *, VALUE_PAIR *);
void		vp_printlist(FILE *, VALUE_PAIR *);
#define		fprint_attr_val vp_print

/*
 *	Dictionary functions.
 */
int		dict_addvendor(const char *name, int value);
int		dict_addattr(const char *name, int vendor, int type, int value, ATTR_FLAGS flags);
int		dict_addvalue(const char *namestr, char *attrstr, int value);
int		dict_init(const char *dir, const char *fn);
DICT_ATTR	*dict_attrbyvalue(int attr);
DICT_ATTR	*dict_attrbyname(const char *attr);
DICT_VALUE	*dict_valbyattr(int attr, int val);
DICT_VALUE	*dict_valbyname(int attr, const char *val);
int		dict_vendorbyname(const char *name);
DICT_VENDOR	*dict_vendorbyvalue(int vendor);

/*
 *  Compatibility
 */
#define dict_vendorcode
#define dict_vendorpec


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

void		librad_md5_calc(u_char *, u_char *, u_int);

/* hmac.c */

void lrad_hmac_md5(const unsigned char *text, int text_len,
		   const unsigned char *key, int key_len,
		   unsigned char *digest);

/* hmacsha1.c */

void lrad_hmac_sha1(const unsigned char *text, int text_len,
		    const unsigned char *key, int key_len,
		    unsigned char *digest);

/* radius.c */
int		rad_send(RADIUS_PACKET *, const RADIUS_PACKET *, const char *secret);
RADIUS_PACKET	*rad_recv(int fd);
int		rad_decode(RADIUS_PACKET *packet, RADIUS_PACKET *original, const char *secret);
RADIUS_PACKET	*rad_alloc(int newvector);
void		rad_free(RADIUS_PACKET **);
int		rad_pwencode(char *encpw, int *len, const char *secret, const char *vector);
int		rad_pwdecode(char *encpw, int len, const char *secret, const char *vector);
int		rad_tunnel_pwencode(char *encpw, int *len, const char *secret, const char *vector);
int		rad_tunnel_pwdecode(uint8_t *encpw, int *len, const char *secret, const char *vector);
int		rad_chap_encode(RADIUS_PACKET *packet, char *output, int id, VALUE_PAIR *password);

/* valuepair.c */
VALUE_PAIR	*paircreate(int attr, int type);
void		pairfree(VALUE_PAIR **);
void            pairbasicfree(VALUE_PAIR *pair);
VALUE_PAIR	*pairfind(VALUE_PAIR *, int);
void		pairdelete(VALUE_PAIR **, int);
void		pairadd(VALUE_PAIR **, VALUE_PAIR *);
void            pairreplace(VALUE_PAIR **first, VALUE_PAIR *add);
VALUE_PAIR	*paircopy(VALUE_PAIR *vp);
VALUE_PAIR	*paircopy2(VALUE_PAIR *vp, int attr);
void		pairmove(VALUE_PAIR **to, VALUE_PAIR **from);
void		pairmove2(VALUE_PAIR **to, VALUE_PAIR **from, int attr);
VALUE_PAIR	*pairparsevalue(VALUE_PAIR *vp, const char *value);
VALUE_PAIR	*pairmake(const char *attribute, const char *value, int operator);
VALUE_PAIR	*pairread(char **ptr, LRAD_TOKEN *eol);
LRAD_TOKEN	userparse(char *buffer, VALUE_PAIR **first_pair);
VALUE_PAIR     *readvp2(FILE *fp, int *pfiledone, const char *errprefix);

/*
 *	Error functions.
 */
#ifdef _LIBRADIUS
void		librad_log(const char *, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 1, 2)))
#endif
;
#endif
void		librad_perror(const char *, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 1, 2)))
#endif
;
extern char	librad_errstr[];
extern int	librad_dodns;	/* 0 = no dns lookups */
extern int	librad_debug;	/* 0 = no debugging information */
extern int	librad_max_attributes; /* per incoming packet */

/*
 *	Several handy miscellaneous functions.
 */
char *		ip_hostname (char *buf, size_t buflen, uint32_t ipaddr);
uint32_t	ip_getaddr (const char *);
char *		ip_ntoa(char *, uint32_t);
uint32_t	ip_addr(const char *);
char		*ifid_ntoa(char *buffer, size_t size, uint8_t *ifid);
uint8_t		*ifid_aton(const char *ifid_str, uint8_t *ifid);
char		*ipv6_ntoa(char *buffer, size_t size, void *ip6addr);
int		ipv6_addr(const char *ip6_str, void *ip6addr);
char		*strNcpy(char *dest, const char *src, int n);
void		rad_lowercase(char *str);
void		rad_rmspace(char *str);
int		rad_lockfd(int fd, int lock_len);
int		rad_lockfd_nonblock(int fd, int lock_len);
int		rad_unlockfd(int fd, int lock_len);

#ifdef ASCEND_BINARY
/* filters.c */
int		ascend_parse_filter(VALUE_PAIR *pair);
void		print_abinary(VALUE_PAIR *vp, u_char *buffer, int len);
#endif /*ASCEND_BINARY*/

#ifdef HAVE_LOCAL_SNPRINTF
#include <stdarg.h>
int snprintf(char *str, size_t count, const char *fmt, ...);
int vsnprintf(char *str, size_t count, const char *fmt, va_list arg);
#endif

/* random numbers in isaac.c */
/* context of random number generator */
typedef struct lrad_randctx {
  uint32_t randcnt;
  uint32_t randrsl[256];
  uint32_t randmem[256];
  uint32_t randa;
  uint32_t randb;
  uint32_t randc;
} lrad_randctx;

void lrad_isaac(lrad_randctx *ctx);
void lrad_randinit(lrad_randctx *ctx, int flag);
uint32_t lrad_rand(void);	/* like rand(), but better. */

/* crypt wrapper from crypt.c */
int lrad_crypt_check(const char *key, const char *salt);

/* rbtree.c */
typedef struct rbtree_t rbtree_t;
typedef struct rbnode_t rbnode_t;

rbtree_t       *rbtree_create(int (*Compare)(const void *, const void *),
			       void (*freeNode)(void *),
			       int replace_flag);
void		rbtree_free(rbtree_t *tree);
int		rbtree_insert(rbtree_t *tree, const void *Data);
void		rbtree_delete(rbtree_t *tree, rbnode_t *Z);
rbnode_t       *rbtree_find(rbtree_t *tree, const void *Data);
void	       *rbtree_finddata(rbtree_t *tree, const void *Data);
int		rbtree_num_elements(rbtree_t *tree);
void	       *rbtree_node2data(rbtree_t *tree, rbnode_t *node);

/* callback order for walking  */
typedef enum { PreOrder, InOrder, PostOrder } RBTREE_ORDER;
int rbtree_walk(rbtree_t *tree, int (*callback)(void *), RBTREE_ORDER order);

#endif /*LIBRADIUS_H*/
