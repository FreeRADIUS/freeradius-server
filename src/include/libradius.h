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
#include <sys/types.h>

#include "radius.h"
#include "token.h"

#ifdef WIN32
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
#endif

#define AUTH_VECTOR_LEN		16
#define MAX_STRING_LEN		254	/* RFC2138: string 0-253 octets */

#define PW_AUTH_UDP_PORT                1645
#define PW_ACCT_UDP_PORT                1646

#ifdef _LIBRADIUS
#  define AUTH_HDR_LEN		20
#  define VENDORPEC_USR		429
#  define VENDOR(x)		(x >> 16)
#  define DEBUG			if (librad_debug) printf
#  define debug_pair(vp)	do { if (librad_debug) { \
					putchar('\t'); \
					vp_print(stdout, vp); \
					putchar('\n'); \
				     } \
				} while(0)
#endif

typedef unsigned int UINT4;

typedef struct dict_attr {
	char			name[32];
	int			attr;
	int			type;
	int			vendor;
	struct dict_attr	*next;
} DICT_ATTR;

typedef struct dict_value {
	char			name[32];
	char			attrname[32];
	int			attr;
	int			value;
	struct dict_value	*next;
} DICT_VALUE;

typedef struct dict_vendor {
	char			vendorname[32];
	int			vendorpec;
	int			vendorcode;
	struct dict_vendor	*next;
} DICT_VENDOR;

typedef struct value_pair {
	char			name[32];
	int			attribute;
	int			type;
	int			length; /* of strvalue */
	UINT4			lvalue;
	int			operator;
	int			addport;
	u_char			strvalue[MAX_STRING_LEN];
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
	UINT4			src_ipaddr;
	UINT4			dst_ipaddr;
	u_short			src_port;
	u_short			dst_port;
	int			id;
	int			code;
	char			vector[16];
	time_t			timestamp;
	int			verified;
	char			*data;
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
int		dict_addattr(const char *name, int vendor, int type, int value);
int		dict_addvalue(const char *namestr, char *attrstr, int value);
int		dict_init(const char *dir, const char *fn);
DICT_ATTR	*dict_attrbyvalue(int attr);
DICT_ATTR	*dict_attrbyname(const char *attr);
DICT_VALUE	*dict_valbyattr(int attr, int val);
DICT_VALUE	*dict_valbyname(const char *val);
int		dict_vendorcode(int);
int		dict_vendorpec(int);
int		dict_vendorname(const char *name);

#if 1 /* FIXME: compat */
#define dict_attrget	dict_attrbyvalue
#define dict_attrfind	dict_attrbyname
#define dict_valfind	dict_valbyname
/*#define dict_valget	dict_valbyattr almost but not quite*/
#endif

/* md5.c */

void		librad_md5_calc(u_char *, u_char *, u_int);

/* radius.c */
int		rad_send(RADIUS_PACKET *, const char *secret);
RADIUS_PACKET	*rad_recv(int fd);
int		rad_decode(RADIUS_PACKET *packet, const char *secret);
RADIUS_PACKET	*rad_alloc(int newvector);
void		rad_free(RADIUS_PACKET *);
int		rad_pwencode(char *encpw, int *len, const char *secret, const char *vector);
int		rad_pwdecode(char *encpw, int len, const char *secret, const char *vector);
int		rad_chap_encode(RADIUS_PACKET *packet, char *output, int id, VALUE_PAIR *password);
int		calc_digest (RADIUS_PACKET *packet, const char *secret);
int		calc_acctdigest(RADIUS_PACKET *packet, const char *secret,
			char *data, int len);

/* valuepair.c */
VALUE_PAIR	*paircreate(int attr, int type);
void		pairfree(VALUE_PAIR *);
VALUE_PAIR	*pairfind(VALUE_PAIR *, int);
void		pairdelete(VALUE_PAIR **, int);
void		pairadd(VALUE_PAIR **, VALUE_PAIR *);
VALUE_PAIR	*paircopy(VALUE_PAIR *vp);
VALUE_PAIR	*paircopy2(VALUE_PAIR *vp, int attr);
void		pairmove(VALUE_PAIR **to, VALUE_PAIR **from);
void		pairmove2(VALUE_PAIR **to, VALUE_PAIR **from, int attr);
VALUE_PAIR	*pairmake(const char *attribute, const char *value, int operator);
VALUE_PAIR	*pairread(char **ptr, int *eol);
int		userparse(char *buffer, VALUE_PAIR **first_pair);

/*
 *	Error functions.
 */
#ifdef _LIBRADIUS
void		librad_log(const char *, ...);
#endif
void		librad_perror(const char *, ...);
extern char	librad_errstr[];
extern int	librad_dodns;
extern int	librad_debug;

/*
 *	Several handy miscellaneous functions.
 */
char *		ip_hostname (UINT4);
UINT4		ip_getaddr (const char *);
char *		ip_ntoa(char *, UINT4);
UINT4		ip_addr(const char *);
char		*strNcpy(char *dest, const char *src, int n);

#ifdef ASCEND_BINARY
/* filters.c */
int		filterBinary(VALUE_PAIR *pair, const char *valstr);
void		print_abinary(VALUE_PAIR *vp, u_char *buffer, int len);
#endif ASCEND_BINARY

#endif LIBRADIUS_H
