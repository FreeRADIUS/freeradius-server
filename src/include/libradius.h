#ifndef LIBRADIUS_H
#define LIBRADIUS_H

/*
 * libradius.h	Structures and prototypes
 *		for the radius library.
 *
 * Version:	@(#)libradius.h	 1.00  19-Jul-1999  miquels@cistron.nl
 *
 */

#include "autoconf.h"
#include <sys/types.h>

#include "radius.h"
#include "token.h"

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
int		dict_addvendor(char *name, int value);
int		dict_addattr(char *name, int vendor, int type, int value);
int		dict_addvalue(char *namestr, char *attrstr, int value);
int		dict_init(char *dir, char *fn);
DICT_ATTR	*dict_attrbyvalue(int attr);
DICT_ATTR	*dict_attrbyname(char *attr);
DICT_VALUE	*dict_valbyattr(int attr, int val);
DICT_VALUE	*dict_valbyname(char *val);
int		dict_vendorcode(int);
int		dict_vendorpec(int);
int		dict_vendorname(char *name);

#if 1 /* FIXME: compat */
#define dict_attrget	dict_attrbyvalue
#define dict_attrfind	dict_attrbyname
#define dict_valfind	dict_valbyname
/*#define dict_valget	dict_valbyattr almost but not quite*/
#endif

/* md5.c */

void		librad_md5_calc(u_char *, u_char *, u_int);

/* radius.c */
int		rad_send(RADIUS_PACKET *, int fd, char *secret);
RADIUS_PACKET	*rad_recv(int fd);
int		rad_decode(RADIUS_PACKET *packet, char *secret);
RADIUS_PACKET	*rad_alloc(int newvector);
void		rad_free(RADIUS_PACKET *);
int		rad_pwencode(char *encpw, int *len, char *secret, char *vector);
int		rad_pwdecode(char *encpw, int len, char *secret, char *vector);
int		calc_digest (RADIUS_PACKET *packet, char *secret);
int		calc_acctdigest(RADIUS_PACKET *packet, char *secret,
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
VALUE_PAIR	*pairmake(char *attribute, char *value, int operator);
VALUE_PAIR	*pairread(char **ptr, int *eol);
int		userparse(char *buffer, VALUE_PAIR **first_pair);

/*
 *	Error functions.
 */
#ifdef _LIBRADIUS
void		librad_log(char *, ...);
#endif
void		librad_perror(char *, ...);
extern char	librad_errstr[];
extern int	librad_dodns;
extern int	librad_debug;

/*
 *	Several handy miscellaneous functions.
 */
char *		ip_hostname (UINT4);
UINT4		ip_getaddr (char *);
char *		ip_ntoa(char *, UINT4);
UINT4		ip_addr(char *);

#ifdef ASCEND_BINARY
/* filters.c */
int		filterBinary(VALUE_PAIR *pair, char *valstr);
void		print_abinary(VALUE_PAIR *vp, u_char *buffer, int len);
#endif ASCEND_BINARY

#endif LIBRADIUS_H
