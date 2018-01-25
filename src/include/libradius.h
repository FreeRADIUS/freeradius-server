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
 * @copyright 1999-2014 The FreeRADIUS server project
 */
RCSIDH(libradius_h, "$Id$")

/*
 *  Compiler hinting macros.  Included here for 3rd party consumers
 *  of libradius.h.
 */
#include <freeradius-devel/build.h>

/*
 *  Let any external program building against the library know what
 *  features the library was built with.
 */
#include <freeradius-devel/features.h>

#ifdef WITHOUT_VERSION_CHECK
#  define RADIUSD_MAGIC_NUMBER	((uint64_t) (0xf4ee4ad3f4ee4ad3))
#  define MAGIC_PREFIX(_x)	((uint8_t) 0x00)
#  define MAGIC_VERSION(_x)	((uint32_t) 0x00000000)
#  define MAGIC_COMMIT(_x)	((uint32_t) 0x00000000)
#else
#  ifdef RADIUSD_VERSION_COMMIT
#    define RADIUSD_MAGIC_NUMBER ((uint64_t) HEXIFY3(f, RADIUSD_VERSION, RADIUSD_VERSION_COMMIT))
#  else
#    define RADIUSD_MAGIC_NUMBER ((uint64_t) HEXIFY3(f, RADIUSD_VERSION, 00000))
#  endif
#  define MAGIC_PREFIX(_x)	((uint8_t) (_x >> 56))
#  define MAGIC_VERSION(_x)	((uint32_t) ((_x >> 32) & 0x00ffffff))
#  define MAGIC_COMMIT(_x)	((uint32_t) (_x & 0xffffffff))
#endif

/*
 *  Talloc memory allocation is used in preference to malloc throughout
 *  the libraries and server.
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
#include <freeradius-devel/radius.h>
#include <freeradius-devel/token.h>
#include <freeradius-devel/hash.h>
#include <freeradius-devel/regex.h>

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

#if defined(WITH_VERIFY_PTR)
#  define FREE_MAGIC (0xF4EEF4EE)

/*
 * @FIXME
 *  Add if (_x->da) (void) talloc_get_type_abort(_x->da, DICT_ATTR);
 *  to the macro below when dictionaries are talloced.
 */
#  define VERIFY_VP(_x)		fr_pair_verify(__FILE__,  __LINE__, _x)
#  define VERIFY_LIST(_x)	fr_pair_list_verify(__FILE__,  __LINE__, NULL, _x)
#  define VERIFY_PACKET(_x)	(void) talloc_get_type_abort(_x, RADIUS_PACKET)
#else
/*
 *  Even if were building without WITH_VERIFY_PTR
 *  the pointer must not be NULL when these various macros are used
 *  so we can add some sneaky soft asserts.
 */
#  define VERIFY_VP(_x)		fr_assert(_x)
#  define VERIFY_LIST(_x)	fr_assert(_x)
#  define VERIFY_PACKET(_x)	fr_assert(_x)
#endif

#define AUTH_VECTOR_LEN		16
#define CHAP_VALUE_LENGTH       16
#define MAX_STRING_LEN		254	/* RFC2138: string 0-253 octets */
#define FR_MAX_VENDOR		(1 << 24) /* RFC limitations */

#ifdef _LIBRADIUS
#  define RADIUS_HDR_LEN	20
#  define VENDORPEC_USR		429
#  define VENDORPEC_LUCENT	4846
#  define VENDORPEC_STARENT	8164
#  define DEBUG			if (fr_debug_lvl && fr_log_fp) fr_printf_log
#endif

#  define debug_pair(vp)	do { if (fr_debug_lvl && fr_log_fp) { \
					vp_print(fr_log_fp, vp); \
				     } \
				} while(0)

#define TAG_VALID(x)		((x) > 0 && (x) < 0x20)
#define TAG_VALID_ZERO(x)	((x) < 0x20)
#define TAG_ANY			INT8_MIN
#define TAG_NONE		0
/** Check if tags are equal
 *
 * @param _x tag were matching on.
 * @param _y tag belonging to the attribute were checking.
 */
#define TAG_EQ(_x, _y) ((_x == _y) || (_x == TAG_ANY) || ((_x == TAG_NONE) && (_y == TAG_ANY)))
#define ATTRIBUTE_EQ(_x, _y) ((_x && _y) && (_x->da == _y->da) && (!_x->da->flags.has_tag || TAG_EQ(_x->tag, _y->tag)))

#define NUM_ANY			INT_MIN
#define NUM_ALL			(INT_MIN + 1)
#define NUM_COUNT		(INT_MIN + 2)
#define NUM_LAST		(INT_MIN + 3)

#define PAD(_x, _y)		(_y - ((_x) % _y))

#define PRINTF_LIKE(n)		CC_HINT(format(printf, n, n+1))
#define NEVER_RETURNS		CC_HINT(noreturn)
#define UNUSED			CC_HINT(unused)
#define BLANK_FORMAT		" "	/* GCC_LINT whines about empty formats */

typedef struct attr_flags {
	unsigned int 	is_unknown : 1;				//!< Attribute number or vendor is unknown.
	unsigned int	is_tlv : 1;				//!< Is a sub attribute.

	unsigned int	has_tag : 1;				//!< Tagged attribute.
	unsigned int	array : 1; 				//!< Pack multiples into 1 attr.
	unsigned int	has_value : 1;				//!< Has a value.
	unsigned int	has_value_alias : 1; 			//!< Has a value alias.
	unsigned int	has_tlv : 1; 				//!< Has sub attributes.

	unsigned int	extended : 1; 				//!< Extended attribute.
	unsigned int	long_extended : 1; 			//!< Long format.
	unsigned int	evs : 1;				//!< Extended VSA.
	unsigned int	wimax: 1;				//!< WiMAX format=1,1,c.

	unsigned int	concat : 1;				//!< concatenate multiple instances
	unsigned int	is_pointer : 1;				//!< data is a pointer

	unsigned int	virtual : 1;				//!< for dynamic expansion

	unsigned int	compare : 1;				//!< has a paircompare registered

	uint8_t		encrypt;      				//!< Ecryption method.
	uint8_t		length;
} ATTR_FLAGS;

/*
 *  Values of the encryption flags.
 */
#define FLAG_ENCRYPT_NONE	    (0)
#define FLAG_ENCRYPT_USER_PASSWORD   (1)
#define FLAG_ENCRYPT_TUNNEL_PASSWORD (2)
#define FLAG_ENCRYPT_ASCEND_SECRET   (3)

extern const FR_NAME_NUMBER dict_attr_types[];
extern const size_t dict_attr_sizes[PW_TYPE_MAX][2];
extern const int fr_attr_max_tlv;
extern const int fr_attr_shift[];
extern const unsigned int fr_attr_mask[];

/** dictionary attribute
 *
 */
typedef struct dict_attr {
	unsigned int		attr;
	PW_TYPE			type;
	unsigned int		vendor;
	ATTR_FLAGS		flags;
	char			name[1];
} DICT_ATTR;

/** value of an enumerated attribute
 *
 */
typedef struct dict_value {
	unsigned int		attr;
	unsigned int		vendor;
	int			value;
	char			name[1];
} DICT_VALUE;

/** dictionary vendor
 *
 */
typedef struct dict_vendor {
	unsigned int		vendorpec;
	size_t			type; 				//!< Length of type data
	size_t			length;				//!< Length of length data
	size_t			flags;
	char			name[1];
} DICT_VENDOR;

/** Union containing all data types supported by the server
 *
 * This union contains all data types that can be represented by VALUE_PAIRs. It may also be used in other parts
 * of the server where values of different types need to be stored.
 *
 * PW_TYPE should be an enumeration of the values in this union.
 */
typedef union value_data {
	char const	        *strvalue;			//!< Pointer to UTF-8 string.
	uint8_t const		*octets;			//!< Pointer to binary string.
	uint32_t		integer;			//!< 32bit unsigned integer.
	struct in_addr		ipaddr;				//!< IPv4 Address.
	uint32_t		date;				//!< Date (32bit Unix timestamp).
	size_t			filter[32/sizeof(size_t)];	//!< Ascend binary format a packed data
								//!< structure.

	uint8_t			ifid[8];			//!< IPv6 interface ID (should be struct?).
	struct in6_addr		ipv6addr;			//!< IPv6 Address.
	uint8_t			ipv6prefix[18];			//!< IPv6 prefix (should be struct?).

	uint8_t			byte;				//!< 8bit unsigned integer.
	uint16_t		ushort;				//!< 16bit unsigned integer.

	uint8_t			ether[6];			//!< Ethernet (MAC) address.

	int32_t			sinteger;			//!< 32bit signed integer.
	uint64_t		integer64;			//!< 64bit unsigned integer.

	uint8_t			ipv4prefix[6];			//!< IPv4 prefix (should be struct?).

	void			*ptr;				//!< generic pointer.
} value_data_t;

/** The type of value a VALUE_PAIR contains
 *
 * This is used to add structure to nested VALUE_PAIRs and specifies what type of node it is (set, list, data).
 *
 * xlat is another type of data node which must first be expanded before use.
 */
typedef enum value_type {
	VT_NONE = 0,						//!< VALUE_PAIR has no value.
	VT_SET,							//!< VALUE_PAIR has children.
	VT_LIST,						//!< VALUE_PAIR has multiple values.
	VT_DATA,						//!< VALUE_PAIR has a single value.
	VT_XLAT							//!< valuepair value must be xlat expanded when it's
								//!< added to VALUE_PAIR tree.
} value_type_t;

/** Stores an attribute, a value and various bits of other data
 *
 * VALUE_PAIRs are the main data structure used in the server
 *
 * They also specify what behaviour should be used when the attribute is merged into a new list/tree.
 */
typedef struct value_pair {
	DICT_ATTR const		*da;				//!< Dictionary attribute defines the attribute
								//!< number, vendor and type of the attribute.

	struct value_pair	*next;

	FR_TOKEN		op;				//!< Operator to use when moving or inserting
								//!< valuepair into a list.

	int8_t			tag;				//!< Tag value used to group valuepairs.

	union {
	//	VALUE_SET	*set;				//!< Set of child attributes.
	//	VALUE_LIST	*list;				//!< List of values for
								//!< multivalued attribute.
	//	value_data_t	*data;				//!< Value data for this attribute.

		char const 	*xlat;				//!< Source string for xlat expansion.
	} value;

	value_type_t		type;				//!< Type of pointer in value union.

	size_t			length;				//!< of Data field.
	value_data_t		data;
} VALUE_PAIR;

/** Abstraction to allow iterating over different configurations of VALUE_PAIRs
 *
 * This allows functions which do not care about the structure of collections of VALUE_PAIRs
 * to iterate over all members in a collection.
 *
 * Field within a vp_cursor should not be accessed directly, and vp_cursors should only be
 * manipulated with the pair* functions.
 */
typedef struct vp_cursor {
	VALUE_PAIR	**first;
	VALUE_PAIR	*found;					//!< pairfind marker.
	VALUE_PAIR	*last;					//!< Temporary only used for fr_cursor_insert
	VALUE_PAIR	*current;				//!< The current attribute.
	VALUE_PAIR	*next;					//!< Next attribute to process.
} vp_cursor_t;

/** A VALUE_PAIR in string format.
 *
 * Used to represent pairs in the legacy 'users' file format.
 */
typedef struct value_pair_raw {
	char l_opand[256];					//!< Left hand side of the pair.
	char r_opand[1024];					//!< Right hand side of the pair.

	FR_TOKEN quote;						//!< Type of quoting around the r_opand.

	FR_TOKEN op;						//!< Operator.
} VALUE_PAIR_RAW;

#define vp_strvalue	data.strvalue
#define vp_integer	data.integer
#define vp_ipaddr	data.ipaddr.s_addr
#define vp_date		data.date
#define vp_filter	data.filter
#define vp_octets	data.octets
#define vp_ifid		data.ifid
#define vp_ipv6addr	data.ipv6addr
#define vp_ipv6prefix	data.ipv6prefix
#define vp_byte		data.byte
#define vp_short	data.ushort
#define vp_ether	data.ether
#define vp_signed	data.sinteger
#define vp_integer64	data.integer64
#define vp_ipv4prefix	data.ipv4prefix
#define vp_length	length

typedef struct fr_ipaddr_t {
	int		af;	/* address family */
	union {
		struct in_addr	ip4addr;
		struct in6_addr ip6addr; /* maybe defined in missing.h */
	} ipaddr;
	uint8_t		prefix;
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
	int			proto;
#endif
} RADIUS_PACKET;

typedef enum {
	DECODE_FAIL_NONE = 0,
	DECODE_FAIL_MIN_LENGTH_PACKET,
	DECODE_FAIL_MIN_LENGTH_FIELD,
	DECODE_FAIL_MIN_LENGTH_MISMATCH,
	DECODE_FAIL_HEADER_OVERFLOW,
	DECODE_FAIL_UNKNOWN_PACKET_CODE,
	DECODE_FAIL_INVALID_ATTRIBUTE,
	DECODE_FAIL_ATTRIBUTE_TOO_SHORT,
	DECODE_FAIL_ATTRIBUTE_OVERFLOW,
	DECODE_FAIL_MA_INVALID_LENGTH,
	DECODE_FAIL_ATTRIBUTE_UNDERFLOW,
	DECODE_FAIL_TOO_MANY_ATTRIBUTES,
	DECODE_FAIL_MA_MISSING,
	DECODE_FAIL_TOO_MANY_AUTH,
	DECODE_FAIL_MAX
} decode_fail_t;

/*
 *	Version check.
 */
int		fr_check_lib_magic(uint64_t magic);

/*
 *	Printing functions.
 */
int		fr_utf8_char(uint8_t const *str, ssize_t inlen);
char const     	*fr_utf8_strchr(int *chr_len, char const *str, char const *chr);
size_t		fr_prints(char *out, size_t outlen, char const *in, ssize_t inlen, char quote);
size_t		fr_prints_len(char const *in, ssize_t inlen, char quote);
char		*fr_aprints(TALLOC_CTX *ctx, char const *in, ssize_t inlen, char quote);

#define		is_truncated(_ret, _max) ((_ret) >= (_max))
#define		truncate_len(_ret, _max) (((_ret) >= (_max)) ? ((_max) - 1) : _ret)
size_t   	vp_prints_value(char *out, size_t outlen, VALUE_PAIR const *vp, char quote);


char     	*vp_aprints_value(TALLOC_CTX *ctx, VALUE_PAIR const *vp, char quote);

size_t    	vp_prints_value_json(char *out, size_t outlen, VALUE_PAIR const *vp);
size_t		vp_prints(char *out, size_t outlen, VALUE_PAIR const *vp);
void		vp_print(FILE *, VALUE_PAIR const *);
void		vp_printlist(FILE *, VALUE_PAIR const *);
char		*vp_aprints_type(TALLOC_CTX *ctx, PW_TYPE type);

char		*vp_aprints(TALLOC_CTX *ctx, VALUE_PAIR const *vp, char quote);
#define		fprint_attr_val vp_print

/*
 *	Dictionary functions.
 */
#define DICT_VALUE_MAX_NAME_LEN (128)
#define DICT_VENDOR_MAX_NAME_LEN (128)
#define DICT_ATTR_MAX_NAME_LEN (128)

#define DICT_ATTR_SIZE sizeof(DICT_ATTR) + DICT_ATTR_MAX_NAME_LEN

extern const int dict_attr_allowed_chars[256];
int		dict_valid_name(char const *name);
int		str2argv(char *str, char **argv, int max_argc);
int		dict_str2oid(char const *ptr, unsigned int *pattr,
			     unsigned int *pvendor, int tlv_depth);
int		dict_addvendor(char const *name, unsigned int value);
int		dict_addattr(char const *name, int attr, unsigned int vendor, PW_TYPE type, ATTR_FLAGS flags);
int		dict_addvalue(char const *namestr, char const *attrstr, int value);
int		dict_init(char const *dir, char const *fn);
void		dict_free(void);
int		dict_read(char const *dir, char const *filename);

void 		dict_attr_free(DICT_ATTR const **da);
int		dict_unknown_from_fields(DICT_ATTR *da, unsigned int attr, unsigned int vendor);
DICT_ATTR const *dict_unknown_afrom_fields(TALLOC_CTX *ctx, unsigned int attr, unsigned int vendor);
int		dict_unknown_from_str(DICT_ATTR *da, char const *name);
int		dict_unknown_from_substr(DICT_ATTR *da, char const **name);
DICT_ATTR const *dict_unknown_afrom_str(TALLOC_CTX *ctx, char const *name);
DICT_ATTR const *dict_unknown_add(DICT_ATTR const *old);

DICT_ATTR const	*dict_attrbyvalue(unsigned int attr, unsigned int vendor);
DICT_ATTR const	*dict_attrbyname(char const *attr);
DICT_ATTR const *dict_attrbyname_substr(char const **name);
DICT_ATTR const	*dict_attrbytype(unsigned int attr, unsigned int vendor,
				 PW_TYPE type);
DICT_ATTR const	*dict_attrbyparent(DICT_ATTR const *parent, unsigned int attr,
					   unsigned int vendor);
DICT_ATTR const *dict_parent(unsigned int attr, unsigned int vendor);
int		dict_attr_child(DICT_ATTR const *parent,
				unsigned int *pattr, unsigned int *pvendor);
DICT_VALUE	*dict_valbyattr(unsigned int attr, unsigned int vendor, int val);
DICT_VALUE	*dict_valbyname(unsigned int attr, unsigned int vendor, char const *val);
char const	*dict_valnamebyattr(unsigned int attr, unsigned int vendor, int value);
int		dict_vendorbyname(char const *name);
DICT_VENDOR	*dict_vendorbyvalue(int vendor);

#if 1 /* FIXME: compat */
#define dict_attrget	dict_attrbyvalue
#define dict_attrfind	dict_attrbyname
#define dict_valfind	dict_valbyname
/*#define dict_valget	dict_valbyattr almost but not quite*/
#endif

/* radius.c */
int		rad_send(RADIUS_PACKET *, RADIUS_PACKET const *, char const *secret);
bool		rad_packet_ok(RADIUS_PACKET *packet, int flags, decode_fail_t *reason);
RADIUS_PACKET	*rad_recv(TALLOC_CTX *ctx, int fd, int flags);
ssize_t rad_recv_header(int sockfd, fr_ipaddr_t *src_ipaddr, uint16_t *src_port, int *code);
void		rad_recv_discard(int sockfd);
int		rad_verify(RADIUS_PACKET *packet, RADIUS_PACKET *original,
			   char const *secret);
int		rad_decode(RADIUS_PACKET *packet, RADIUS_PACKET *original, char const *secret);
int		rad_encode(RADIUS_PACKET *packet, RADIUS_PACKET const *original,
			   char const *secret);
int		rad_sign(RADIUS_PACKET *packet, RADIUS_PACKET const *original,
			 char const *secret);

int rad_digest_cmp(uint8_t const *a, uint8_t const *b, size_t length);
RADIUS_PACKET	*rad_alloc(TALLOC_CTX *ctx, bool new_vector);
RADIUS_PACKET	*rad_alloc_reply(TALLOC_CTX *ctx, RADIUS_PACKET *);
RADIUS_PACKET *rad_copy_packet(TALLOC_CTX *ctx, RADIUS_PACKET const *in);

void		rad_free(RADIUS_PACKET **);
int		rad_pwencode(char *encpw, size_t *len, char const *secret,
			     uint8_t const *vector);
int		rad_pwdecode(char *encpw, size_t len, char const *secret,
			     uint8_t const *vector);

#define	FR_TUNNEL_PW_ENC_LENGTH(_x) (2 + 1 + _x + PAD(_x + 1, 16))
ssize_t		rad_tunnel_pwencode(char *encpw, size_t *len, char const *secret,
				    uint8_t const *vector);
ssize_t		rad_tunnel_pwdecode(uint8_t *encpw, size_t *len,
				    char const *secret, uint8_t const *vector);
int		rad_chap_encode(RADIUS_PACKET *packet, uint8_t *output,
				int id, VALUE_PAIR *password);

int		rad_attr_ok(RADIUS_PACKET const *packet, RADIUS_PACKET const *original,
			    DICT_ATTR *da, uint8_t const *data, size_t length);
int		rad_tlv_ok(uint8_t const *data, size_t length,
			   size_t dv_type, size_t dv_length);

ssize_t		data2vp(TALLOC_CTX *ctx,
			RADIUS_PACKET *packet, RADIUS_PACKET const *original,
			char const *secret,
			DICT_ATTR const *da, uint8_t const *start,
			size_t const attrlen, size_t const packetlen,
			VALUE_PAIR **pvp);

ssize_t		rad_attr2vp(TALLOC_CTX *ctx,
			    RADIUS_PACKET *packet, RADIUS_PACKET const *original,
			    char const *secret,
			    uint8_t const *data, size_t length,
			    VALUE_PAIR **pvp);

ssize_t rad_data2vp_tlvs(TALLOC_CTX *ctx,
			 RADIUS_PACKET *packet, RADIUS_PACKET const *original,
			 char const *secret, DICT_ATTR const *da,
			 uint8_t const *start, size_t length,
			 VALUE_PAIR **pvp);

ssize_t		rad_vp2data(uint8_t const **out, VALUE_PAIR const *vp);

int		rad_vp2extended(RADIUS_PACKET const *packet,
				RADIUS_PACKET const *original,
				char const *secret, VALUE_PAIR const **pvp,
				uint8_t *ptr, size_t room);
int		rad_vp2wimax(RADIUS_PACKET const *packet,
			     RADIUS_PACKET const *original,
			     char const *secret, VALUE_PAIR const **pvp,
			     uint8_t *ptr, size_t room);

int		rad_vp2vsa(RADIUS_PACKET const *packet, RADIUS_PACKET const *original,
			   char const *secret, VALUE_PAIR const **pvp, uint8_t *start,
			   size_t room);

int		rad_vp2rfc(RADIUS_PACKET const *packet,
			   RADIUS_PACKET const *original,
			   char const *secret, VALUE_PAIR const **pvp,
			   uint8_t *ptr, size_t room);

int		rad_vp2attr(RADIUS_PACKET const *packet,
			    RADIUS_PACKET const *original, char const *secret,
			    VALUE_PAIR const **pvp, uint8_t *ptr, size_t room);

/* pair.c */
VALUE_PAIR	*fr_pair_afrom_da(TALLOC_CTX *ctx, DICT_ATTR const *da);
VALUE_PAIR	*fr_pair_afrom_num(TALLOC_CTX *ctx, unsigned int attr, unsigned int vendor);
int		fr_pair_to_unknown(VALUE_PAIR *vp);
void		fr_pair_list_free(VALUE_PAIR **);
VALUE_PAIR	*fr_pair_find_by_num(VALUE_PAIR *, unsigned int attr, unsigned int vendor, int8_t tag);
VALUE_PAIR	*fr_pair_find_by_da(VALUE_PAIR *, DICT_ATTR const *da, int8_t tag);

VALUE_PAIR	*fr_cursor_init(vp_cursor_t *cursor, VALUE_PAIR * const *node);
void		fr_cursor_copy(vp_cursor_t *out, vp_cursor_t *in);
VALUE_PAIR	*fr_cursor_first(vp_cursor_t *cursor);
VALUE_PAIR	*fr_cursor_last(vp_cursor_t *cursor);
VALUE_PAIR	*fr_cursor_next_by_num(vp_cursor_t *cursor, unsigned int attr, unsigned int vendor, int8_t tag);

VALUE_PAIR	*fr_cursor_next_by_da(vp_cursor_t *cursor, DICT_ATTR const *da, int8_t tag)
		CC_HINT(nonnull);

VALUE_PAIR	*fr_cursor_next(vp_cursor_t *cursor);
VALUE_PAIR	*fr_cursor_next_peek(vp_cursor_t *cursor);
VALUE_PAIR	*fr_cursor_current(vp_cursor_t *cursor);
void		fr_cursor_insert(vp_cursor_t *cursor, VALUE_PAIR *vp);
void		fr_cursor_merge(vp_cursor_t *cursor, VALUE_PAIR *vp);
VALUE_PAIR	*fr_cursor_remove(vp_cursor_t *cursor);
VALUE_PAIR	*fr_cursor_replace(vp_cursor_t *cursor, VALUE_PAIR *new);
void		fr_pair_delete_by_num(VALUE_PAIR **, unsigned int attr, unsigned int vendor, int8_t tag);
void		fr_pair_add(VALUE_PAIR **, VALUE_PAIR *);
void		fr_pair_replace(VALUE_PAIR **first, VALUE_PAIR *add);
int		fr_pair_cmp(VALUE_PAIR *a, VALUE_PAIR *b);
int		fr_pair_list_cmp(VALUE_PAIR *a, VALUE_PAIR *b);

typedef		int8_t (*fr_cmp_t)(void const *a, void const *b);
int8_t		attrcmp(void const *a, void const *b);
int8_t		fr_pair_cmp_by_da_tag(void const *a, void const *b);
void		fr_pair_list_sort(VALUE_PAIR **vps, fr_cmp_t cmp);
void		fr_pair_validate_debug(TALLOC_CTX *ctx, VALUE_PAIR const *failed[2]);
bool		fr_pair_validate(VALUE_PAIR const *failed[2], VALUE_PAIR *filter, VALUE_PAIR *list);
bool 		fr_pair_validate_relaxed(VALUE_PAIR const *failed[2], VALUE_PAIR *filter, VALUE_PAIR *list);
VALUE_PAIR	*fr_pair_copy(TALLOC_CTX *ctx, VALUE_PAIR const *vp);
VALUE_PAIR	*fr_pair_list_copy(TALLOC_CTX *ctx, VALUE_PAIR *from);
VALUE_PAIR	*fr_pair_list_copy_by_num(TALLOC_CTX *ctx, VALUE_PAIR *from, unsigned int attr, unsigned int vendor, int8_t tag);
void		fr_pair_steal(TALLOC_CTX *ctx, VALUE_PAIR *vp);
void		fr_pair_value_memcpy(VALUE_PAIR *vp, uint8_t const * src, size_t len);
void		fr_pair_value_memsteal(VALUE_PAIR *vp, uint8_t const *src);
void		fr_pair_value_strsteal(VALUE_PAIR *vp, char const *src);
void		fr_pair_value_strcpy(VALUE_PAIR *vp, char const * src);
void		fr_pair_value_bstrncpy(VALUE_PAIR *vp, void const * src, size_t len);
void		fr_pair_value_sprintf(VALUE_PAIR *vp, char const * fmt, ...) CC_HINT(format (printf, 2, 3));
void		fr_pair_list_move(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR **from);
void		fr_pair_list_move_by_num(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR **from,
					 unsigned int attr, unsigned int vendor, int8_t tag);
void		fr_pair_list_mcopy_by_num(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR **from,
					  unsigned int attr, unsigned int vendor, int8_t tag);
VALUE_PAIR	*fr_pair_afrom_ip_str(TALLOC_CTX *ctx, char const *value,
			     DICT_ATTR *ipv4, DICT_ATTR *ipv6, DICT_ATTR *ipv4_prefix, DICT_ATTR *ipv6_prefix);
int		fr_pair_value_from_str(VALUE_PAIR *vp, char const *value, size_t len);
VALUE_PAIR	*fr_pair_make(TALLOC_CTX *ctx, VALUE_PAIR **vps, char const *attribute, char const *value, FR_TOKEN op);
int 		fr_pair_mark_xlat(VALUE_PAIR *vp, char const *value);
FR_TOKEN 	fr_pair_raw_from_str(char const **ptr, VALUE_PAIR_RAW *raw);
FR_TOKEN	fr_pair_list_afrom_str(TALLOC_CTX *ctx, char const *buffer, VALUE_PAIR **head);
int		fr_pair_list_afrom_file(TALLOC_CTX *ctx, VALUE_PAIR **out, FILE *fp, bool *pfiledone);


/** Compare two attributes using and operator.
 *
 * @return 1 if equal, 0 if not eaqual, -1 on error.
 */
#define		fr_pair_cmp_op(_op, _a, _b)	value_data_cmp_op(_op, _a->da->type, &_a->data, _a->vp_length, _b->da->type, &_b->data, _b->vp_length)

/* value.c */
int		value_data_cmp(PW_TYPE a_type, value_data_t const *a, size_t a_len,
			       PW_TYPE b_type, value_data_t const *b, size_t b_len);

int		value_data_cmp_op(FR_TOKEN op,
				  PW_TYPE a_type, value_data_t const *a, size_t a_len,
				  PW_TYPE b_type, value_data_t const *b, size_t b_len);

ssize_t		value_data_from_str(TALLOC_CTX *ctx, value_data_t *dst,
				    PW_TYPE *src_type, DICT_ATTR const *src_enumv,
				    char const *src, ssize_t src_len, char quote);

ssize_t		value_data_cast(TALLOC_CTX *ctx, value_data_t *dst,
				PW_TYPE dst_type, DICT_ATTR const *dst_enumv,
				PW_TYPE src_type, DICT_ATTR const *src_enumv,
				value_data_t const *src, size_t src_len);

ssize_t		value_data_copy(TALLOC_CTX *ctx, value_data_t *dst, PW_TYPE type,
				const value_data_t *src, size_t src_len);

size_t		value_data_prints(char *out, size_t outlen,
				  PW_TYPE type, DICT_ATTR const *enumv,
				  value_data_t const *data, ssize_t inlen, char quote);

char		*value_data_aprints(TALLOC_CTX *ctx,
				    PW_TYPE type, DICT_ATTR const *enumv, value_data_t const *data,
				    size_t inlen, char quote);

/*
 *	Error functions.
 */
void		fr_strerror_printf(char const *, ...) CC_HINT(format (printf, 1, 2));
void		fr_perror(char const *, ...) CC_HINT(format (printf, 1, 2));


char const	*fr_strerror(void);
char const	*fr_syserror(int num);
extern bool	fr_dns_lookups;	/* do IP -> hostname lookups? */
extern bool	fr_hostname_lookups; /* do hostname -> IP lookups? */
extern int	fr_debug_lvl;	/* 0 = no debugging information */
extern uint32_t	fr_max_attributes; /* per incoming packet */
#define	FR_MAX_PACKET_CODE (52)
extern char const *fr_packet_codes[FR_MAX_PACKET_CODE];
#define is_radius_code(_x) ((_x > 0) && (_x < FR_MAX_PACKET_CODE))
extern FILE	*fr_log_fp;
void		rad_print_hex(RADIUS_PACKET const *packet);
void		fr_printf_log(char const *, ...) CC_HINT(format (printf, 1, 2));

/*
 *	Several handy miscellaneous functions.
 */
int		fr_set_signal(int sig, sig_t func);
int		fr_unset_signal(int sig);
int		fr_link_talloc_ctx_free(TALLOC_CTX *parent, TALLOC_CTX *child);
char const	*fr_inet_ntop(int af, void const *src);
char const 	*ip_ntoa(char *, uint32_t);
int		fr_pton4(fr_ipaddr_t *out, char const *value, ssize_t inlen, bool resolve, bool fallback);
int		fr_pton6(fr_ipaddr_t *out, char const *value, ssize_t inlen, bool resolve, bool fallback);
int		fr_pton(fr_ipaddr_t *out, char const *value, ssize_t inlen, int af, bool resolve);
int		fr_pton_port(fr_ipaddr_t *out, uint16_t *port_out, char const *value, ssize_t inlen, int af,
			     bool resolve);
int		fr_ntop(char *out, size_t outlen, fr_ipaddr_t const *addr);
char		*ifid_ntoa(char *buffer, size_t size, uint8_t const *ifid);
uint8_t		*ifid_aton(char const *ifid_str, uint8_t *ifid);
int		rad_lockfd(int fd, int lock_len);
int		rad_lockfd_nonblock(int fd, int lock_len);
int		rad_unlockfd(int fd, int lock_len);
char		*fr_abin2hex(TALLOC_CTX *ctx, uint8_t const *bin, size_t inlen);
size_t		fr_bin2hex(char *hex, uint8_t const *bin, size_t inlen);
size_t		fr_hex2bin(uint8_t *bin, size_t outlen, char const *hex, size_t inlen);
uint32_t	fr_strtoul(char const *value, char **end);
bool		is_whitespace(char const *value);
bool		is_printable(void const *value, size_t len);
bool		is_integer(char const *value);
bool		is_zero(char const *value);

int		fr_ipaddr_cmp(fr_ipaddr_t const *a, fr_ipaddr_t const *b);

int		ip_hton(fr_ipaddr_t *out, int af, char const *hostname, bool fallback);
char const	*ip_ntoh(fr_ipaddr_t const *src, char *dst, size_t cnt);
struct in_addr	fr_inaddr_mask(struct in_addr const *ipaddr, uint8_t prefix);
struct in6_addr	fr_in6addr_mask(struct in6_addr const *ipaddr, uint8_t prefix);
void		fr_ipaddr_mask(fr_ipaddr_t *addr, uint8_t prefix);
int		fr_ipaddr2sockaddr(fr_ipaddr_t const *ipaddr, uint16_t port,
				   struct sockaddr_storage *sa, socklen_t *salen);
int		fr_sockaddr2ipaddr(struct sockaddr_storage const *sa, socklen_t salen,
				   fr_ipaddr_t *ipaddr, uint16_t *port);
int		fr_nonblock(int fd);
int		fr_blocking(int fd);
ssize_t		fr_writev(int fd, struct iovec[], int iovcnt, struct timeval *timeout);

ssize_t		fr_utf8_to_ucs2(uint8_t *out, size_t outlen, char const *in, size_t inlen);
size_t		fr_prints_uint128(char *out, size_t outlen, uint128_t const num);
int		fr_get_time(char const *date_str, time_t *date);
int8_t		fr_pointer_cmp(void const *a, void const *b);
void		fr_quick_sort(void const *to_sort[], int min_idx, int max_idx, fr_cmp_t cmp);
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
int		ascend_parse_filter(value_data_t *out, char const *value, size_t len);
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
int		fr_crypt_check(char const *key, char const *salt);

/* cbuff.c */

typedef struct fr_cbuff fr_cbuff_t;

fr_cbuff_t	*fr_cbuff_alloc(TALLOC_CTX *ctx, uint32_t size, bool lock);
void		fr_cbuff_rp_insert(fr_cbuff_t *cbuff, void *obj);
void		*fr_cbuff_rp_next(fr_cbuff_t *cbuff, TALLOC_CTX *ctx);

/* debug.c */
typedef enum {
	DEBUG_STATE_UNKNOWN_NO_PTRACE		= -3,	//!< We don't have ptrace so can't check.
	DEBUG_STATE_UNKNOWN_NO_PTRACE_CAP	= -2,	//!< CAP_SYS_PTRACE not set for the process.
	DEBUG_STATE_UNKNOWN			= -1,	//!< Unknown, likely fr_get_debug_state() not called yet.
	DEBUG_STATE_NOT_ATTACHED		= 0,	//!< We can attach, so a debugger must not be.
	DEBUG_STATE_ATTACHED			= 1	//!< We can't attach, it's likely a debugger is already tracing.
} fr_debug_state_t;

#define FR_FAULT_LOG(fmt, ...) fr_fault_log(fmt "\n", ## __VA_ARGS__)
typedef void (*fr_fault_log_t)(char const *msg, ...) CC_HINT(format (printf, 1, 2));
extern fr_debug_state_t fr_debug_state;

/** Optional callback passed to fr_fault_setup
 *
 * Allows optional logic to be run before calling the main fault handler.
 *
 * If the callback returns < 0, the main fault handler will not be called.
 *
 * @param signum signal raised.
 * @return 0 on success < 0 on failure.
 */
typedef int (*fr_fault_cb_t)(int signum);
typedef struct fr_bt_marker fr_bt_marker_t;

void		fr_store_debug_state(void);
char const	*fr_debug_state_to_msg(fr_debug_state_t state);
void		fr_debug_break(bool always);
void		backtrace_print(fr_cbuff_t *cbuff, void *obj);
int		fr_backtrace_do(fr_bt_marker_t *marker);
fr_bt_marker_t	*fr_backtrace_attach(fr_cbuff_t **cbuff, TALLOC_CTX *obj);

void		fr_panic_on_free(TALLOC_CTX *ctx);
int		fr_set_dumpable_init(void);
int		fr_set_dumpable(bool allow_core_dumps);
int		fr_reset_dumpable(void);
int		fr_log_talloc_report(TALLOC_CTX *ctx);
void		fr_fault(int sig);
void		fr_talloc_fault_setup(void);
int		fr_fault_setup(char const *cmd, char const *program);
void		fr_fault_set_cb(fr_fault_cb_t func);
void		fr_fault_set_log_fd(int fd);
void		fr_fault_log(char const *msg, ...) CC_HINT(format (printf, 1, 2));

#  ifdef WITH_VERIFY_PTR
void		fr_pair_verify(char const *file, int line, VALUE_PAIR const *vp);
void		fr_pair_list_verify(char const *file, int line, TALLOC_CTX *expected, VALUE_PAIR *vps);
#  endif

bool		fr_assert_cond(char const *file, int line, char const *expr, bool cond);
#  define	fr_assert(_x) fr_assert_cond(__FILE__,  __LINE__, #_x, (_x))

void		NEVER_RETURNS _fr_exit(char const *file, int line, int status);
#  define	fr_exit(_x) _fr_exit(__FILE__,  __LINE__, (_x))

void		NEVER_RETURNS _fr_exit_now(char const *file, int line, int status);
#  define	fr_exit_now(_x) _fr_exit_now(__FILE__,  __LINE__, (_x))

/* rbtree.c */
typedef struct rbtree_t rbtree_t;
typedef struct rbnode_t rbnode_t;

/* callback order for walking  */
typedef enum {
	RBTREE_PRE_ORDER,
	RBTREE_IN_ORDER,
	RBTREE_POST_ORDER,
	RBTREE_DELETE_ORDER
} rb_order_t;

#define RBTREE_FLAG_NONE    (0)
#define RBTREE_FLAG_REPLACE (1 << 0)
#define RBTREE_FLAG_LOCK    (1 << 1)

typedef int (*rb_comparator_t)(void const *ctx, void const *data);
typedef int (*rb_walker_t)(void *ctx, void *data);
typedef void (*rb_free_t)(void *data);

rbtree_t	*rbtree_create(TALLOC_CTX *ctx, rb_comparator_t compare, rb_free_t node_free, int flags);
void		rbtree_free(rbtree_t *tree);
bool		rbtree_insert(rbtree_t *tree, void *data);
rbnode_t	*rbtree_insert_node(rbtree_t *tree, void *data);
void		rbtree_delete(rbtree_t *tree, rbnode_t *z);
bool		rbtree_deletebydata(rbtree_t *tree, void const *data);
rbnode_t	*rbtree_find(rbtree_t *tree, void const *data);
void		*rbtree_finddata(rbtree_t *tree, void const *data);
uint32_t	rbtree_num_elements(rbtree_t *tree);
void		*rbtree_node2data(rbtree_t *tree, rbnode_t *node);

/*
 *	The callback should be declared as:
 *	int callback(void *context, void *data)
 *
 *	The "context" is some user-defined context.
 *	The "data" is the pointer to the user data in the node,
 *	NOT the node itself.
 *
 *	It should return 0 if all is OK, and !0 for any error.
 *	The walking will stop on any error.
 *
 *	Except with RBTREE_DELETE_ORDER, where the callback should return <0 for
 *	errors, and may return 1 to delete the current node and halt,
 *	or 2 to delete the current node and continue.  This may be
 *	used to batch-delete select nodes from a locked rbtree.
 */
int		rbtree_walk(rbtree_t *tree, rb_order_t order, rb_walker_t compare, void *context);

/*
 *	FIFOs
 */
typedef struct	fr_fifo_t fr_fifo_t;
typedef void (*fr_fifo_free_t)(void *);
fr_fifo_t	*fr_fifo_create(TALLOC_CTX *ctx, int max_entries, fr_fifo_free_t freeNode);
void		fr_fifo_free(fr_fifo_t *fi);
int		fr_fifo_push(fr_fifo_t *fi, void *data);
void		*fr_fifo_pop(fr_fifo_t *fi);
void		*fr_fifo_peek(fr_fifo_t *fi);
unsigned int	fr_fifo_num_elements(fr_fifo_t *fi);

/*
 *	socket.c
 */
int		fr_socket_client_unix(char const *path, bool async);
int		fr_socket_client_udp(fr_ipaddr_t *src_ipaddr, fr_ipaddr_t *dst_ipaddr, uint16_t dst_port, bool async);
int		fr_socket_client_tcp(fr_ipaddr_t *src_ipaddr, fr_ipaddr_t *dst_ipaddr, uint16_t dst_port, bool async);
int		fr_socket_wait_for_connect(int sockfd, struct timeval *timeout);

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/packet.h>

#ifdef WITH_TCP
#  include <freeradius-devel/tcp.h>
#endif

#endif /*LIBRADIUS_H*/
