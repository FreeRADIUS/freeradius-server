/* Coverity Scan model
 *
 * This is a modeling file for Coverity Scan. Modeling helps to avoid false
 * positives.
 *
 * - A model file can't #include any header files.
 * - Therefore only some built-in primitives like int, char and void are
 *   available but not wchar_t, NULL etc.
 * - Modeling doesn't need full structs and typedefs. Rudimentary structs
 *   and similar types are sufficient.
 * - An uninitialized local pointer is not an error. It signifies that the
 *   variable could be either NULL or have some data.
 *
 * Coverity Scan doesn't pick up modifications automatically. The model file
 * must be uploaded by an admin in the analysis settings of
 * https://scan.coverity.com/projects/freeradius-freeradius-server?tab=analysis_settings
 */

typedef unsigned char bool;

typedef unsigned int mode_t;
typedef long long int off_t;

typedef long int ssize_t;
typedef unsigned long int size_t;

typedef union {
} pthread_mutex_t;

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
#define UINT8_MAX 255
typedef unsigned int uint32_t;

typedef ssize_t	fr_slen_t;

typedef struct {
	char	*p;
}	fr_sbuff_t;

typedef struct {
	uint8_t	*p;
}	fr_dbuff_t;

typedef enum {
	FR_SBUFF_PARSE_OK			= 0,		//!< No error.
	FR_SBUFF_PARSE_ERROR_NOT_FOUND		= -1,		//!< String does not contain a token
								///< matching the output type.
	FR_SBUFF_PARSE_ERROR_TRAILING		= -2,		//!< Trailing characters found.
	FR_SBUFF_PARSE_ERROR_FORMAT		= -3,		//!< Format of data was invalid.
	FR_SBUFF_PARSE_ERROR_OUT_OF_SPACE	= -4,		//!< No space available in output buffer.
	FR_SBUFF_PARSE_ERROR_NUM_OVERFLOW	= -5,		//!< Integer type would overflow.
	FR_SBUFF_PARSE_ERROR_NUM_UNDERFLOW	= -6		//!< Integer type would underflow.
} fr_sbuff_parse_error_t;

fr_slen_t fr_base16_encode_nstd(fr_sbuff_t *out, fr_dbuff_t *in, char const alphabet[static SBUFF_CHAR_CLASS])
{
	fr_slen_t	result;

	if (result >= 0) __coverity_write_buffer_bytes__(out->p, result);

	return result;
}

fr_slen_t fr_base16_decode_nstd(fr_sbuff_parse_error_t *err, fr_dbuff_t *out, fr_sbuff_t *in,
				bool no_trailing, uint8_t const alphabet[static SBUFF_CHAR_CLASS])
{
	fr_slen_t	result;

	if (result >= 0) __coverity_write_buffer_bytes__(out->p, result + 1);

	return result;
}

/*
 * Here we can use __coverity_writeall__(), which tells coverity "however big the thing
 * pointed at is, consider it all written."
 */

typedef enum {
	FR_TYPE_NULL = 0,			//!< Invalid (uninitialised) attribute type.

	FR_TYPE_STRING,				//!< String of printable characters.
	FR_TYPE_OCTETS,				//!< Raw octets.

	FR_TYPE_IPV4_ADDR,			//!< 32 Bit IPv4 Address.
	FR_TYPE_IPV4_PREFIX,			//!< IPv4 Prefix.
	FR_TYPE_IPV6_ADDR,			//!< 128 Bit IPv6 Address.
	FR_TYPE_IPV6_PREFIX,			//!< IPv6 Prefix.
	FR_TYPE_IFID,				//!< Interface ID.
	FR_TYPE_COMBO_IP_ADDR,			//!< IPv4 or IPv6 address depending on length.
	FR_TYPE_COMBO_IP_PREFIX,		//!< IPv4 or IPv6 address prefix depending on length.
	FR_TYPE_ETHERNET,			//!< 48 Bit Mac-Address.

	FR_TYPE_BOOL,				//!< A truth value.

	FR_TYPE_UINT8,				//!< 8 Bit unsigned integer.
	FR_TYPE_UINT16,				//!< 16 Bit unsigned integer.
	FR_TYPE_UINT32,				//!< 32 Bit unsigned integer.
	FR_TYPE_UINT64,				//!< 64 Bit unsigned integer.


	FR_TYPE_INT8,				//!< 8 Bit signed integer.
	FR_TYPE_INT16,				//!< 16 Bit signed integer.
	FR_TYPE_INT32,				//!< 32 Bit signed integer.
	FR_TYPE_INT64,				//!< 64 Bit signed integer.

	FR_TYPE_FLOAT32,			//!< Single precision floating point.
	FR_TYPE_FLOAT64,			//!< Double precision floating point.

	FR_TYPE_DATE,				//!< Unix time stamp, always has value >2^31

	FR_TYPE_TIME_DELTA,			//!< A period of time measured in nanoseconds.

	FR_TYPE_SIZE,				//!< Unsigned integer capable of representing any memory
						//!< address on the local system.

	FR_TYPE_TLV,				//!< Contains nested attributes.
	FR_TYPE_STRUCT,				//!< like TLV, but without T or L, and fixed-width children

	FR_TYPE_VSA,				//!< Vendor-Specific, for RADIUS attribute 26.
	FR_TYPE_VENDOR,				//!< Attribute that represents a vendor in the attribute tree.

	FR_TYPE_GROUP,				//!< A grouping of other attributes
	FR_TYPE_VALUE_BOX,			//!< A boxed value.

	FR_TYPE_VOID,				//!< User data.  Should be a talloced chunk
						///< assigned to the ptr value of the union.

	FR_TYPE_MAX				//!< Number of defined data types.
} fr_type_t;

typedef struct {
}	fr_dict_attr_t;

typedef struct {
}	fr_value_box_t;

typedef struct {
}	fr_dict_attr_flags_t;

ssize_t fr_sbuff_out_bstrncpy_exact(fr_sbuff_t *out, fr_sbuff_t *in, size_t len)
{
	ssize_t	result;

	if (result >= 0) __coverity_write_buffer_bytes__(out->p, result);

	return result;
}

size_t fr_sbuff_out_bstrncpy_allowed(fr_sbuff_t *out, fr_sbuff_t *in, size_t len,
				     bool const allowed[static SBUFF_CHAR_CLASS])
{
	size_t	result;

	__coverity_write_buffer_bytes__(out->p, result + 1);

	return result;
}

typedef struct {
} 	fr_sbuff_term_t;
typedef struct {
} 	fr_sbuff_unescape_rules_t;

size_t fr_sbuff_out_bstrncpy_until(fr_sbuff_t *out, fr_sbuff_t *in, size_t len,
				   fr_sbuff_term_t const *tt,
				   fr_sbuff_unescape_rules_t const *u_rules)
{
	size_t	result;

	__coverity_write_buffer_bytes__(out->p, result + 1);

	return result;
}

size_t fr_sbuff_out_unescape_until(fr_sbuff_t *out, fr_sbuff_t *in, size_t len,
				   fr_sbuff_term_t const *tt,
				   fr_sbuff_unescape_rules_t const *u_rules)
{
	size_t	result;

	__coverity_write_buffer_bytes__(out->p, result + 1);

	return result;
}

ssize_t fr_dict_attr_oid_print(fr_sbuff_t *out,
			       fr_dict_attr_t const *ancestor, fr_dict_attr_t const *da, bool numeric)
{
	ssize_t	result;

	if (result > 0) __coverity_write_buffer_bytes__(out->p, result);

	return result;
}

typedef struct {
}	fr_dict_t;

ssize_t fr_dict_attr_flags_print(fr_sbuff_t *out, fr_dict_t const *dict, fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	ssize_t	result;

	if (result > 0) __coverity_write_buffer_bytes__(out->p, result);

	return result;
}

typedef struct {
} request_t;

typedef size_t (*xlat_escape_legacy_t)(request_t *request, char *out, size_t outlen, char const *in, void *arg);

ssize_t xlat_eval(char *out, size_t outlen, request_t *request,
		  char const *fmt, xlat_escape_legacy_t escape, void const *escape_ctx)
{
	ssize_t	result;

	if (result > 0) __coverity_write_buffer_bytes__(out, result + 1);

	return result;
}

typedef struct {
} tmpl_t;

typedef struct {
} fr_sbuff_escape_rules_t;

fr_slen_t tmpl_print(fr_sbuff_t *out, tmpl_t const *vpt,
                     fr_sbuff_escape_rules_t const *e_rules)
{
	fr_slen_t result;

	if (result >= 0) __coverity_write_buffer_bytes__(out->p, result + 1);

	return result;
}

#ifndef MD5_DIGEST_LENGTH
#  define MD5_DIGEST_LENGTH 16
#endif

void fr_md5_calc(uint8_t out[static MD5_DIGEST_LENGTH], uint8_t const *in, size_t inlen)
{
	__coverity_write_buffer_bytes__(out, MD5_DIGEST_LENGTH);
}

typedef struct {
} decode_fail_t;

bool fr_radius_ok(uint8_t const *packet, size_t *packet_len_p,
                  uint32_t max_attributes, bool require_message_authenticator, decode_fail_t *reason)
{
	bool result;

	if (result) {
		__coverity_mark_pointee_as_sanitized__(&packet, TAINTED_SCALAR_GENERIC);
		__coverity_mark_pointee_as_sanitized__(packet, TAINTED_SCALAR_GENERIC);
		__coverity_mark_pointee_as_sanitized__(packet_len_p, TAINTED_SCALAR_GENERIC);
	}
	return result;
}

typedef struct {
} fr_ipaddr_t;

int fr_inet_pton4(fr_ipaddr_t *out, char const *value, ssize_t inlen, bool resolve, bool fallback, bool mask_bits)
{
	int result;

	__coverity_writeall__(out);
	return result;
}
