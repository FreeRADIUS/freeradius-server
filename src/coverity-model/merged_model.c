/*
 * Below are modeling functions that use Coverity functions (the __coverity_*__())
 * to tell it the functions' intent.
 *
 * Summary: there doesn't appear to be any way we can run cov-make-library, which
 * leaves us with uploading it via the Coverity web page. We found out the hard
 * way that just preprocessing won't cut it. Coverity can't handle the expansions
 * of some of the macro usage in FreeRADIUS. In fact, one (open source) Coverity
 * modeling file says in comments that you *can't* include header files.
 *
 * That said... coverity models only describe the modeled functions' effects that
 * matter to coverity. There's an example in the Coverity docs modeling a function
 * that calls fopen(), and it actually typedefs FILE as an empty structure. It works..
 * because coverity is told what happens only in terms of the FILE * fopen() returns.
 *
 * We can't always get away with that. For example, initializing a value box, if
 * successful, writes sizeof(fr_value_box_t) bytes, so coverity has to know enough
 * to accurately determine that. We may find other issues as well... ah! If the models
 * keep things symbolic, maybe we CAN get away with only mentioning referenced fields.
 *
 * All this leads to possible coupling between the declarations and typedefs herein
 * and the real ones in FreeRADIUS header files, so that changes in the latter may
 * require changes to the former. So... We will declare ONLY what the modeling functions
 * need, mentioning their source, until we find out that more is necessary.
 *
 * NOTE: Any time this file changes, it must be reuploaded via the coverity scan web
 * interface.
 */

typedef unsigned char bool;

typedef unsigned int mode_t;
typedef long long int off_t;

typedef long int ssize_t;
typedef unsigned long int size_t;

typedef union {
} pthread_mutex_t;

/* from src/lib/server/exfile.[ch] */

typedef struct exfile_s {
	pthread_mutex_t		mutex;
	bool			locking;
} exfile_t;

static int exfile_open_lock(exfile_t *ef, char const *filename, mode_t permissions, off_t *offset)
{
    int result;

    if (result > 0) __coverity_exclusive_lock_acquire__((void *) &ef->mutex);
    return result;
}

static int exfile_close_lock(exfile_t *ef, int fd)
{
    int result;

    __coverity_exclusive_lock_release__((void *) &ef->mutex);
    return result;
}

/* from src/lib/server/pool.[ch] */

typedef struct {
} request_t;

typedef struct {
	pthread_mutex_t	mutex;
} fr_pool_t;

typedef struct {
} fr_pool_connection_t;

typedef struct {
} fr_time_t;

static fr_pool_connection_t *connection_spawn(fr_pool_t *pool, request_t *request, fr_time_t now, bool in_use, bool unlock)
{
	fr_pool_connection_t *result;

	if (result && !unlock)  __coverity_exclusive_lock_acquire__((void *) &pool->mutex);
	return result;
}

static fr_pool_connection_t *connection_find(fr_pool_t *pool, void *conn)
{
	fr_pool_connection_t *result;

	if (result)  __coverity_exclusive_lock_acquire__((void *) &pool->mutex);
	return result;
}

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

fr_slen_t fr_base16_encode_nstd(fr_sbuff_t *out, fr_dbuff_t *in, char const alphabet[static UINT8_MAX + 1])
{
	fr_slen_t	result;

	if (result >= 0) __coverity_write_buffer_bytes__(out->p, result);

	return result;
}

fr_slen_t fr_base16_decode_nstd(fr_sbuff_parse_error_t *err, fr_dbuff_t *out, fr_sbuff_t *in,
				bool no_trailing, uint8_t const alphabet[static UINT8_MAX + 1])
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

static void fr_value_box_init(fr_value_box_t *vb, fr_type_t type, fr_dict_attr_t const *enumv, bool tainted)
{
	__coverity_writeall__(vb);
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

typedef enum {
	TMPL_ATTR_REF_PREFIX_YES = 0,			//!< Attribute refs must have '&' prefix.
	TMPL_ATTR_REF_PREFIX_NO,			//!< Attribute refs have no '&' prefix.
	TMPL_ATTR_REF_PREFIX_AUTO 			//!< Attribute refs may have a '&' prefix.
} tmpl_attr_prefix_t;

typedef struct {
} fr_sbuff_escape_rules_t;

fr_slen_t tmpl_print(fr_sbuff_t *out, tmpl_t const *vpt,
                     tmpl_attr_prefix_t ar_prefix, fr_sbuff_escape_rules_t const *e_rules)
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
