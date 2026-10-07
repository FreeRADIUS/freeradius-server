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

/*
 * Field order matches the real structs, so p is at the same offset.
 */
typedef struct {
	char	*buff;
	char	*start;
	char	*end;
	char	*p;
}	fr_sbuff_t;

typedef struct {
	uint8_t	*buff;
	uint8_t	*start;
	uint8_t	*end;
	uint8_t	*p;
}	fr_dbuff_t;

typedef enum {
	FR_SBUFF_OK			= 0,
	FR_SBUFF_ERR_NO_SPACE		= -1,
	FR_SBUFF_ERR_EXTEND		= -2,
	FR_SBUFF_ERR_INPUT_EMPTY	= -3,
	FR_SBUFF_ERR_INPUT_SHORT	= -4,
	FR_SBUFF_ERR_NOT_FOUND		= -5,
	FR_SBUFF_ERR_TRAILING		= -6,
	FR_SBUFF_ERR_FORMAT		= -7,
	FR_SBUFF_ERR_OVERFLOW		= -8,
	FR_SBUFF_ERR_UNDERFLOW		= -9,
	FR_SBUFF_ERR_UNINITIALISED	= -10
} fr_sbuff_err_t;

#define SBUFF_CHAR_CLASS UINT8_MAX + 1

fr_slen_t fr_base16_encode_nstd(fr_sbuff_t *out, fr_dbuff_t *in, char const alphabet[static SBUFF_CHAR_CLASS])
{
	fr_slen_t	result;

	/* result hex characters, plus the terminating '\0' */
	if (result >= 0) __coverity_write_buffer_bytes__(out->p, result + 1);

	return result;
}

fr_slen_t fr_base16_decode_nstd(fr_sbuff_err_t *err, fr_dbuff_t *out, fr_sbuff_t *in,
				bool no_trailing, uint8_t const alphabet[static SBUFF_CHAR_CLASS])
{
	fr_slen_t	result;

	/* result decoded bytes, no terminator */
	if (result >= 0) __coverity_write_buffer_bytes__(out->p, result);

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

fr_sbuff_err_t fr_sbuff_out_bstrncpy_exact(fr_sbuff_t *out, fr_sbuff_t *in, size_t len)
{
	fr_sbuff_err_t	result;

	if (result == FR_SBUFF_OK) __coverity_write_buffer_bytes__(out->p, len);

	return result;
}

fr_sbuff_err_t fr_sbuff_out_bstrncpy_allowed(size_t *len, fr_sbuff_t *out, fr_sbuff_t *in, size_t max,
					     bool const allowed[static SBUFF_CHAR_CLASS])
{
	fr_sbuff_err_t	result;
	size_t		copied;

	__coverity_write_buffer_bytes__(out->p, copied + 1);
	if (len) *len = copied;

	return result;
}

typedef struct {
} 	fr_sbuff_term_t;
typedef struct {
} 	fr_sbuff_unescape_rules_t;

fr_sbuff_err_t fr_sbuff_out_bstrncpy_until(size_t *len, fr_sbuff_t *out, fr_sbuff_t *in, size_t max,
					   fr_sbuff_term_t const *tt,
					   fr_sbuff_unescape_rules_t const *u_rules)
{
	fr_sbuff_err_t	result;
	size_t		copied;

	__coverity_write_buffer_bytes__(out->p, copied + 1);
	if (len) *len = copied;

	return result;
}

fr_sbuff_err_t fr_sbuff_out_unescape_until(size_t *len, fr_sbuff_t *out, fr_sbuff_t *in, size_t max,
					   fr_sbuff_term_t const *tt,
					   fr_sbuff_unescape_rules_t const *u_rules)
{
	fr_sbuff_err_t	result;
	size_t		copied;

	__coverity_write_buffer_bytes__(out->p, copied + 1);
	if (len) *len = copied;

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

/*
 * talloc_get_type_abort() aborts unless ptr is a talloc chunk of the named
 * type, so the pointer it returns is checked, even if ptr came from a read().
 */
void *_talloc_get_type_abort(const void *ptr, const char *name, const char *location)
{
	__coverity_mark_pointee_as_sanitized__(&ptr, TAINTED_SCALAR_GENERIC);
	return (void *)ptr;
}

/*
 * from src/lib/server/exfile.[ch]
 *
 * In the model, exfile_open() returns holding ef->mutex only when the
 * returned file descriptor is >= 0, and exfile_close() always releases
 * ef->mutex.  The real functions take ef->mutex only when ef->locking is
 * true.  Callers pair every successful exfile_open() with exfile_close()
 * whether or not ef->locking is true, so the model takes and releases
 * ef->mutex unconditionally.
 */
typedef struct exfile_s {
	pthread_mutex_t	mutex;
} exfile_t;

int exfile_open(exfile_t *ef, char const *filename, mode_t permissions, int flags, off_t *offset)
{
	int	result;
	off_t	real_offset;

	if (result >= 0) {
		__coverity_exclusive_lock_acquire__(&ef->mutex);
		if (offset) *offset = real_offset;
	}

	return result;
}

int exfile_close(exfile_t *ef, int fd)
{
	int	result;

	__coverity_exclusive_lock_release__(&ef->mutex);

	return result;
}

/*
 * from src/lib/util/test/acutest.h
 *
 * acutest_check_() returns the condition it was passed, so TEST_ASSERT()
 * only reaches the noreturn acutest_abort_() when the condition is false.
 * Without the model the analyser does not carry the condition through the
 * call, and follows the failure path past the assertion into the code the
 * assertion guards.
 */
int acutest_check_(int cond, char const *file, int line, char const *fmt, ...)
{
	return cond;
}

void acutest_abort_(void)
{
	__coverity_panic__();
}

/*
 * from src/lib/io/atomic_queue.c
 *
 * atomic_ring_segment_publish() stores the new segment into h->next and
 * ring->head with atomic stores, which the analyser does not treat as
 * publishing the pointer, so it reports the segment as leaked when the
 * caller returns.  The consumer frees the segment once it advances past.
 */
typedef struct {
} fr_atomic_ring_t;

typedef struct {
} fr_atomic_ring_segment_t;

void atomic_ring_segment_publish(fr_atomic_ring_t *ring, fr_atomic_ring_segment_t *h, fr_atomic_ring_segment_t *n)
{
	__coverity_escape__(n);
}
