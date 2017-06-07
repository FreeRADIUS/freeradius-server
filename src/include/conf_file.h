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
#ifndef _FR_CONFFILE_H
#define _FR_CONFFILE_H
/**
 * $Id$
 *
 * @file include/conf_file.h
 * @brief API to parse FreeRADIUS configuration file format, and convert string
 *	values to native C datatypes.
 *
 * @copyright 2015  The FreeRADIUS server project
 */
RCSIDH(conf_file_h, "$Id$")

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <freeradius-devel/token.h>
#include <freeradius-devel/rbtree.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Export the minimum amount of information about these structs
 */
typedef struct conf_item CONF_ITEM;	//!< Generic configuration element, extended to become
					///< a #CONF_PAIR, a #CONF_SECTION or #CONF_DATA.
typedef struct conf_pair CONF_PAIR;	//!< #CONF_ITEM with an attribute, an operator and a value.
typedef struct conf_part CONF_SECTION;	//!< #CONF_ITEM used to group multiple #CONF_PAIR and #CONF_SECTION, together.
typedef struct conf_data CONF_DATA;	//!< #CONF_ITEM used to associate arbitrary data
					///< with a #CONF_PAIR or #CONF_SECTION.

/*
 * Dumb hack for GCC which explodes with lots of errors masking the real
 * error cause, if we don't use typdefs for these structures.
 */
typedef struct timeval _timeval_t;

#ifdef HAVE_BUILTIN_CHOOSE_EXPR
typedef void _mismatch_vp_tmpl;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_vp_tmpl_m;	//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_char;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_char_m;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_bool;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_bool_m;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_uint32;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_uint32_m;	//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_fripaddr;	//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_fripaddr_m;	//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_time;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_time_m;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_abinary;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_abinary_m;	//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_uint8;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_uint8_m;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_uint8_m_m;	//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_ifid;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_ifid_m;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_uint16;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_uint16_m;	//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_ethernet;	//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_ethernet_m;	//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_int32;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_int32_m;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_uint64;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_uint64_m;	//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_size;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_size_m;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_timeval;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_timeval_m;	//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void _mismatch_default;		//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.

typedef void conf_type_mismatch;	//!< Dummy type used to indicate FR_TYPE_*/C type mismatch.
typedef void conf_type_invalid;		//!< Dummy type used to indicate invalid FR_TYPE_*.

/** Check if two types are compatible (the C11 way)
 *
 * Expands to 1 if types are compatible, else 0.
 *
 * @param _x pointer to check.
 * @param _t type to check compatibility with.
 */
#define is_compatible(_x, _t) _Generic((_x), _t:1, default: 0)

/** Check the type #_t matches the destination data type
 *
 * Validation macro to check the type of the pointer or offset #_p passed in
 * matches the type #_t of the configuration item.
 *
 * Uses various magic builtin precompilation functions, so will likely only
 * work with recent versions of clang and gcc.
 *
 * @note The warnings/errors emitted are usually awful.
 *
 * @param _t a #fr_type_t value with optional FR_TYPE_* flags.
 * @param _ct data type of global or struct field, obtained with ``__typeof__``.
 * @param _p Pointer or offset.
 */
#  define FR_CONF_TYPE_CHECK(_t, _ct, _p) \
__builtin_choose_expr((_t) & FR_TYPE_SUBSECTION, _p, \
__builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_SIZE) && !((_t) & FR_TYPE_MULTI), \
	__builtin_choose_expr(is_compatible((_ct), size_t *), _p, (_mismatch_size) 0), \
__builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_SIZE) && ((_t) & FR_TYPE_MULTI), \
	__builtin_choose_expr(is_compatible((_ct), size_t **), _p, (_mismatch_size_m) 0), \
__builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_DATE) && !((_t) & FR_TYPE_MULTI), \
	__builtin_choose_expr(is_compatible((_ct), time_t *), _p, (_mismatch_time) 0), \
__builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_DATE) && ((_t) & FR_TYPE_MULTI), \
	__builtin_choose_expr(is_compatible((_ct), time_t **), _p, (_mismatch_time_m) 0), \
_Generic((_ct), \
	vp_tmpl_t **	: __builtin_choose_expr(((_t) & FR_TYPE_TMPL) && !((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_vp_tmpl) 0), \
	vp_tmpl_t ***	: __builtin_choose_expr(((_t) & FR_TYPE_TMPL) && ((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_vp_tmpl_m) 0), \
	char const **	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_STRING) && !((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_char) 0), \
	char const ***	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_STRING) && ((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_char_m) 0), \
	bool *		: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_BOOL) && !((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_bool) 0), \
	bool **		: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_BOOL) && ((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_bool_m) 0), \
	uint32_t * 	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_UINT32) && !((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_uint32) 0), \
	uint32_t **	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_UINT32) && ((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_uint32_m) 0), \
	fr_ipaddr_t *	: __builtin_choose_expr(((FR_BASE_TYPE(_t) == FR_TYPE_IPV4_ADDR) || \
						(FR_BASE_TYPE(_t) == FR_TYPE_IPV4_PREFIX) || \
						(FR_BASE_TYPE(_t) == FR_TYPE_IPV6_ADDR) || \
						(FR_BASE_TYPE(_t) == FR_TYPE_IPV6_PREFIX) || \
						(FR_BASE_TYPE(_t) == FR_TYPE_COMBO_IP_ADDR)) || \
						!((_t) & FR_TYPE_MULTI), _p, (_mismatch_fripaddr) 0), \
	fr_ipaddr_t **	: __builtin_choose_expr(((FR_BASE_TYPE(_t) == FR_TYPE_IPV4_ADDR) || \
						(FR_BASE_TYPE(_t) == FR_TYPE_IPV4_PREFIX) || \
						(FR_BASE_TYPE(_t) == FR_TYPE_IPV6_ADDR) || \
						(FR_BASE_TYPE(_t) == FR_TYPE_IPV6_PREFIX) || \
						(FR_BASE_TYPE(_t) == FR_TYPE_COMBO_IP_ADDR)) && \
						((_t) & FR_TYPE_MULTI), _p, (_mismatch_fripaddr_m) 0), \
	size_t[32/sizeof(size_t)] : __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_ABINARY) && !((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_abinary) 0), \
	size_t*[32/sizeof(size_t)] : __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_ABINARY) && ((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_abinary_m) 0), \
	uint8_t const *	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_OCTETS) && !((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_uint8) 0), \
	uint8_t const **: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_OCTETS) && ((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_uint8_m) 0), \
	uint8_t *	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_UINT8) && !((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_uint8) 0), \
	uint8_t **	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_UINT8) && ((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_uint8_m) 0), \
	uint8_t[8]	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_IFID) && !(_t & FR_TYPE_MULTI), \
			_p, (_mismatch_ifid) 0), \
	uint8_t*[8]	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_IFID) && ((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_ifid_m) 0), \
	uint16_t *	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_UINT16) && !((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_uint16) 0), \
	uint16_t **	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_UINT16) && ((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_uint16_m) 0), \
	uint8_t[6]	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_ETHERNET) && !((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_ethernet) 0), \
	uint8_t*[6]	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_ETHERNET) && ((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_ethernet_m) 0), \
	int32_t	*	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_INT32) && !((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_int32) 0), \
	int32_t **	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_INT32) && ((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_int32_m) 0), \
	uint64_t *	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_UINT64) && !((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_uint64) 0), \
	uint64_t **	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_UINT64) && ((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_uint64_m) 0), \
	_timeval_t *	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_TIMEVAL) && !((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_timeval) 0), \
	_timeval_t **	: __builtin_choose_expr((FR_BASE_TYPE(_t) == FR_TYPE_TIMEVAL) && ((_t) & FR_TYPE_MULTI), \
			_p, (_mismatch_timeval_m) 0), \
	default: (conf_type_mismatch)0))))))

#  define FR_CONF_OFFSET(_n, _t, _s, _f) \
	.name = _n, \
	.type = _t, \
	.offset = FR_CONF_TYPE_CHECK((_t), &(((_s *)NULL)->_f), offsetof(_s, _f))
#  define FR_CONF_IS_SET_OFFSET(_n, _t, _s, _f) \
	.name = _n, \
	.type = (_t) | FR_TYPE_IS_SET, \
	.offset = FR_CONF_TYPE_CHECK((_t), &(((_s *)NULL)->_f), offsetof(_s, _f)), \
	.is_set_offset = offsetof(_s, _f ## _is_set)
#  define FR_CONF_POINTER(_n, _t, _p) \
	.name = _n, \
	.type = _t, \
	.data = FR_CONF_TYPE_CHECK((_t), (_p), _p)

#  define FR_CONF_IS_SET_POINTER(_n, _t, _p) \
	.name = _n, \
	.type = (_t) | FR_TYPE_IS_SET, \
	.data = FR_CONF_TYPE_CHECK((_t), (_p), _p), \
	.is_set_ptr = _p ## _is_set
#  define FR_ITEM_POINTER(_t, _p) _t, FR_CONF_TYPE_CHECK((_t), (_p), _p)

/** A CONF_PARSER multi-subsection
 *
 * Parse multiple instance of a subsection.
 *
 * @param _n	name of subsection to search for.
 * @param _t	Must be FR_TYPE_SUBSECTION | FR_TYPE_MULTI and any optional flags.
 * @param _s	instance data struct.
 * @param _f	field in instance data struct.
 * @param _sub	CONF_PARSER array to use to parse subsection data.
 */
#  define FR_CONF_SUBSECTION_ALLOC(_n, _t, _s, _f, _sub) \
	.name = _n, \
	.type = (_t), \
	.offset = FR_CONF_TYPE_CHECK((_t), &(((_s *)NULL)->_f), offsetof(_s, _f)), \
	.subcs = _sub, \
	.subcs_size = sizeof(**(((_s *)0)->_f))
#else
#  define FR_CONF_OFFSET(_n, _t, _s, _f) \
	.name = _n, \
	.type = _t, \
	.offset = offsetof(_s, _f)
#  define FR_CONF_IS_SET_OFFSET(_n, _t, _s, _f) \
	.name = _n, \
	.type = (_t) | FR_TYPE_IS_SET, \
	.offset = offsetof(_s, _f), \
	.is_set_offset = offsetof(_s, _f ## _is_set)
#  define FR_CONF_POINTER(_n, _t, _p) \
	.name = _n, \
	.type = _t, \
	.data = _p
#  define FR_CONF_IS_SET_POINTER(_n, _t, _p) \
	.name = _n, \
	.type = (_t) | FR_TYPE_IS_SET, \
	.data = _p, \
	.is_set_ptr = _p ## _is_set
#  define FR_ITEM_POINTER(_t, _p) _t, _p

/** A CONF_PARSER multi-subsection
 *
 * Parse multiple instance of a subsection.
 *
 * @param _n	name of subsection to search for.
 * @param _t	Must be FR_TYPE_SUBSECTION | FR_TYPE_MULTI and any optional flags.
 * @param _s	instance data struct.
 * @param _f	field in instance data struct.
 * @param _sub	CONF_PARSER array to use to parse subsection data.
 */
#  define FR_CONF_SUBSECTION_ALLOC(_n, _t, _s, _f, _sub) \
	.name = _n, \
	.type = _t, \
	.offset = offsetof(_s, _f), \
	.subcs = _sub, \
	.subcs_size = sizeof(**(((_s *)0)->_f))
#endif


#define FR_CONF_DEPRECATED(_n, _t, _p, _f) \
	.name = _n, \
	.type = (_t) | FR_TYPE_DEPRECATED

/*
 *  Instead of putting the information into a configuration structure,
 *  the configuration file routines MAY just parse it directly into
 *  user-supplied variables.
 */
#define FR_TYPE_SUBSECTION	102

/** @name #CONF_PARSER type flags
 *
 * These flags should be or'd with another FR_TYPE_* value to create validation
 * rules for the #cf_pair_parse function.
 *
 * @note File FR_TYPE_FILE_* types have a base type of string, so they're validated
 *	 correctly by the config parser.
 * @{
 */
#define FR_TYPE_DEPRECATED		(1 << 10) 			//!< If a matching #CONF_PAIR is found,
									//!< error out with a deprecated message.
#define FR_TYPE_REQUIRED		(1 << 11) 			//!< Error out if no matching #CONF_PAIR
									//!< is found, and no dflt value is set.
#define FR_TYPE_ATTRIBUTE		(1 << 12) 			//!< Value must resolve to attribute in dict
									//!< (deprecated, use #FR_TYPE_TMPL).
#define FR_TYPE_SECRET			(1 << 13)			 //!< Only print value if debug level >= 3.

#define FR_TYPE_FILE_INPUT		((1 << 14) | FR_TYPE_STRING)	//!< File matching value must exist,
								     	//!< and must be readable.
#define FR_TYPE_FILE_OUTPUT		((1 << 15) | FR_TYPE_STRING)	//!< File matching value must exist,
									//!< and must be writable.

#define FR_TYPE_XLAT			(1 << 16) 			//!< string will be dynamically expanded.
#define FR_TYPE_TMPL			(1 << 17) 			//!< CONF_PAIR should be parsed as a template.

#define FR_TYPE_MULTI			(1 << 18) 			//!< CONF_PAIR can have multiple copies.
#define FR_TYPE_NOT_EMPTY		(1 << 19)			//!< CONF_PAIR is required to have a non zero
									//!< length value.
#define FR_TYPE_FILE_EXISTS		((1 << 20) | FR_TYPE_STRING)	//!< File matching value must exist

#define FR_TYPE_IS_SET			(1 << 21)			//!< Write whether this config item was
									//!< left as the default to is_set_offset
									//!< or is_set_ptr.

#define FR_BASE_TYPE(_t)		(0xff & (_t))
/* @} **/

#define FR_SIZE_COND_CHECK(_name, _var, _cond, _new)\
do {\
	if (!(_cond)) {\
		WARN("Ignoring \"" _name " = %zu\", forcing to \"" _name " = %zu\"", _var, _new);\
		_var = _new;\
	}\
} while (0)

#define FR_SIZE_BOUND_CHECK(_name, _var, _op, _bound) FR_SIZE_COND_CHECK(_name, _var, (_var _op _bound), _bound)

#define FR_INTEGER_COND_CHECK(_name, _var, _cond, _new)\
do {\
	if (!(_cond)) {\
		WARN("Ignoring \"" _name " = %i\", forcing to \"" _name " = %i\"", _var, _new);\
		_var = _new;\
	}\
} while (0)

#define FR_INTEGER_BOUND_CHECK(_name, _var, _op, _bound) FR_INTEGER_COND_CHECK(_name, _var, (_var _op _bound), _bound)

#define FR_TIMEVAL_BOUND_CHECK(_name, _var, _op, _bound_sec, _bound_usec)\
do {\
	struct timeval _bound = {_bound_sec, _bound_usec};\
	if (!timercmp(_var, &_bound, _op)) {\
		WARN("Ignoring \"" _name " = %d.%.06d\", forcing to \"" _name " = %d.%06d\"",\
		     (int)(_var)->tv_sec, (int)(_var)->tv_usec,\
		     (int)_bound.tv_sec, (int)_bound.tv_usec);\
		*_var = _bound;\
	}\
} while (0)

#define FR_TIMEVAL_TO_MS(_x) (((_x)->tv_usec / 1000) + ((_x)->tv_sec * (uint64_t)1000))
#define FR_TIMESPEC_TO_MS(_x) (((_x)->tv_usec / 1000000) + ((_x)->tv_sec * (uint64_t)1000))
extern bool check_config;

/** Defines a #CONF_PAIR to C data type mapping
 *
 * Is typically used to define mappings between module sections, and module instance structs.
 * May also be used to set global configuration options.
 *
 * Offset/data values should be set using #FR_CONF_OFFSET or #FR_CONF_POINTER.
 *
 * Example with #FR_CONF_OFFSET :
 @code{.c}
   static CONF_PARSER module_config[] = {
   	{ FR_CONF_OFFSET("example", FR_TYPE_STRING | FR_TYPE_NOT_EMPTY, example_instance_t, example), .dflt = "default_value" },
   	CONF_PARSER_TERMINATOR
   }
 @endcode
 *
 * Example with #FR_CONF_POINTER :
 @code{.c}
   static CONF_PARSER global_config[] = {
   	{ FR_CONF_POINTER("example", FR_TYPE_STRING | FR_TYPE_NOT_EMPTY, &my_global), .dflt = "default_value" },
   	CONF_PARSER_TERMINATOR
   }
 @endcode
 *
 * @see FR_CONF_OFFSET
 * @see FR_CONF_POINTER
 * @see cf_section_parse
 * @see cf_pair_parse
 */
typedef struct CONF_PARSER {
	char const	*name;			//!< Name of the #CONF_ITEM to parse.
	uint32_t	type;			//!< A #fr_type_t value, may be or'd with one or more FR_TYPE_* flags.
						//!< @see cf_pair_parse.

	size_t		offset;			//!< Relative offset of field or structure to write the parsed value to.
						//!< When #type is set to #FR_TYPE_SUBSECTION, may be used to specify
						//!< a base offset to add to all offsets contained within the
						//!< subsection.
						//!< @note Must be used exclusively to #data.

	void		*data;			//!< Pointer to a static variable to write the parsed value to.
						//!< @note Must be used exclusively to #offset.

	/** Where to write status if FR_TYPE_IS_DEFAULT is set
	 *
	 * @note Which field is used, is determined by whether
	 *	data ptr is set.
	 */
	union {
		size_t		is_set_offset;	//!< If type contains FR_TYPE_IS_DEFAULT write status to bool.
						//!< at this address.
		void		*is_set_ptr;	//!< If type contains FR_TYPE_IS_DEFAULT write status to ptr
						//!< at this address.
	};

	union {
		char const	*dflt;		//!< Default as it would appear in radiusd.conf.

		struct {
			struct CONF_PARSER const *subcs;	//!< When type is set to #FR_TYPE_SUBSECTION, should
							//!< be a pointer to the start of another array of
							//!< #CONF_PARSER structs, forming the subsection.
			size_t		subcs_size;	//!< If non-zero, allocate structs of this size to hold
							//!< the parsed data.
		};
	};

	FR_TOKEN	quote;			//!< Quoting around the default value.  Only used for templates.
} CONF_PARSER;

#define CONF_PARSER_TERMINATOR	{ .name = NULL, .type = ~(UINT32_MAX - 1), \
				  .offset = 0, .data = NULL, .dflt = NULL, .quote = T_INVALID }

#define CONF_PARSER_PARTIAL_TERMINATOR	{ .name = NULL, .type = ~(UINT32_MAX - 1), \
					  .offset = 1, .data = NULL, .dflt = NULL, .quote = T_INVALID }

typedef int (*cf_walker_t)(void *data, void *ctx);

void		cf_file_check_user(uid_t uid, gid_t gid);

CONF_PAIR	*cf_pair_alloc(CONF_SECTION *parent, char const *attr, char const *value,
			       FR_TOKEN op, FR_TOKEN lhs_type, FR_TOKEN rhs_type);
CONF_PAIR	*cf_pair_dup(CONF_SECTION *parent, CONF_PAIR *cp);
void		cf_pair_add(CONF_SECTION *parent, CONF_PAIR *cp);

CONF_SECTION	*cf_section_alloc(CONF_SECTION *parent, char const *name1, char const *name2);
CONF_SECTION	*cf_section_dup(CONF_SECTION *parent, CONF_SECTION const *cs,
				char const *name1, char const *name2, bool copy_meta);
void		cf_section_add(CONF_SECTION *parent, CONF_SECTION *cs);
int		cf_pair_replace(CONF_SECTION *cs, CONF_PAIR *cp, char const *value);
int		cf_pair_parse(TALLOC_CTX *ctx, CONF_SECTION *cs, char const *name, unsigned int type, void *data,
			      char const *dflt, FR_TOKEN dflt_quote);
int		cf_section_parse(TALLOC_CTX *ctx, void *base, CONF_SECTION *cs, CONF_PARSER const *variables);
int		cf_section_parse_pass2(void *base, CONF_SECTION *cs, CONF_PARSER const *variables);
const CONF_PARSER *cf_section_parse_table(CONF_SECTION *cs);
int		cf_file_read(CONF_SECTION *cs, char const *file);
void		cf_file_free(CONF_SECTION *cs);

CONF_PAIR	*cf_pair_find(CONF_SECTION const *, char const *name);
CONF_PAIR	*cf_pair_find_next(CONF_SECTION const *, CONF_PAIR const *, char const *name);
CONF_SECTION	*cf_section_find_name2(CONF_SECTION const *section,
				       char const *name1, char const *name2);
CONF_SECTION	*cf_subsection_find(CONF_SECTION const *, char const *name);
CONF_SECTION	*cf_subsection_find_name2(CONF_SECTION const *, char const *name1, char const *name2);
char const 	*cf_section_value_find(CONF_SECTION const *, char const *attr);
CONF_SECTION	*cf_top_section(CONF_SECTION *cs);

#define		cf_data_find(_cs, _type, _name) (_type *)_cf_data_find(_cs, #_type, _name)
void		*_cf_data_find(CONF_SECTION const *cs, char const *type, char const *name);

#define		cf_data_add(_cs, _data, _name, _free) _cf_data_add(_cs, _data, _name, _free)
int		_cf_data_add(CONF_SECTION *cs, void const *data, char const *name, bool free);

#define		cf_data_remove(_cs, _type, _name) (_type *)_cf_data_remove(_cs, #_type, _name)
void		*_cf_data_remove(CONF_SECTION *cs, char const *type, char const *name);

#define		cf_data_walk(_cs, _type, _cb, _ctx) _cf_data_walk(_cs, #_type, _cb, _ctx)
int		_cf_data_walk(CONF_SECTION *cs, char const *type, cf_walker_t cb, void *ctx);

char const	*cf_pair_attr(CONF_PAIR const *pair);
char const	*cf_pair_value(CONF_PAIR const *pair);
FR_TOKEN	cf_pair_operator(CONF_PAIR const *pair);
FR_TOKEN	cf_pair_attr_type(CONF_PAIR const *pair);
FR_TOKEN	cf_pair_value_type(CONF_PAIR const *pair);

char const	*cf_section_name1(CONF_SECTION const *cs);
char const	*cf_section_name2(CONF_SECTION const *cs);
char const	*cf_section_name(CONF_SECTION const *cs);
char const	*cf_section_argv(CONF_SECTION const *cs, int argc);
FR_TOKEN	cf_section_name2_type(CONF_SECTION const *cs);
FR_TOKEN	cf_section_argv_type(CONF_SECTION const *cs, int argc);

CONF_SECTION 	*cf_subsection_find_next(CONF_SECTION const *section,
					 CONF_SECTION const *subsection,
					 char const *name1);
CONF_SECTION	*cf_section_find_next(CONF_SECTION const *section,
				      CONF_SECTION const *subsection,
				      char const *name1);

int		cf_section_lineno(CONF_SECTION const *section);
int		cf_pair_lineno(CONF_PAIR const *pair);
char const	*cf_pair_filename(CONF_PAIR const *pair);
char const	*cf_section_filename(CONF_SECTION const *section);
CONF_ITEM	*cf_item_find_next(CONF_SECTION const *section, CONF_ITEM const *item);
int		cf_pair_count(CONF_SECTION const *cs);

CONF_SECTION	*cf_item_parent(CONF_ITEM const *ci);
CONF_SECTION	*cf_item_root(CONF_ITEM const *ci);

bool		cf_item_is_section(CONF_ITEM const *item);
bool		cf_item_is_pair(CONF_ITEM const *item);
CONF_PAIR	*cf_item_to_pair(CONF_ITEM const *item);
CONF_SECTION	*cf_item_to_section(CONF_ITEM const *item);
CONF_ITEM	*cf_pair_to_item(CONF_PAIR const *cp);
CONF_ITEM	*cf_section_to_item(CONF_SECTION const *cs);

/*
 *	Log an error related to a section
 */
void		cf_log_err(CONF_ITEM const *ci, char const *fmt, ...)		CC_HINT(format (printf, 2, 3));
void		cf_log_err_cs(CONF_SECTION const *cs, char const *fmt, ...)	CC_HINT(format (printf, 2, 3));
void		cf_log_perr_cs(CONF_SECTION const *cs, char const *fmt, ...)	CC_HINT(format (printf, 2, 3));
void		cf_log_err_cp(CONF_PAIR const *cp, char const *fmt, ...)	CC_HINT(format (printf, 2, 3));
void		cf_log_perr_cp(CONF_PAIR const *cp, char const *fmt, ...)	CC_HINT(format (printf, 2, 3));
void		cf_log_err_by_name(CONF_SECTION const *parent,
				   char const *name, char const *fmt, ...) CC_HINT(format (printf, 3, 4));
void		cf_log_warn_cp(CONF_PAIR const *cp, char const *fmt, ...)	CC_HINT(format (printf, 2, 3));
void		cf_log_warn(CONF_SECTION const *cs, char const *fmt, ...)	CC_HINT(format (printf, 2, 3));
void		cf_log_info(CONF_SECTION const *cs, char const *fmt, ...)	CC_HINT(format (printf, 2, 3));
void		cf_log_module(CONF_SECTION const *cs, char const *fmt, ...)	CC_HINT(format (printf, 2, 3));

void		cf_item_add(CONF_SECTION *cs, CONF_ITEM *ci);
CONF_ITEM	*cf_reference_item(CONF_SECTION const *parentcs,
				   CONF_SECTION const *outercs,
				   char const *ptr);

#ifdef WITH_CONF_WRITE
size_t cf_section_write(FILE *fp, CONF_SECTION *cs, int depth);
#endif

#define CF_FILE_NONE   (0)
#define CF_FILE_ERROR  (1)
#define CF_FILE_CONFIG (1 << 2)
#define CF_FILE_MODULE (1 << 3)
int cf_file_changed(CONF_SECTION *cs, rb_walker_t callback);

#ifdef __cplusplus
}
#endif

#endif /* _FR_CONFFILE_H */
