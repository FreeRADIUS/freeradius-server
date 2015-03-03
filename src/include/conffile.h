#ifndef _CONFFILE_H
#define _CONFFILE_H

/*
 * conffile.h	Defines for the conffile parsing routines.
 *
 * Version:	$Id$
 *
 */

RCSIDH(conffile_h, "$Id$")

#include <stddef.h>
#include <freeradius-devel/token.h>
#include <sys/time.h>

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


typedef void conf_type_mismatch;
typedef void conf_type_invalid;

#if defined(HAVE_BUILTIN_CHOOSE_EXPR) && defined(HAVE_BUILTIN_TYPES_COMPATIBLE_P)
/*
 * Dumb hack for GCC which explodes with lots of errors masking the real
 * error cause, if we don't use typdefs for these structures.
 */
typedef struct timeval _timeval_t;

/*
 * Validation macro to check the type of the pointer or offset passed in
 * matches the type of the configuration item.
 */
#  define FR_CONF_TYPE_CHECK(_t, _ct, _p) \
	__builtin_choose_expr((_t & PW_TYPE_TMPL),\
		__builtin_choose_expr(__builtin_types_compatible_p(value_pair_tmpl_t **, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_STRING),\
		__builtin_choose_expr(__builtin_types_compatible_p(char const **, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_BOOLEAN),\
		__builtin_choose_expr(__builtin_types_compatible_p(bool *, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_SUBSECTION),\
		_p,\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_INTEGER),\
		__builtin_choose_expr(__builtin_types_compatible_p(uint32_t *, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_IPV4_ADDR),\
		__builtin_choose_expr(__builtin_types_compatible_p(fr_ipaddr_t *, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_DATE),\
		__builtin_choose_expr(__builtin_types_compatible_p(uint32_t *, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_ABINARY),\
		__builtin_choose_expr(__builtin_types_compatible_p(size_t[32/sizeof(size_t)], _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_OCTETS),\
		__builtin_choose_expr(__builtin_types_compatible_p(uint8_t *, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_IFID),\
		__builtin_choose_expr(__builtin_types_compatible_p(uint8_t[8], _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_IPV6_ADDR),\
		__builtin_choose_expr(__builtin_types_compatible_p(fr_ipaddr_t *, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_IPV6_PREFIX),\
		__builtin_choose_expr(__builtin_types_compatible_p(fr_ipaddr_t *, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_BYTE),\
		__builtin_choose_expr(__builtin_types_compatible_p(uint8_t *, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_SHORT),\
		__builtin_choose_expr(__builtin_types_compatible_p(uint16_t *, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_ETHERNET),\
		__builtin_choose_expr(__builtin_types_compatible_p(uint8_t[6], _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_SIGNED),\
		__builtin_choose_expr(__builtin_types_compatible_p(int32_t *, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_COMBO_IP_ADDR),\
		__builtin_choose_expr(__builtin_types_compatible_p(fr_ipaddr_t *, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_INTEGER64),\
		__builtin_choose_expr(__builtin_types_compatible_p(uint64_t *, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_IPV4_PREFIX),\
		__builtin_choose_expr(__builtin_types_compatible_p(fr_ipaddr_t *, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_TIMEVAL),\
		__builtin_choose_expr(__builtin_types_compatible_p(_timeval_t *, _ct), _p, (conf_type_mismatch) 0),\
	__builtin_choose_expr((((_t) & 0xff) == PW_TYPE_COMBO_IP_PREFIX),\
		__builtin_choose_expr(__builtin_types_compatible_p(fr_ipaddr_t *, _ct), _p, (conf_type_mismatch) 0),\
		(conf_type_invalid) 0\
	)))))))))))))))))))))

#  define FR_CONF_OFFSET(_t, _s, _f)	_t, FR_CONF_TYPE_CHECK((_t), __typeof__(&(((_s *)NULL)->_f)), offsetof(_s, _f)), NULL
#  define FR_CONF_POINTER(_t, _p)	_t, 0, FR_CONF_TYPE_CHECK((_t), __typeof__(_p), _p)
#  define FR_ITEM_POINTER(_t, _p)	_t, FR_CONF_TYPE_CHECK((_t), __typeof__(_p), _p)
#else
#  define FR_CONF_OFFSET(_t, _s, _f)	_t, offsetof(_s, _f), NULL
#  define FR_CONF_POINTER(_t, _p)	_t, 0, _p
#  define FR_ITEM_POINTER(_t, _p)	_t, _p
#endif

/*
 *  Instead of putting the information into a configuration structure,
 *  the configuration file routines MAY just parse it directly into
 *  user-supplied variables.
 */
#define PW_TYPE_SUBSECTION	102

/** @name #CONF_PARSER type flags
 *
 * These flags should be |'rd with another PW_TYPE_* value to create validation
 * rules for the #cf_item_parse function.
 *
 * @note File PW_TYPE_FILE_* ypes have a base type of string, so they're validated
 *	 correctly by the config parser.
 * @{
 */
#define PW_TYPE_DEPRECATED	(1 << 10) //!< If a matching #CONF_PAIR is found, error out with a deprecated message.
#define PW_TYPE_REQUIRED	(1 << 11) //!< Error out if no matching #CONF_PAIR is found, and no dflt value is set.
#define PW_TYPE_ATTRIBUTE	(1 << 12) //!< Value must resolve to attribute in dict (deprecated, use #PW_TYPE_TMPL).
#define PW_TYPE_SECRET		(1 << 13) //!< Only print value if debug level >= 3.

#define PW_TYPE_FILE_INPUT	((1 << 14) | PW_TYPE_STRING) //!< File matching value must exist, and must be readable.
#define PW_TYPE_FILE_OUTPUT	((1 << 15) | PW_TYPE_STRING) //!< File matching value must exist, and must be writeable.

#define PW_TYPE_XLAT		(1 << 16) //!< string will be dynamically expanded.
#define PW_TYPE_TMPL		(1 << 17) //!< CONF_PAIR should be parsed as a template.

#define PW_TYPE_MULTI		(1 << 18) //!< CONF_PAIR can have multiple copies.
#define PW_TYPE_NOT_EMPTY	(1 << 19) //!< CONF_PAIR is required to have a non zero length value.
/* @} **/

#define FR_INTEGER_COND_CHECK(_name, _var, _cond, _new)\
do {\
	if (!(_cond)) {\
		WARN("WARNING: Ignoring \"" _name " = %i\", forcing to \"" _name " = %i\"", _var, _new);\
		_var = _new;\
	}\
} while (0)

#define FR_INTEGER_BOUND_CHECK(_name, _var, _op, _bound) FR_INTEGER_COND_CHECK(_name, _var, (_var _op _bound), _bound)

#define FR_TIMEVAL_BOUND_CHECK(_name, _var, _op, _bound_sec, _bound_usec)\
do {\
	struct timeval _bound = {_bound_sec, _bound_usec};\
	if (!timercmp(_var, &_bound, _op)) {\
		WARN("WARNING: Ignoring \"" _name " = %d.%.06d\", forcing to \"" _name " = %d.%06d\"",\
			(int)(_var)->tv_sec, (int)(_var)->tv_usec,\
			(int)_bound.tv_sec, (int)_bound.tv_usec);\
		*_var = _bound;\
	}\
} while (0)

/** Used to parse a CONF_ITEM into a native type
 *
 */
typedef struct CONF_PARSER {
	char const	*name;			//!< Name of the CONF_ITEM to parse.
	int		type;			//!< PW_TYPE_STRING, etc. Not the enum type as it may be
						//!< mixed with flags.

	size_t		offset;			//!< Relative offset of field or structure to write the parsed value to.
						//!< Must be used exclusively to data.

	void		*data;			//!< Absolute pointer to a static variable to write the parsed value to.
						//!< Must be used exclusively to offset.

	const void	*dflt;			//!< Default as it would appear in radiusd.conf, or a pointer to a
						//!< CONF_PARSER struct (the subsection) if type is PW_TYPE_SUBSECTION.
} CONF_PARSER;

CONF_PAIR	*cf_pair_alloc(CONF_SECTION *parent, char const *attr, char const *value,
			       FR_TOKEN op, FR_TOKEN lhs_type, FR_TOKEN rhs_type);
CONF_PAIR	*cf_pair_dup(CONF_SECTION *parent, CONF_PAIR *cp);
void		cf_pair_add(CONF_SECTION *parent, CONF_PAIR *cp);

CONF_SECTION	*cf_section_alloc(CONF_SECTION *parent, char const *name1, char const *name2);
CONF_SECTION	*cf_section_dup(CONF_SECTION *parent, CONF_SECTION const *cs,
				char const *name1, char const *name2, bool copy_meta);
void		cf_section_add(CONF_SECTION *parent, CONF_SECTION *cs);
int		cf_pair_replace(CONF_SECTION *cs, CONF_PAIR *cp, char const *value);
int		cf_item_parse(CONF_SECTION *cs, char const *name, unsigned int type, void *data, char const *dflt);
int		cf_section_parse(CONF_SECTION *, void *base, CONF_PARSER const *variables);
int		cf_section_parse_pass2(CONF_SECTION *, void *base, CONF_PARSER const *variables);
const CONF_PARSER *cf_section_parse_table(CONF_SECTION *cs);
int		cf_file_read(CONF_SECTION *cs, char const *file);
void		cf_file_free(CONF_SECTION *cs);
int		cf_file_include(CONF_SECTION *cs, char const *file);

CONF_PAIR	*cf_pair_find(CONF_SECTION const *, char const *name);
CONF_PAIR	*cf_pair_find_next(CONF_SECTION const *, CONF_PAIR const *, char const *name);
CONF_SECTION	*cf_section_find(char const *name);
CONF_SECTION	*cf_section_find_name2(CONF_SECTION const *section,
				       char const *name1, char const *name2);
CONF_SECTION	*cf_section_sub_find(CONF_SECTION const *, char const *name);
CONF_SECTION	*cf_section_sub_find_name2(CONF_SECTION const *, char const *name1, char const *name2);
char const 	*cf_section_value_find(CONF_SECTION const *, char const *attr);
CONF_SECTION	*cf_top_section(CONF_SECTION *cs);

void *cf_data_find(CONF_SECTION const *, char const *);
int cf_data_add(CONF_SECTION *, char const *, void *, void (*)(void *));
void *cf_data_remove(CONF_SECTION *cs, char const *name);

char const *cf_pair_attr(CONF_PAIR const *pair);
char const *cf_pair_value(CONF_PAIR const *pair);
FR_TOKEN cf_pair_operator(CONF_PAIR const *pair);
FR_TOKEN cf_pair_attr_type(CONF_PAIR const *pair);
FR_TOKEN cf_pair_value_type(CONF_PAIR const *pair);
VALUE_PAIR *cf_pairtovp(CONF_PAIR *pair);
char const *cf_section_name1(CONF_SECTION const *cs);
char const *cf_section_name2(CONF_SECTION const *cs);
char const *cf_section_name(CONF_SECTION const *cs);
FR_TOKEN cf_section_name2_type(CONF_SECTION const *cs);
int dump_config(CONF_SECTION const *cs);
CONF_SECTION *cf_subsection_find_next(CONF_SECTION const *section,
				      CONF_SECTION const *subsection,
				      char const *name1);
CONF_SECTION *cf_section_find_next(CONF_SECTION const *section,
				   CONF_SECTION const *subsection,
				   char const *name1);
int cf_section_lineno(CONF_SECTION const *section);
int cf_pair_lineno(CONF_PAIR const *pair);
char const *cf_pair_filename(CONF_PAIR const *pair);
char const *cf_section_filename(CONF_SECTION const *section);
CONF_ITEM *cf_item_find_next(CONF_SECTION const *section, CONF_ITEM const *item);
int cf_pair_count(CONF_SECTION const *cs);
CONF_SECTION *cf_item_parent(CONF_ITEM const *ci);
bool cf_item_is_section(CONF_ITEM const *item);
bool cf_item_is_pair(CONF_ITEM const *item);
CONF_PAIR *cf_item_to_pair(CONF_ITEM const *item);
CONF_SECTION *cf_item_to_section(CONF_ITEM const *item);
CONF_ITEM *cf_pair_to_item(CONF_PAIR const *cp);
CONF_ITEM *cf_section_to_item(CONF_SECTION const *cs);

void cf_log_err(CONF_ITEM const *ci, char const *fmt, ...)		CC_HINT(format (printf, 2, 3));
void cf_log_err_cs(CONF_SECTION const *cs, char const *fmt, ...)	CC_HINT(format (printf, 2, 3));
void cf_log_err_cp(CONF_PAIR const *cp, char const *fmt, ...)		CC_HINT(format (printf, 2, 3));
void cf_log_info(CONF_SECTION const *cs, char const *fmt, ...)		CC_HINT(format (printf, 2, 3));
void cf_log_module(CONF_SECTION const *cs, char const *fmt, ...)	CC_HINT(format (printf, 2, 3));

void cf_item_add(CONF_SECTION *cs, CONF_ITEM *ci);
CONF_ITEM *cf_reference_item(CONF_SECTION const *parentcs,
			     CONF_SECTION *outercs,
			     char const *ptr);

extern CONF_SECTION *root_config;
extern bool cf_new_escape;

#ifdef __cplusplus
}
#endif

#endif /* _CONFFILE_H */
