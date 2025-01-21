#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/**
 * $Id$
 *
 * @file unlang/call_env.h
 * @brief Structures and functions for handling call environments.
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(call_env_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/dlist.h>

typedef struct call_env_parser_s	call_env_parser_t;
typedef struct call_env_parsed_s	call_env_parsed_t;
typedef struct call_env_method_s	call_env_method_t;
typedef struct call_env_ctx_s		call_env_ctx_t;
typedef struct call_env_s		call_env_t;

FR_DLIST_TYPES(call_env_parsed)
FR_DLIST_TYPEDEFS(call_env_parsed, call_env_parsed_head_t, call_env_parsed_entry_t)

#include <freeradius-devel/util/value.h>
#include <freeradius-devel/unlang/action.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/tmpl.h>

typedef enum {
	CALL_ENV_SUCCESS = 0,
	CALL_ENV_MISSING = -1,
	CALL_ENV_INVALID = -2
} call_env_result_t;

/** What type of structure is produced by the parsing phase
 */
typedef enum {
	CALL_ENV_PARSE_TYPE_TMPL = 1,				//!< Output of the parsing phase is a tmpl_t.
	CALL_ENV_PARSE_TYPE_VALUE_BOX,				//!< Output of the parsing phase is a single value box (static data).
	CALL_ENV_PARSE_TYPE_VOID				//!< Output of the parsing phase is undefined (a custom structure).
} call_env_parse_type_t;

/** What type of structure is produced by the evaluation phase
 */
typedef enum {
	CALL_ENV_RESULT_TYPE_VALUE_BOX = 1,			//!< Output of the evaluation phase is a single value box.
	CALL_ENV_RESULT_TYPE_VALUE_BOX_LIST,			//!< Output of the evaluation phase is a list of value boxes.
} call_env_result_type_t;

DIAG_OFF(attributes)
typedef enum CC_HINT(flag_enum) {
	CALL_ENV_FLAG_NONE 		= 0,
	CALL_ENV_FLAG_REQUIRED 		= 1,			//!< Associated conf pair or section is required.
	CALL_ENV_FLAG_CONCAT 		= (1 << 1),		//!< If the tmpl produced multiple boxes they should be concatenated.
	CALL_ENV_FLAG_SINGLE 		= (1 << 2),		//!< If the tmpl produces more than one box this is an error.
	CALL_ENV_FLAG_MULTI 		= (1 << 3),		//!< Multiple instances of the conf pairs are allowed.  Resulting
								///< boxes are stored in an array - one entry per conf pair.
	CALL_ENV_FLAG_NULLABLE 		= (1 << 4),		//!< Tmpl expansions are allowed to produce no output.
	CALL_ENV_FLAG_FORCE_QUOTE 	= (1 << 5),		//!< Force quote method when parsing tmpl.  This is for corner cases
								///< where tmpls should always be parsed with a particular quoting
								///< regardless of how they are in the config file.  E.g. the `program`
								///< option of `rlm_exec` should always be parsed as T_BACK_QUOTED_STRING.
	CALL_ENV_FLAG_PARSE_ONLY	= (1 << 6),		//!< The result of parsing will not be evaluated at runtime.
	CALL_ENV_FLAG_ATTRIBUTE		= (1 << 7),		//!< Tmpl MUST contain an attribute reference.
	CALL_ENV_FLAG_SUBSECTION	= (1 << 8),		//!< This is a subsection.
	CALL_ENV_FLAG_PARSE_MISSING	= (1 << 9),		//!< If this subsection is missing, still parse it.  Useful for cases where
								///< there is a callback which always needs to be run to set up required
								///< data structures.
	CALL_ENV_FLAG_SECRET		= (1 << 10),		//!< The value is a secret, and should not be logged.
	CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE = (1 << 11),		//!< bare words are treated as an attribute, but strings may
								///< be xlats.  Should not be used with CALL_ENV_FLAG_ATTRIBUTE.
								///< as that flag _always_ parses it as an attribute.
} call_env_flags_t;
DIAG_ON(attributes)

/** @name #conf_parser_t flags checks
 *
 * @{
 */
/** Evaluates to true if flags are valid for a pair
 *
 * @param[in] _flags to evaluate
 */
#define call_env_pair_flags(_flags)		(((_flags) & (CALL_ENV_FLAG_SUBSECTION)) == 0)

/** Evaluates to true if flags are valid for a subsection
 *
 * @param[in] _flags to evaluate
 */
#define call_env_subsection_flags(_flags)	(((_flags) & (CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_SINGLE | CALL_ENV_FLAG_MULTI | CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_FORCE_QUOTE | CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_PARSE_MISSING)) == 0)

#define call_env_required(_flags)		((_flags) & CALL_ENV_FLAG_REQUIRED)

#define call_env_concat(_flags)			((_flags) & CALL_ENV_FLAG_CONCAT)

#define call_env_single(_flags)			((_flags) & CALL_ENV_FLAG_SINGLE)

#define call_env_multi(_flags)			((_flags) & CALL_ENV_FLAG_MULTI)

#define call_env_nullable(_flags)		((_flags) & CALL_ENV_FLAG_NULLABLE)

#define call_env_force_quote(_flags)		((_flags) & CALL_ENV_FLAG_FORCE_QUOTE)

#define call_env_parse_only(_flags)		((_flags) & CALL_ENV_FLAG_PARSE_ONLY)

#define call_env_attribute(_flags)		((_flags) & CALL_ENV_FLAG_ATTRIBUTE)

#define call_env_is_subsection(_flags)		((_flags) & CALL_ENV_FLAG_SUBSECTION)

#define call_env_parse_missing(_flags)		((_flags) & CALL_ENV_FLAG_PARSE_MISSING)

#define call_env_secret(_flags)			((_flags) & CALL_ENV_FLAG_SECRET)

#define call_env_bare_word_attribute(_flags)	((_flags) & CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE)
/** @} */

/** Callback for performing custom parsing of a #CONF_PAIR
 *
 * @param[in] ctx		to allocate any data in.
 * @param[out] out		Where to write the result of parsing.
 * @param[in] t_rules		we're parsing attributes with.  Contains the default dictionary and nested 'caller' tmpl_rules_t.
 * @param[in] ci		The #CONF_SECTION or #CONF_PAIR to parse.
 * @param[in] cec		information about how the call env is being used.
 * @param[in] rule		Parse rules - How the #CONF_PAIR or #CONF_SECTION should be converted.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*call_env_parse_pair_t)(TALLOC_CTX *ctx, void *out, tmpl_rules_t const *t_rules, CONF_ITEM *ci, call_env_ctx_t const *cec, call_env_parser_t const *rule);

/** Callback for performing custom parsing of a #CONF_SECTION
 *
 * The callback function is expected to call call_env_parsed_add to allocate a new
 * call_env_parsed_t, and either call_env_parsed_set_tmpl, or call_env_parsed_set_data to populate
 * the call env_parsed_t structure.
 *
 * @param[in] ctx		to allocate any data in.
 * @param[out] out		Where to write the result of parsing.
 * @param[in] t_rules		we're parsing attributes with.  Contains the default dictionary and nested 'caller' tmpl_rules_t.
 * @param[in] ci		The #CONF_SECTION or #CONF_PAIR to parse.
 * @param[in] cec		information about how the call env is being used.
 * @param[in] rule		Parse rules - How the #CONF_PAIR or #CONF_SECTION should be converted.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*call_env_parse_section_t)(TALLOC_CTX *ctx, call_env_parsed_head_t *out, tmpl_rules_t const *t_rules, CONF_ITEM *ci,
				        call_env_ctx_t const *cec, call_env_parser_t const *rule);

/** Per method call config
 *
 * Similar to a conf_parser_t used to hold details of conf pairs
 * which are evaluated per call for each module method / xlat.
 *
 * This allows the conf pairs to be evaluated within the appropriate context
 * and use the appropriate dictionaries for where the module is in use.
 */
struct call_env_parser_s {
	char const			*name;			//!< Of conf pair to pass to tmpl_tokenizer.
	call_env_flags_t		flags;			//!< Flags controlling parser behaviour.

	union {
		struct {
			fr_type_t			cast_type;	//!< To cast boxes to. Also contains flags controlling parser behaviour.

			call_env_result_type_t		type;		//!< Type of structure boxes will be written to.
			size_t				size;		//!< Size of structure boxes will be written to.
			char const			*type_name;	//!< Name of structure type boxes will be written to.
			size_t				offset;		//!< Where to write the result of evaluating the tmpl_t produced in the parsing phase.

			char const			*dflt;		//!< Default string to pass to the tmpl_tokenizer if no CONF_PAIR found.
			fr_token_t			dflt_quote;	//!< Quoting for the default string.

			call_env_parse_pair_t		func;		//!< Callback for parsing a CONF_PAIR

			struct {
				ssize_t 			offset;		//!< Where to write the result of the parsing phase.
										///< This is usually a tmpl_t, but could be other things when a callback
										///< function is used to parse the CONF_SECTION or CONF_PAIR.

				call_env_parse_type_t		type;		//!< What type of output the parsing phase is expected to produce.
			} parsed;

			fr_value_box_safe_for_t		literals_safe_for;	//!< What safe_for value to assign any literals that are arguments to the tmpl_t.
			tmpl_escape_t			escape;			//!< Escape method to use when evaluating tmpl_t.
		} pair;

		struct {
			char const			*name2;		//!< Second identifier for a section
			call_env_parser_t const		*subcs;		//!< Nested definitions for subsection.

			call_env_parse_section_t	func;		//!< Callback for parsing CONF_SECTION.
    		} section;
  	};

	void const *uctx;					//!< User context for callback functions.
};

typedef enum {
	CALL_ENV_CTX_TYPE_MODULE = 1,				//!< The callenv is registered to a module method.
	CALL_ENV_CTX_TYPE_XLAT					//!< The callenv is registered to an xlat.
} call_env_ctx_type_t;

struct call_env_ctx_s {
	call_env_ctx_type_t		type;			//!< Type of callenv ctx.

	module_instance_t const		*mi;			//!< Module instance that the callenv is registered to.
								///< Available for both module methods, and xlats.

	section_name_t const		*asked;			//!< The actual name1/name2 that resolved to a
								///< module_method_binding_t.
};

#define CALL_ENV_TERMINATOR { NULL }

/** Helper macro for populating the size/type fields of a #call_env_method_t from the output structure type
 */
#define FR_CALL_ENV_METHOD_OUT(_inst) \
	.inst_size = sizeof(_inst), \
	.inst_type = STRINGIFY(_inst) \

struct call_env_method_s {
	size_t				inst_size;		//!< Size of per call env.
	char const			*inst_type;		//!< Type of per call env.
	call_env_parser_t const		*env;			//!< Parsing rules for call method env.
};

/** Structure containing both a talloc pool, a list of parsed call_env_pairs
 */
struct call_env_s {
	call_env_parsed_head_t		parsed;			//!< The per call parsed call environment.
	call_env_method_t const		*method;		//!< The method this call env is for.
};

/** Where we're specifying a parsing phase output field, determine its type
 */
#define CALL_ENV_PARSE_TYPE(_s, _f) \
_Generic((((_s *)NULL)->_f), \
	tmpl_t const *			: CALL_ENV_PARSE_TYPE_TMPL, \
	tmpl_t *			: CALL_ENV_PARSE_TYPE_TMPL, \
	fr_value_box_t const *		: CALL_ENV_PARSE_TYPE_VALUE_BOX, \
	fr_value_box_t *		: CALL_ENV_PARSE_TYPE_VALUE_BOX, \
	default				: CALL_ENV_PARSE_TYPE_VOID \
)

/** Derive whether tmpl can only emit a single box.
 */
#define FR_CALL_ENV_SINGLE(_s, _f, _c) \
_Generic((((_s *)NULL)->_f), \
	fr_value_box_t			: __builtin_choose_expr(_c, CALL_ENV_FLAG_NONE, CALL_ENV_FLAG_SINGLE), \
	fr_value_box_t *		: __builtin_choose_expr(_c, CALL_ENV_FLAG_NONE, CALL_ENV_FLAG_SINGLE), \
	fr_value_box_list_t		: CALL_ENV_FLAG_NONE, \
	fr_value_box_list_t *		: CALL_ENV_FLAG_NONE, \
	default				: CALL_ENV_FLAG_NONE \
)

/** Derive whether multi conf pairs are allowed from target field type.
 */
#define FR_CALL_ENV_MULTI(_s, _f) \
_Generic((((_s *)NULL)->_f), \
	fr_value_box_t			: CALL_ENV_FLAG_NONE, \
	fr_value_box_t *		: CALL_ENV_FLAG_MULTI, \
	fr_value_box_list_t		: CALL_ENV_FLAG_NONE, \
	fr_value_box_list_t *		: CALL_ENV_FLAG_MULTI \
)

/** Only FR_TYPE_STRING and FR_TYPE_OCTETS can be concatenated.
 */
#define FR_CALL_ENV_CONCAT(_c, _ct) \
__builtin_choose_expr(_ct == FR_TYPE_STRING, _c, \
__builtin_choose_expr(_ct == FR_TYPE_OCTETS, _c, \
__builtin_choose_expr(_c, (void)0, false)))

/** Mapping from field types to destination type enum
 */
#define FR_CALL_ENV_DST_TYPE(_s, _f) \
_Generic((((_s *)NULL)->_f), \
	fr_value_box_t			: CALL_ENV_RESULT_TYPE_VALUE_BOX, \
	fr_value_box_t *		: CALL_ENV_RESULT_TYPE_VALUE_BOX, \
	fr_value_box_list_t		: CALL_ENV_RESULT_TYPE_VALUE_BOX_LIST, \
	fr_value_box_list_t *		: CALL_ENV_RESULT_TYPE_VALUE_BOX_LIST \
)

#define FR_CALL_ENV_DST_SIZE(_s, _f) \
_Generic((((_s *)NULL)->_f), \
	fr_value_box_t			: sizeof(fr_value_box_t), \
	fr_value_box_t *		: sizeof(fr_value_box_t), \
	fr_value_box_list_t		: sizeof(fr_value_box_list_t), \
	fr_value_box_list_t *		: sizeof(fr_value_box_list_t), \
	default				: 0 \
)

#define FR_CALL_ENV_RESULT_TYPE_NAME(_s, _f) \
_Generic((((_s *)NULL)->_f), \
	fr_value_box_t			: "fr_value_box_t", \
	fr_value_box_t *		: "fr_value_box_t", \
	fr_value_box_list_t		: "fr_value_box_list_t", \
	fr_value_box_list_t *		: "fr_value_box_list_t", \
	default				: NULL \
)

typedef void _mismatch_flags;		//!< Dummy type used to indicate bad flags.

#define CALL_ENV_FLAGS(_cast_type, _flags, _struct, _field) \
	(FR_CALL_ENV_CONCAT(((_flags) & CALL_ENV_FLAG_CONCAT), _cast_type) | \
			FR_CALL_ENV_SINGLE(_struct, _field, ((_flags) & CALL_ENV_FLAG_CONCAT)) | \
			FR_CALL_ENV_MULTI(_struct, _field) |\
			((_flags) & ~CALL_ENV_FLAG_CONCAT)) \

/** Specify a call_env_parser_t which writes out runtime results to the specified field
 *
 * @param[in] _name		of the conf pair to parse.
 * @param[in] _cast_type	Cast any value boxes produced to this type.
 * @param[in] _flags		controlling parser behaviour.
 * @param[in] _struct		which contains the field to write the result of the evaluation phase to.
 * @param[in] _field		where to write the result.
 */
#define FR_CALL_ENV_OFFSET(_name, _cast_type, _flags, _struct, _field) \
	.name = _name, \
	.flags = CALL_ENV_FLAGS(_cast_type, _flags, _struct, _field), \
	.pair = { \
		.cast_type = _cast_type, \
		.type = FR_CALL_ENV_DST_TYPE(_struct, _field), \
		.size = FR_CALL_ENV_DST_SIZE(_struct, _field), \
		.type_name = FR_CALL_ENV_RESULT_TYPE_NAME(_struct, _field), \
		.offset = offsetof(_struct, _field), \
		.parsed = { \
			.offset = -1, \
			.type = CALL_ENV_PARSE_TYPE_TMPL \
		} \
	}

/** Specify a call_env_parser_t which writes out runtime results and the result of the parsing phase to the fields specified
 *
 * @param[in] _name		of the conf pair to parse.
 * @param[in] _cast_type	Cast any value boxes produced to this type.
 * @param[in] _flags		controlling parser behaviour.
 * @param[in] _struct		which contains the field to write the result of the evaluation phase to.
 * @param[in] _field		where to write the result.
 * @param[in] _parse_field	where to write the result of the parsing phase.
 *				This must be a field in the specified _struct.
 */
#define FR_CALL_ENV_PARSE_OFFSET(_name, _cast_type, _flags, _struct, _field, _parse_field) \
	.name = _name, \
	.flags = CALL_ENV_FLAGS(_cast_type, _flags, _struct, _field), \
	.pair = { \
		.cast_type = _cast_type, \
		.type = FR_CALL_ENV_DST_TYPE(_struct, _field), \
		.size = FR_CALL_ENV_DST_SIZE(_struct, _field), \
		.type_name = FR_CALL_ENV_RESULT_TYPE_NAME(_struct, _field), \
		.offset = offsetof(_struct, _field), \
		.parsed = { \
			.offset = offsetof(_struct, _parse_field), \
			.type = CALL_ENV_PARSE_TYPE(_struct, _parse_field) \
		} \
	}

/** Specify a call_env_parser_t which writes out the result of the parsing phase to the field specified
 *
 * @param[in] _name		of the conf pair to parse.
 * @param[in] _cast_type	Sets the cast used by the tmpl.
 * @param[in] _flags		controlling parser behaviour.
 * @param[in] _struct		which contains the field to write the result of the evaluation phase to.
 * @param[in] _parse_field	where to write the result of the parsing phase.
 *				This must be a field in the specified _struct.
 */
#define FR_CALL_ENV_PARSE_ONLY_OFFSET(_name, _cast_type, _flags, _struct, _parse_field) \
	.name = _name, \
	.flags = (_flags) | CALL_ENV_FLAG_PARSE_ONLY, \
	.pair = { \
		.cast_type = _cast_type, \
		.parsed = { \
			.offset = offsetof(_struct, _parse_field), \
			.type = CALL_ENV_PARSE_TYPE(_struct, _parse_field) \
		} \
	}

/** Specify a call_env_parser_t which defines a nested subsection
 */
#define FR_CALL_ENV_SUBSECTION(_name, _name2, _flags, _subcs ) \
	.name = _name, \
	.flags = CALL_ENV_FLAG_SUBSECTION | (_flags), \
	.section = { \
		.name2 = _name2, \
		.subcs = _subcs, \
	}

/** Specify a call_env_parser_t which parses a subsection using a callback function
 */
#define FR_CALL_ENV_SUBSECTION_FUNC(_name, _name2, _flags, _func) \
	.name = _name, \
	.flags = CALL_ENV_FLAG_SUBSECTION | (_flags), \
	.section = { \
		.name2 = _name2, \
		.func = _func \
	}

/** @name Expand a call_env_t
 * @{
 */
unlang_action_t call_env_expand(TALLOC_CTX *ctx, request_t *request, call_env_result_t *result, void **env_data, call_env_t const *call_env);
/** @} */

/** @name Functions that implement standard parsing behaviour which can be called by callbacks
 * @{
 */
int call_env_parse_pair(TALLOC_CTX *ctx, void *out, tmpl_rules_t const *t_rules, CONF_ITEM *ci,
			call_env_ctx_t const *cec, call_env_parser_t const *rule);
/** @} */

/** @name Functions to be used by the section callbacks to add parsed data.
 * @{
 */
call_env_parsed_t *call_env_parsed_add(TALLOC_CTX *ctx, call_env_parsed_head_t *head, call_env_parser_t const *rule);

void call_env_parsed_set_tmpl(call_env_parsed_t *parsed, tmpl_t const *tmpl);

void call_env_parsed_set_value(call_env_parsed_t *parsed, fr_value_box_t const *vb);

void call_env_parsed_set_data(call_env_parsed_t *parsed, void const *data);

void call_env_parsed_set_multi_index(call_env_parsed_t *parsed, size_t count, size_t index);

void call_env_parsed_free(call_env_parsed_head_t *parsed, call_env_parsed_t *ptr);
/** @} */

/** @name Allocate a new call env
 * @{
 */
call_env_t *call_env_alloc(TALLOC_CTX *ctx, char const *name, call_env_method_t const *call_env_method,
			   tmpl_rules_t const *rules, CONF_SECTION *cs, call_env_ctx_t const *cec) CC_HINT(nonnull(3,4,5));
/** @} */

#ifdef __cplusplus
}
#endif
