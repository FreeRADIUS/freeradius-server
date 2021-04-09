/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Parse dictionary files
 *
 * @file src/lib/util/dict_tokenize.c
 *
 * @copyright 2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/radius/defs.h>
#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/dict_fixup_priv.h>
#include <freeradius-devel/util/dict_priv.h>
#include <freeradius-devel/util/file.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/talloc.h>

#include <sys/stat.h>
#include <ctype.h>

#define MAX_ARGV (16)

/** Parser context for dict_from_file
 *
 * Allows vendor and TLV context to persist across $INCLUDEs
 */
#define MAX_STACK (32)
typedef struct {
	fr_dict_t		*dict;			//!< The dictionary before the current BEGIN-PROTOCOL block.
	char			*filename;		//!< name of the file we're reading
	int			line;			//!< line number of this file
	fr_dict_attr_t const	*da;			//!< the da we care about
	fr_type_t		nest;			//!< for manual vs automatic begin / end things
	int			member_num;		//!< structure member numbers
	ssize_t			struct_size;		//!< size of the struct.
} dict_tokenize_frame_t;

typedef struct {
	fr_dict_t		*dict;			//!< Protocol dictionary we're inserting attributes into.

	dict_tokenize_frame_t	stack[MAX_STACK];     	//!< stack of attributes to track
	int			stack_depth;		//!< points to the last used stack frame

	fr_dict_attr_t		*value_attr;		//!< Cache of last attribute to speed up
							///< value processing.
	fr_dict_attr_t const   	*relative_attr;		//!< for ".82" instead of "1.2.3.82".
							///< only for parents of type "tlv"
	dict_fixup_ctx_t	fixup;
} dict_tokenize_ctx_t;

#define CURRENT_FRAME(_dctx)	(&(_dctx)->stack[(_dctx)->stack_depth])

/*
 *	String split routine.  Splits an input string IN PLACE
 *	into pieces, based on spaces.
 */
int fr_dict_str_to_argv(char *str, char **argv, int max_argc)
{
	int argc = 0;

	while (*str) {
		if (argc >= max_argc) break;

		/*
		 *	Chop out comments early.
		 */
		if (*str == '#') {
			*str = '\0';
			break;
		}

		while ((*str == ' ') ||
		       (*str == '\t') ||
		       (*str == '\r') ||
		       (*str == '\n'))
			*(str++) = '\0';

		if (!*str) break;

		argv[argc] = str;
		argc++;

		while (*str &&
		       (*str != ' ') &&
		       (*str != '\t') &&
		       (*str != '\r') &&
		       (*str != '\n'))
			str++;
	}

	return argc;
}

static int dict_read_sscanf_i(unsigned int *pvalue, char const *str)
{
	int ret = 0;
	int base = 10;
	static char const *tab = "0123456789";

	if ((str[0] == '0') &&
	    ((str[1] == 'x') || (str[1] == 'X'))) {
		tab = "0123456789abcdef";
		base = 16;

		str += 2;
	}

	while (*str) {
		char const *c;

		if (*str == '.') break;

		c = memchr(tab, tolower((int)*str), base);
		if (!c) return 0;

		ret *= base;
		ret += (c - tab);
		str++;
	}

	*pvalue = ret;
	return 1;
}

/** Set a new root dictionary attribute
 *
 * @note Must only be called once per dictionary.
 *
 * @param[in] dict		to modify.
 * @param[in] name		of dictionary root.
 * @param[in] proto_number	The artificial (or IANA allocated) number for the protocol.
 *				This is only used for
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int dict_root_set(fr_dict_t *dict, char const *name, unsigned int proto_number)
{
	fr_dict_attr_t *da;

	fr_dict_attr_flags_t flags = {
		.is_root = 1,
		.type_size = 1,
		.length = 1
	};

	if (!fr_cond_assert(!dict->root)) {
		fr_strerror_const("Dictionary root already set");
		return -1;
	}

	da = dict_attr_alloc(dict->pool, NULL, name, proto_number, FR_TYPE_TLV, &flags);
	if (unlikely(!da)) return -1;

	dict->root = da;
	dict->root->dict = dict;
	DA_VERIFY(dict->root);

	return 0;
}

static int dict_process_type_field(dict_tokenize_ctx_t *ctx, char const *name, fr_type_t *type_p,
				   fr_dict_attr_flags_t *flags)
{
	char *p;
	fr_type_t type;

	/*
	 *	Some types can have fixed length
	 */
	p = strchr(name, '[');
	if (p) {
		char *q;
		unsigned int length;

		*p = '\0';
		q = strchr(p + 1, ']');
		if (!q) {
			fr_strerror_printf("Invalid format for '%s[...]'", name);
			return -1;
		}

		*q = '\0';

		if (!dict_read_sscanf_i(&length, p + 1)) {
			fr_strerror_printf("Invalid length for '%s[...]'", name);
			return -1;
		}

		/*
		 *	"length" has to fit into a uint8_t field.
		 */
		if ((length == 0) || (length > 255)) {
			fr_strerror_printf("Invalid length for '%s[...]'", name);
			return -1;
		}

		/*
		 *	Now that we have a length, check the data type.
		 */
		if (strcmp(name, "octets") == 0) {
			type = FR_TYPE_OCTETS;

		} else if (strcmp(name, "string") == 0) {
			type = FR_TYPE_STRING;

		} else if (strcmp(name, "struct") == 0) {
			type = FR_TYPE_STRUCT;

		} else if (strcmp(name, "bit") == 0) {
			if (ctx->stack[ctx->stack_depth].da->type != FR_TYPE_STRUCT) {
				fr_strerror_const("Bit fields can only be used inside of a STRUCT");
				return -1;
			}

			flags->extra = 1;
			flags->subtype = FLAG_BIT_FIELD;

			if (length == 1) {
				type = FR_TYPE_BOOL;
			} else if (length < 8) {
				type = FR_TYPE_UINT8;
			} else if (length < 16) {
				type = FR_TYPE_UINT16;
			} else if (length < 32) {
				type = FR_TYPE_UINT32;
			} else if (length < 56) { /* for laziness in encode / decode */
				type = FR_TYPE_UINT64;
			} else {
				fr_strerror_const("Invalid length for bit field");
				return -1;
			}

			/*
			 *	Cache where on a byte boundary this
			 *	bit field ends.  We could have the
			 *	validation function loop through all
			 *	previous siblings, but that's
			 *	annoying.
			 */
			flags->flag_byte_offset = length;

		} else {
			fr_strerror_const("Only 'octets' types can have a 'length' parameter");
			return -1;
		}

		flags->length = length;
		*type_p = type;
		return 0;
	}

	/*
	 *	find the type of the attribute.
	 */
	type = fr_table_value_by_str(fr_value_box_type_table, name, FR_TYPE_NULL);
	if (fr_type_is_null(type)) {
		fr_strerror_printf("Unknown data type '%s'", name);
		return -1;
	}

	*type_p = type;
	return 0;
}

static int dict_process_flag_field(dict_tokenize_ctx_t *ctx, char *name, fr_type_t type, fr_dict_attr_flags_t *flags,
				   char **ref)
{
	char *p, *next = NULL;

	if (ref) *ref = NULL;

	for (p = name; p && *p != '\0' ; p = next) {
		char *key, *value;

		key = p;

		/*
		 *	Allow for "key1,key2".  But is has to be the
		 *	last string in the flags field.
		 */
		if (ctx->dict->subtype_table) {
			int subtype;

			subtype = fr_table_value_by_str(ctx->dict->subtype_table, key, -1);
			if (subtype >= 0) {
				if (flags->subtype != 0) {
					fr_strerror_printf("Conflicting flag '%s'", key);
					return -1;
				}

				flags->subtype = subtype;
				break;
			}
		}


		/*
		 *	Search for the first '=' or ','
		 */
		for (next = p + 1; *next && (*next != '=') && (*next != ','); next++) {
			/* do nothing */
		}

		/*
		 *	We have a value, zero out the '=' and point to the value.
		 */
		if (*next == '=') {
			*(next++) = '\0';
			value = next;

			if (!*value || (*value == ',')) {
				fr_strerror_printf("Missing value after '%s='", key);
				return -1;
			}
		} else {
			value = NULL;
		}

		/*
		 *	Skip any trailing text in the value.
		 */
		for (/* nothing */; *next; next++) {
			if (*next == ',') {
				*(next++) = '\0';
				break;
			}
		}

		/*
		 *	Marks the attribute up as internal.
		 *	This means it can use numbers outside of the allowed
		 *	protocol range, and also means it will not be included
		 *	in replies or proxy requests.
		 */
		if (strcmp(key, "internal") == 0) {
			flags->internal = 1;

		} else if (strcmp(key, "array") == 0) {
			flags->array = 1;

		} else if (strcmp(key, "virtual") == 0) {
			flags->virtual = 1;

		} else if (strcmp(key, "key") == 0) {
			if ((type != FR_TYPE_UINT8) && (type != FR_TYPE_UINT16) && (type != FR_TYPE_UINT32)) {
				fr_strerror_const("The 'key' flag can only be used for attributes of type 'uint8', 'uint16', or 'uint32'");
				return -1;
			}

			if (flags->extra) {
				fr_strerror_const("Bit fields cannot be key fields");
				return -1;
			}

			flags->extra = 1;
			flags->subtype = FLAG_KEY_FIELD;

		} else if (strcmp(key, "length") == 0) {
			if (!value || (strcmp(value, "uint16") != 0)) {
				fr_strerror_const("The 'length' flag can only be used with value 'uint16'");
			}

			flags->extra = 1;
			flags->subtype = FLAG_LENGTH_UINT16;

		} else if ((type == FR_TYPE_DATE) || (type == FR_TYPE_TIME_DELTA)) {
			flags->length = 4;
			flags->flag_time_res = FR_TIME_RES_SEC;

			if (strncmp(key, "uint", 4) == 0) {
				fr_type_t subtype;

				subtype = fr_table_value_by_str(fr_value_box_type_table, name, FR_TYPE_NULL);
				if (fr_type_is_null(subtype)) {
				unknown_type:
					fr_strerror_printf("Unknown or unsupported %s type '%s'",
							   fr_table_str_by_value(fr_value_box_type_table, type, "<UNKNOWN>"),
							   key);
					return -1;
				}

				switch (subtype) {
					default:
						goto unknown_type;

				case FR_TYPE_INT16:
					if (type == FR_TYPE_DATE) goto unknown_type;
					FALL_THROUGH;

				case FR_TYPE_UINT16:
					flags->length = 2;
					break;

				case FR_TYPE_INT32:
					if (type == FR_TYPE_DATE) goto unknown_type;
					FALL_THROUGH;

				case FR_TYPE_UINT32:
					flags->length = 4;
					break;

				case FR_TYPE_INT64:
					if (type == FR_TYPE_DATE) goto unknown_type;
					FALL_THROUGH;

				case FR_TYPE_UINT64:
					flags->length = 8;
					break;
				}
			} else {
				int precision;

				precision = fr_table_value_by_str(date_precision_table, key, -1);
				if (precision < 0) {
					fr_strerror_printf("Unknown %s precision '%s'",
							   fr_table_str_by_value(fr_value_box_type_table, type, "<UNKNOWN>"),
							   key);
					return -1;
				}
				flags->flag_time_res = precision;
			}

		} else if (strcmp(key, "ref") == 0) {
			if (!value) {
				fr_strerror_const("Missing attribute name for 'ref=...'");
				return -1;
			}

			if (flags->extra) {
				fr_strerror_const("Cannot use 'ref' with other flags");
				return -1;
			}

			if (type != FR_TYPE_GROUP) {
				fr_strerror_printf("The 'ref' flag cannot be used for type '%s'",
						   fr_table_str_by_value(fr_value_box_type_table, type, "<UNKNOWN>"));
				return -1;
			}

			*ref = talloc_strdup(ctx->fixup.pool, value);

		} else if (strcmp(key, "clone") == 0) {
			if (!value) {
				fr_strerror_const("Missing attribute name for 'clone=...'");
				return -1;
			}

			if ((type != FR_TYPE_TLV) && (type != FR_TYPE_STRUCT) &&
			    !(flags->extra && (flags->subtype == FLAG_KEY_FIELD))) {
				fr_strerror_printf("The 'clone' flag cannot be used for type '%s'",
						   fr_table_str_by_value(fr_value_box_type_table, type, "<UNKNOWN>"));
				return -1;
			}

			*ref = talloc_strdup(ctx->fixup.pool, value);

		} else if (ctx->dict->subtype_table) {
			int subtype;

			if (value) value[-1] = '='; /* hackity hack */

			/*
			 *	Protocol should use strings
			 *	"key1,key2" to allow for multiple
			 *	flags.
			 */
			if (flags->extra || flags->subtype) {
				fr_strerror_printf("Cannot add flag '%s' - another flag is already set",
						   key);
				return -1;
			}

			subtype = fr_table_value_by_str(ctx->dict->subtype_table, key, -1);
			if (subtype < 0) goto unknown_option;

			flags->subtype = subtype;

		} else {
		unknown_option:
			fr_strerror_printf("Unknown option '%s'", key);
			return -1;
		}
	}

	/*
	 *	Check that the flags are valid.
	 */
	if (!dict_attr_flags_valid(ctx->dict, ctx->stack[ctx->stack_depth].da, name, NULL, type, flags)) return -1;

	return 0;
}


static int dict_gctx_push(dict_tokenize_ctx_t *ctx, fr_dict_attr_t const *da)
{
	if ((ctx->stack_depth + 1) >= MAX_STACK) {
		fr_strerror_const_push("Attribute definitions are nested too deep.");
		return -1;
	}

	ctx->stack_depth++;
	memset(&ctx->stack[ctx->stack_depth], 0, sizeof(ctx->stack[ctx->stack_depth]));

	ctx->stack[ctx->stack_depth].dict = ctx->stack[ctx->stack_depth - 1].dict;
	ctx->stack[ctx->stack_depth].da = da;
	ctx->stack[ctx->stack_depth].filename = ctx->stack[ctx->stack_depth - 1].filename;
	ctx->stack[ctx->stack_depth].line = ctx->stack[ctx->stack_depth - 1].line;

	return 0;
}

static fr_dict_attr_t const *dict_gctx_unwind(dict_tokenize_ctx_t *ctx)
{
	while ((ctx->stack_depth > 0) &&
	       (ctx->stack[ctx->stack_depth].nest == FR_TYPE_NULL)) {
		ctx->stack_depth--;
	}

	return ctx->stack[ctx->stack_depth].da;
}

/*
 *	Process the ALIAS command
 *
 *	ALIAS name ref
 *
 *	Creates an attribute "name" in the root namespace of the current
 *	dictionary, which is a pointer to "ref".
 */
static int dict_read_process_alias(dict_tokenize_ctx_t *ctx, char **argv, int argc)
{
	fr_dict_attr_t const	*da;
	fr_dict_attr_t 		*self;
	fr_dict_attr_t const	*parent = ctx->dict->root;
	fr_hash_table_t		*namespace;

	if (argc != 2) {
		fr_strerror_const("Invalid ALIAS syntax");
		return -1;
	}

	/*
	 *	Dictionaries need to have real names, not shitty ones.
	 */
	if (strncmp(argv[0], "Attr-", 5) == 0) {
		fr_strerror_const("Invalid ALIAS name");
		return -1;
	}

	da = dict_attr_by_name(NULL, parent, argv[0]);
	if (da) {
		fr_strerror_printf("ALIAS '%s' conflicts with another attribute in namespace %s",
				   argv[0], parent->name);
		return -1;
	}

	/*
	 *	The <ref> can be a name.
	 *
	 *	Note that we don't do fixups here.  ALIASes MUST point
	 *	to attributes which exist.
	 */
	da = fr_dict_attr_by_oid(NULL, parent, argv[1]);
	if (!da) {
		fr_strerror_printf("Attribute %s does not exist in dictionary %s", argv[1], parent->name);
		return -1;

	}

	if (fr_dict_attr_ref(da)) {
		fr_strerror_const("An ALIAS MUST NOT refer to an ATTRIBUTE which also has 'ref=...'");
		return -1;
	}

	/*
	 *	Note that we do NOT call fr_dict_attr_add() here.
	 *
	 *	When that function adds two equivalent attributes, the
	 *	second one is prioritized for printing.  For ALIASes,
	 *	we want the pre-existing one to be prioritized.
	 *
	 *	i.e. you can lookup the ALIAS by "name", but you
	 *	actually get returned "ref".
	 */
	self = dict_attr_alloc(ctx->dict->pool, parent, argv[0], da->attr, da->type, &da->flags);
	if (unlikely(!self)) return -1;

	self->dict = ctx->dict;
	dict_attr_ref_set(self, da);

	namespace = dict_attr_namespace(parent);
	if (!namespace) {
		fr_strerror_printf("Attribute '%s' does not contain a namespace", parent->name);
	error:
		talloc_const_free(da);
		return -1;
	}

	if (!fr_hash_table_insert(namespace, self)) {
		fr_strerror_const("Internal error storing attribute");
		goto error;
	}

	return 0;
}

/*
 *	Process the ATTRIBUTE command
 */
static int dict_read_process_attribute(dict_tokenize_ctx_t *ctx, char **argv, int argc,
				       fr_dict_attr_flags_t *base_flags)
{
	bool			set_relative_attr = true;

	ssize_t			slen;
	unsigned int		attr;

	fr_type_t      		type;
	fr_dict_attr_flags_t	flags;
	fr_dict_attr_t const	*parent, *da;
	char			*ref = NULL;

	if ((argc < 3) || (argc > 4)) {
		fr_strerror_const("Invalid ATTRIBUTE syntax");
		return -1;
	}

	/*
	 *	Dictionaries need to have real names, not shitty ones.
	 */
	if (strncmp(argv[0], "Attr-", 5) == 0) {
		fr_strerror_const("Invalid ATTRIBUTE name");
		return -1;
	}

	memcpy(&flags, base_flags, sizeof(flags));

	if (dict_process_type_field(ctx, argv[2], &type, &flags) < 0) return -1;

	if (flags.extra && (flags.subtype == FLAG_BIT_FIELD)) {
		fr_strerror_const("Bit fields can only be defined as a MEMBER of a STRUCT");
		return -1;
	}

	/*
	 *	Relative OIDs apply ONLY to attributes of type 'tlv'.
	 */
	if (type != FR_TYPE_TLV) set_relative_attr = false;

	/*
	 *	A non-relative ATTRIBUTE definition means that it is
	 *	in the context of the previous BEGIN-FOO.  So we
	 *	unwind the stack to match.
	 */
	if (argv[1][0] != '.') {
		parent = dict_gctx_unwind(ctx);

		/*
		 *	Allow '0xff00' as attribute numbers, but only
		 *	if there is no OID component.
		 */
		if (strchr(argv[1], '.') == 0) {
			if (!dict_read_sscanf_i(&attr, argv[1])) {
				fr_strerror_const("Invalid ATTRIBUTE number");
				return -1;
			}

		} else {
			slen = fr_dict_attr_by_oid_legacy(ctx->dict, &parent, &attr, argv[1]);
			if (slen <= 0) return -1;
		}

	} else {
		if (!ctx->relative_attr) {
			fr_strerror_const("Unknown parent for partial OID");
			return -1;
		}

		parent = ctx->relative_attr;
		set_relative_attr = false;

		slen = fr_dict_attr_by_oid_legacy(ctx->dict, &parent, &attr, argv[1]);
		if (slen <= 0) return -1;
	}

	if (!fr_cond_assert(parent)) return -1;	/* Should have provided us with a parent */

	/*
	 *	Members of a 'struct' MUST use MEMBER, not ATTRIBUTE.
	 */
	if (parent->type == FR_TYPE_STRUCT) {
		fr_strerror_printf("Member %s of ATTRIBUTE %s type 'struct' MUST use the \"MEMBER\" keyword",
				   argv[0], parent->name);
		return -1;
	}

	/*
	 *	Parse options.
	 */
	if (argc >= 4) {
		if (dict_process_flag_field(ctx, argv[3], type, &flags, &ref) < 0) return -1;
	} else {
		if (!dict_attr_flags_valid(ctx->dict, parent, argv[3], NULL, type, &flags)) return -1;
	}

#ifdef WITH_DICTIONARY_WARNINGS
	/*
	 *	Hack to help us discover which vendors have illegal
	 *	attributes.
	 */
	if (!vendor && (attr < 256) &&
	    !strstr(fn, "rfc") && !strstr(fn, "illegal")) {
		fprintf(stderr, "WARNING: Illegal Attribute %s in %s\n",
			argv[0], fn);
	}
#endif

#ifdef __clang_analyzer__
	if (!ctx->dict) return -1;
#endif

	/*
	 *	Dynamically define where VSAs go.  Note that we CANNOT
	 *	define VSAs until we define an attribute of type VSA!
	 */
	if ((type == FR_TYPE_VSA) && (parent->flags.is_root)) {
		ctx->dict->vsa_parent = attr;
	}

	/*
	 *	Add in an attribute
	 */
	if (fr_dict_attr_add(ctx->dict, parent, argv[0], attr, type, &flags) < 0) return -1;

	/*
	 *	If we need to set the previous attribute, we have to
	 *	look it up by number.  This lets us set the
	 *	*canonical* previous attribute, and not any potential
	 *	duplicate which was just added.
	 */
	da = dict_attr_child_by_num(parent, attr);
	if (!da) {
		fr_strerror_printf("Failed to find attribute '%s' we just added.", argv[0]);
		return -1;
	}

#ifndef NDEBUG
	if (!dict_attr_by_name(NULL, parent, argv[0])) {
		fr_strerror_printf("Failed to find attribute '%s' we just added.", argv[0]);
		return -1;
	}
#endif

	if (set_relative_attr) ctx->relative_attr = da;

	/*
	 *	Groups can refer to other dictionaries, or other attributes.
	 */
	if (type == FR_TYPE_GROUP) {
		fr_dict_attr_t		*self;
		fr_dict_t		*dict;
		char			*p;

		memcpy(&self, &da, sizeof(self)); /* const issues */

		/*
		 *	No qualifiers, just point it to the root of the current dictionary.
		 */
		if (!ref) {
			dict = ctx->dict;
			da = ctx->dict->root;
			goto check;
		}

		da = fr_dict_attr_by_oid(NULL, parent, ref);
		if (da) {
			dict = ctx->dict;
			goto check;
		}

		/*
		 *	The attribute doesn't exist, and the reference
		 *	is FOO, it might be just a ref to a
		 *	dictionary.
		 */
		p = strchr(ref, '.');
		if (!p) goto save;

		/*
		 *	Get / skip protocol name.
		 */
		slen = dict_by_protocol_substr(NULL, &dict, &FR_SBUFF_IN(ref, strlen(ref)), ctx->dict);
		if (slen < 0) {
			talloc_free(ref);
			return -1;
		}

		/*
		 *	No known dictionary, so we're asked to just
		 *	use the whole string.  Which we did above.  So
		 *	either it's a bad ref, OR it's a ref to a
		 *	dictionary which doesn't exist.
		 */
		if (slen == 0) {
		save:
			if (dict_fixup_group(&ctx->fixup, CURRENT_FRAME(ctx)->filename, CURRENT_FRAME(ctx)->line,
					     self, ref, talloc_array_length(ref) - 1) < 0) {
			oom:
				talloc_free(ref);
				return -1;
			}
			talloc_free(ref);

			return 0;

		} else if (ref[slen] == '\0') {
			da = dict->root;
			goto check;

		} else {
			/*
			 *	Look up the attribute.
			 */
			da = fr_dict_attr_by_oid(NULL, parent, ref + slen);
			if (!da) {
				fr_strerror_printf("protocol loaded, but no attribute '%s'", ref + slen);
				talloc_free(ref);
				return -1;
			}

		check:
			if (fr_dict_attr_ref(da)) {
				fr_strerror_const("References MUST NOT refer to an ATTRIBUTE which also has 'ref=...'");
				talloc_free(ref);
				return -1;
			}

			talloc_free(ref);
			self->dict = dict;

			dict_attr_ref_set(self, da);
		}
	}

	/*
	 *	It's a "clone" thing.
	 */
	if (ref) {
		if (dict_fixup_clone(&ctx->fixup, CURRENT_FRAME(ctx)->filename, CURRENT_FRAME(ctx)->line,
				     fr_dict_attr_unconst(parent), fr_dict_attr_unconst(da),
				     ref, talloc_array_length(ref) - 1) < 0) goto oom;
		talloc_free(ref);
		return 0;
	}

	/*
	 *	Adding an attribute of type 'struct' is an implicit
	 *	BEGIN-STRUCT.
	 */
	if (type == FR_TYPE_STRUCT) {
		if (dict_gctx_push(ctx, da) < 0) return -1;
		ctx->value_attr = NULL;
	} else {
		memcpy(&ctx->value_attr, &da, sizeof(da));
	}

	return 0;
}


/*
 *	Process the MEMBER command
 */
static int dict_read_process_member(dict_tokenize_ctx_t *ctx, char **argv, int argc,
				       fr_dict_attr_flags_t *base_flags)
{
	fr_type_t      		type;
	fr_dict_attr_flags_t	flags;
	char			*ref = NULL;

	if ((argc < 2) || (argc > 3)) {
		fr_strerror_const("Invalid MEMBER syntax");
		return -1;
	}

	if (ctx->stack[ctx->stack_depth].da->type != FR_TYPE_STRUCT) {
		fr_strerror_const("MEMBER can only be used for ATTRIBUTEs of type 'struct'");
		return -1;
	}

	/*
	 *	Dictionaries need to have real names, not shitty ones.
	 */
	if (strncmp(argv[0], "Attr-", 5) == 0) {
		fr_strerror_const("Invalid MEMBER name");
		return -1;
	}

	memcpy(&flags, base_flags, sizeof(flags));

	if (dict_process_type_field(ctx, argv[1], &type, &flags) < 0) return -1;

	/*
	 *	Parse options.
	 */
	if (argc >= 3) {
		if (dict_process_flag_field(ctx, argv[2], type, &flags, &ref) < 0) return -1;

		if (ref && (type != FR_TYPE_TLV) && !(flags.extra && (flags.subtype == FLAG_KEY_FIELD))) {
			fr_strerror_const("Only MEMBERs of type 'tlv' or with 'key' flags can have references");\
			return -1;
		}

	} else {
		if (!dict_attr_flags_valid(ctx->dict, ctx->stack[ctx->stack_depth].da, argv[2], NULL, type, &flags)) return -1;
	}

#ifdef __clang_analyzer__
	if (!ctx->dict) return -1;
#endif

	/*
	 *	Double check bit field magic
	 */
	if (ctx->stack[ctx->stack_depth].member_num > 0) {
		fr_dict_attr_t const *previous;

		previous = dict_attr_child_by_num(ctx->stack[ctx->stack_depth].da,
						  ctx->stack[ctx->stack_depth].member_num);
		if (!previous) {
			fr_strerror_const("Failed to find previous MEMBER");
			return -1;
		}

		/*
		 *	Check that the previous bit field ended on a
		 *	byte boundary.
		 */
		if (previous->flags.extra && (previous->flags.subtype == FLAG_BIT_FIELD)) {
			/*
			 *	This attribute is a bit field.  Keep
			 *	track of where in the byte we are
			 *	located.
			 */
			if (flags.extra && (flags.subtype == FLAG_BIT_FIELD)) {
				flags.flag_byte_offset = (flags.length + previous->flags.flag_byte_offset) & 0x07;

			} else {
				if (previous->flags.flag_byte_offset != 0) {
					fr_strerror_printf("Previous bitfield %s did not end on a byte boundary",
							   previous->name);
					return -1;
				}
			}
		}
	}

	/*
	 *	Check if the parent 'struct' is fixed size.  And if
	 *	so, complain if we're adding a variable sized member.
	 */
	if (ctx->stack[ctx->stack_depth].da->flags.length &&
	    ((type == FR_TYPE_STRING) || (type == FR_TYPE_TLV) ||
	     ((type == FR_TYPE_OCTETS) && !flags.length))) {
		fr_strerror_printf("'struct' %s has fixed size %u, we cannot add a variable-sized member.",
				   ctx->stack[ctx->stack_depth].da->name, ctx->stack[ctx->stack_depth].da->flags.length);
		return -1;
	}

	/*
	 *	Ensure that no previous child has "key" or "length" set.
	 */
	if (type == FR_TYPE_TLV) {
		int i;

		for (i = 0; i <= ctx->stack[ctx->stack_depth].member_num; i++) {
			fr_dict_attr_t const *da;

			da = dict_attr_child_by_num(ctx->stack[ctx->stack_depth].da, i);
			if (!da) continue; /* really should be WTF? */

			if (fr_dict_attr_is_key_field(da)) {
				fr_strerror_printf("'struct' %s has a 'key' field %s, and cannot end with a TLV %s",
						   ctx->stack[ctx->stack_depth].da->name, da->name, argv[0]);
				return -1;
			}

			if (da_is_length_field(da)) {
				fr_strerror_printf("'struct' %s has a 'length' field %s, and cannot end with a TLV %s",
						   ctx->stack[ctx->stack_depth].da->name, da->name, argv[0]);
				return -1;
			}
		}
	}

	/*
	 *	Add the MEMBER to the parent.
	 */
	if (fr_dict_attr_add(ctx->dict,
			     ctx->stack[ctx->stack_depth].da,
			     argv[0],
			     ++ctx->stack[ctx->stack_depth].member_num,
			     type, &flags) < 0) return -1;

	/*
	 *	A 'struct' can have a MEMBER of type 'tlv', but ONLY
	 *	as the last entry in the 'struct'.  If we see that,
	 *	set the previous attribute to the TLV we just added.
	 *	This allows the children of the TLV to be parsed as
	 *	partial OIDs, so we don't need to know the full path
	 *	to them.
	 */
	if (type == FR_TYPE_TLV) {
		ctx->relative_attr = dict_attr_child_by_num(ctx->stack[ctx->stack_depth].da,
							    ctx->stack[ctx->stack_depth].member_num);
		if (dict_gctx_push(ctx, ctx->relative_attr) < 0) return -1;

	} else {

		/*
		 *	Add the size of this member to the parent struct.
		 */
		ctx->stack[ctx->stack_depth].struct_size += flags.length;

		/*
		 *	Check for overflow.
		 */
		if (ctx->stack[ctx->stack_depth].da->flags.length &&
		    (ctx->stack[ctx->stack_depth].struct_size > ctx->stack[ctx->stack_depth].da->flags.length)) {
			fr_strerror_printf("'struct' %s has fixed size %u, but member %s overflows that length",
					   ctx->stack[ctx->stack_depth].da->name, ctx->stack[ctx->stack_depth].da->flags.length,
					   argv[0]);
			return -1;
		}
	}

	if (ref) {
		int ret;

		ret = dict_fixup_clone(&ctx->fixup, CURRENT_FRAME(ctx)->filename, CURRENT_FRAME(ctx)->line,
				       fr_dict_attr_unconst(CURRENT_FRAME(ctx)->da),
				       dict_attr_child_by_num(CURRENT_FRAME(ctx)->da, CURRENT_FRAME(ctx)->member_num),
				       ref, talloc_array_length(ref) - 1);
		talloc_free(ref);

		if (ret < 0) return -1;
	}

	return 0;
}


/** Process a value alias
 *
 */
static int dict_read_process_value(dict_tokenize_ctx_t *ctx, char **argv, int argc)
{
	fr_dict_attr_t		*da;
	fr_value_box_t		value;
	fr_dict_attr_t const 	*parent = ctx->stack[ctx->stack_depth].da;

	if (argc != 3) {
		fr_strerror_const("Invalid VALUE syntax");
		return -1;
	}

	/*
	 *	Most VALUEs are bunched together by ATTRIBUTE.  We can
	 *	save a lot of lookups on dictionary initialization by
	 *	caching the last attribute for a VALUE.
	 *
	 *	If it's not the same, we look up the attribute in the
	 *	current context, which is generally:
	 *
	 *	* the current attribute of type `struct`
	 *	* if no `struct`, then the VENDOR for VSAs
	 *	* if no VENDOR, then the dictionary root
	 */
	if (!ctx->value_attr || (strcasecmp(argv[0], ctx->value_attr->name) != 0)) {
		fr_dict_attr_t const *tmp;

		if (!(tmp = fr_dict_attr_by_oid(NULL, parent, argv[0]))) goto fixup;
		ctx->value_attr = fr_dict_attr_unconst(tmp);
	}
	da = ctx->value_attr;

	/*
	 *	Remember which attribute is associated with this
	 *	value.  This allows us to define enum
	 *	values before the attribute exists, and fix them
	 *	up later.
	 */
	if (!da) {
	fixup:
		if (!fr_cond_assert_msg(ctx->fixup.pool, "fixup pool context invalid")) return -1;

		if (dict_fixup_enumv(&ctx->fixup,
				     CURRENT_FRAME(ctx)->filename, CURRENT_FRAME(ctx)->line,
				     argv[0], strlen(argv[0]),
				     argv[1], strlen(argv[1]),
				     argv[2], strlen(argv[2]), parent) < 0) {
			fr_strerror_const("Out of memory");
			return -1;
		}
		return 0;
	}

	/*
	 *	Only a few data types can have VALUEs defined.
	 */
	switch (da->type) {
	case FR_TYPE_STRUCTURAL:
	case FR_TYPE_NULL:
	case FR_TYPE_MAX:
		fr_strerror_printf_push("Cannot define VALUE for Attribute '%s' of data type \"%s\"", da->name,
					fr_table_str_by_value(fr_value_box_type_table, da->type, "<INVALID>"));
		return -1;

	default:
		break;
	}

	if (fr_value_box_from_str(NULL, &value, da->type, NULL, argv[2], -1, '\0', false) < 0) {
		fr_strerror_printf_push("Invalid VALUE for Attribute '%s'", da->name);
		return -1;
	}

	if (fr_dict_enum_add_name(da, argv[1], &value, false, true) < 0) {
		fr_value_box_clear(&value);
		return -1;
	}
	fr_value_box_clear(&value);

	return 0;
}

/*
 *	Process the FLAGS command
 */
static int dict_read_process_flags(UNUSED fr_dict_t *dict, char **argv, int argc,
				   fr_dict_attr_flags_t *base_flags)
{
	bool sense = true;

	if (argc == 1) {
		char *p;

		p = argv[0];
		if (*p == '!') {
			sense = false;
			p++;
		}

		if (strcmp(p, "internal") == 0) {
			base_flags->internal = sense;
			return 0;
		}
	}

	fr_strerror_const("Invalid FLAGS syntax");
	return -1;
}


/** Process a STRUCT name attr value
 *
 * Define struct 'name' when key 'attr' has 'value'.
 *
 *  Which MUST be a sub-structure of another struct
 */
static int dict_read_process_struct(dict_tokenize_ctx_t *ctx, char **argv, int argc)
{
	int				i;
	fr_dict_attr_t const   		*da;
	fr_dict_attr_t const	       	*parent = NULL;
	fr_value_box_t			value;
	unsigned int			attr;
	fr_dict_attr_flags_t		flags;
	char				*key_attr = argv[1];
	char			        *name = argv[0];

	if (argc != 3) {
		fr_strerror_const("Invalid STRUCT syntax");
		return -1;
	}

	fr_assert(ctx->stack_depth > 0);

	/*
	 *	Unwind the stack until we find a parent which has a child named "key_attr"
	 */
	for (i = ctx->stack_depth; i > 0; i--) {
		parent = dict_attr_by_name(NULL, ctx->stack[i].da, key_attr);
		if (parent) {
			ctx->stack_depth = i;
			break;
		}
	}

	/*
	 *	Else maybe it's a fully qualified name?
	 */
	if (!parent) {
		parent = fr_dict_attr_by_oid(NULL, ctx->stack[ctx->stack_depth].da->dict->root, key_attr);
	}

	if (!parent) {
		fr_strerror_printf("Invalid STRUCT definition, unknown key attribute %s",
				   key_attr);
		return -1;
	}

	if (!fr_dict_attr_is_key_field(parent)) {
		fr_strerror_printf("Attribute '%s' is not a 'key' attribute", key_attr);
		return -1;
	}

	/*
	 *	Rely on dict_attr_flags_valid() to ensure that
	 *	da->type is an unsigned integer, AND that da->parent->type == struct
	 */
	if (!fr_cond_assert(parent->parent->type == FR_TYPE_STRUCT)) return -1;

	memset(&flags, 0, sizeof(flags));

	/*
	 *	Parse the value.
	 */
	if (fr_value_box_from_str(NULL, &value, parent->type, NULL, argv[2], -1, '\0', false) < 0) {
		fr_strerror_printf_push("Invalid value for STRUCT \"%s\"", argv[2]);
		return -1;
	}

	/*
	 *	@todo - auto-number from a parent UNION, instead of overloading the value.
	 */
	switch (parent->type) {
	case FR_TYPE_UINT8:
		attr = value.vb_uint8;
		break;

	case FR_TYPE_UINT16:
		attr = value.vb_uint16;
		break;

	case FR_TYPE_UINT32:
		attr = value.vb_uint32;
		break;

	default:
		fr_strerror_printf("Invalid data type in attribute '%s'", key_attr);
		return -1;
	}

	/*
	 *	Add the keyed STRUCT to the global namespace, and as a child of "parent".
	 */
	if (fr_dict_attr_add(ctx->dict, parent, name, attr, FR_TYPE_STRUCT, &flags) < 0) return -1;

	da = dict_attr_by_name(NULL, parent, name);
	if (!da) return -1;

	/*
	 *	A STRUCT definition is an implicit BEGIN-STRUCT.
	 */
	ctx->relative_attr = NULL;
	if (dict_gctx_push(ctx, da) < 0) return -1;

	/*
	 *	Add the VALUE to the parent attribute, and ensure that
	 *	the VALUE also contains a pointer to the child struct.
	 */
	if (dict_attr_enum_add_name(fr_dict_attr_unconst(parent), name, &value, false, true, da) < 0) {
		fr_value_box_clear(&value);
		return -1;
	}
	fr_value_box_clear(&value);

	return 0;
}

static int dict_read_parse_format(char const *format, unsigned int *pvalue, int *ptype, int *plength,
				  bool *pcontinuation)
{
	char const *p;
	int type, length;
	bool continuation = false;

	if (strncasecmp(format, "format=", 7) != 0) {
		fr_strerror_printf("Invalid format for VENDOR.  Expected 'format=', got '%s'",
				   format);
		return -1;
	}

	p = format + 7;
	if ((strlen(p) < 3) ||
	    !isdigit((int)p[0]) ||
	    (p[1] != ',') ||
	    !isdigit((int)p[2]) ||
	    (p[3] && (p[3] != ','))) {
		fr_strerror_printf("Invalid format for VENDOR.  Expected text like '1,1', got '%s'",
				   p);
		return -1;
	}

	type = (int)(p[0] - '0');
	length = (int)(p[2] - '0');

	if ((type != 1) && (type != 2) && (type != 4)) {
		fr_strerror_printf("Invalid type value %d for VENDOR", type);
		return -1;
	}

	if ((length != 0) && (length != 1) && (length != 2)) {
		fr_strerror_printf("Invalid length value %d for VENDOR", length);
		return -1;
	}

	if (p[3] == ',') {
		if (!p[4]) {
			fr_strerror_printf("Invalid format for VENDOR.  Expected text like '1,1', got '%s'",
					   p);
			return -1;
		}

		if ((p[4] != 'c') ||
		    (p[5] != '\0')) {
			fr_strerror_printf("Invalid format for VENDOR.  Expected text like '1,1', got '%s'",
					   p);
			return -1;
		}
		continuation = true;

		if ((*pvalue != VENDORPEC_WIMAX) ||
		    (type != 1) || (length != 1)) {
			fr_strerror_const("Only WiMAX VSAs can have continuations");
			return -1;
		}
	}

	*ptype = type;
	*plength = length;
	*pcontinuation = continuation;
	return 0;
}

/** Register the specified dictionary as a protocol dictionary
 *
 * Allows vendor and TLV context to persist across $INCLUDEs
 */
static int dict_read_process_protocol(char **argv, int argc)
{
	unsigned int	value;
	unsigned int	type_size = 0;
	fr_dict_t	*dict;
	fr_dict_attr_t	*mutable;
	bool		require_dl = false;

	if ((argc < 2) || (argc > 3)) {
		fr_strerror_const("Missing arguments after PROTOCOL.  Expected PROTOCOL <num> <name>");
		return -1;
	}

	/*
	 *	 Validate all entries
	 */
	if (!dict_read_sscanf_i(&value, argv[1])) {
		fr_strerror_printf("Invalid number '%s' following PROTOCOL", argv[1]);
		return -1;
	}

	/*
	 *	255 protocols FR_TYPE_GROUP type_size hack
	 */
	if ((value == 0) || (value > 255)) {
		fr_strerror_printf("Invalid value '%u' following PROTOCOL", value);
		return -1;
	}

	/*
	 *	Look for a format statement.  This may specify the
	 *	type length of the protocol's types.
	 */
	if (argc == 3) {
		char const *p;
		char *q;

		/*
		 *	For now, we don't allow multiple options here.
		 *
		 *	@todo - allow multiple options.
		 */
		if (strcmp(argv[2], "verify=lib") == 0) {
			require_dl = true;
			goto post_option;
		}

		if (strncasecmp(argv[2], "format=", 7) != 0) {
			fr_strerror_printf("Invalid format for PROTOCOL.  Expected 'format=', got '%s'", argv[2]);
			return -1;
		}
		p = argv[2] + 7;

		type_size = strtoul(p, &q, 10);
		if (q != (p + strlen(p))) {
			fr_strerror_printf("Found trailing garbage '%s' after format specifier", p);
			return -1;
		}
	}
post_option:

	/*
	 *	Cross check name / number.
	 */
	dict = dict_by_protocol_name(argv[0]);
	if (dict) {
#ifdef __clang_analyzer__
		if (!dict->root) return -1;
#endif

		if (dict->root->attr != value) {
			fr_strerror_printf("Conflicting numbers %u vs %u for PROTOCOL \"%s\"",
					   dict->root->attr, value, dict->root->name);
			return -1;
		}

	} else if ((dict = dict_by_protocol_num(value)) != NULL) {
#ifdef __clang_analyzer__
		if (!dict->root || !dict->root->name || !argv[0]) return -1;
#endif

		if (strcasecmp(dict->root->name, argv[0]) != 0) {
			fr_strerror_printf("Conflicting names current \"%s\" vs new \"%s\" for PROTOCOL %u",
					   dict->root->name, argv[0], dict->root->attr);
			return -1;
		}
	}

	/*
	 *	And check types no matter what.
	 */
	if (dict) {
		if (type_size && (dict->root->flags.type_size != type_size)) {
			fr_strerror_printf("Conflicting flags for PROTOCOL \"%s\" (current %d versus new %d)",
					   dict->root->name, dict->root->flags.type_size, type_size);
			return -1;
		}
		return 0;
	}

	dict = dict_alloc(dict_gctx);

	/*
	 *	Try to load protocol-specific validation routines.
	 *	Some protocols don't need them, so it's OK if the
	 *	validation routines don't exist.
	 */
	if ((dict_dlopen(dict, argv[0]) < 0) && require_dl) {
	error:
		talloc_free(dict);
		return -1;
	}

	/*
	 *	Set the root attribute with the protocol name
	 */
	if (dict_root_set(dict, argv[0], value) < 0) goto error;

	if (dict_protocol_add(dict) < 0) goto error;

	mutable = UNCONST(fr_dict_attr_t *, dict->root);
	if (!type_size) {
		mutable->flags.type_size = dict->default_type_size;
		mutable->flags.length = dict->default_type_length;
	} else {
		mutable->flags.type_size = type_size;
		mutable->flags.length = 1; /* who knows... */
	}

	return 0;
}

/*
 *	Process the VENDOR command
 */
static int dict_read_process_vendor(fr_dict_t *dict, char **argv, int argc)
{
	unsigned int			value;
	int				type, length;
	bool				continuation = false;
	fr_dict_vendor_t const		*dv;
	fr_dict_vendor_t		*mutable;

	if ((argc < 2) || (argc > 3)) {
		fr_strerror_const("Invalid VENDOR syntax");
		return -1;
	}

	/*
	 *	 Validate all entries
	 */
	if (!dict_read_sscanf_i(&value, argv[1])) {
		fr_strerror_const("Invalid number in VENDOR");
		return -1;
	}

	/*
	 *	Look for a format statement.  Allow it to over-ride the hard-coded formats below.
	 */
	if (argc == 3) {
		if (dict_read_parse_format(argv[2], &value, &type, &length, &continuation) < 0) return -1;

	} else {
		type = length = 1;
	}

	/* Create a new VENDOR entry for the list */
	if (dict_vendor_add(dict, argv[0], value) < 0) return -1;

	dv = fr_dict_vendor_by_num(dict, value);
	if (!dv) {
		fr_strerror_const("Failed adding format for VENDOR");
		return -1;
	}

	mutable = UNCONST(fr_dict_vendor_t *, dv);
	mutable->type = type;
	mutable->length = length;
	mutable->flags = continuation;

	return 0;
}

static int dict_finalise(dict_tokenize_ctx_t *ctx)
{
	if (dict_fixup_apply(&ctx->fixup) < 0) return -1;

	ctx->value_attr = NULL;
	ctx->relative_attr = NULL;

	return 0;
}

/** Parse a dictionary file
 *
 * @param[in] ctx	Contains the current state of the dictionary parser.
 *			Used to track what PROTOCOL, VENDOR or TLV block
 *			we're in. Block context changes in $INCLUDEs should
 *			not affect the context of the including file.
 * @param[in] dir_name	Directory containing the dictionary we're loading.
 * @param[in] filename	we're parsing.
 * @param[in] src_file	The including file.
 * @param[in] src_line	Line on which the $INCLUDE or $INCLUDE- statement was found.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _dict_from_file(dict_tokenize_ctx_t *ctx,
			   char const *dir_name, char const *filename,
			   char const *src_file, int src_line)
{
	FILE			*fp;
	char 			dir[256], fn[256];
	char			buf[256];
	char			*p;
	int			line = 0;
	bool			was_member = false;

	struct stat		statbuf;
	char			*argv[MAX_ARGV];
	int			argc;
	fr_dict_attr_t const	*da;

	/*
	 *	Base flags are only set for the current file
	 */
	fr_dict_attr_flags_t	base_flags;

	if (!fr_cond_assert(!ctx->dict->root || ctx->stack[ctx->stack_depth].da)) return -1;

	if ((strlen(dir_name) + 3 + strlen(filename)) > sizeof(dir)) {
		fr_strerror_printf_push("%s: Filename name too long", "Error reading dictionary");
		return -1;
	}

	/*
	 *	If it's an absolute dir, forget the parent dir,
	 *	and remember the new one.
	 *
	 *	If it's a relative dir, tack on the current filename
	 *	to the parent dir.  And use that.
	 */
	if (!FR_DIR_IS_RELATIVE(filename)) {
		strlcpy(dir, filename, sizeof(dir));
		p = strrchr(dir, FR_DIR_SEP);
		if (p) {
			p[1] = '\0';
		} else {
			strlcat(dir, "/", sizeof(dir));
		}

		strlcpy(fn, filename, sizeof(fn));
	} else {
		strlcpy(dir, dir_name, sizeof(dir));
		p = strrchr(dir, FR_DIR_SEP);
		if (p) {
			if (p[1]) strlcat(dir, "/", sizeof(dir));
		} else {
			strlcat(dir, "/", sizeof(dir));
		}
		strlcat(dir, filename, sizeof(dir));
		p = strrchr(dir, FR_DIR_SEP);
		if (p) {
			p[1] = '\0';
		} else {
			strlcat(dir, "/", sizeof(dir));
		}

		p = strrchr(filename, FR_DIR_SEP);
		if (p) {
			snprintf(fn, sizeof(fn), "%s%s", dir, p);
		} else {
			snprintf(fn, sizeof(fn), "%s%s", dir, filename);
		}
	}

	ctx->stack[ctx->stack_depth].filename = fn;

	if ((fp = fopen(fn, "r")) == NULL) {
		if (!src_file) {
			fr_strerror_printf_push("Couldn't open dictionary %s: %s", fr_syserror(errno), fn);
		} else {
			fr_strerror_printf_push("Error reading dictionary: %s[%d]: Couldn't open dictionary '%s': %s",
						fr_cwd_strip(src_file), src_line, fn,
						fr_syserror(errno));
		}
		return -2;
	}

	/*
	 *	If fopen works, this works.
	 */
	if (stat(fn, &statbuf) < 0) {
		fclose(fp);
		return -1;
	}

	if (!S_ISREG(statbuf.st_mode)) {
		fclose(fp);
		fr_strerror_printf_push("Dictionary is not a regular file: %s", fn);
		return -1;
	}

	/*
	 *	Globally writable dictionaries means that users can control
	 *	the server configuration with little difficulty.
	 */
#ifdef S_IWOTH
	if ((statbuf.st_mode & S_IWOTH) != 0) {
		fclose(fp);
		fr_strerror_printf_push("Dictionary is globally writable: %s. "
					"Refusing to start due to insecure configuration", fn);
		return -1;
	}
#endif

	/*
	 *	Seed the random pool with data.
	 */
	fr_rand_seed(&statbuf, sizeof(statbuf));

	memset(&base_flags, 0, sizeof(base_flags));

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		ctx->stack[ctx->stack_depth].line = line++;

		switch (buf[0]) {
		case '#':
		case '\0':
		case '\n':
		case '\r':
			continue;
		}

		/*
		 *  Comment characters should NOT be appearing anywhere but
		 *  as start of a comment;
		 */
		p = strchr(buf, '#');
		if (p) *p = '\0';

		argc = fr_dict_str_to_argv(buf, argv, MAX_ARGV);
		if (argc == 0) continue;

		if (argc == 1) {
			fr_strerror_const("Invalid entry");

		error:
			fr_strerror_printf_push("Failed parsing dictionary at %s[%d]", fr_cwd_strip(fn), line);
			fclose(fp);
			return -1;
		}

		/*
		 *	Process VALUE lines.
		 */
		if (strcasecmp(argv[0], "VALUE") == 0) {
			if (dict_read_process_value(ctx, argv + 1, argc - 1) == -1) goto error;
			continue;
		}

		/*
		 *	Perhaps this is a MEMBER of a struct
		 *
		 *	@todo - create child ctx, so that we can have
		 *	nested structs.
		 */
		if (strcasecmp(argv[0], "MEMBER") == 0) {
			if (dict_read_process_member(ctx,
						     argv + 1, argc - 1,
						     &base_flags) == -1) goto error;
			was_member = true;
			continue;
		}

		/*
		 *	Finalise a STRUCT.
		 */
		if (was_member) {
			da = ctx->stack[ctx->stack_depth].da;

			if (da->type == FR_TYPE_STRUCT) {

				/*
				 *	The structure was fixed-size,
				 *	but the fields don't fill it.
				 *	That's an error.
				 *
				 *	Since process_member() checks
				 *	for overflow, the check here
				 *	is really only for underflow.
				 */
				if (da->flags.length &&
				    (ctx->stack[ctx->stack_depth].struct_size != da->flags.length)) {
					fr_strerror_printf("MEMBERs of 'struct' %s do not exactly fill the fixed-size structure",
							   da->name);
					goto error;
				}

				/*
				 *	If the structure is fixed
				 *	size, AND small enough to fit
				 *	into an 8-bit length field,
				 *	then update the length field
				 *	with the structure size/
				 */
				if (ctx->stack[ctx->stack_depth].struct_size <= 255) {
					UNCONST(fr_dict_attr_t *, da)->flags.length = ctx->stack[ctx->stack_depth].struct_size;
				} /* else length 0 means "unknown / variable size / too large */
			} else {
				fr_assert(da->type == FR_TYPE_TLV);
			}

			was_member = false;
		}

		/*
		 *	Perhaps this is an attribute.
		 */
		if (strcasecmp(argv[0], "ALIAS") == 0) {
			if (dict_read_process_alias(ctx,
						    argv + 1, argc - 1) == -1) goto error;
			continue;
		}

		/*
		 *	Perhaps this is an attribute.
		 */
		if (strcasecmp(argv[0], "ATTRIBUTE") == 0) {
			if (dict_read_process_attribute(ctx,
							argv + 1, argc - 1,
							&base_flags) == -1) goto error;
			continue;
		}

		/*
		 *	Process FLAGS lines.
		 */
		if (strcasecmp(argv[0], "FLAGS") == 0) {
			if (dict_read_process_flags(ctx->dict, argv + 1, argc - 1, &base_flags) == -1) goto error;
			continue;
		}

		/*
		 *	Process STRUCT lines.
		 */
		if (strcasecmp(argv[0], "STRUCT") == 0) {
			if (dict_read_process_struct(ctx, argv + 1, argc - 1) == -1) goto error;
			continue;
		}

		/*
		 *	See if we need to import another dictionary.
		 */
		if (strncasecmp(argv[0], "$INCLUDE", 8) == 0) {
			int ret;
			int stack_depth = ctx->stack_depth;

			/*
			 *	Allow "$INCLUDE" or "$INCLUDE-", but
			 *	not anything else.
			 */
			if ((argv[0][8] != '\0') && ((argv[0][8] != '-') || (argv[0][9] != '\0'))) goto invalid_keyword;

			/*
			 *	Included files operate on a copy of the context.
			 *
			 *	This copy means that they inherit the
			 *	current context, including parents,
			 *	TLVs, etc.  But if the included file
			 *	leaves a "dangling" TLV or "last
			 *	attribute", then it won't affect the
			 *	parent.
			 */

			ret = _dict_from_file(ctx, dir, argv[1], fn, line);
			if ((ret == -2) && (argv[0][8] == '-')) {
				fr_strerror_clear(); /* delete all errors */
				ret = 0;
			}

			if (ret < 0) {
				fr_strerror_printf_push("from $INCLUDE at %s[%d]", fr_cwd_strip(fn), line);
				fclose(fp);
				return -1;
			}

			if (ctx->stack_depth < stack_depth) {
				fr_strerror_printf_push("unexpected END-??? in $INCLUDE at %s[%d]",
							fr_cwd_strip(fn), line);
				fclose(fp);
				return -1;
			}

			while (ctx->stack_depth > stack_depth) {
				if (ctx->stack[ctx->stack_depth].nest == FR_TYPE_NULL) {
					ctx->stack_depth--;
					continue;
				}

				fr_strerror_printf_push("BEGIN-??? without END-... in file $INCLUDEd from %s[%d]",
							fr_cwd_strip(fn), line);
				fclose(fp);
				return -1;
			}

			/*
			 *	Reset the filename.
			 */
			ctx->stack[ctx->stack_depth].filename = fn;
			continue;
		} /* $INCLUDE */

		/*
		 *	Reset the previous attribute when we see
		 *	VENDOR or PROTOCOL or BEGIN/END-VENDOR, etc.
		 */
		ctx->value_attr = NULL;
		ctx->relative_attr = NULL;

		/*
		 *	Process VENDOR lines.
		 */
		if (strcasecmp(argv[0], "VENDOR") == 0) {
			if (dict_read_process_vendor(ctx->dict, argv + 1, argc - 1) == -1) goto error;
			continue;
		}

		/*
		 *	Process PROTOCOL line.  Defines a new protocol.
		 */
		if (strcasecmp(argv[0], "PROTOCOL") == 0) {
			if (argc < 2) {
				fr_strerror_const_push("Invalid PROTOCOL entry");
				goto error;
			}
			if (dict_read_process_protocol(argv + 1, argc - 1) == -1) goto error;
			continue;
		}

		/*
		 *	Switches the current protocol context
		 */
		if (strcasecmp(argv[0], "BEGIN-PROTOCOL") == 0) {
			fr_dict_t *found;

			if (argc != 2) {
				fr_strerror_const_push("Invalid BEGIN-PROTOCOL entry");
				goto error;
			}

			/*
			 *	If we're not parsing in the context of the internal
			 *	dictionary, then we don't allow BEGIN-PROTOCOL
			 *	statements.
			 */
			if (ctx->dict != dict_gctx->internal) {
				fr_strerror_const_push("Nested BEGIN-PROTOCOL statements are not allowed");
				goto error;
			}

			found = dict_by_protocol_name(argv[1]);
			if (!found) {
				fr_strerror_printf("Unknown protocol '%s'", argv[1]);
				goto error;
			}

			/*
			 *	Add a temporary fixup pool
			 *
			 *	@todo - make a nested ctx?
			 */
			dict_fixup_init(NULL, &ctx->fixup);

			// check if there's a linked library for the
			// protocol.  The values can be unknown (we
			// try to load one), or non-existent, or
			// known.  For the last two, we don't try to
			// load anything.

			ctx->dict = found;

			if (dict_gctx_push(ctx, ctx->dict->root) < 0) goto error;
			ctx->stack[ctx->stack_depth].nest = FR_TYPE_MAX;
			continue;
		}

		/*
		 *	Switches back to the previous protocol context
		 */
		if (strcasecmp(argv[0], "END-PROTOCOL") == 0) {
			fr_dict_t const *found;

			if (argc != 2) {
				fr_strerror_const("Invalid END-PROTOCOL entry");
				goto error;
			}

			found = dict_by_protocol_name(argv[1]);
			if (!found) {
				fr_strerror_printf("END-PROTOCOL %s does not refer to a valid protocol", argv[1]);
				goto error;
			}

			if (found != ctx->dict) {
				fr_strerror_printf("END-PROTOCOL %s does not match previous BEGIN-PROTOCOL %s",
						   argv[1], found->root->name);
				goto error;
			}

			/*
			 *	Pop the stack until we get to a PROTOCOL nesting.
			 */
			while ((ctx->stack_depth > 0) && (ctx->stack[ctx->stack_depth].nest != FR_TYPE_MAX)) {
				if (ctx->stack[ctx->stack_depth].nest != FR_TYPE_NULL) {
					fr_strerror_printf_push("END-PROTOCOL %s with mismatched BEGIN-??? %s", argv[1],
						ctx->stack[ctx->stack_depth].da->name);
					goto error;
				}

				ctx->stack_depth--;
			}

			if (ctx->stack_depth == 0) {
				fr_strerror_printf_push("END-PROTOCOL %s with no previous BEGIN-PROTOCOL", argv[1]);
				goto error;
			}

			if (found->root != ctx->stack[ctx->stack_depth].da) {
				fr_strerror_printf_push("END-PROTOCOL %s does not match previous BEGIN-PROTOCOL %s", argv[1],
							ctx->stack[ctx->stack_depth].da->name);
				goto error;
			}

			/*
			 *	Applies fixups to any attributes added
			 *	to the protocol dictionary.  Note that
			 *	the finalise function prints out the
			 *	original filename / line of the
			 *	error. So we don't need to do that
			 *	here.
			 */
			if (dict_finalise(ctx) < 0) {
				fclose(fp);
				return -1;
			}

			ctx->stack_depth--;
			ctx->dict = ctx->stack[ctx->stack_depth].dict;
			continue;
		}

		/*
		 *	Switches TLV parent context
		 */
		if (strcasecmp(argv[0], "BEGIN-TLV") == 0) {
			fr_dict_attr_t const *common;

			if (argc != 2) {
				fr_strerror_const_push("Invalid BEGIN-TLV entry");
				goto error;
			}

			da = fr_dict_attr_by_oid(NULL, ctx->stack[ctx->stack_depth].da, argv[1]);
			if (!da) {
				fr_strerror_const_push("Failed resolving attribute in BEGIN-TLV entry");
				goto error;
			}

			if (da->type != FR_TYPE_TLV) {
				fr_strerror_printf_push("Attribute '%s' should be a 'tlv', but is a '%s'",
							argv[1],
							fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
				goto error;
			}

			common = fr_dict_attr_common_parent(ctx->stack[ctx->stack_depth].da, da, true);
			if (!common ||
			    (common->type == FR_TYPE_VSA)) {
				fr_strerror_printf_push("Attribute '%s' should be a child of '%s'",
							argv[1], ctx->stack[ctx->stack_depth].da->name);
				goto error;
			}

			if (dict_gctx_push(ctx, da) < 0) goto error;
			ctx->stack[ctx->stack_depth].nest = FR_TYPE_TLV;
			continue;
		} /* BEGIN-TLV */

		/*
		 *	Switches back to previous TLV parent
		 */
		if (strcasecmp(argv[0], "END-TLV") == 0) {
			if (argc != 2) {
				fr_strerror_const_push("Invalid END-TLV entry");
				goto error;
			}



			da = fr_dict_attr_by_oid(NULL, ctx->stack[ctx->stack_depth - 1].da, argv[1]);
			if (!da) {
				fr_strerror_const_push("Failed resolving attribute in END-TLV entry");
				goto error;
			}

			/*
			 *	Pop the stack until we get to a TLV nesting.
			 */
			while ((ctx->stack_depth > 0) && (ctx->stack[ctx->stack_depth].nest != FR_TYPE_TLV)) {
				if (ctx->stack[ctx->stack_depth].nest != FR_TYPE_NULL) {
					fr_strerror_printf_push("END-TLV %s with mismatched BEGIN-??? %s", argv[1],
						ctx->stack[ctx->stack_depth].da->name);
					goto error;
				}

				ctx->stack_depth--;
			}

			if (ctx->stack_depth == 0) {
				fr_strerror_printf_push("END-TLV %s with no previous BEGIN-TLV", argv[1]);
				goto error;
			}

			if (da != ctx->stack[ctx->stack_depth].da) {
				fr_strerror_printf_push("END-TLV %s does not match previous BEGIN-TLV %s", argv[1],
							ctx->stack[ctx->stack_depth].da->name);
				goto error;
			}

			ctx->stack_depth--;
			continue;
		} /* END-VENDOR */

		if (strcasecmp(argv[0], "BEGIN-VENDOR") == 0) {
			fr_dict_vendor_t const	*vendor;
			fr_dict_attr_flags_t	flags;

			fr_dict_attr_t const	*vsa_da;
			fr_dict_attr_t const	*vendor_da;
			fr_dict_attr_t		*new;

			if (argc < 2) {
				fr_strerror_const_push("Invalid BEGIN-VENDOR entry");
				goto error;
			}

			vendor = fr_dict_vendor_by_name(ctx->dict, argv[1]);
			if (!vendor) {
				fr_strerror_printf_push("Unknown vendor '%s'", argv[1]);
				goto error;
			}

			/*
			 *	Check for extended attr VSAs
			 *
			 *	BEGIN-VENDOR foo parent=Foo-Encapsulation-Attr
			 */
			if (argc > 2) {
				if (strncmp(argv[2], "parent=", 7) != 0) {
					fr_strerror_printf_push("BEGIN-VENDOR invalid argument (%s)", argv[2]);
					goto error;
				}

				p = argv[2] + 7;
				da = fr_dict_attr_by_oid(NULL, ctx->stack[ctx->stack_depth].da, p);
				if (!da) {
					fr_strerror_printf_push("BEGIN-VENDOR invalid argument (%s)", argv[2]);
					goto error;
				}

				if (da->type != FR_TYPE_VSA) {
					fr_strerror_printf_push("Invalid parent for BEGIN-VENDOR.  "
								"Attribute '%s' should be 'vsa' but is '%s'", p,
								fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
					goto error;
				}

				vsa_da = da;

			} else if (!ctx->dict->vsa_parent) {
				fr_strerror_printf_push("BEGIN-VENDOR is forbidden for protocol %s - it has no ATTRIBUTE of type 'vsa'",
							ctx->dict->root->name);
				goto error;

			} else {
				/*
				 *	Check that the protocol-specific VSA parent exists.
				 */
				vsa_da = dict_attr_child_by_num(ctx->stack[ctx->stack_depth].da, ctx->dict->vsa_parent);
				if (!vsa_da) {
					fr_strerror_printf_push("Failed finding VSA parent for Vendor %s",
								vendor->name);
					goto error;
				}
			}

			/*
			 *	Create a VENDOR attribute on the fly, either in the context
			 *	of the VSA (26) attribute.
			 */
			vendor_da = dict_attr_child_by_num(vsa_da, vendor->pen);
			if (!vendor_da) {
				memset(&flags, 0, sizeof(flags));

				flags.type_size = ctx->dict->default_type_size;
				flags.length = ctx->dict->default_type_length;

				/*
				 *	See if this vendor has
				 *	specific sizes for type /
				 *	length.
				 *
				 *	@todo - Make this more protocol agnostic!
				 */
				if ((vsa_da->type == FR_TYPE_VSA) &&
				    (vsa_da->parent->flags.is_root)) {
					fr_dict_vendor_t const *dv;

					dv = fr_dict_vendor_by_num(ctx->dict, vendor->pen);
					if (dv) {
						flags.type_size = dv->type;
						flags.length = dv->length;
					}
				}

				new = dict_attr_alloc(ctx->dict->pool,
						      vsa_da, argv[1], vendor->pen, FR_TYPE_VENDOR, &flags);
				if (unlikely(!new)) goto error;

				if (dict_attr_child_add(UNCONST(fr_dict_attr_t *, vsa_da), new) < 0) {
					talloc_free(new);
					goto error;
				}

				if (dict_attr_add_to_namespace(UNCONST(fr_dict_attr_t *, vsa_da), new) < 0) {
					talloc_free(new);
					goto error;
				}

				vendor_da = new;
			}

			if (dict_gctx_push(ctx, vendor_da) < 0) goto error;
			ctx->stack[ctx->stack_depth].nest = FR_TYPE_VENDOR;
			continue;
		} /* BEGIN-VENDOR */

		if (strcasecmp(argv[0], "END-VENDOR") == 0) {
			fr_dict_vendor_t const *vendor;

			if (argc != 2) {
				fr_strerror_const_push("Invalid END-VENDOR entry");
				goto error;
			}

			vendor = fr_dict_vendor_by_name(ctx->dict, argv[1]);
			if (!vendor) {
				fr_strerror_printf_push("Unknown vendor '%s'", argv[1]);
				goto error;
			}

			/*
			 *	Pop the stack until we get to a VENDOR nesting.
			 */
			while ((ctx->stack_depth > 0) && (ctx->stack[ctx->stack_depth].nest != FR_TYPE_VENDOR)) {
				if (ctx->stack[ctx->stack_depth].nest != FR_TYPE_NULL) {
					fr_strerror_printf_push("END-VENDOR %s with mismatched BEGIN-??? %s", argv[1],
						ctx->stack[ctx->stack_depth].da->name);
					goto error;
				}

				ctx->stack_depth--;
			}

			if (ctx->stack_depth == 0) {
				fr_strerror_printf_push("END-VENDOR %s with no previous BEGIN-VENDOR", argv[1]);
				goto error;
			}

			if (vendor->pen != ctx->stack[ctx->stack_depth].da->attr) {
				fr_strerror_printf_push("END-VENDOR %s does not match previous BEGIN-VENDOR %s", argv[1],
							ctx->stack[ctx->stack_depth].da->name);
				goto error;
			}

			ctx->stack_depth--;
			continue;
		} /* END-VENDOR */

		/*
		 *	Any other string: We don't recognize it.
		 */
	invalid_keyword:
		fr_strerror_printf_push("Invalid keyword '%s'", argv[0]);
		goto error;
	}

	/*
	 *	Note that we do NOT walk back up the stack to check
	 *	for missing END-FOO to match BEGIN-FOO.  The context
	 *	was copied from the parent, so there are guaranteed to
	 *	be missing things.
	 */

	fclose(fp);
	return 0;
}

static int dict_from_file(fr_dict_t *dict,
			  char const *dir_name, char const *filename,
			  char const *src_file, int src_line)
{
	int ret;
	dict_tokenize_ctx_t ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.dict = dict;
	dict_fixup_init(NULL, &ctx.fixup);
	ctx.stack[0].dict = dict;
	ctx.stack[0].da = dict->root;
	ctx.stack[0].nest = FR_TYPE_MAX;

	ret = _dict_from_file(&ctx, dir_name, filename, src_file, src_line);
	if (ret < 0) {
		talloc_free(ctx.fixup.pool);
		return ret;
	}

	/*
	 *	Applies  to any attributes added to the *internal*
	 *	dictionary.
	 *
	 *	Fixups should have been applied already to any protocol
	 *	dictionaries.
	 */
	return dict_finalise(&ctx);
}

/** (Re-)Initialize the special internal dictionary
 *
 * This dictionary has additional programatically generated attributes added to it,
 * and is checked in addition to the protocol specific dictionaries.
 *
 * @note The dictionary pointer returned in out must have its reference counter
 *	 decremented with #fr_dict_free when no longer used.
 *
 * @param[out] out		Where to write pointer to the internal dictionary.
 * @param[in] dict_subdir	name of the internal dictionary dir (may be NULL).
 * @param[in] dependent		Either C src file, or another dictionary.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_internal_afrom_file(fr_dict_t **out, char const *dict_subdir, char const *dependent)
{
	fr_dict_t		*dict;
	char			*dict_path = NULL;
	size_t			i;
	fr_dict_attr_flags_t	flags = { .internal = true };
	char			*type_name;

	if (unlikely(!dict_gctx)) {
		fr_strerror_const("fr_dict_global_ctx_init() must be called before loading dictionary files");
		return -1;
	}

	/*
	 *	Increase the reference count of the internal dictionary.
	 */
	if (dict_gctx->internal) {
		 dict_dependent_add(dict_gctx->internal, dependent);
		 *out = dict_gctx->internal;
		 return 0;
	}

	dict_path = dict_subdir ?
		    talloc_asprintf(NULL, "%s%c%s", fr_dict_global_ctx_dir(), FR_DIR_SEP, dict_subdir) :
		    talloc_strdup(NULL, fr_dict_global_ctx_dir());

	dict = dict_alloc(dict_gctx);
	if (!dict) {
	error:
		if (!dict_gctx->internal) talloc_free(dict);
		talloc_free(dict_path);
		return -1;
	}

	/*
	 *	Set the root name of the dictionary
	 */
	if (dict_root_set(dict, "internal", 0) < 0) goto error;

	/*
	 *	Add cast attributes.  We do it this way,
	 *	so cast attributes get added automatically for new types.
	 *
	 *	We manually add the attributes to the dictionary, and bypass
	 *	fr_dict_attr_add(), because we know what we're doing, and
	 *	that function does too many checks.
	 */
	for (i = 0; i < fr_value_box_type_table_len; i++) {
		fr_dict_attr_t			*n;
		fr_table_num_ordered_t const	*p = &fr_value_box_type_table[i];

		if (p->value == FR_TYPE_VENDOR) continue;	/* These can't exist in the root */

		type_name = talloc_typed_asprintf(NULL, "Tmp-Cast-%s", p->name.str);

		n = dict_attr_alloc(dict->pool, dict->root, type_name,
				    FR_CAST_BASE + p->value, p->value, &flags);
		if (!n) {
			talloc_free(type_name);
			goto error;
		}

		if (dict_attr_add_to_namespace(dict->root, n) < 0) {
			fr_strerror_printf_push("Failed inserting '%s' into internal dictionary", type_name);
			talloc_free(type_name);
			goto error;
		}

		talloc_free(type_name);

		/*
		 *	Set up parenting for the attribute.
		 */
		if (dict_attr_child_add(dict->root, n) < 0) goto error;
	}

	if (dict_path && dict_from_file(dict, dict_path, FR_DICTIONARY_FILE, NULL, 0) < 0) goto error;

	talloc_free(dict_path);

	dict_dependent_add(dict, dependent);

	if (!dict_gctx->internal) {
		dict_gctx->internal = dict;
		dict_dependent_add(dict, "global");
	}

	*out = dict;

	return 0;
}

/** (Re)-initialize a protocol dictionary
 *
 * Initialize the directory, then fix the attr number of all attributes.
 *
 * @param[out] out		Where to write a pointer to the new dictionary.  Will free existing
 *				dictionary if files have changed and *out is not NULL.
 * @param[in] proto_name	that we're loading the dictionary for.
 * @param[in] proto_dir		Explicitly set where to hunt for the dictionary files.  May be NULL.
 * @param[in] dependent		Either C src file, or another dictionary.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_protocol_afrom_file(fr_dict_t **out, char const *proto_name, char const *proto_dir, char const *dependent)
{
	char		*dict_dir = NULL;
	fr_dict_t	*dict;

	*out = NULL;

	if (unlikely(!dict_gctx)) {
		fr_strerror_const("fr_dict_global_ctx_init() must be called before loading dictionary files");
		return -1;
	}

	if (unlikely(!dict_gctx->internal)) {
		fr_strerror_const("Internal dictionary must be initialised before loading protocol dictionaries");
		return -1;
	}

	/*
	 *	Increment the reference count if the dictionary
	 *	has already been loaded and return that.
	 */
	dict = dict_by_protocol_name(proto_name);
	if (dict && dict->autoloaded) {
		 dict_dependent_add(dict, dependent);
		*out = dict;
		return 0;
	}

	if (!proto_dir) {
		dict_dir = talloc_asprintf(NULL, "%s%c%s", fr_dict_global_ctx_dir(), FR_DIR_SEP, proto_name);
	} else {
		dict_dir = talloc_asprintf(NULL, "%s%c%s", fr_dict_global_ctx_dir(), FR_DIR_SEP, proto_dir);
	}

	/*
	 *	Start in the context of the internal dictionary,
	 *	and switch to the context of a protocol dictionary
	 *	when we hit a BEGIN-PROTOCOL line.
	 *
	 *	This allows a single file to provide definitions
	 *	for multiple protocols, which'll probably be useful
	 *	at some point.
	 */
	if (dict_from_file(dict_gctx->internal, dict_dir, FR_DICTIONARY_FILE, NULL, 0) < 0) {
	error:
		talloc_free(dict_dir);
		return -1;
	}

	/*
	 *	Check the dictionary actually defined the protocol
	 */
	dict = dict_by_protocol_name(proto_name);
	if (!dict) {
		fr_strerror_printf("Dictionary \"%s\" missing \"BEGIN-PROTOCOL %s\" declaration", dict_dir, proto_name);
		goto error;
	}

	talloc_free(dict_dir);

	/*
	 *	If we're autoloading a previously defined dictionary,
	 *	then mark up the dictionary as now autoloaded.
	 */
	if (!dict->autoloaded) dict->autoloaded = true;

	dict_dependent_add(dict, dependent);

	*out = dict;

	return 0;
}

/* Alloc a new root dictionary attribute
 *
 * @note Must only be called once per dictionary.
 *
 * @param[in] proto_name	that we're loading the dictionary for.
 * @param[in] proto_number	The artificial (or IANA allocated) number for the protocol.
 * @return
 *	- A pointer to the new dict context on success.
 *	- NULL on failure.
 */
fr_dict_t *fr_dict_alloc(char const *proto_name, unsigned int proto_number)
{
	fr_dict_t	*dict;

	if (unlikely(!dict_gctx)) {
		fr_strerror_printf("fr_dict_global_ctx_init() must be called before loading dictionary files");
		return NULL;
	}

	/*
	 *	Alloc dict instance.
	 */
	dict = dict_alloc(dict_gctx);
	if (!dict) return NULL;

	/*
	 *	Set the root name of the dictionary
	 */
	if (dict_root_set(dict, proto_name, proto_number) < 0) {
		talloc_free(dict);
		return NULL;
	}

	return dict;
}

/** Read supplementary attribute definitions into an existing dictionary
 *
 * @param[in] dict	Existing dictionary.
 * @param[in] dir	dictionary is located in.
 * @param[in] filename	of the dictionary.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
int fr_dict_read(fr_dict_t *dict, char const *dir, char const *filename)
{
	INTERNAL_IF_NULL(dict, -1);

	if (unlikely(dict->read_only)) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root(dict)->name);
		return -1;
	}

	if (!dict->vendors_by_name) {
		fr_strerror_printf("%s: Must initialise dictionary before calling fr_dict_read()", __FUNCTION__);
		return -1;
	}

	return dict_from_file(dict, dir, filename, NULL, 0);
}

/*
 *	External API for testing
 */
int fr_dict_parse_str(fr_dict_t *dict, char *buf, fr_dict_attr_t const *parent)
{
	int	argc;
	char	*argv[MAX_ARGV];
	int	ret;
	fr_dict_attr_flags_t base_flags;
	dict_tokenize_ctx_t ctx;

	INTERNAL_IF_NULL(dict, -1);

	argc = fr_dict_str_to_argv(buf, argv, MAX_ARGV);
	if (argc == 0) return 0;


	memset(&ctx, 0, sizeof(ctx));
	ctx.dict = dict;
	ctx.stack[0].dict = dict;
	ctx.stack[0].da = dict->root;
	ctx.stack[0].nest = FR_TYPE_MAX;

	if (dict_fixup_init(NULL, &ctx.fixup) < 0) return -1;

	if (strcasecmp(argv[0], "VALUE") == 0) {
		if (argc < 4) {
			fr_strerror_printf("VALUE needs at least 4 arguments, got %i", argc);
		error:
			TALLOC_FREE(ctx.fixup.pool);
			return -1;
		}

		if (!fr_dict_attr_by_oid(NULL, fr_dict_root(dict), argv[1])) {
			fr_strerror_printf("Attribute '%s' does not exist in dictionary \"%s\"",
					   argv[1], dict->root->name);
			goto error;
		}
		ret = dict_read_process_value(&ctx, argv + 1, argc - 1);
		if (ret < 0) goto error;

	} else if (strcasecmp(argv[0], "ATTRIBUTE") == 0) {
		if (parent && (parent != dict->root)) ctx.stack[++ctx.stack_depth].da = parent;

		memset(&base_flags, 0, sizeof(base_flags));

		ret = dict_read_process_attribute(&ctx,
						  argv + 1, argc - 1, &base_flags);
		if (ret < 0) goto error;
	} else if (strcasecmp(argv[0], "VENDOR") == 0) {
		ret = dict_read_process_vendor(dict, argv + 1, argc - 1);
		if (ret < 0) goto error;
	} else {
		fr_strerror_printf("Invalid input '%s'", argv[0]);
		goto error;
	}

	return dict_finalise(&ctx);
}
