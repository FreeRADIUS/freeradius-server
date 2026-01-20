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

/** Code to apply fctx and finalisation steps to a dictionary
 *
 * @file src/lib/util/dict_fixup.c
 *
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2020,2024 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/file.h>
#include <freeradius-devel/util/value.h>

#include "dict_fixup_priv.h"

/** Common fields for every fixup structure
 *
 */
typedef struct {
	fr_dlist_t		entry;			//!< Entry in linked list of fctx.
} dict_fixup_common_t;

/** Add an enumeration value to an attribute that wasn't defined at the time the value was parsed
 *
 */
typedef struct {
	dict_fixup_common_t	common;			//!< Common fields.

	char			*filename;		//!< where the line being fixed up.
	int			line;			//!< ditto.

	char			*alias;			//!< we need to create.
	fr_dict_attr_t		*alias_parent;		//!< Where to add the alias.

	char			*ref;			//!< what the alias references.
	fr_dict_attr_t		*ref_parent;		//!< Parent attribute to resolve the 'attribute' string in.
} dict_fixup_alias_t;

/** Add an enumeration value to an attribute that wasn't defined at the time the value was parsed
 *
 */
typedef struct {
	dict_fixup_common_t	common;			//!< Common fields.

	char			*filename;		//!< where the line being fixed up.
	int			line;			//!< ditto.

	char			*attribute;		//!< we couldn't find (and will need to resolve later).
	char			*name;			//!< Raw enum name.
	char			*value;			//!< Raw enum value.  We can't do anything with this until
							//!< we know the attribute type, which we only find out later.

	fr_dict_attr_t const	*parent;		//!< Parent attribute to resolve the 'attribute' string in.
} dict_fixup_enumv_t;

/** Resolve a group reference
 *
 */
typedef struct {
	dict_fixup_common_t	common;			//!< Common fields.

	fr_dict_attr_t		*da;			//!< FR_TYPE_GROUP to fix
	char 			*ref;			//!< the reference name
} dict_fixup_group_t;

/** Clone operation from one tree node to another
 *
 */
typedef struct {
	dict_fixup_common_t	common;			//!< Common fields.

	fr_dict_attr_t		*da;			//!< to populate with cloned information.
	char 			*ref;			//!< the target attribute to clone
} dict_fixup_clone_t;

/** Run fixup callbacks for a VSA
 *
 */
typedef struct {
	dict_fixup_common_t	common;			//!< Common fields.

	fr_dict_attr_t		*da;			//!< FR_TYPE_VSA to fix
} dict_fixup_vsa_t;

/** Dictionary attribute namespaces need their hash tables finalised
 *
 */
typedef struct {
	dict_fixup_common_t	common;			//!< Common fields.

	fr_hash_table_t		*hash;			//!< We need to finalise.
} dict_fixup_hash_t;

/** Initialise common fields in fixup struct, and add it to a fixup list
 *
 * @param[in] fixup_list	to add fixup to.
 * @param[in] common		common header to populate.
 * @return
 *	- 0 on success.
 *	- -1 on out of memory.
 */
static inline CC_HINT(always_inline) int dict_fixup_common(fr_dlist_head_t *fixup_list, dict_fixup_common_t *common)
{
	fr_dlist_insert_tail(fixup_list, common);

	return 0;
}

/** Resolve a reference string to a dictionary attribute
 *
 * @param[out] da_p		Where the attribute will be stored
 * @param[in] rel		Relative attribute to resolve from.
 * @param[in] in		Reference string.
 * @return
 *	- <0 on error
 *	- 0 on parse OK, but *da_p is NULL;
 *	- 1 for parse OK, and *da_p is !NULL
 */
int fr_dict_protocol_reference(fr_dict_attr_t const **da_p, fr_dict_attr_t const *rel, fr_sbuff_t *in)
{
	fr_dict_t			*dict = fr_dict_unconst(rel->dict);
	fr_dict_attr_t const		*da = rel;
	ssize_t				slen;

	*da_p = NULL;

	/*
	 *	Are we resolving a foreign reference?
	 */
	if (fr_sbuff_next_if_char(in, '@')) {
		char proto_name[FR_DICT_ATTR_MAX_NAME_LEN + 1];
		fr_sbuff_t proto_name_sbuff = FR_SBUFF_OUT(proto_name, sizeof(proto_name));

		/*
		 *	@.foo is "foo from the current root".
		 *
		 *	This is a bit clearer than "foo".
		 */
		if (fr_sbuff_next_if_char(in, '.')) {
			if (fr_sbuff_is_char(in, '.')) goto above_root;

			da = rel->dict->root;
			goto more;
		}

		slen = dict_by_protocol_substr(NULL, &dict, in, NULL);
		/* Need to load it... */
		if (slen <= 0) {
			/* Quiet coverity */
			fr_sbuff_terminate(&proto_name_sbuff);

			/* Fixme, probably want to limit allowed chars */
			if (fr_sbuff_out_bstrncpy_until(&proto_name_sbuff, in, SIZE_MAX,
							&FR_SBUFF_TERMS(L(""), L(".")), NULL) <= 0) {
			invalid_name:
				fr_strerror_const("Invalid protocol name");
				return -1;
			}

			/*
			 *	The filenames are lowercase.  The names in the dictionaries are case-insensitive.  So
			 *	we mash the name to all lowercase.
			 */
			fr_tolower(proto_name);

			/*
			 *	Catch this early, so people don't do stupid things
			 *	like put slashes in the references and then claim
			 *	it's a security issue.
			 */
			if (fr_dict_valid_oid_str(proto_name, -1) < 0) goto invalid_name;

			/*
			 *	Load the new dictionary, and mark it as loaded from our dictionary.
			 */
			if (fr_dict_protocol_afrom_file(&dict, proto_name, NULL, (rel->dict)->root->name) < 0) {
				fr_strerror_printf_push("Perhaps there is a '.' missing before the attribute name in %.*s ?",
							(int) fr_sbuff_used(in), fr_sbuff_start(in));
				return -1;
			}

			if (!fr_hash_table_insert((rel->dict)->autoref, dict)) {
				fr_strerror_const("Failed inserting into internal autoref table");
				return -1;
			}
		}

		/*
		 *	Didn't stop at an attribute ref... we're done
		 */
		if (fr_sbuff_eof(in)) {
			*da_p = dict->root;
			return 1;
		}

		da = dict->root;
	}

	/*
	 *	ref=.foo is a ref from the current parent.
	 *
	 *	ref=@foo is a ref from the root of the tree.
	 */

	if (!fr_sbuff_next_if_char(in, '.')) {
		fr_strerror_printf("Invalid reference '%s' - it should start with '@' (from the root), or '.' (from the parent)",
				   fr_sbuff_start(in));
		return -1;
	}

	/*
	 *	First '.' makes it relative, subsequent ones traverse up the tree.
	 *
	 *	No '.' means use the root.
	 */
	while (fr_sbuff_next_if_char(in, '.')) {
		if (!da->parent) {
		above_root:
			fr_strerror_const("Reference attempted to navigate above dictionary root");
			return -1;
		}
		da = da->parent;
	}

	/*
	 *	Look up the attribute.  Note that this call will
	 *	update *da_p with a partial reference if it exists.
	 */
more:
	slen = fr_dict_attr_by_oid_substr(NULL, da_p, da, in, NULL);
	if (slen < 0) return -1;

	if (slen == 0) {
		*da_p = NULL;
		return 0;
	}

	return 1;
}

/** Add an enumeration value to an attribute which has not yet been defined
 *
 * @param[in] fctx		Holds current dictionary parsing information.
 * @param[in] filename		this fixup relates to.
 * @param[in] line		this fixup relates to.
 * @param[in] attr		The OID string pointing to the attribute
 *				to add the enumeration value to.
 * @param[in] attr_len		The length of the attr string.
 * @param[in] name		The name of the enumv.
 * @param[in] name_len		Length of the name string.
 * @param[in] value		Value string.  This is kept as a string until we know
 *				what type we want to transform it into.
 * @param[in] value_len		Length of the value string.
 * @param[in] parent		of this attribute.
 * @return
 *	- 0 on success.
 *	- -1 on out of memory.
 */
int dict_fixup_enumv_enqueue(dict_fixup_ctx_t *fctx, char const *filename, int line,
			     char const *attr, size_t attr_len,
			     char const *name, size_t name_len,
			     char const *value, size_t value_len,
			     fr_dict_attr_t const *parent)
{
	dict_fixup_enumv_t *fixup;

	fixup = talloc(fctx->pool, dict_fixup_enumv_t);
	if (!fixup) {
	oom:
		fr_strerror_const("Out of memory");
		return -1;
	}
	*fixup = (dict_fixup_enumv_t) {
		.attribute = talloc_bstrndup(fixup, attr, attr_len),
		.name = talloc_bstrndup(fixup, name, name_len),
		.value = talloc_bstrndup(fixup, value, value_len),
		.parent = parent
	};
	if (!fixup->attribute || !fixup->name || !fixup->value) goto oom;

	fixup->filename = talloc_strdup(fixup, filename);
	if (!fixup->filename) goto oom;
	fixup->line = line;

	return dict_fixup_common(&fctx->enumv, &fixup->common);
}

/** Add a previously defined enumeration value to an existing attribute
 *
 * @param[in] fctx		Holds current dictionary parsing information.
 * @param[in] fixup		Hash table to fill.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(always_inline) int dict_fixup_enumv_apply(UNUSED dict_fixup_ctx_t *fctx, dict_fixup_enumv_t *fixup)
{
	fr_dict_attr_t 		*da;
	fr_value_box_t		value = FR_VALUE_BOX_INITIALISER_NULL(value);
	fr_type_t		type;
	int			ret;
	fr_dict_attr_t const	*da_const;

	da_const = fr_dict_attr_by_oid(NULL, fixup->parent, fixup->attribute);
	if (!da_const) {
		fr_strerror_printf_push("Failed resolving ATTRIBUTE referenced by VALUE '%s' at %s[%d]",
					fixup->name, fr_cwd_strip(fixup->filename), fixup->line);
		return -1;
	}
	da = fr_dict_attr_unconst(da_const);
	type = da->type;

	if (fr_value_box_from_str(fixup, &value, type, NULL,
				  fixup->value, talloc_array_length(fixup->value) - 1,
				  NULL) < 0) {
		fr_strerror_printf_push("Invalid VALUE '%pV' for attribute '%s' at %s[%d]",
					fr_box_strvalue_buffer(fixup->value),
					da->name,
					fr_cwd_strip(fixup->filename), fixup->line);
		return -1;
	}

	ret = fr_dict_enum_add_name(da, fixup->name, &value, false, false);
	fr_value_box_clear(&value);
	da->flags.has_fixup = false;

	return ret;
}

/** Resolve a group reference
 *
 * This is required as the reference may point to another dictionary which
 * hasn't been loaded yet.
 *
 * @param[in] fctx		Holds current dictionary parsing information.
 * @param[in] da		The group dictionary attribute.
 * @param[in] ref		OID string representing what the group references.
 * @return
 *	- 0 on success.
 *	- -1 on out of memory.
 */
int dict_fixup_group_enqueue(dict_fixup_ctx_t *fctx, fr_dict_attr_t *da, char const *ref)
{
	dict_fixup_group_t *fixup;

	fixup = talloc(fctx->pool, dict_fixup_group_t);
	if (!fixup) {
		fr_strerror_const("Out of memory");
		return -1;
	}
	*fixup = (dict_fixup_group_t) {
		.da = da,
		.ref = talloc_strdup(fixup, ref),
	};

	da->flags.has_fixup = true;

	return dict_fixup_common(&fctx->group, &fixup->common);
}

/** Resolve a group reference
 *
 * @param[in] fctx		Holds current dictionary parsing information.
 * @param[in] fixup		Hash table to fill.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(always_inline) int dict_fixup_group_apply(UNUSED dict_fixup_ctx_t *fctx, dict_fixup_group_t *fixup)
{
	fr_dict_attr_t const *da;

	(void) fr_dict_protocol_reference(&da, fixup->da->parent, &FR_SBUFF_IN_STR(fixup->ref));
	if (!da) {
		fr_strerror_printf_push("Failed resolving reference for attribute %s at %s[%d]",
					fixup->da->name, fr_cwd_strip(fixup->da->filename), fixup->da->line);
		return -1;
	}

	if (da->type != FR_TYPE_TLV) {
		fr_strerror_printf("References MUST be to attributes of type 'tlv' at %s[%d]",
				   fr_cwd_strip(fixup->da->filename), fixup->da->line);
		return -1;
	}

	if (fr_dict_attr_ref(da)) {
		fr_strerror_printf("References MUST NOT refer to an ATTRIBUTE which also has 'ref=...' at %s[%d]",
				   fr_cwd_strip(fixup->da->filename), fixup->da->line);
		return -1;
	}

	fixup->da->flags.has_fixup = false;

	return dict_attr_ref_resolve(fixup->da, da);
}

/** Clone one area of a tree into another
 *
 * These must be processed later to ensure that we've finished building an
 * attribute by the time it has been cloned.
 *
 * @param[in] fctx		Holds current dictionary parsing information.
 * @param[in] da		The group dictionary attribute.
 * @param[in] ref		OID string representing what the group references..
 * @return
 *	- 0 on success.
 *	- -1 on out of memory.
 */
int dict_fixup_clone_enqueue(dict_fixup_ctx_t *fctx, fr_dict_attr_t *da, char const *ref)
{
	dict_fixup_clone_t *fixup;

	fr_assert(!fr_type_is_leaf(da->type));

	/*
	 *	Delay type checks until we've loaded all of the
	 *	dictionaries.  This means that errors are produced
	 *	later, but that shouldn't matter for the default
	 *	dictionaries.  They're supposed to work.
	 */
	fixup = talloc(fctx->pool, dict_fixup_clone_t);
	if (!fixup) {
		fr_strerror_const("Out of memory");
		return -1;
	}
	*fixup = (dict_fixup_clone_t) {
		.da = da,
		.ref = talloc_typed_strdup(fixup, ref)
	};

	return dict_fixup_common(&fctx->clone, &fixup->common);
}

/** Clone a dictionary attribute from a ref
 *
 * @param[in] dst_p	will either be inserted directly, with fields from the clone, or will be
 *			cloned, and then inserted.  In this case the original dst da will be freed
 *			and the new cloned attribute will be written back to dst_p.
 * @param[in] src	to clone.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int dict_fixup_clone(fr_dict_attr_t **dst_p, fr_dict_attr_t const *src)
{
	fr_dict_attr_t		*dst = *dst_p;
	fr_dict_t		*dict = fr_dict_unconst(dst->dict);

	/*
	 *	@todo - allow this for structural attributes, so long as they don't have a child TLV.
	 */
	if (src->dict->proto != dst->dict->proto) {
		fr_strerror_printf("Incompatible protocols.  Referenced '%s', referencing '%s'.  Defined at %s[%d]",
				   src->dict->proto->name, dst->dict->proto->name, dst->filename, dst->line);
		return -1;
	}

	/*
	 *	The referenced DA is higher than the one we're creating.  Ensure it's not a parent.
	 *
	 *	@todo - Do we want to require that aliases only go deeper in the tree?  Otherwise aliases can
	 *	make the tree a lot more complicated.
	 */
	if (src->depth < dst->depth) {
		fr_dict_attr_t const *parent;

		for (parent = dst->parent; !parent->flags.is_root; parent = parent->parent) {
			if (parent == src) {
				fr_strerror_printf("References MUST NOT be to a parent attribute %s at %s[%d]",
						   parent->name, fr_cwd_strip(dst->filename), dst->line);
				return -1;
			}
		}
	}

	if (fr_dict_attr_ref(src)) {
		fr_strerror_printf("References MUST NOT refer to an ATTRIBUTE which itself has a 'ref=...' at %s[%d]",
				   fr_cwd_strip(dst->filename), dst->line);
		return -1;
	}

	/*
	 *	Leaf attributes can be cloned.  TLV and STRUCT can be cloned.  But all other data types cannot
	 *	be cloned.
	 *
	 *	And while we're at it, copy the flags over.
	 */
	switch (src->type) {
	default:
		fr_strerror_printf("References MUST NOT refer to an attribute of data type '%s' at %s[%d]",
				   fr_type_to_str(src->type), fr_cwd_strip(dst->filename), dst->line);
		return -1;

	case FR_TYPE_TLV:
		dst->flags.type_size = src->flags.type_size;
		dst->flags.length = src->flags.length;
		FALL_THROUGH;

	case FR_TYPE_STRUCT:
		if (!dict_attr_children(src)) {
			fr_strerror_printf_push("Reference %s has no children defined at %s[%d]",
						src->name, fr_cwd_strip(dst->filename), dst->line);
			return -1;
		}
		break;
	}

	dst->flags.array = src->flags.array;
	dst->flags.is_known_width = src->flags.is_known_width;
	dst->flags.internal = src->flags.internal;
	dst->flags.name_only = src->flags.name_only;

	/*
	 *	Clone the children from the source to the dst.
	 *
	 *	Note that the destination may already have children!
	 */
	if (dict_attr_acopy_children(dict, dst, src) < 0) {
		fr_strerror_printf("Failed populating attribute '%s' with children of %s - %s", dst->name, src->name, fr_strerror());
		return -1;
	}

	return fr_dict_attr_add_initialised(dst);
}

/** Clone one are of a tree into another
 *
 * @param[in] fctx		Holds current dictionary parsing information.
 * @param[in] fixup		Containing source/destination of the clone.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(always_inline) int dict_fixup_clone_apply(UNUSED dict_fixup_ctx_t *fctx, dict_fixup_clone_t *fixup)
{
	fr_dict_attr_t const	*src;

	(void) fr_dict_protocol_reference(&src, fixup->da->parent, &FR_SBUFF_IN_STR(fixup->ref));
	if (!src) {
		fr_strerror_printf_push("Failed resolving reference for attribute %s at %s[%d]",
					fixup->da->name, fr_cwd_strip(fixup->da->filename), fixup->da->line);
		return -1;
	}

	fixup->da->flags.has_fixup = false;
	return dict_fixup_clone(&fixup->da, src);
}

/** Clone enumeration values from one attribute to another
 *
 * These must be processed later to ensure that we've finished building an
 * attribute by the time it has been cloned.
 *
 * @param[in] fctx		Holds current dictionary parsing information.
 * @param[in] da		The group dictionary attribute.
 * @param[in] ref		OID string representing what the group references..
 * @return
 *	- 0 on success.
 *	- -1 on out of memory.
 */
int dict_fixup_clone_enum_enqueue(dict_fixup_ctx_t *fctx, fr_dict_attr_t *da, char const *ref)
{
	dict_fixup_clone_t *fixup;

	fr_assert(fr_type_is_leaf(da->type));

	/*
	 *	Delay type checks until we've loaded all of the
	 *	dictionaries.  This means that errors are produced
	 *	later, but that shouldn't matter for the default
	 *	dictionaries.  They're supposed to work.
	 */
	fixup = talloc(fctx->pool, dict_fixup_clone_t);
	if (!fixup) {
		fr_strerror_const("Out of memory");
		return -1;
	}
	*fixup = (dict_fixup_clone_t) {
		.da = da,
		.ref = talloc_typed_strdup(fixup, ref)
	};

	return dict_fixup_common(&fctx->clone_enum, &fixup->common);
}

/** Clone one are of a tree into another
 *
 * @param[in] fctx		Holds current dictionary parsing information.
 * @param[in] fixup		Containing source/destination of the clone.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(always_inline) int dict_fixup_clone_enum_apply(UNUSED dict_fixup_ctx_t *fctx, dict_fixup_clone_t *fixup)
{
	fr_dict_attr_t const	*src;

	/*
	 *	This extension must already exist.
	 */
	fr_assert(fr_dict_attr_ext(fixup->da, FR_DICT_ATTR_EXT_ENUMV));

	/*
	 *	Find the referenced attribute, and validate it.
	 */
	(void) fr_dict_protocol_reference(&src, fixup->da->parent, &FR_SBUFF_IN_STR(fixup->ref));
	if (!src) {
		fr_strerror_printf_push("Failed resolving reference for attribute %s at %s[%d]",
					fixup->da->name, fr_cwd_strip(fixup->da->filename), fixup->da->line);
		return -1;
	}

	if (!fr_dict_attr_ext(src, FR_DICT_ATTR_EXT_ENUMV)) {
		fr_strerror_printf_push("Reference %s has no VALUEs defined at %s[%d]",
					fixup->ref, fr_cwd_strip(fixup->da->filename), fixup->da->line);
		return -1;
	}

	/*
	 *	Allow enums to be copied from any protocol, so long as the attribute is not a key, and not of
	 *	type 'attribute'.
	 */
	if (fr_dict_attr_is_key_field(src) || fr_dict_attr_is_key_field(fixup->da) || (src->type == FR_TYPE_ATTR)) {
		fr_strerror_printf("Cannot clone VALUEs from 'key=...' or type 'attribute' at %s[%d]",
				   fixup->da->filename, fixup->da->line);
		return -1;
	}

	if (fr_dict_attr_ref(src)) {
		fr_strerror_printf("References MUST NOT refer to an ATTRIBUTE which itself has a 'ref=...' at %s[%d]",
				   fr_cwd_strip(fixup->da->filename), fixup->da->line);
		return -1;
	}

	if (!dict_attr_ext_copy(&fixup->da, src, FR_DICT_ATTR_EXT_ENUMV)) {
		fr_strerror_printf("Reference copied no VALUEs from type type '%s' at %s[%d]",
					fr_type_to_str(fixup->da->type),
					fr_cwd_strip(fixup->da->filename), fixup->da->line);
		return -1;
	}

	fixup->da->flags.has_fixup = false;
	return 0;
}

/** Push a fixup for a VSA.
 *
 *  This is required so that we can define VENDORs for all VSAs, even
 *  if the dictionary doesn't contain VENDOR children for that VSA.
 *  This fixup means that we can define VENDORs elsewhere, and then
 *  use them in all VSA definitions.  It means that we don't have to
 *  do these lookups at run-time.
 *
 * @param[in] fctx		Holds current dictionary parsing information.
 * @param[in] da		The group dictionary attribute.
 * @return
 *	- 0 on success.
 *	- -1 on out of memory.
 */
int dict_fixup_vsa_enqueue(dict_fixup_ctx_t *fctx, fr_dict_attr_t *da)
{
	dict_fixup_vsa_t *fixup;

	fixup = talloc(fctx->pool, dict_fixup_vsa_t);
	if (!fixup) {
		fr_strerror_const("Out of memory");
		return -1;
	}
	*fixup = (dict_fixup_vsa_t) {
		.da = da,
	};

	return dict_fixup_common(&fctx->vsa, &fixup->common);
}

/** Run VSA fixups
 *
 * @param[in] fctx		Holds current dictionary parsing information.
 * @param[in] fixup		entry for fixup
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(always_inline) int dict_fixup_vsa_apply(UNUSED dict_fixup_ctx_t *fctx, dict_fixup_vsa_t *fixup)
{
	fr_dict_vendor_t *dv;
	fr_dict_t *dict = fr_dict_unconst(fr_dict_by_da(fixup->da));
	fr_hash_iter_t iter;

	if (!dict->vendors_by_num) return 0;

	for (dv = fr_hash_table_iter_init(dict->vendors_by_num, &iter);
	     dv;
	     dv = fr_hash_table_iter_next(dict->vendors_by_num, &iter)) {
		if (dict_attr_child_by_num(fixup->da, dv->pen)) continue;

		if (fr_dict_attr_add(dict, fixup->da, dv->name, dv->pen, FR_TYPE_VENDOR, NULL) < 0) return -1;
	}

	fixup->da->flags.has_fixup = false;
	return 0;
}


/** Resolve a group reference
 *
 * This is required as the reference may point to another dictionary which
 * hasn't been loaded yet.
 *
 * @param[in] fctx		Holds current dictionary parsing information.
 * @param[in] filename		this fixup relates to.
 * @param[in] line		this fixup relates to.
 * @param[in] alias_parent	where to add the alias.
 * @param[in] alias		alias to add.
 * @param[in] ref_parent	attribute that should contain the reference.
 * @param[in] ref		OID string representing what the group references.
 * @return
 *	- 0 on success.
 *	- -1 on out of memory.
 */
int dict_fixup_alias_enqueue(dict_fixup_ctx_t *fctx, char const *filename, int line,
			     fr_dict_attr_t *alias_parent, char const *alias,
			     fr_dict_attr_t *ref_parent, char const *ref)
{
	dict_fixup_alias_t *fixup;

	fixup = talloc(fctx->pool, dict_fixup_alias_t);
	if (!fixup) {
	oom:
		fr_strerror_const("Out of memory");
		return -1;
	}
	*fixup = (dict_fixup_alias_t) {
		.alias = talloc_typed_strdup(fixup, alias),
		.alias_parent = alias_parent,
		.ref = talloc_typed_strdup(fixup, ref),
		.ref_parent = ref_parent
	};

	fixup->filename = talloc_strdup(fixup, filename);
	if (!fixup->filename) goto oom;
	fixup->line = line;

	return dict_fixup_common(&fctx->alias, &fixup->common);
}

static inline CC_HINT(always_inline) int dict_fixup_alias_apply(UNUSED dict_fixup_ctx_t *fctx, dict_fixup_alias_t *fixup)
{
	fr_dict_attr_t const *da;

	/*
	 *	The <ref> can be a name.
	 */
	da = fr_dict_attr_by_oid(NULL, fixup->ref_parent, fixup->ref);
	if (!da) {
		fr_strerror_printf("Attribute '%s' aliased by '%s' doesn't exist in namespace '%s', at %s[%d]",
				   fixup->ref, fixup->alias, fixup->ref_parent->name, fixup->filename, fixup->line);
		return -1;
	}

	fr_dict_attr_unconst(da)->flags.has_fixup = false;
	return dict_attr_alias_add(fixup->alias_parent, fixup->alias, da, true);
}

/** Initialise a fixup ctx
 *
 * @param[in] ctx	to allocate the fixup pool in.
 * @param[in] fctx	to initialise.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int dict_fixup_init(TALLOC_CTX *ctx, dict_fixup_ctx_t *fctx)
{
	if (fctx->pool) return 0;

	fr_dlist_talloc_init(&fctx->enumv, dict_fixup_enumv_t, common.entry);
	fr_dlist_talloc_init(&fctx->group, dict_fixup_group_t, common.entry);
	fr_dlist_talloc_init(&fctx->clone, dict_fixup_clone_t, common.entry);
	fr_dlist_talloc_init(&fctx->clone_enum, dict_fixup_clone_t, common.entry);
	fr_dlist_talloc_init(&fctx->vsa, dict_fixup_vsa_t, common.entry);
	fr_dlist_talloc_init(&fctx->alias, dict_fixup_alias_t, common.entry);

	fctx->pool = talloc_pool(ctx, DICT_FIXUP_POOL_SIZE);
	if (!fctx->pool) return -1;

	return 0;
}

/** Apply all outstanding fixes to a set of dictionaries
 *
 */
int dict_fixup_apply(dict_fixup_ctx_t *fctx)
{

#define APPLY_FIXUP(_fctx, _list, _func, _type) \
do { \
	_type *_fixup; \
	while ((_fixup = fr_dlist_head(&(_fctx)->_list))) { \
		if (_func(_fctx, _fixup) < 0) return -1; \
		fr_dlist_remove(&(_fctx)->_list, _fixup); \
		talloc_free(_fixup); \
	} \
} while (0)

	/*
	 *	Apply all the fctx in order
	 *

	 *	- Enumerations first as they have no dependencies
	 *	- Group references next, as group attributes may be cloned.
	 *	- Clones last as all other references and additions should
	 *	  be applied before cloning.
	 *	- Clone enum clones the enumeration values from a dedicated
	 *	  enum, or another attribute with enumerations.
	 *	- VSAs
	 *	- Aliases last as all attributes need to be defined.
	 */
	APPLY_FIXUP(fctx, enumv,	dict_fixup_enumv_apply, dict_fixup_enumv_t);
	APPLY_FIXUP(fctx, group,	dict_fixup_group_apply, dict_fixup_group_t);
	APPLY_FIXUP(fctx, clone,	dict_fixup_clone_apply, dict_fixup_clone_t);
	APPLY_FIXUP(fctx, clone_enum,	dict_fixup_clone_enum_apply, dict_fixup_clone_t);
	APPLY_FIXUP(fctx, vsa,		dict_fixup_vsa_apply,   dict_fixup_vsa_t);
	APPLY_FIXUP(fctx, alias,	dict_fixup_alias_apply, dict_fixup_alias_t);

	TALLOC_FREE(fctx->pool);

	return 0;
}

/** Fixup all hash tables in the dictionary so they're suitable for threaded access
 *
 */
static int _dict_attr_fixup_hash_tables(fr_dict_attr_t const *da, UNUSED void *uctx)
{
	{
		fr_dict_attr_ext_enumv_t *ext;

		ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_ENUMV);
		if (ext) {
			if (ext->value_by_name) fr_hash_table_fill(ext->value_by_name);
			if (ext->name_by_value) fr_hash_table_fill(ext->name_by_value);
		}
	}

	{
		fr_hash_table_t	*hash;

		hash = dict_attr_namespace(da);
		if (hash) fr_hash_table_fill(hash);
	}

	return 0;
}

/** Walk a dictionary finalising the hash tables in all attributes with a distinct namespace
 *
 * @param[in] dict	to finalise namespaces for.
 */
void dict_hash_tables_finalise(fr_dict_t *dict)
{
	fr_dict_attr_t *root = fr_dict_attr_unconst(fr_dict_root(dict));

	(void)_dict_attr_fixup_hash_tables(root, NULL);

	fr_dict_walk(root, _dict_attr_fixup_hash_tables, NULL);

	/*
	 *	Walk over all of the hash tables to ensure they're
	 *	initialized.  We do this because the threads may perform
	 *	lookups, and we don't want multi-threaded re-ordering
	 *	of the table entries.  That would be bad.
	 */
	fr_hash_table_fill(dict->vendors_by_name);
	fr_hash_table_fill(dict->vendors_by_num);
}
