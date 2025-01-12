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
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/talloc.h>
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

/** Resolve a ref= or copy= value to a dictionary */

/** Resolve a reference string to a dictionary attribute
 *
 * @param[in] rel		Relative attribute to resolve from.
 * @param[in] ref		Reference string.
 * @param[in] absolute_root	If true, and there is no '.' prefix, searching will begin from
 *				the root of the dictionary, else we pretend there was a '.' and
 *				search from rel.
 */
fr_dict_attr_t const *dict_protocol_reference(fr_dict_attr_t const *rel, char const *ref, bool absolute_root)
{
	fr_dict_t			*dict = fr_dict_unconst(rel->dict);
	fr_dict_attr_t const		*da = rel, *found;
	ssize_t				slen;
	fr_sbuff_t			sbuff = FR_SBUFF_IN(ref, strlen(ref));

	/*
	 *	Are we resolving a foreign reference?
	 */
	if (fr_sbuff_next_if_char(&sbuff, '@')) {
		char proto_name[FR_DICT_ATTR_MAX_NAME_LEN + 1];
		fr_sbuff_t proto_name_sbuff = FR_SBUFF_OUT(proto_name, sizeof(proto_name));

		slen = dict_by_protocol_substr(NULL, &dict, &sbuff, NULL);
		/* Need to load it... */
		if (slen <= 0) {
			/* Quiet coverity */
			fr_sbuff_terminate(&proto_name_sbuff);

			/* Fixme, probably want to limit allowed chars */
			if (fr_sbuff_out_bstrncpy_until(&proto_name_sbuff, &sbuff, SIZE_MAX,
							&FR_SBUFF_TERMS(L(""), L(".")), NULL) <= 0) {
			invalid_name:
				fr_strerror_const("Invalid protocol name");
				return NULL;
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
				return NULL;
			}

			if (!fr_hash_table_insert((rel->dict)->autoref, dict)) {
				fr_strerror_const("Failed inserting into internal autoref table");
				return NULL;
			}
		}

		/*
		 *	Didn't stop at an attribute ref... we're done
		 */
		if (!fr_sbuff_next_if_char(&sbuff, '.')) {
			return dict->root;
		}

		da = dict->root;
	}

	/*
	 *	First '.' makes it reletive, subsequent ones traverse up the tree.
	 *
	 *	No '.' means use the root.
	 */
	if (fr_sbuff_next_if_char(&sbuff, '.')) {
		while (fr_sbuff_next_if_char(&sbuff, '.')) {
			if (!da->parent) {
				fr_strerror_const("Reference attempted to navigate above dictionary root");
				return NULL;
			}
			da = da->parent;
		}
	} else {
		da = absolute_root ? dict->root : rel;
	}

	/*
	 *	Look up the attribute.
	 */
	if (fr_dict_attr_by_oid_substr(NULL, &found, da, &sbuff, NULL) <= 0) return NULL;

	return found;
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
				  NULL, false) < 0) {
		fr_strerror_printf_push("Invalid VALUE '%pV' for attribute '%s' at %s[%d]",
					fr_box_strvalue_buffer(fixup->value),
					da->name,
					fr_cwd_strip(fixup->filename), fixup->line);
		return -1;
	}

	ret = fr_dict_enum_add_name(da, fixup->name, &value, false, false);
	fr_value_box_clear(&value);

	if (ret < 0) return -1;

	return 0;
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

	da = dict_protocol_reference(fixup->da->parent, fixup->ref, true);
	if (!da) {
		fr_strerror_printf_push("Failed resolving reference for attribute at %s[%d]",
					fr_cwd_strip(fixup->da->filename), fixup->da->line);
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
	if (unlikely(dict_attr_ref_resolve(fixup->da, da) < 0)) return -1;

	return 0;
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
	fr_dict_attr_t		*cloned;

	if (src->dict->proto != dst->dict->proto) {
		fr_strerror_printf("Incompatible protocols.  Referenced '%s', referencing '%s'.  Defined at %s[%d]",
				   src->dict->proto->name, dst->dict->proto->name, dst->filename, dst->line);
		return -1;
	}

	/*
	 *	The referenced DA is higher than the one we're
	 *	creating.  Ensure it's not a parent.
	 */
	if (src->depth < dst->depth) {
		fr_dict_attr_t const *parent;

		for (parent = dst->parent; !parent->flags.is_root; parent = parent->parent) {
			if (parent == src) {
				fr_strerror_printf("References MUST NOT refer to a parent attribute %s at %s[%d]",
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
	 *	If the attributes are of different types, then we have
	 *	to _manually_ clone the values.  This means looping
	 *	over the ref da, and _casting_ the values to the new
	 *	data type.  If the cast succeeds, we add the value.
	 *	Otherwise we don't
	 *
	 *	We do this if the source type is a leaf node, AND the
	 *	types are different, or the destination has no
	 *	children.
	 */
	if (!fr_type_is_non_leaf(dst->type) &&
	    ((src->type != dst->type) || !dict_attr_children(src))) {
		int copied;

		/*
		 *	Only TLV and STRUCT types can be the source or destination of clones.
		 *
		 *	Leaf types can be cloned, even if they're
		 *	different types.  But only if they don't have
		 *	children (i.e. key fields).
		 */
		if (fr_type_is_non_leaf(src->type) || fr_type_is_non_leaf(dst->type) ||
		    dict_attr_children(src) || dict_attr_children(dst)) {
			fr_strerror_printf("Reference MUST be to a simple data type of type '%s' at %s[%d]",
					   fr_type_to_str(dst->type),
					   fr_cwd_strip(dst->filename), dst->line);
			return -1;
		}

		/*
		 *	We copy all of the VALUEs over from the source
		 *	da by hand, by casting them.
		 *
		 *	We have to do this work manually because we
		 *	can't call dict_attr_acopy(), as that function
		 *	copies the VALUE with the *source* data type,
		 *	where we need the *destination* data type.
		 */
		copied = dict_attr_acopy_enumv(dst, src);
		if (copied < 0) return -1;

		if (!copied) {
			fr_strerror_printf("Reference copied no VALUEs from type type '%s' at %s[%d]",
					   fr_type_to_str(dst->type),
					   fr_cwd_strip(dst->filename), dst->line);
			return -1;
		}

		return 0;
	}

	/*
	 *	Can't clone KEY fields directly, you MUST clone the parent struct.
	 */
	if (!fr_type_is_non_leaf(src->type) || fr_dict_attr_is_key_field(src) || fr_dict_attr_is_key_field(dst)) {
		fr_strerror_printf("Invalid reference from '%s' to %s", dst->name, src->name);
		return -1;
	}

	/*
	 *	Copy the source attribute, but with a
	 *	new name and a new attribute number.
	 */
	cloned = dict_attr_acopy(dict->pool, src, dst->name);
	if (!cloned) {
		fr_strerror_printf("Failed copying attribute '%s' to %s", src->name, dst->name);
		return -1;
	}

	cloned->attr = dst->attr;
	cloned->parent = dst->parent; /* we need to re-parent this attribute */
	cloned->depth = cloned->parent->depth + 1;

	/*
	 *	Copy any pre-existing children over.
	 */
	if (dict_attr_children(dst)) {
		if (dict_attr_acopy_children(dict, cloned, dst) < 0) {
			fr_strerror_printf("Failed populating attribute '%s' with children of %s", src->name, dst->name);
			return -1;
		}
	}

	/*
	 *	Copy children of the DA we're cloning.
	 */
	if (dict_attr_children(src)) {
		if (dict_attr_acopy_children(dict, cloned, src) < 0) {
			fr_strerror_printf("Failed populating attribute '%s' with children of %s", src->name, dst->name);
			return -1;
		}
	}

	if (fr_dict_attr_add_initialised(cloned) < 0) {
		talloc_free(cloned);
		return -1;
	}

	/*
	 *	Free the original and pass back our new cloned attribute
	 */
	talloc_free(dst);
	*dst_p = cloned;

	return 0;
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

	src = dict_protocol_reference(fixup->da->parent, fixup->ref, true);
	if (!src) {
		fr_strerror_printf_push("Failed resolving reference for attribute at %s[%d]",
					fr_cwd_strip(fixup->da->filename), fixup->da->line);
		return -1;
	}

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
	int			copied;

	src = dict_protocol_reference(fixup->da->parent, fixup->ref, true);
	if (!src) {
		fr_strerror_printf_push("Failed resolving reference for attribute at %s[%d]",
					fr_cwd_strip(fixup->da->filename), fixup->da->line);
		return -1;
	}

	if (src->dict->proto != fixup->da->dict->proto) {
		fr_strerror_printf("Incompatible protocols.  Referenced '%s', referencing '%s'.  Defined at %s[%d]",
				   src->dict->proto->name, fixup->da->dict->proto->name, fixup->da->filename, fixup->da->line);
		return -1;
	}

	if (fr_dict_attr_ref(src)) {
		fr_strerror_printf("References MUST NOT refer to an ATTRIBUTE which itself has a 'ref=...' at %s[%d]",
				   fr_cwd_strip(fixup->da->filename), fixup->da->line);
		return -1;
	}

	if (!fr_type_is_non_leaf(fixup->da->type)) {
		fr_strerror_printf("enum copy can only be applied to leaf types, not %s", fr_type_to_str(fixup->da->type));
		return -1;
	}

	if (src->type != fixup->da->type) {
		fr_strerror_printf("enum copy type mismatch.  src '%s', dst '%s'",
				   fr_type_to_str(src->type), fr_type_to_str(fixup->da->type));
		return -1;
	}

	/*
	 *	We copy all of the VALUEs over from the source
	 *	da by hand, by casting them.
	 *
	 *	We have to do this work manually because we
	 *	can't call dict_attr_acopy(), as that function
	 *	copies the VALUE with the *source* data type,
	 *	where we need the *destination* data type.
	 */
	copied = dict_attr_acopy_enumv(fixup->da, src);
	if (copied < 0) return -1;

	if (!copied) {
		fr_strerror_printf("Reference copied no VALUEs from type type '%s' at %s[%d]",
					fr_type_to_str(fixup->da->type),
					fr_cwd_strip(fixup->da->filename), fixup->da->line);
		return -1;
	}

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

	return dict_attr_alias_add(fixup->alias_parent, fixup->alias, da);
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
