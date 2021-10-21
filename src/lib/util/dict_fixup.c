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
 * @copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/file.h>
#include "dict_fixup_priv.h"

/** Common fields for every fixup structure
 *
 */
typedef struct {
	fr_dlist_t		entry;			//!< Entry in linked list of fctx.

	char			*filename;		//!< where the line being fixed up.
	int			line;			//!< ditto.
} dict_fixup_common_t;

/** Add an enumeration value to an attribute that wasn't defined at the time the value was parsed
 *
 */
typedef struct {
	dict_fixup_common_t	common;			//!< Common fields.

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

	fr_dict_attr_t   	*parent;		//!< parent where we add the clone
	fr_dict_attr_t		*da;			//!< FR_TYPE_TLV to clone
	char 			*ref;			//!< the target attribute to clone
} dict_fixup_clone_t;

/** Dictionary attribute namespaces need their hash tables finalised
 *
 */
typedef struct {
	dict_fixup_common_t	common;			//!< Common fields.

	fr_hash_table_t		*hash;			//!< We need to finalise.
} dict_fixup_hash_t;

/** Initialise common fields in fixup struct, and add it to a fixup list
 *
 * @param[in] filename		this fixup relates to.
 * @param[in] line		this fixup relates to.
 * @param[in] fixup_list	to add fixup to.
 * @param[in] common		common header to populate.
 * @return
 *	- 0 on success.
 *	- -1 on out of memory.
 */
static inline CC_HINT(always_inline) int dict_fixup_common(char const *filename, int line,
							   fr_dlist_head_t *fixup_list, dict_fixup_common_t *common)
{
	common->filename = talloc_strdup(common, filename);
	if (!common->filename) {
		fr_strerror_const("Out of memory");
		return -1;
	}
	common->line = line;

	fr_dlist_insert_tail(fixup_list, common);

	return 0;
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
 * @return
 *	- 0 on success.
 *	- -1 on out of memory.
 */
int dict_fixup_enumv(dict_fixup_ctx_t *fctx, char const *filename, int line,
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

	return dict_fixup_common(filename, line, &fctx->enumv, &fixup->common);
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
	fr_value_box_t		value;
	fr_type_t		type;
	int			ret;
	fr_dict_attr_t const	*da_const;

	da_const = fr_dict_attr_by_oid(NULL, fixup->parent, fixup->attribute);
	if (!da_const) {
		fr_strerror_printf_push("Failed resolving ATTRIBUTE referenced by VALUE '%s' at %s[%d]",
					fixup->name, fr_cwd_strip(fixup->common.filename), fixup->common.line);
		return -1;
	}
	da = fr_dict_attr_unconst(da_const);
	type = da->type;

	if (fr_value_box_from_str(fixup, &value, type, NULL,
				  fixup->value, talloc_array_length(fixup->value) - 1, '\0', false) < 0) {
		fr_strerror_printf_push("Invalid VALUE for Attribute '%s' at %s[%d]",
					da->name,
					fr_cwd_strip(fixup->common.filename), fixup->common.line);
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
 * @param[in] filename		this fixup relates to.
 * @param[in] line		this fixup relates to.
 * @param[in] da		The group dictionary attribute.
 * @param[in] ref		OID string representing what the group references.
 * @param[in] ref_len		Length of the reference string.
 * @return
 *	- 0 on success.
 *	- -1 on out of memory.
 */
int dict_fixup_group(dict_fixup_ctx_t *fctx, char const *filename, int line,
		     fr_dict_attr_t *da, char const *ref, size_t ref_len)
{
	dict_fixup_group_t *fixup;

	fixup = talloc(fctx->pool, dict_fixup_group_t);
	if (!fixup) {
		fr_strerror_const("Out of memory");
		return -1;
	}
	*fixup = (dict_fixup_group_t) {
		.da = da,
		.ref = talloc_bstrndup(fixup, ref, ref_len)
	};

	return dict_fixup_common(filename, line, &fctx->group, &fixup->common);
}

static fr_dict_attr_t const *dict_find_or_load_reference(fr_dict_t **dict_def, char const *ref, char const *filename, int line)
{
	fr_dict_t		*dict;
	fr_dict_attr_t const	*da;
	char			*p;
	ssize_t			slen;

	da = fr_dict_attr_by_oid(NULL, fr_dict_root(*dict_def), ref);
	if (da) return da;

	/*
	 *	The attribute doesn't exist, and the reference
	 *	isn't in a "PROTO.ATTR" format, die.
	 */
	p = strchr(ref, '.');

	/*
	 *	Get / skip protocol name.
	 */
	slen = dict_by_protocol_substr(NULL,
				       &dict, &FR_SBUFF_IN(ref, strlen(ref)),
				       *dict_def);
	if (slen <= 0) {
		fr_dict_t *other;

		if (p) *p = '\0';

		/*
		 *	Can't load the dictionary we're loading.
		 */
		if (dict == *dict_def) {
			fr_strerror_printf("Cannot reference parent dictionary %s from within the same dictionary", fr_dict_root(dict)->name);
			return NULL;
		}

		if (fr_dict_protocol_afrom_file(&other, ref, NULL, filename) < 0) {
			return NULL;
		}

		if (p) *p = '.';

		/*
		 *	Grab the protocol name again
		 */
		dict = other;
		if (!p) {
			*dict_def = other;
			return other->root;
		}

		slen = p - ref;
	}

	if (slen < 0) {
	invalid_reference:
		fr_strerror_printf("Invalid attribute reference '%s' at %s[%d]",
				   ref,
				   fr_cwd_strip(filename), line);
		return NULL;
	}

	/*
	 *	No known dictionary, so we're asked to just
	 *	use the whole string.  Which we did above.  So
	 *	either it's a bad ref, OR it's a ref to a
	 *	dictionary which doesn't exist.
	 */
	if (slen == 0) goto invalid_reference;

	/*
	 *	Look up the attribute.
	 */
	da = fr_dict_attr_by_oid(NULL, fr_dict_root(dict), ref + slen + 1);
	if (!da) {
		fr_strerror_printf("No such attribute '%s' in reference at %s[%d]",
				   ref + slen + 1, fr_cwd_strip(filename), line);
		return NULL;
	}

	*dict_def = dict;
	return da;
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
	fr_dict_t *dict = fr_dict_unconst(fr_dict_by_da(fixup->da));

	/*
	 *
	 *	We avoid refcount loops by using the "autoref"
	 *	table.  If a "group" attribute refers to a
	 *	dictionary which does not exist, we load it,
	 *	increment its reference count, and add it to
	 *	the autoref table.
	 *
	 *	If a group attribute refers to a dictionary
	 *	which does exist, we check that dictionaries
	 *	"autoref" table.  If OUR dictionary is there,
	 *	then we do nothing else.  That dictionary
	 *	points to us via refcounts, so we can safely
	 *	point to it.  The refcounts ensure that we
	 *	won't be free'd before the other one is
	 *	free'd.
	 *
	 *	If our dictionary is NOT in the other
	 *	dictionaries autoref table, then it was loaded
	 *	via some other method.  We increment its
	 *	refcount, and add it to our autoref table.
	 *
	 *	Then when this dictionary is being free'd, we
	 *	also free the dictionaries in our autoref
	 *	table.
	 */
	da = dict_find_or_load_reference(&dict, fixup->ref, fixup->common.filename, fixup->common.line);
	if (!da) return -1;

	if (da->type != FR_TYPE_TLV) {
		fr_strerror_printf("References MUST be to attributes of type 'tlv' at %s[%d]",
				   fr_cwd_strip(fixup->common.filename), fixup->common.line);
		return -1;
	}

	if (fr_dict_attr_ref(da)) {
		fr_strerror_printf("References MUST NOT refer to an ATTRIBUTE which also has 'ref=...' at %s[%d]",
				   fr_cwd_strip(fixup->common.filename), fixup->common.line);
		return -1;
	}
	dict_attr_ref_set(fixup->da, da);

	return 0;
}

/** Clone one area of a tree into another
 *
 * These must be processed later to ensure that we've finished building an
 * attribute by the time it has been cloned.
 *
 * @param[in] fctx		Holds current dictionary parsing information.
 * @param[in] filename		this fixup relates to.
 * @param[in] line		this fixup relates to.
 * @param[in] da		The group dictionary attribute.
 * @param[in] ref		OID string representing what the group references.
 * @param[in] ref_len		Length of the reference string.
 * @return
 *	- 0 on success.
 *	- -1 on out of memory.
 */
int dict_fixup_clone(dict_fixup_ctx_t *fctx, char const *filename, int line,
		     fr_dict_attr_t *parent, fr_dict_attr_t *da,
		     char const *ref, size_t ref_len)
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
		.parent = parent,
		.da = da,
		.ref = talloc_bstrndup(fixup, ref, ref_len)
	};

	return dict_fixup_common(filename, line, &fctx->clone, &fixup->common);
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
	fr_dict_attr_t const	*da;
	fr_dict_attr_t		*cloned;
	fr_dict_t		*dict = fr_dict_unconst(fr_dict_by_da(fixup->da));

	/*
	 *	We can't clone our parents.
	 */
	da = fr_dict_attr_by_oid(NULL, fr_dict_root(dict), fixup->ref);
	if (da) {
		/*
		 *	The referenced DA is higher than the one we're
		 *	creating.  Ensure it's not a parent.
		 */
		if (da->depth < fixup->da->depth) {
			fr_dict_attr_t const *parent;

			for (parent = fixup->da->parent; !parent->flags.is_root; parent = parent->parent) {
				if (parent == da) {
					fr_strerror_printf("References MUST NOT refer to a parent attribute %s at %s[%d]",
							   parent->name, fr_cwd_strip(fixup->common.filename), fixup->common.line);
					return -1;
				}
			}
		}
	} else {
		da = dict_find_or_load_reference(&dict, fixup->ref, fixup->common.filename, fixup->common.line);
		if (!da) return -1;
	}

	if (fr_dict_attr_ref(da)) {
		fr_strerror_printf("References MUST NOT refer to an ATTRIBUTE which itself has a 'ref=...' at %s[%d]",
				   fr_cwd_strip(fixup->common.filename), fixup->common.line);
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
	if (!fr_type_is_non_leaf(fixup->da->type) &&
	    ((da->type != fixup->da->type) || !dict_attr_children(da))) {
		int copied;

		/*
		 *	Structural types cannot be the source or destination of clones.
		 *
		 *	Leaf types can be cloned, even if they're
		 *	different types.  But only if they don't have
		 *	children (i.e. key fields).
		 */
		if (fr_type_is_non_leaf(da->type) || fr_type_is_non_leaf(fixup->da->type) ||
		    dict_attr_children(da) || dict_attr_children(fixup->da)) {
			fr_strerror_printf("Reference MUST be to a simple data type of type '%s' at %s[%d]",
					   fr_table_str_by_value(fr_value_box_type_table, fixup->da->type, "<UNKNOWN>"),
					   fr_cwd_strip(fixup->common.filename), fixup->common.line);
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
		copied = dict_attr_acopy_enumv(fixup->da, da);
		if (copied < 0) return -1;

		if (!copied) {
			fr_strerror_printf("Reference copied no VALUEs from type type '%s' at %s[%d]",
					   fr_table_str_by_value(fr_value_box_type_table, fixup->da->type, "<UNKNOWN>"),
					   fr_cwd_strip(fixup->common.filename), fixup->common.line);
			return -1;
		}

		/*
		 *	We don't need to copy any children, so leave
		 *	fixup->da in the dictionary.
		 */
		return 0;
	}

	/*
	 *	Can't clone KEY fields directly, you MUST clone the parent struct.
	 */
	if (!fr_type_is_non_leaf(da->type) || fr_dict_attr_is_key_field(da) || fr_dict_attr_is_key_field(fixup->da)) {
		fr_strerror_printf("Invalid reference from '%s' to %s", fixup->ref, da->name);
		return -1;
	}

	/*
	 *	Copy the source attribute, but with a
	 *	new name and a new attribute number.
	 */
	cloned = dict_attr_acopy(dict->pool, da, fixup->da->name);
	if (!cloned) {
		fr_strerror_printf("Failed copying attribute '%s' to %s", da->name, fixup->ref);
		return -1;
	}

	cloned->attr = fixup->da->attr;
	cloned->parent = fixup->parent; /* we need to re-parent this attribute */
	cloned->depth = cloned->parent->depth + 1;

	/*
	 *	Copy any pre-existing children over.
	 */
	if (dict_attr_children(fixup->da)) {
		if (dict_attr_acopy_children(dict, cloned, fixup->da) < 0) {
			fr_strerror_printf("Failed copying attribute '%s' from children of %s", da->name, fixup->ref);
			return -1;
		}
	}

	/*
	 *	Copy children of the DA we're cloning.
	 */
	if (dict_attr_children(da)) {
		if (dict_attr_acopy_children(dict, cloned, da) < 0) {
			fr_strerror_printf("Failed copying attribute '%s' from children of %s", da->name, fixup->ref);
			return -1;
		}

		if (dict_attr_child_add(fr_dict_attr_unconst(fixup->parent), cloned) < 0) {
			fr_strerror_printf("Failed adding attribute %s", da->name);
			talloc_free(cloned);
			return -1;
		}
	}

	if (dict_attr_add_to_namespace(fixup->parent, cloned) < 0) return -1;

	return 0;
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
	 *	- Hash table fctx last.
	 */
	APPLY_FIXUP(fctx, enumv, dict_fixup_enumv_apply, dict_fixup_enumv_t);
	APPLY_FIXUP(fctx, group, dict_fixup_group_apply, dict_fixup_group_t);
	APPLY_FIXUP(fctx, clone, dict_fixup_clone_apply, dict_fixup_clone_t);

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
