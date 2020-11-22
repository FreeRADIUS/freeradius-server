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

/** Deal with 'unknown' attributes, creating ephemeral dictionary attributes for them
 *
 * @file src/lib/util/dict_unknown.c
 *
 * @copyright 2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/dict_priv.h>

/** Copy a known or unknown attribute to produce an unknown attribute with the specified name
 *
 * Will copy the complete hierarchy down to the first known attribute.
 */
fr_dict_attr_t *fr_dict_unknown_acopy(TALLOC_CTX *ctx, fr_dict_attr_t const *da, char const *new_name)
{
	fr_dict_attr_t		*n;
	fr_dict_attr_t const	*parent;
	fr_dict_attr_flags_t	flags = da->flags;
	fr_type_t		type = da->type;

	/*
	 *	Set the unknown flag, and clear other flags which are
	 *	no longer relevant.
	 */
	flags.is_unknown = 1;
	flags.array = 0;
	flags.has_value = 0;

	/*
	 *	Allocate an attribute.
	 */
	n = dict_attr_alloc_null(ctx);
	if (!n) return NULL;

	/*
	 *	We want to have parent / child relationships, AND to
	 *	copy all unknown parents, AND to free the unknown
	 *	parents when this 'da' is freed.  We therefore talloc
	 *	the parent from the 'da'.
	 */
	if (da->parent->flags.is_unknown) {
		parent = fr_dict_unknown_acopy(n, da->parent, NULL);
		if (!parent) {
			talloc_free(n);
			return NULL;
		}

	} else {
		parent = da->parent;
	}

	/*
	 *	VENDOR and TLV are structural, and can have unknown
	 *	children.  But they're left alone.  All other base
	 *	types are mangled to OCTETs.
	 */
	switch (type) {
	case FR_TYPE_VENDOR:
	case FR_TYPE_TLV:
	case FR_TYPE_VSA:
		break;

	default:
		type = FR_TYPE_OCTETS;
		break;
	}

	/*
	 *	Initialize the rest of the fields.
	 */
	dict_attr_init(&n, parent, new_name ? new_name : da->name, da->attr, type, &flags);
	dict_attr_ext_copy_all(&n, da);
	DA_VERIFY(n);

	return n;
}

/** Converts an unknown to a known by adding it to the internal dictionaries.
 *
 * Does not free old #fr_dict_attr_t, that is left up to the caller.
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] old		unknown attribute to add.
 * @return
 *	- Existing #fr_dict_attr_t if old was found in a dictionary.
 *	- A new entry representing old.
 */
fr_dict_attr_t const *fr_dict_unknown_add(fr_dict_t *dict, fr_dict_attr_t const *old)
{
	fr_dict_attr_t const *da;
	fr_dict_attr_t const *parent;
	fr_dict_attr_flags_t flags;

	if (unlikely(dict->read_only)) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root(dict)->name);
		return NULL;
	}

	da = fr_dict_attr_by_name(NULL, old->parent, old->name);
	if (da) return da;

	/*
	 *	Define the complete unknown hierarchy
	 */
	if (old->parent && old->parent->flags.is_unknown) {
		parent = fr_dict_unknown_add(dict, old->parent);
		if (!parent) {
			fr_strerror_printf_push("Failed adding parent \"%s\"", old->parent->name);
			return NULL;
		}
	} else {
#ifdef __clang_analyzer__
		if (!old->parent) return NULL;
#endif
		parent = old->parent;
	}

	memcpy(&flags, &old->flags, sizeof(flags));
	flags.is_unknown = 0;

	/*
	 *	If this is a vendor, we skip most of the sanity
	 *	checks and add it to the vendor hash, and add it
	 *	as a child attribute to the Vendor-Specific
	 *	container.
	 */
	if (old->type == FR_TYPE_VENDOR) {
		fr_dict_attr_t *mutable, *n;

		if (dict_vendor_add(dict, old->name, old->attr) < 0) return NULL;

		n = dict_attr_alloc(dict->pool, parent, old->name, old->attr, old->type, &flags);
		if (unlikely(!n)) return NULL;

		/*
		 *	Setup parenting for the attribute
		 */
		memcpy(&mutable, &old->parent, sizeof(mutable));
		if (dict_attr_child_add(mutable, n) < 0) return NULL;

		return n;
	}

	/*
	 *	Look up the attribute by number.  If it doesn't exist,
	 *	add it both by name and by number.  If it does exist,
	 *	add it only by name.
	 */
	da = fr_dict_attr_child_by_num(parent, old->attr);
	if (da) {
		fr_dict_attr_t *n;

		n = dict_attr_alloc(dict->pool, parent, old->name, old->attr, old->type, &flags);
		if (!n) return NULL;

		/*
		 *	Add the unknown by NAME.  e.g. if the admin does "Attr-26", we want
		 *	to return "Attr-26", and NOT "Vendor-Specific".  The rest of the server
		 *	is responsible for converting "Attr-26 = 0x..." to an actual attribute,
		 *	if it so desires.
		 */
		if (dict_attr_add_to_namespace(dict, parent, n) < 0) {
			talloc_free(n);
			return NULL;
		}

		return n;
	}

#ifdef __clang_analyzer__
	if (!old->name) return NULL;
#endif

	/*
	 *	Add the attribute by both name and number.
	 *
	 *	Fixme - Copy extensions?
	 */
	if (fr_dict_attr_add(dict, parent, old->name, old->attr, old->type, &flags) < 0) return NULL;

	/*
	 *	For paranoia, return it by name.
	 */
	return fr_dict_attr_by_name(NULL, parent, old->name);
}

/** Free dynamically allocated (unknown attributes)
 *
 * If the da was dynamically allocated it will be freed, else the function
 * will return without doing anything.
 *
 * @param[in] da to free.
 */
void fr_dict_unknown_free(fr_dict_attr_t const **da)
{
	fr_dict_attr_t **tmp;

	if (!da || !*da) return;

	/* Don't free real DAs */
	if (!(*da)->flags.is_unknown) {
		return;
	}

	memcpy(&tmp, &da, sizeof(*tmp));
	talloc_free(*tmp);

	*tmp = NULL;
}
/** Allocates an unknown attribute
 *
 * @note If vendor != 0, an unknown vendor (may) also be created, parented by
 *	the correct VSA attribute. This is accessible via da->parent,
 *	and will be use the unknown da as its talloc parent.
 *
 * @param[in] ctx		to allocate DA in.
 * @param[in] parent		of the unknown attribute (may also be unknown).
 * @param[in] attr		number.
 * @param[in] vendor		number.
 * @return 0 on success.
 */
fr_dict_attr_t const *fr_dict_unknown_afrom_fields(TALLOC_CTX *ctx, fr_dict_attr_t const *parent,
						   unsigned int vendor, unsigned int attr)
{
	fr_dict_attr_t const	*da;
	fr_dict_attr_t		*n;
	fr_dict_attr_t		*new_parent = NULL;
	fr_dict_attr_flags_t	flags = {
					.is_unknown	= 1
				};

	if (!fr_cond_assert(parent)) {
		fr_strerror_printf("%s: Invalid argument - parent was NULL", __FUNCTION__);
		return NULL;
	}

	/*
	 *	If there's a vendor specified, we check to see
	 *	if the parent is a VSA, and if it is
	 *	we either lookup the vendor to get the correct
	 *	attribute, or bridge the gap in the tree, with an
	 *	unknown vendor.
	 *
	 *	We need to do the check, as the parent could be
	 *	a TLV, in which case the vendor should be known
	 *	and we don't need to modify the parent.
	 */
	if (vendor && (parent->type == FR_TYPE_VSA)) {
		da = fr_dict_attr_child_by_num(parent, vendor);
		if (!da) {
			if (fr_dict_unknown_vendor_afrom_num(ctx, &new_parent, parent, vendor) < 0) return NULL;
			da = new_parent;
		}
		parent = da;

	/*
	 *	Need to clone the unknown hierachy, as unknown
	 *	attributes must parent the complete heirachy,
	 *	and cannot share any parts with any other unknown
	 *	attributes.
	 */
	} else if (parent->flags.is_unknown) {
		new_parent = fr_dict_unknown_acopy(ctx, parent, NULL);
		parent = new_parent;
	}

	n = dict_attr_alloc(ctx, parent, NULL, attr, FR_TYPE_OCTETS, &flags);
	if (!n) return NULL;

	/*
	 *	The config files may reference the unknown by name.
	 *	If so, use the pre-defined name instead of an unknown
	 *	one!
	 */
	da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_by_da(parent)), n->name);
	if (da) {
		fr_dict_unknown_free(&parent);
		parent = n;
		fr_dict_unknown_free(&parent);
		return da;
	}

	/*
	 *	Ensure the parent is freed at the same time as the
	 *	unknown DA.  This should be OK as we never parent
	 *	multiple unknown attributes off the same parent.
	 */
	if (new_parent && new_parent->flags.is_unknown) talloc_steal(n, new_parent);

	return n;
}

/** Build an unknown vendor, parented by a VSA attribute
 *
 * This allows us to complete the path back to the dictionary root in the case
 * of unknown attributes with unknown vendors.
 *
 * @note Will return known vendors attributes where possible.  Do not free directly,
 *	use #fr_dict_unknown_free.
 *
 * @param[in] ctx to allocate the vendor attribute in.
 * @param[out] out		Where to write point to new unknown dict attr
 *				representing the unknown vendor.
 * @param[in] parent		of the VSA attribute.
 * @param[in] vendor		id.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_unknown_vendor_afrom_num(TALLOC_CTX *ctx, fr_dict_attr_t **out,
				     fr_dict_attr_t const *parent, unsigned int vendor)
{
	fr_dict_attr_flags_t	flags = {
					.is_unknown = 1,
					.type_size = 1,
					.length = 1
				};

	if (!fr_cond_assert(parent)) {
		fr_strerror_printf("%s: Invalid argument - parent was NULL", __FUNCTION__);
		return -1;
	}

	*out = NULL;

	/*
	 *	Vendor attributes can occur under VSA attribute.
	 */
	switch (parent->type) {
	case FR_TYPE_VSA:
		if (!fr_cond_assert(!parent->flags.is_unknown)) return -1;

		*out = dict_attr_alloc(ctx, parent, NULL, vendor, FR_TYPE_VENDOR, &flags);

		return 0;

	case FR_TYPE_VENDOR:
		if (!fr_cond_assert(!parent->flags.is_unknown)) return -1;
		fr_strerror_printf("Unknown vendor cannot be parented by another vendor");
		return -1;

	default:
		fr_strerror_printf("Unknown vendors can only be parented by 'vsa' or 'evs' "
				   "attributes, not '%s'", fr_table_str_by_value(fr_value_box_type_table, parent->type, "?Unknown?"));
		return -1;
	}
}

/** Initialise a fr_dict_attr_t from a number
 *
 * @copybrief fr_dict_unknown_afrom_fields
 *
 * @param[in] ctx		to allocate the attribute in.
 * @param[out] out		Where to write the new attribute to.
 * @param[in] parent		of the unknown attribute (may also be unknown).
 * @param[in] num		of the unknown attribute.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_unknown_tlv_afrom_num(TALLOC_CTX *ctx, fr_dict_attr_t **out,
				  fr_dict_attr_t const *parent, unsigned int num)
{
	fr_dict_attr_t		*da;
	fr_dict_attr_flags_t	flags = {
					.is_unknown = true,
				};

	switch (parent->type) {
	case FR_TYPE_STRUCTURAL_EXCEPT_VSA:
		fr_strerror_printf("%s: Cannot allocate unknown tlv attribute (%u) with parent type %s",
				   __FUNCTION__,
				   num,
				   fr_table_str_by_value(fr_value_box_type_table, parent->type, "<INVALID>"));
		return -1;

	default:
		break;
	}

	*out = NULL;

	da = dict_attr_alloc(ctx, parent, NULL, num, FR_TYPE_TLV, &flags);
	if (!da) return -1;

	*out = da;

	return 0;
}

/** Initialise a fr_dict_attr_t from a number
 *
 * @copybrief fr_dict_unknown_afrom_fields
 *
 * @param[in] ctx		to allocate the attribute in.
 * @param[out] out		Where to write the new attribute to.
 * @param[in] parent		of the unknown attribute (may also be unknown).
 * @param[in] num		of the unknown attribute.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_unknown_attr_afrom_num(TALLOC_CTX *ctx, fr_dict_attr_t **out,
				   fr_dict_attr_t const *parent, unsigned int num)
{
	fr_dict_attr_t		*da;
	fr_dict_attr_flags_t	flags = {
					.is_unknown = true,
				};

	switch (parent->type) {
	case FR_TYPE_STRUCTURAL_EXCEPT_VSA:
		break;

	default:
		fr_strerror_printf("%s: Cannot allocate unknown octets attribute (%u) with parent type %s",
				   __FUNCTION__,
				   num,
				   fr_table_str_by_value(fr_value_box_type_table, parent->type, "<INVALID>"));
		return -1;
	}

	*out = NULL;

	da = dict_attr_alloc(ctx, parent, NULL, num, FR_TYPE_OCTETS, &flags);
	if (!da) return -1;

	*out = da;

	return 0;
}

/** Create a fr_dict_attr_t from an ASCII attribute and value
 *
 * Where the attribute name is in the form:
 *  - Attr-%d
 *  - Attr-%d.%d.%d...
 *
 * @copybrief fr_dict_unknown_afrom_fields
 *
 * @note If vendor != 0, an unknown vendor (may) also be created, parented by
 *	the correct VSA attribute. This is accessible via vp->parent,
 *	and will be use the unknown da as its talloc parent.
 *
 * @param[in] ctx		to alloc new attribute in.
 * @param[out] out		Where to write the head of the chain unknown
 *				dictionary attributes.
 * @param[in] parent		Attribute to use as the root for resolving OIDs in.
 *				Usually the root of a protocol dictionary.
 * @param[in] in		of attribute.
 * @return
 *	- The number of bytes parsed on success.
 *	- <= 0 on failure.  Negative offset indicates parse error position.
 */
ssize_t fr_dict_unknown_afrom_oid_substr(TALLOC_CTX *ctx,
					 fr_dict_attr_err_t *err, fr_dict_attr_t **out,
			      	  	 fr_dict_attr_t const *parent, fr_sbuff_t *in)
{
	fr_dict_attr_t const	*our_parent;
	fr_dict_attr_t		*n = NULL;
	fr_dict_attr_err_t	our_err;
	fr_dict_attr_flags_t	flags = {
					.is_unknown = true
				};
	fr_sbuff_marker_t	start;
	ssize_t			slen;

	if (!fr_cond_assert(parent)) {
		fr_strerror_printf("%s: Invalid argument - parent was NULL", __FUNCTION__);
		return -1;
	}

	*out = NULL;

	fr_sbuff_marker(&start, in);

	/*
	 *	Resolve all the known bits first...
	 */
	slen = fr_dict_attr_by_oid_substr(&our_err, &our_parent, parent, in);
	switch (our_err) {
	/*
	 *	Um this is awkward, we were asked to
	 *	produce an unknown but all components
	 *	are known...
	 *
	 *	Just exit and pass back the known
	 *	attribute.
	 */
	case FR_DICT_ATTR_OK:
		*out = fr_dict_attr_unconst(our_parent);	/* Which is the resolved attribute in this case */
		if (err) *err = FR_DICT_ATTR_OK;
		return fr_sbuff_marker_release_behind(&start);

	/*
	 *	This is what we want... Everything
	 *      up to the non-matching OID was valid.
	 *
	 *	our_parent should be left pointing
	 *	to the last known attribute, or be
	 *	so to NULL if we couldn't resolve
	 *	anything.
	 */
	case FR_DICT_ATTR_NOTFOUND:
		if (our_parent) {
			switch (parent->type) {
			case FR_TYPE_STRUCTURAL:
				break;

			default:
				fr_strerror_printf("Parent OID component (%s) specified a non-structural type (%s)",
						   our_parent->name,
						   fr_table_str_by_value(fr_value_box_type_table,
									 our_parent->type, "<INVALID>"));
				goto error;
			}
		} else {
			our_parent = parent;
		}
		break;

	/*
	 *	All other errors are fatal.
	 */
	default:
		if (err) *err = our_err;
		fr_sbuff_marker_release(&start);
		return slen;
	}

	/*
	 *	Allocate the final attribute first, so that any
	 *	unknown parents can be freed when this da is freed.
	 *
	 *      See fr_dict_unknown_acopy() for more details.
	 *
	 *	Note also that we copy the input name, even if it is
	 *	not normalized.
	 *
	 *	While the name of this attribute is "Attr-#.#.#", one
	 *	or more of the leading components may, in fact, be
	 *	known.
	 */
	n = dict_attr_alloc_null(ctx);

	/*
	 *	fr_dict_attr_by_oid_substr parsed *something*
	 *	we expected the next component to be a '.'.
	 */
	if (fr_sbuff_behind(&start) > 0) {
		if (!fr_sbuff_next_if_char(in, '.')) {	/* this is likely a logic bug if the test fails ? */
			fr_strerror_printf("Missing OID component separator %s", fr_sbuff_current(&start));
		error:
			if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
			talloc_free(n);
			return -fr_sbuff_marker_release_reset_behind(&start);
		}
	} else if (fr_sbuff_next_if_char(in, '.')) {
		our_parent = fr_dict_root(fr_dict_by_da(parent));		/* From the root */
	}

	/*
	 *	Loop until there's no more component separators.
	 */
	do {
		uint32_t		num;
		fr_sbuff_parse_error_t	sberr;

		fr_sbuff_out(&sberr, &num, in);
		switch (sberr) {
		case FR_SBUFF_PARSE_OK:
			switch (our_parent->type) {
			/*
			 *	If the parent is a VSA, this component
			 *	must specify a vendor.
			 */
			case FR_TYPE_VSA:
			{
				fr_dict_attr_t	*ni;

				if (fr_dict_unknown_vendor_afrom_num(n, &ni, our_parent, num) < 0) goto error;
				our_parent = ni;
			}
				break;

			/*
			 *	If it's structural, this component must
			 *	specify a TLV.
			 */
			case FR_TYPE_STRUCTURAL_EXCEPT_VSA:
			{
				fr_dict_attr_t	*ni;

				if (fr_dict_unknown_tlv_afrom_num(n, &ni, our_parent, num) < 0) goto error;
				our_parent = ni;
			}
				break;

			default:
			{
				char name[20];

				/*
				 *	Leaf type with more components
				 *	is an error.
				 */
				if (fr_sbuff_is_char(in, '.')) {
					fr_strerror_printf("Interior OID component cannot proceed a %s type",
							   fr_table_str_by_value(fr_value_box_type_table,
										 our_parent->type, "<INVALID>"));
					goto error;
				}

				snprintf(name, sizeof(name), "%u", num);
				dict_attr_init(&n, our_parent, name, num, FR_TYPE_OCTETS, &flags);
			}
				break;
			}
			break;

		default:
		{
			fr_sbuff_marker_t c_start;

			fr_sbuff_marker(&c_start, in);
			fr_sbuff_adv_past_allowed(in, FR_DICT_ATTR_MAX_NAME_LEN, fr_dict_attr_allowed_chars);
			fr_strerror_printf("Unknown attribute \"%.*s\"",
					   (int)fr_sbuff_behind(&c_start), fr_sbuff_current(&c_start));

			return -fr_sbuff_marker_release_reset_behind(&start);
		}
		}
	} while (fr_sbuff_next_if_char(in, '.'));

	DA_VERIFY(n);

	*out = n;

	return fr_sbuff_marker_release_behind(&start);
}

/** Check to see if we can convert a nested TLV structure to known attributes
 *
 * @param[in] dict			to search in.
 * @param[in] da			Nested tlv structure to convert.
 * @return
 *	- NULL if we can't.
 *	- Known attribute if we can.
 */
fr_dict_attr_t const *fr_dict_attr_known(fr_dict_t const *dict, fr_dict_attr_t const *da)
{
	INTERNAL_IF_NULL(dict, NULL);

	if (!da->flags.is_unknown) return da;	/* It's known */

	if (da->parent) {
		fr_dict_attr_t const *parent;

		parent = fr_dict_attr_known(dict, da->parent);
		if (!parent) return NULL;

		return fr_dict_attr_child_by_num(parent, da->attr);
	}

	if (dict->root == da) return dict->root;
	return NULL;
}

