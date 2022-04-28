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

/** Converts an unknown to a known by adding it to the internal dictionaries.
 *
 * Does not free old #fr_dict_attr_t, that is left up to the caller.
 *
 * @param[in] dict		of protocol context we're operating in.
 *				If NULL the internal dictionary will be used.
 * @param[in] unknown		attribute to add.
 * @return
 *	- Existing #fr_dict_attr_t if unknown was found in a dictionary.
 *	- A new entry representing unknown.
 */
fr_dict_attr_t const *fr_dict_unknown_add(fr_dict_t *dict, fr_dict_attr_t const *unknown)
{
	fr_dict_attr_t const *da;
	fr_dict_attr_t const *parent;
	fr_dict_attr_flags_t flags;

	if (unlikely(dict->read_only)) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root(dict)->name);
		return NULL;
	}

	da = fr_dict_attr_by_name(NULL, unknown->parent, unknown->name);
	if (da) {
		if (da->attr == unknown->attr) return da;

		fr_strerror_printf("Unknown attribute '%s' conflicts with existing attribute in context %s",
				   da->name, unknown->parent->name);
		return da;
	}

	/*
	 *	Define the complete unknown hierarchy
	 */
	if (unknown->parent && unknown->parent->flags.is_unknown) {
		parent = fr_dict_unknown_add(dict, unknown->parent);
		if (!parent) {
			fr_strerror_printf_push("Failed adding parent \"%s\"", unknown->parent->name);
			return NULL;
		}
	} else {
#ifdef __clang_analyzer__
		if (!unknown->parent) return NULL;
#endif
		parent = unknown->parent;
	}

	memcpy(&flags, &unknown->flags, sizeof(flags));
	flags.is_unknown = 0;

	/*
	 *	If this is a vendor, we skip most of the sanity
	 *	checks and add it to the vendor hash, and add it
	 *	as a child attribute to the Vendor-Specific
	 *	container.
	 */
	if (unknown->type == FR_TYPE_VENDOR) {
		fr_dict_attr_t *n;

		if (dict_vendor_add(dict, unknown->name, unknown->attr) < 0) return NULL;

		n = dict_attr_alloc(dict->pool, parent, unknown->name, unknown->attr, unknown->type,
				    &(dict_attr_args_t){ .flags = &flags });
		if (unlikely(!n)) return NULL;

		/*
		 *	Setup parenting for the attribute
		 */
		if (dict_attr_child_add(UNCONST(fr_dict_attr_t *, unknown->parent), n) < 0) return NULL;

		return n;
	}

	/*
	 *	Look up the attribute by number.  If it doesn't exist,
	 *	add it both by name and by number.  If it does exist,
	 *	add it only by name.
	 */
	da = fr_dict_attr_child_by_num(parent, unknown->attr);
	if (da) {
		fr_dict_attr_t *n;

		n = dict_attr_alloc(dict->pool, parent, unknown->name, unknown->attr, unknown->type,
				    &(dict_attr_args_t){ .flags = &flags });
		if (!n) return NULL;

		/*
		 *	Add the unknown by NAME.  e.g. if the admin does "Attr-26", we want
		 *	to return "Attr-26", and NOT "Vendor-Specific".  The rest of the server
		 *	is responsible for converting "Attr-26 = 0x..." to an actual attribute,
		 *	if it so desires.
		 */
		if (dict_attr_add_to_namespace(parent, n) < 0) {
			talloc_free(n);
			return NULL;
		}

		return n;
	}

#ifdef __clang_analyzer__
	if (!unknown->name) return NULL;
#endif

	/*
	 *	Add the attribute by both name and number.
	 *
	 *	Fixme - Copy extensions?
	 */
	if (fr_dict_attr_add(dict, parent, unknown->name, unknown->attr, unknown->type, &flags) < 0) return NULL;

	/*
	 *	For paranoia, return it by name.
	 */
	return fr_dict_attr_by_name(NULL, parent, unknown->name);
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

/**  Allocate an unknown DA.
 *
 */
static fr_dict_attr_t *dict_unknown_alloc(TALLOC_CTX *ctx, fr_dict_attr_t const *da, fr_type_t type)
{
	fr_dict_attr_t		*n;
	fr_dict_attr_t const	*parent;
	fr_dict_attr_flags_t	flags = da->flags;

	fr_assert(!da->flags.is_root); /* cannot copy root attributes */

	/*
	 *	Set the unknown flag, and copy only those other flags
	 *	which we know to be correct.
	 */
	flags.is_unknown = 1;
	flags.array = 0;
	flags.has_value = 0;
	flags.length = 0;	/* not fixed length */
	flags.extra = 0;

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
	if (da->parent && da->parent->flags.is_unknown) {
		parent = fr_dict_unknown_afrom_da(n, da->parent);
		if (!parent) {
			talloc_free(n);
			return NULL;
		}

	} else {
		parent = da->parent;
	}

	/*
	 *	Initialize the rest of the fields.
	 */
	dict_attr_init(&n, parent, da->name, da->attr, type, &(dict_attr_args_t){ .flags = &flags });
	if (type != FR_TYPE_OCTETS) dict_attr_ext_copy_all(&n, da);
	DA_VERIFY(n);

	return n;
}

/** Copy a known or unknown attribute to produce an unknown attribute with the specified name
 *
 * Will copy the complete hierarchy down to the first known attribute.
 */
fr_dict_attr_t *fr_dict_unknown_afrom_da(TALLOC_CTX *ctx, fr_dict_attr_t const *da)
{
	fr_type_t type = da->type;

	/*
	 *	VENDOR, etc. are logical containers, and can have
	 *	unknown children, so they're left alone.  All other
	 *	base types are mangled to OCTETs.
	 *
	 *	Note that we can't allocate an unknown STRUCT.  If the
	 *	structure is malformed, then it's just a sequence of
	 *	OCTETS.  Similarly, if a GROUP is malformed, then we
	 *	have no idea what's inside of it, and we make it OCTETS.
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

	return dict_unknown_alloc(ctx, da, type);
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
 * @param[in] parent		of the VSA attribute.
 * @param[in] vendor		id.
 * @return
 *	- An fr_dict_attr_t on success.
 *	- NULL on failure.
 */
fr_dict_attr_t	*fr_dict_unknown_vendor_afrom_num(TALLOC_CTX *ctx,
						  fr_dict_attr_t const *parent, unsigned int vendor)
{
	fr_dict_attr_flags_t	flags = {
					.is_unknown = 1,
					.type_size = 1,
					.length = 1
				};

	/*
	 *	Vendor attributes can occur under VSA attribute.
	 */
	switch (parent->type) {
	case FR_TYPE_VSA:
		if (!fr_cond_assert(!parent->flags.is_unknown)) return NULL;
		return dict_attr_alloc(ctx, parent, NULL, vendor, FR_TYPE_VENDOR,
				       &(dict_attr_args_t){ .flags = &flags });

	case FR_TYPE_VENDOR:
		if (!fr_cond_assert(!parent->flags.is_unknown)) return NULL;
		fr_strerror_const("Unknown vendor cannot be parented by another vendor");
		return NULL;

	default:
		fr_strerror_printf("Unknown vendors can only be parented by a vsa, not a %s",
				   fr_type_to_str(parent->type));
		return NULL;
	}
}

/** Initialise a fr_dict_attr_t from a number
 *
 * @param[in] ctx		to allocate the attribute in.
 * @param[in] parent		of the unknown attribute (may also be unknown).
 * @param[in] num		of the unknown attribute.
 * @return
 *	- An fr_dict_attr_t on success.
 *	- NULL on failure.
 */
fr_dict_attr_t *fr_dict_unknown_tlv_afrom_num(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, unsigned int num)
{
	fr_dict_attr_flags_t	flags = {
					.is_unknown = true,
				};

	if (!fr_type_is_structural_except_vsa(parent->type)) {
		fr_strerror_printf("%s: Cannot allocate unknown tlv attribute (%u) with parent type %s",
				   __FUNCTION__,
				   num,
				   fr_type_to_str(parent->type));
		return NULL;
	}

	return dict_attr_alloc(ctx, parent, NULL, num, FR_TYPE_TLV,
			       &(dict_attr_args_t){ .flags = &flags });
}

/** Initialise a fr_dict_attr_t from a number
 *
 * @param[in] ctx		to allocate the attribute in.
 * @param[in] parent		of the unknown attribute (may also be unknown).
 * @param[in] num		of the unknown attribute.
 * @return
 *	- An fr_dict_attr_t on success.
 *	- NULL on failure.
 */
fr_dict_attr_t	*fr_dict_unknown_attr_afrom_num(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, unsigned int num)
{
	fr_dict_attr_flags_t	flags = {
					.is_unknown = true,
				};

	if (!fr_type_is_structural_except_vsa(parent->type)) {
		fr_strerror_printf("%s: Cannot allocate unknown octets attribute (%u) with parent type %s",
				   __FUNCTION__,
				   num,
				   fr_type_to_str(parent->type));
		return NULL;
	}

	return dict_attr_alloc(ctx, parent, NULL, num, FR_TYPE_OCTETS,
			       &(dict_attr_args_t){ .flags = &flags });
}

/** Initialise an octets type attribute from a da
 *
 * @param[in] ctx		to allocate the attribute in.
 * @param[in] da		of the unknown attribute.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
fr_dict_attr_t	*fr_dict_unknown_attr_afrom_da(TALLOC_CTX *ctx, fr_dict_attr_t const *da)
{
	return dict_unknown_alloc(ctx, da, FR_TYPE_OCTETS);
}

/** Initialise two #fr_dict_attr_t from numbers
 *
 * @param[in] ctx		to allocate the unknown attributes in.
 * @param[in] parent		of the unknown attribute (may also be unknown).
 * @param[in] vendor		of the unknown attribute.
 * @param[in] attr		of the unknown attribute.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
fr_dict_attr_t	*fr_dict_unknown_afrom_fields(TALLOC_CTX *ctx, fr_dict_attr_t const *parent,
					      unsigned int vendor, unsigned int attr)
{
	fr_dict_attr_t *unknown_vendor, *unknown;

	unknown_vendor = fr_dict_unknown_vendor_afrom_num(ctx, parent, vendor);
	if (unlikely(!unknown_vendor)) return NULL;

	unknown = fr_dict_unknown_attr_afrom_num(ctx, unknown_vendor, attr);
	if (unlikely(!unknown)) {
		talloc_free(unknown_vendor);
		return NULL;
	}
	talloc_steal(unknown, unknown_vendor);

	return unknown;
}

/** Create a fr_dict_attr_t from an ASCII attribute and value
 *
 * Where the attribute name is in the form:
 *  - %d
 *  - %d.%d.%d...
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
 * @param[in] tt		Terminal strings.
 * @return
 *	- The number of bytes parsed on success.
 *	- <= 0 on failure.  Negative offset indicates parse error position.
 */
ssize_t fr_dict_unknown_afrom_oid_substr(TALLOC_CTX *ctx,
					 fr_dict_attr_err_t *err, fr_dict_attr_t **out,
			      	  	 fr_dict_attr_t const *parent,
			      	  	 fr_sbuff_t *in, fr_sbuff_term_t const *tt)
{
	fr_dict_attr_t const	*our_parent;
	fr_dict_attr_t		*n = NULL;
	fr_dict_attr_err_t	our_err;
	fr_dict_attr_flags_t	flags = {
					.is_unknown = true
				};
	fr_sbuff_marker_t	start;
	ssize_t			slen;
	bool			is_raw;

	*out = NULL;

	fr_sbuff_marker(&start, in);

	is_raw = fr_sbuff_adv_past_str_literal(in, "raw");

	/*
	 *	Resolve all the known bits first...
	 */
	slen = fr_dict_attr_by_oid_substr(&our_err, &our_parent, parent, in, tt);
	switch (our_err) {
	/*
	 *	Um this is awkward, we were asked to
	 *	produce an unknown but all components
	 *	are known...
	 *
	 *	Just exit and pass back the known
	 *	attribute, unless we got a raw prefix
	 *	in which case process that.
	 */
	case FR_DICT_ATTR_OK:
		if (is_raw) {
			*out = fr_dict_unknown_attr_afrom_da(ctx, our_parent);
			if (!*out) {
				if (err) *err = FR_DICT_ATTR_PARSE_ERROR;
			} else {
				(*out)->flags.is_raw = 1;
				if (err) *err = FR_DICT_ATTR_OK;
			}
		} else {
			*out = fr_dict_attr_unconst(our_parent);	/* Which is the resolved attribute in this case */
			if (err) *err = FR_DICT_ATTR_OK;
		}

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
						   fr_type_to_str(our_parent->type));
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
	 *      See fr_dict_unknown_afrom_da() for more details.
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
			fr_strerror_printf("Missing OID component separator %s", fr_sbuff_current(in));
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
	for (;;) {
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

				if (fr_sbuff_next_if_char(in, '.')) {
					ni = fr_dict_unknown_vendor_afrom_num(n, our_parent, num);
					if (!ni) goto error;
					our_parent = ni;
					continue;
				}
				if (dict_attr_init(&n, our_parent, NULL, num, FR_TYPE_VENDOR,
						   &(dict_attr_args_t){ .flags = &flags }) < 0) goto error;
			}
				break;

			/*
			 *	If it's structural, this component must
			 *	specify a TLV.
			 */
			case FR_TYPE_STRUCTURAL_EXCEPT_VSA:
			{
				fr_dict_attr_t	*ni;

				if (fr_sbuff_next_if_char(in, '.')) {
					ni = fr_dict_unknown_tlv_afrom_num(n, our_parent, num);
					if (!ni) goto error;
					our_parent = ni;
					continue;
				}
			}
				FALL_THROUGH;

			default:
				/*
				 *	Leaf type with more components
				 *	is an error.
				 */
				if (fr_sbuff_is_char(in, '.')) {
					fr_strerror_printf("Interior OID component cannot proceed a %s type",
							   fr_type_to_str(our_parent->type));
					goto error;
				}
				flags.is_raw = is_raw;
				if (dict_attr_init(&n, our_parent, NULL, num, FR_TYPE_OCTETS,
						   &(dict_attr_args_t){ .flags = &flags }) < 0) goto error;
				break;
			}
			break;

		default:
		{
			fr_sbuff_marker_t c_start;

			fr_sbuff_marker(&c_start, in);
			fr_sbuff_adv_past_allowed(in, FR_DICT_ATTR_MAX_NAME_LEN, fr_dict_attr_allowed_chars, NULL);
			fr_strerror_printf("Unknown attribute \"%.*s\" for parent \"%s\"",
					   (int)fr_sbuff_behind(&c_start), fr_sbuff_current(&c_start), our_parent->name);
			goto error;
		}
		}
		break;
	};

	DA_VERIFY(n);

	*out = n;

	return fr_sbuff_marker_release_behind(&start);
}

/** Fixup the parent of an unknown attribute using an equivalent known attribute
 *
 * This can be useful where an unknown attribute's ancestors are added to
 * a dictionary but not the unknown attribute itself.
 *
 * @param[in] da	to fixup.
 * @param[in] parent	to assign.  If NULL, we will attempt to resolve
 *			the parent in the dictionary the current unknown
 *			attribute extends.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dict_attr_unknown_parent_to_known(fr_dict_attr_t *da, fr_dict_attr_t const *parent)
{
	fr_dict_attr_t const *da_u, *da_k;

	if (parent) {
		/*
		 *	Walk back up the hierarchy until we get to a known
		 *	ancestor on the unknown side.
		 */
		for (da_u = da->parent, da_k = parent;
		     da_k && da_u && da_u->flags.is_unknown;
		     da_u = da_u->parent, da_k = da_k->parent) {
			if (unlikely(da_u->attr != da_k->attr)) {
				fr_strerror_printf("Unknown parent number %u does not match "
						   "known parent number %u (%s)",
						   da_u->attr, da_k->attr, da_k->name);
				return -1;
			}

			if (unlikely(da_u->depth != da_k->depth)) {
				fr_strerror_printf("Unknown parent depth %u does not match "
						   "known parent depth %u (%s)",
						   da_u->depth, da_k->depth, da_k->name);
				return -1;
			}
		}
		if ((da_k == NULL) != (da_u == NULL)) {
			fr_strerror_printf("Truncated or over-extended hierarchy "
					   "for unknown attribute %u", da->attr);
			return -1;
		}
	} else {
		parent = fr_dict_attr_unknown_resolve(fr_dict_by_da(da), da->parent);
		if (!parent) {
			fr_strerror_printf("Failed resolving unknown attribute %u "
					   "in dictionary", da->attr);
			return -1;
		}
	}

	da->parent = parent;

	return 0;
}

/** Check to see if we can convert a nested TLV structure to known attributes
 *
 * @param[in] dict			to search in.
 * @param[in] da			Nested tlv structure to convert.
 * @return
 *	- NULL if we can't.
 *	- Known attribute if we can.
 */
fr_dict_attr_t const *fr_dict_attr_unknown_resolve(fr_dict_t const *dict, fr_dict_attr_t const *da)
{
	INTERNAL_IF_NULL(dict, NULL);

	if (!da->flags.is_unknown) return da;	/* It's known */

	if (da->parent) {
		fr_dict_attr_t const *parent;

		parent = fr_dict_attr_unknown_resolve(dict, da->parent);
		if (!parent) return NULL;

		return fr_dict_attr_child_by_num(parent, da->attr);
	}

	if (dict->root == da) return dict->root;
	return NULL;
}
