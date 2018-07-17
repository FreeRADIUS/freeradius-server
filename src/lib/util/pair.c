/*
 * pair.c	Functions to handle VALUE_PAIRs
 *
 * Version:	$Id$
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/regex.h>

#include <ctype.h>

/** Free a VALUE_PAIR
 *
 * @note Do not call directly, use talloc_free instead.
 *
 * @param vp to free.
 * @return 0
 */
static int _fr_pair_free(NDEBUG_UNUSED VALUE_PAIR *vp)
{
#ifndef NDEBUG
	vp->vp_uint32 = FREE_MAGIC;
#endif

#ifdef TALLOC_DEBUG
	talloc_report_depth_cb(NULL, 0, -1, fr_talloc_verify_cb, NULL);
#endif
	return 0;
}


VALUE_PAIR *fr_pair_alloc(TALLOC_CTX *ctx)
{
	VALUE_PAIR *vp;

	vp = talloc_zero(ctx, VALUE_PAIR);
	if (!vp) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}

	vp->op = T_OP_EQ;
	vp->tag = TAG_ANY;
	vp->type = VT_NONE;

	talloc_set_destructor(vp, _fr_pair_free);

	return vp;
}


/** Dynamically allocate a new attribute
 *
 * Allocates a new attribute and a new dictionary attr if no DA is provided.
 *
 * @note Doesn't require qualification with a dictionary as fr_dict_attr_t are unique.
 *
 * @param[in] ctx	for allocated memory, usually a pointer to a #RADIUS_PACKET
 * @param[in] da	Specifies the dictionary attribute to build the #VALUE_PAIR from.
 * @return
 *	- A new #VALUE_PAIR.
 *	- NULL if an error occurred.
 */
VALUE_PAIR *fr_pair_afrom_da(TALLOC_CTX *ctx, fr_dict_attr_t const *da)
{
	VALUE_PAIR *vp;

	/*
	 *	Caller must specify a da else we don't know what the attribute type is.
	 */
	if (!da) {
		fr_strerror_printf("Invalid arguments");
		return NULL;
	}

	vp = fr_pair_alloc(ctx);
	if (!vp) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}

	/*
	 *	Use the 'da' to initialize more fields.
	 */
	vp->da = da;
	vp->vp_type = da->type;
	vp->data.enumv = da;

	return vp;
}

/** Create a new valuepair
 *
 * If attr and vendor match a dictionary entry then a VP with that #fr_dict_attr_t
 * will be returned.
 *
 * If attr or vendor are uknown will call dict_attruknown to create a dynamic
 * #fr_dict_attr_t of #FR_TYPE_OCTETS.
 *
 * Which type of #fr_dict_attr_t the #VALUE_PAIR was created with can be determined by
 * checking @verbatim vp->da->flags.is_unknown @endverbatim.
 *
 * @param[in] ctx for allocated memory, usually a pointer to a #RADIUS_PACKET.
 * @param[in] attr number.
 * @param[in] vendor number.
 * @return
 *	- A new #VALUE_PAIR.
 *	- NULL on error.
 */
VALUE_PAIR *fr_pair_afrom_num(TALLOC_CTX *ctx, unsigned int vendor, unsigned int attr)
{
	fr_dict_attr_t const *da;
	fr_dict_attr_t const *parent;

	if (vendor == 0) {
		da = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal), attr);
		goto alloc;
	}

	parent = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal), FR_VENDOR_SPECIFIC);
	if (!parent) return NULL;

	parent = fr_dict_attr_child_by_num(parent, vendor);
	if (!parent) return NULL;

	da = fr_dict_attr_child_by_num(parent, attr);

alloc:
	if (!da) {
		VALUE_PAIR *vp;

		vp = fr_pair_alloc(ctx);
		if (!vp) return NULL;

		/*
		 *	Ensure that the DA is parented by the VP.
		 */
		da = fr_dict_unknown_afrom_fields(ctx, fr_dict_root(fr_dict_internal), vendor, attr);
		if (!da) {
			talloc_free(vp);
			return NULL;
		}

		vp->da = da;
		vp->vp_type = da->type;	/* FR_TYPE_OCTETS */

		return vp;
	}

	return fr_pair_afrom_da(ctx, da);
}

/** Create a new valuepair
 *
 * If attr and vendor match a dictionary entry then a VP with that #fr_dict_attr_t
 * will be returned.
 *
 * If attr or vendor are uknown will call dict_attruknown to create a dynamic
 * #fr_dict_attr_t of #FR_TYPE_OCTETS.
 *
 * Which type of #fr_dict_attr_t the #VALUE_PAIR was created with can be determined by
 * checking @verbatim vp->da->flags.is_unknown @endverbatim.
 *
 * @param[in] ctx	for allocated memory, usually a pointer to a #RADIUS_PACKET.
 * @param[in] parent	of the attribute being allocated (usually a dictionary or vendor).
 * @param[in] attr	number.
 * @return
 *	- A new #VALUE_PAIR.
 *	- NULL on error.
 */
VALUE_PAIR *fr_pair_afrom_child_num(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, unsigned int attr)
{
	fr_dict_attr_t const *da;

	da = fr_dict_attr_child_by_num(parent, attr);
	if (!da) {
		unsigned int		vendor_id = 0;
		fr_dict_attr_t const	*vendor;

		/*
		 *	If parent is a vendor, that's fine. If parent
		 *	is a TLV attribute parented by a vendor, that's
		 *	also fine...
		 */
		vendor = fr_dict_vendor_attr_by_da(parent);
		if (vendor) vendor_id = vendor->attr;

		da = fr_dict_unknown_afrom_fields(ctx, parent,
						  vendor_id, attr);
		if (!da) return NULL;
	}

	return fr_pair_afrom_da(ctx, da);
}

/** Deserialise a value pair from a string
 *
 * Input must be in the format:
 * @verbatim <attribute> = [<qu>]<value>[<qu>] @endverbatim
 *
 * This is intended to be use as a light weight way of deserialising complete
 * attribute/value pairs.  For more complex operations see the map API.
 *
 * This is the companion function for #fr_pair_snprint and #fr_pair_asprint.
 *
 * @param[in] ctx	to allocate pair in.
 * @param[out] out	the VALUE_PAIR we allocated.
 * @param[in] dict	to search for attributes in.
 * @param[in] in	string to convert to VALUE_PAIR.
 * @param[in] tainted	Whether the source of in was untrusted.
 * @return
 *	- <= 0 on failure.
 *	- The number of bytes of name consumed on success.
 */
ssize_t fr_pair_afrom_substr(TALLOC_CTX *ctx, VALUE_PAIR **out,
			     fr_dict_t const *dict, char const *in, bool tainted)
{
	ssize_t			slen;
	VALUE_PAIR		*vp;
	fr_dict_attr_t const	*da;
	char const		*p, *q;
	char			quote;

	p = in;

	slen = fr_dict_attr_by_name_substr(&da, dict, p);
	if (slen <= 0) return slen;

	p += slen;

	while (isspace(*p)) p++;
	if (*p != '=') {
		fr_strerror_printf("Invalid operator '%c'", *p);
		return -(p - in);
	}
	while (isspace(*p)) p++;

	switch (*p) {

	/*
	 *	Note - Unescaping is handled by fr_pair_value_from_str
	 */
	case '"':
	case '\'':
		quote = *p++;

		/*
		 *	Figure out the end of the quoted string
		 *	ignoring escaped quotes.
		 */
		for (q = p; *q != '\0'; q++) {
			if (*q == '\'') {
				switch (*(q + 1)) {
				case '\\':
				case '"':
				case '\'':
					q++;
					continue;

				default:
					break;
				}
			}
		}

		if (*q != quote) {
			fr_strerror_printf("No matching terminating quote");
			return -(p - in);
		}
		break;

	default:
		quote = '\0';
		q = p;

		while (fr_dict_attr_allowed_chars[(uint8_t)*q] != '\0') q++;
		break;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) return 0;

	if (fr_pair_value_from_str(vp, p, q - p, quote, tainted) < 0) {
		talloc_free(vp);
		return -(p - in);
	}

	if (quote != '\0') q++;	/* Advance past trailing quote */

	*out = vp;

	return (q - in);
}

/** Copy a single valuepair
 *
 * Allocate a new valuepair and copy the da from the old vp.
 *
 * @param[in] ctx for talloc
 * @param[in] vp to copy.
 * @return
 *	- A copy of the input VP.
 *	- NULL on error.
 */
VALUE_PAIR *fr_pair_copy(TALLOC_CTX *ctx, VALUE_PAIR const *vp)
{
	VALUE_PAIR *n;

	if (!vp) return NULL;

	VP_VERIFY(vp);

	n = fr_pair_afrom_da(ctx, vp->da);
	if (!n) return NULL;

	memcpy(n, vp, sizeof(*n));

	/*
	 *	Copy the unknown attribute hierarchy
	 */
	if (n->da->flags.is_unknown) {
		n->da = fr_dict_unknown_acopy(n, n->da);
		if (!n->da) {
			talloc_free(n);
			return NULL;
		}
	}
	n->next = NULL;

	/*
	 *	If it's an xlat, copy the raw string and return
	 *	early, so we don't pre-expand or otherwise mangle
	 *	the VALUE_PAIR.
	 */
	if (vp->type == VT_XLAT) {
		n->xlat = talloc_typed_strdup(n, n->xlat);
		return n;
	}

	switch (vp->vp_type) {
	case FR_TYPE_OCTETS:
		n->vp_octets = NULL;	/* else fr_pair_value_memcpy will free vp's value */
		fr_pair_value_memcpy(n, vp->vp_octets, n->vp_length);
		break;

	case FR_TYPE_STRING:
		n->vp_strvalue = NULL;	/* else pairstrnpy will free vp's value */
		fr_pair_value_bstrncpy(n, vp->vp_strvalue, n->vp_length);
		break;

	default:
		break;
	}

	return n;
}

/** Steal one VP
 *
 * @param[in] ctx to move VALUE_PAIR into
 * @param[in] vp VALUE_PAIR to move into the new context.
 */
void fr_pair_steal(TALLOC_CTX *ctx, VALUE_PAIR *vp)
{
	(void) talloc_steal(ctx, vp);

	/*
	 *	The DA may be unknown.  If we're stealing the VPs to a
	 *	different context, copy the unknown DA.  We use the VP
	 *	as a context here instead of "ctx", so that when the
	 *	VP is freed, so is the DA.
	 *
	 *	Since we have no introspection into OTHER VPs using
	 *	the same DA, we can't have multiple VPs use the same
	 *	DA.  So we might as well tie it to this VP.
	 */
	if (vp->da->flags.is_unknown) {
		fr_dict_attr_t *da;
		char *p;
		size_t size;

		size = talloc_get_size(vp->da);

		p = talloc_zero_array(vp, char, size);
		da = (fr_dict_attr_t *) p;
		talloc_set_type(p, fr_dict_attr_t);
		memcpy(da, vp->da, size);
		vp->da = da;
	}
}


/** Create a valuepair from an ASCII attribute and value
 *
 * Where the attribute name is in the form:
 *  - Attr-%d
 *  - Attr-%d.%d.%d...
 *
 * @param ctx for talloc
 * @param attribute name to parse.
 * @param value to parse (must be a hex string).
 * @param op to assign to new valuepair.
 * @return new #VALUE_PAIR or NULL on error.
 */
static VALUE_PAIR *fr_pair_make_unknown(TALLOC_CTX *ctx,
					char const *attribute, char const *value,
					FR_TOKEN op)
{
	VALUE_PAIR		*vp;
	fr_dict_attr_t		*n;

	vp = fr_pair_alloc(ctx);
	if (!vp) return NULL;

	if (fr_dict_unknown_afrom_oid_str(vp, &n, fr_dict_root(fr_dict_internal), attribute) <= 0) {
		talloc_free(vp);
		return NULL;
	}
	vp->da = n;

	/*
	 *	No value.  Nothing more to do.
	 */
	if (!value) return vp;

	/*
	 *	Unknown attributes MUST be of type 'octets'
	 */
	if (strncasecmp(value, "0x", 2) != 0) {
		fr_strerror_printf("Unknown attribute \"%s\" requires a hex "
				   "string, not \"%s\"", attribute, value);
		talloc_free(vp);
		return NULL;
	}

	if (fr_pair_value_from_str(vp, value, -1, '"', false) < 0) {
		talloc_free(vp);
		return NULL;
	}

	vp->op = (op == 0) ? T_OP_EQ : op;
	return vp;
}

/** Create a #VALUE_PAIR from ASCII strings
 *
 * Converts an attribute string identifier (with an optional tag qualifier)
 * and value string into a #VALUE_PAIR.
 *
 * The string value is parsed according to the type of #VALUE_PAIR being created.
 *
 * @param[in] ctx for talloc.
 * @param[in] vps list where the attribute will be added (optional)
 * @param[in] attribute name.
 * @param[in] value attribute value (may be NULL if value will be set later).
 * @param[in] op to assign to new #VALUE_PAIR.
 * @return a new #VALUE_PAIR.
 */
VALUE_PAIR *fr_pair_make(TALLOC_CTX *ctx, VALUE_PAIR **vps,
			 char const *attribute, char const *value, FR_TOKEN op)
{
	fr_dict_attr_t const *da;
	VALUE_PAIR	*vp;
	char		*p;
	int8_t		tag;
	char const	*attrname = attribute;
	char		buffer[FR_DICT_ATTR_MAX_NAME_LEN + 1 + 32];

	/*
	 *    Check for tags in 'Attribute:Tag' format.
	 */
	tag = TAG_NONE;

	p = strchr(attribute, ':');
	if (p) {
		char *end;

		if (!p[1]) {
			fr_strerror_printf("Invalid tag for attribute %s", attribute);
			return NULL;
		}

		strlcpy(buffer, attribute, sizeof(buffer));

		p = buffer + (p - attrname);
		attrname = buffer;

		/* Colon found with something behind it */
		if ((p[1] == '*') && !p[2]) {
			/* Wildcard tag for check items */
			tag = TAG_ANY;
		} else {
			/* It's not a wild card tag */
			tag = strtol(p + 1, &end, 10);
			if (*end) {
				fr_strerror_printf("Unexpected text after tag for attribute %s", attribute);
				return NULL;
			}

			if (!TAG_VALID_ZERO(tag)) {
				fr_strerror_printf("Invalid tag for attribute %s", attribute);
				return NULL;
			}
		}

		/*
		 *	Leave only the attribute name in the buffer.
		 */
		*p = '\0';
	}

	/*
	 *	It's not found in the dictionary, so we use
	 *	another method to create the attribute.
	 */
	da = fr_dict_attr_by_name(NULL, attrname);
	if (!da) {
		if (tag != TAG_NONE) {
			fr_strerror_printf("Invalid tag for attribute %s", attribute);
			return NULL;
		}

		vp = fr_pair_make_unknown(ctx, attrname, value, op);
		if (!vp) return NULL;

		if (vps) fr_pair_add(vps, vp);
		return vp;
	}

	/*
	 *	Untagged attributes can't have a tag.
	 */
	if (!da->flags.has_tag && (tag != TAG_NONE)) {
		fr_strerror_printf("Invalid tag for attribute %s", attribute);
		return NULL;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) return NULL;
	vp->op = (op == 0) ? T_OP_EQ : op;
	vp->tag = tag;

	switch (vp->op) {
	case T_OP_CMP_TRUE:
	case T_OP_CMP_FALSE:
		vp->vp_strvalue = NULL;
		vp->vp_length = 0;
		value = NULL;	/* ignore it! */
		break;

		/*
		 *	Regular expression comparison of integer attributes
		 *	does a STRING comparison of the names of their
		 *	integer attributes.
		 */
	case T_OP_REG_EQ:	/* =~ */
	case T_OP_REG_NE:	/* !~ */
	{
#ifndef HAVE_REGEX
		fr_strerror_printf("Regular expressions are not supported");
		return NULL;
#else
		ssize_t slen;
		regex_t *preg;

		/*
		 *	Someone else will fill in the value.
		 */
		if (!value) break;

		talloc_free(vp);

		slen = regex_compile(ctx, &preg, value, strlen(value), false, false, false, true);
		if (slen <= 0) {
			fr_strerror_printf_push("Error at offset %zu compiling regex for %s", -slen, attribute);
			return NULL;
		}
		talloc_free(preg);

		vp = fr_pair_make(ctx, NULL, attribute, NULL, op);
		if (!vp) return NULL;

		if (fr_pair_mark_xlat(vp, value) < 0) {
			talloc_free(vp);
			return NULL;
		}

		value = NULL;	/* ignore it */
		break;
#endif
	}
	default:
		break;
	}

	/*
	 *	We probably want to fix fr_pair_value_from_str to accept
	 *	octets as values for any attribute.
	 */
	if (value && (fr_pair_value_from_str(vp, value, -1, '\"', true) < 0)) {
		talloc_free(vp);
		return NULL;
	}

	if (vps) fr_pair_add(vps, vp);
	return vp;
}

/** Free memory used by a valuepair list.
 *
 * @todo TLV: needs to free all dependents of each VP freed.
 */
void fr_pair_list_free(VALUE_PAIR **vps)
{
	VALUE_PAIR	*vp;
	fr_cursor_t	cursor;

	if (!vps || !*vps) return;

	fr_cursor_init(&cursor, vps);
	while ((vp = fr_cursor_remove(&cursor))) {
		VP_VERIFY(vp);
		talloc_free(vp);
	}

	*vps = NULL;
}

/** Mark malformed or unrecognised attributed as unknown
 *
 * @param vp to change fr_dict_attr_t of.
 * @return
 *	- 0 on success (or if already unknown).
 *	- -1 on failure.
 */
int fr_pair_to_unknown(VALUE_PAIR *vp)
{
	fr_dict_attr_t const *da;

	VP_VERIFY(vp);

	if (vp->da->flags.is_unknown) return 0;

	if (!fr_cond_assert(vp->da->parent != NULL)) return -1;

	da = fr_dict_unknown_afrom_fields(vp, vp->da->parent, fr_dict_vendor_num_by_da(vp->da), vp->da->attr);
	if (!da) return -1;

	fr_dict_unknown_free(&vp->da);	/* Only frees unknown attributes */
	vp->da = da;

	return 0;
}

/** Mark a valuepair for xlat expansion
 *
 * Copies xlat source (unprocessed) string to valuepair value, and sets value type.
 *
 * @param vp to mark for expansion.
 * @param value to expand.
 * @return
 *	- 0 if marking succeeded.
 *	- -1 if #VALUE_PAIR already had a value, or OOM.
 */
int fr_pair_mark_xlat(VALUE_PAIR *vp, char const *value)
{
	char *raw;

	/*
	 *	valuepair should not already have a value.
	 */
	if (vp->type != VT_NONE) {
		fr_strerror_printf("Pair already has a value");
		return -1;
	}

	raw = talloc_typed_strdup(vp, value);
	if (!raw) {
		fr_strerror_printf("Out of memory");
		return -1;
	}

	vp->type = VT_XLAT;
	vp->xlat = raw;
	vp->vp_length = 0;

	return 0;
}

/** Iterate over pairs with a specified da
 *
 * @param[in,out] prev	The VALUE_PAIR before curr. Will be updated to point to the
 *			pair before the one returned, or the last pair in the list
 *			if no matching pairs found.
 * @param[in] to_eval	The VALUE_PAIR after cursor->current.  Will be checked to
 *			see if it matches the specified fr_dict_attr_t.
 * @param[in] uctx	The fr_dict_attr_t to search for.
 * @return
 *	- Next matching VALUE_PAIR.
 *	- NULL if not more matching VALUE_PAIRs could be found.
 */
void *fr_pair_iter_next_by_da(void **prev, void *to_eval, void *uctx)
{
	VALUE_PAIR	*c, *p;
	fr_dict_attr_t	*da = uctx;

	if (!to_eval) return NULL;

	for (p = *prev, c = to_eval; c; p = c, c = c->next) {
		VP_VERIFY(c);
		if (c->da == da) break;
	}

	*prev = p;

	return c;
}

/** Iterate over pairs which are decedents of the specified da
 *
 * @param[in,out] prev	The VALUE_PAIR before curr. Will be updated to point to the
 *			pair before the one returned, or the last pair in the list
 *			if no matching pairs found.
 * @param[in] to_eval	The VALUE_PAIR after cursor->current.  Will be checked to
 *			see if it matches the specified fr_dict_attr_t.
 * @param[in] uctx	The fr_dict_attr_t to search for.
 * @return
 *	- Next matching VALUE_PAIR.
 *	- NULL if not more matching VALUE_PAIRs could be found.
 */
void *fr_pair_iter_next_by_ancestor(void **prev, void *to_eval, void *uctx)
{
	VALUE_PAIR	*c, *p;
	fr_dict_attr_t	*da = uctx;

	if (!to_eval) return NULL;

	for (p = *prev, c = to_eval; c; p = c, c = c->next) {
		VP_VERIFY(c);
		if (fr_dict_parent_common(da, c->da, true)) break;
	}

	*prev = p;

	return c;
}

/** Find the pair with the matching DAs
 *
 */
VALUE_PAIR *fr_pair_find_by_da(VALUE_PAIR *head, fr_dict_attr_t const *da, int8_t tag)
{
	fr_cursor_t 	cursor;
	VALUE_PAIR	*vp;

	/* List head may be NULL if it contains no VPs */
	if (!head) return NULL;

	LIST_VERIFY(head);

	if (!da) return NULL;

	for (vp = fr_cursor_init(&cursor, &head);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if ((da == vp->da) && TAG_EQ(tag, vp->tag)) return vp;
	}

	return NULL;
}


/** Find the pair with the matching attribute
 *
 * @todo should take DAs and do a pointer comparison.
 */
VALUE_PAIR *fr_pair_find_by_num(VALUE_PAIR *head, unsigned int vendor, unsigned int attr, int8_t tag)
{
	fr_cursor_t 	cursor;
	VALUE_PAIR	*vp;

	/* List head may be NULL if it contains no VPs */
	if (!head) return NULL;

	LIST_VERIFY(head);

	for (vp = fr_cursor_init(&cursor, &head);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (!fr_dict_attr_is_top_level(vp->da)) continue;

	     	if (vendor > 0) {
	     		fr_dict_vendor_t const *dv;

	     		dv = fr_dict_vendor_by_da(vp->da);
	     		if (!dv) continue;

	     		if (dv->pen != vendor) continue;
	     	}

		if ((attr == vp->da->attr) && TAG_EQ(tag, vp->tag)) return vp;
	}

	return NULL;
}

/** Find the pair with the matching attribute
 *
 */
VALUE_PAIR *fr_pair_find_by_child_num(VALUE_PAIR *head, fr_dict_attr_t const *parent, unsigned int attr, int8_t tag)
{
	fr_cursor_t 		cursor;
	fr_dict_attr_t const	*da;
	VALUE_PAIR		*vp;

	/* List head may be NULL if it contains no VPs */
	if (!head) return NULL;

	LIST_VERIFY(head);

	da = fr_dict_attr_child_by_num(parent, attr);
	if (!da) return NULL;

	for (vp = fr_cursor_init(&cursor, &head);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if ((da == vp->da) && TAG_EQ(tag, vp->tag)) return vp;
	}

	return NULL;
}


/** Add a VP to the end of the list.
 *
 * Locates the end of 'head', and links an additional VP 'add' at the end.
 *
 * @param[in] head VP in linked list. Will add new VP to the end of this list.
 * @param[in] add VP to add to list.
 */
void fr_pair_add(VALUE_PAIR **head, VALUE_PAIR *add)
{
	VALUE_PAIR *i;

	if (!add) return;

	VP_VERIFY(add);

	if (*head == NULL) {
		*head = add;
		return;
	}

	for (i = *head; i->next; i = i->next) {
#ifdef WITH_VERIFY_PTR
		VP_VERIFY(i);
		/*
		 *	The same VP should never by added multiple times
		 *	to the same list.
		 */
		(void)fr_cond_assert(i != add);
#endif
	}

	i->next = add;
}

/** Replace all matching VPs
 *
 * Walks over 'head', and replaces the head VP that matches 'replace'.
 *
 * @note Memory used by the VP being replaced will be freed.
 * @note Will not work with unknown attributes.
 *
 * @param[in,out] head VP in linked list. Will search and replace in this list.
 * @param[in] replace VP to replace.
 */
void fr_pair_replace(VALUE_PAIR **head, VALUE_PAIR *replace)
{
	VALUE_PAIR *i, *next;
	VALUE_PAIR **prev = head;

	VP_VERIFY(replace);

	if (*head == NULL) {
		*head = replace;
		return;
	}

	/*
	 *	Not an empty list, so find item if it is there, and
	 *	replace it. Note, we always replace the head one, and
	 *	we ignore any others that might exist.
	 */
	for(i = *head; i; i = next) {
		VP_VERIFY(i);
		next = i->next;

		/*
		 *	Found the head attribute, replace it,
		 *	and return.
		 */
		if ((i->da == replace->da) && ATTR_TAG_MATCH(i, replace->tag)) {
			*prev = replace;

			/*
			 *	Should really assert that replace->next == NULL
			 */
			replace->next = next;
			talloc_free(i);
			return;
		}

		/*
		 *	Point to where the attribute should go.
		 */
		prev = &i->next;
	}

	/*
	 *	If we got here, we didn't find anything to replace, so
	 *	stopped at the last item, which we just append to.
	 */
	*prev = replace;
}

/** Delete matching pairs
 *
 * Delete matching pairs from the attribute list.
 *
 * @param[in,out] head	VP in list.
 * @param[in] attr	to match.
 * @param[in] parent	to match.
 * @param[in] tag	to match. TAG_ANY matches any tag, TAG_NONE matches tagless VPs.
 */
void fr_pair_delete_by_child_num(VALUE_PAIR **head, fr_dict_attr_t const *parent, unsigned int attr, int8_t tag)
{
	VALUE_PAIR		*i, *next;
	VALUE_PAIR		**last = head;
	fr_dict_attr_t const	*da;

	da = fr_dict_attr_child_by_num(parent, attr);
	if (!da) return;

	for (i = *head; i; i = next) {
		VP_VERIFY(i);
		next = i->next;
		if ((i->da == da) && (!i->da->flags.has_tag || TAG_EQ(tag, i->tag))) {
			*last = next;
			talloc_free(i);
		} else {
			last = &i->next;
		}
	}
}

/** Alloc a new VALUE_PAIR (and prepend)
 *
 * @param[in] ctx	to allocate new #VALUE_PAIR in.
 * @param[out] out	Pair we allocated.  May be NULL if the caller doesn't
 *			care about manipulating the VALUE_PAIR.
 * @param[in,out] list	in search and insert into.
 * @param[in] da	of attribute to update.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_add_by_da(TALLOC_CTX *ctx, VALUE_PAIR **out, VALUE_PAIR **list, fr_dict_attr_t const *da)
{
	fr_cursor_t	cursor;
	VALUE_PAIR	*vp;

	(void)fr_cursor_init(&cursor, list);
	vp = fr_pair_afrom_da(ctx, da);
	if (unlikely(!vp)) {
		if (out) *out = NULL;
		return -1;
	}

	fr_cursor_prepend(&cursor, vp);
	if (out) *out = vp;

	return 0;
}

/** Return the first VALUE_PAIR matching the #fr_dict_attr_t or alloc a new VALUE_PAIR (and prepend)
 *
 * @param[in] ctx	to allocate any new #VALUE_PAIR in.
 * @param[out] out	Pair we allocated or found.  May be NULL if the caller doesn't
 *			care about manipulating the VALUE_PAIR.
 * @param[in,out] list	to search for attributes in or prepend attributes to.
 * @param[in] da	of attribute to locate or alloc.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
int fr_pair_update_by_da(TALLOC_CTX *ctx, VALUE_PAIR **out, VALUE_PAIR **list, fr_dict_attr_t const *da)
{
	fr_cursor_t	cursor;
	VALUE_PAIR	*vp;

	vp = fr_cursor_iter_by_da_init(&cursor, list, da);
	if (vp) {
		VP_VERIFY(vp);
		if (out) *out = vp;
		return 1;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (unlikely(!vp)) {
		if (out) *out = NULL;
		return -1;
	}

	fr_cursor_prepend(&cursor, vp);
	if (out) *out = vp;

	return 0;
}

/** Delete matching pairs from the specified list
 *
 * @param[in,out] list	to search for attributes in or prepend attributes to.
 * @param[in] da	to match.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
int fr_pair_delete_by_da(VALUE_PAIR **list, fr_dict_attr_t const *da)
{
	fr_cursor_t	cursor;
	VALUE_PAIR	*vp;
	int		cnt;

	for (vp = fr_cursor_iter_by_da_init(&cursor, list, da), cnt = 0;
	     vp;
	     vp = fr_cursor_next(&cursor), cnt++) fr_cursor_free_item(&cursor);

	return cnt;
}

/** Order attributes by their da, and tag
 *
 * Useful where attributes need to be aggregated, but not necessarily
 * ordered by attribute number.
 *
 * @param[in] a		first dict_attr_t.
 * @param[in] b		second dict_attr_t.
 * @return
 *	- +1 if a > b
 *	- 0 if a == b
 *	- -1 if a < b
 */
int8_t fr_pair_cmp_by_da_tag(void const *a, void const *b)
{
	VALUE_PAIR const *my_a = a;
	VALUE_PAIR const *my_b = b;

	uint8_t cmp;

	VP_VERIFY(my_a);
	VP_VERIFY(my_b);

	cmp = fr_pointer_cmp(my_a->da, my_b->da);
	if (cmp != 0) return cmp;

	return (my_a->tag > my_b->tag) - (my_a->tag < my_b->tag);
}

/** Order attributes by their attribute number, and tag
 *
 * @param[in] a		first dict_attr_t.
 * @param[in] b		second dict_attr_t.
 * @return
 *	- +1 if a > b
 *	- 0 if a == b
 *	- -1 if a < b
 */
static inline int8_t pair_cmp_by_num_tag(void const *a, void const *b)
{
	VALUE_PAIR const *my_a = a;
	VALUE_PAIR const *my_b = b;

	VP_VERIFY(my_a);
	VP_VERIFY(my_b);

	if (my_a->da->attr < my_b->da->attr) return -1;
	if (my_a->da->attr > my_b->da->attr) return +1;

	if (my_a->tag < my_b->tag) return -1;
	if (my_a->tag > my_b->tag) return +1;

	return 0;
}

/** Order attributes by their parent(s), attribute number, and tag
 *
 * Useful for some protocols where attributes of the same number should by aggregated
 * within a packet or container TLV.
 *
 * @param[in] a		first dict_attr_t.
 * @param[in] b		second dict_attr_t.
 * @return
 *	- +1 if a > b
 *	- 0 if a == b
 *	- -1 if a < b
 */
int8_t fr_pair_cmp_by_parent_num_tag(void const *a, void const *b)
{
	VALUE_PAIR const	*vp_a = a;
	VALUE_PAIR const	*vp_b = b;
	fr_dict_attr_t const	*da_a = vp_a->da;
	fr_dict_attr_t const	*da_b = vp_b->da;
	fr_dict_attr_t const	*tlv_stack_a[FR_DICT_MAX_TLV_STACK + 1];
	fr_dict_attr_t const	*tlv_stack_b[FR_DICT_MAX_TLV_STACK + 1];
	int i;

	/*
	 *	Fast path (assuming attributes
	 *	are in the same dictionary).
	 */
	if ((da_a->parent->flags.is_root) && (da_b->parent->flags.is_root)) return pair_cmp_by_num_tag(vp_a, vp_b);

	fr_proto_tlv_stack_build(tlv_stack_a, da_a);
	fr_proto_tlv_stack_build(tlv_stack_b, da_b);

	for (i = 0; (da_a = tlv_stack_a[i]) && (da_b = tlv_stack_b[i]); i++) {
		if (da_a->attr > da_b->attr) return +1;
		if (da_a->attr < da_b->attr) return -1;
	}

	/*
	 *	If a has a shallower attribute
	 *	hierarchy than b, it should come
	 *	before b.
	 */
	if (da_a && !da_b) return +1;
	if (!da_a && da_b) return -1;

	if (vp_a->tag > vp_b->tag) return +1;
	if (vp_a->tag < vp_b->tag) return -1;

	return 0;
}

/** Compare two pairs, using the operator from "a"
 *
 *	i.e. given two attributes, it does:
 *
 *	(b->data) (a->operator) (a->data)
 *
 *	e.g. "foo" != "bar"
 *
 * @param[in] a the head attribute
 * @param[in] b the second attribute
 * @return
 *	- 1 if true.
 *	- 0 if false.
 *	- -1 on failure.
 */
int fr_pair_cmp(VALUE_PAIR *a, VALUE_PAIR *b)
{
	if (!a) return -1;

	VP_VERIFY(a);
	if (b) VP_VERIFY(b);

	switch (a->op) {
	case T_OP_CMP_TRUE:
		return (b != NULL);

	case T_OP_CMP_FALSE:
		return (b == NULL);

		/*
		 *	a is a regex, compile it, print b to a string,
		 *	and then do string comparisons.
		 */
	case T_OP_REG_EQ:
	case T_OP_REG_NE:
#ifndef HAVE_REGEX
		return -1;
#else
		if (!b) return false;

		{
			ssize_t	slen;
			regex_t	*preg;
			char	*value;

			if (!fr_cond_assert(a->vp_type == FR_TYPE_STRING)) return -1;

			slen = regex_compile(NULL, &preg, a->xlat, talloc_array_length(a->xlat) - 1,
					     false, false, false, true);
			if (slen <= 0) {
				fr_strerror_printf_push("Error at offset %zu compiling regex for %s", -slen,
							a->da->name);
				return -1;
			}
			value = fr_pair_asprint(NULL, b, '\0');
			if (!value) {
				talloc_free(preg);
				return -1;
			}

			/*
			 *	Don't care about substring matches, oh well...
			 */
			slen = regex_exec(preg, value, talloc_array_length(value) - 1, NULL, NULL);
			talloc_free(preg);
			talloc_free(value);

			if (slen < 0) return -1;
			if (a->op == T_OP_REG_EQ) return (int)slen;
			return !slen;
		}
#endif

	default:		/* we're OK */
		if (!b) return false;
		break;
	}

	return fr_pair_cmp_op(a->op, b, a);
}

/** Determine equality of two lists
 *
 * This is useful for comparing lists of attributes inserted into a binary tree.
 *
 * @param a head list of #VALUE_PAIR.
 * @param b second list of #VALUE_PAIR.
 * @return
 *	- -1 if a < b.
 *	- 0 if the two lists are equal.
 *	- 1 if a > b.
 *	- -2 on error.
 */
int fr_pair_list_cmp(VALUE_PAIR *a, VALUE_PAIR *b)
{
	fr_cursor_t a_cursor, b_cursor;
	VALUE_PAIR *a_p, *b_p;

	for (a_p = fr_cursor_init(&a_cursor, &a), b_p = fr_cursor_init(&b_cursor, &b);
	     a_p && b_p;
	     a_p = fr_cursor_next(&a_cursor), b_p = fr_cursor_next(&b_cursor)) {
		int ret;

		/* Same VP, no point doing expensive checks */
		if (a_p == b_p) continue;

		ret = (a_p->da < b_p->da) - (a_p->da > b_p->da);
		if (ret != 0) return ret;

		ret = (a_p->tag < b_p->tag) - (a_p->tag > b_p->tag);
		if (ret != 0) return ret;

		ret = fr_value_box_cmp(&a_p->data, &b_p->data);
		if (ret != 0) {
			(void)fr_cond_assert(ret >= -1); 	/* Comparison error */
			return ret;
		}
	}

	if (!a_p && !b_p) return 0;
	if (!a_p) return -1;

	/* if(!b_p) */
	return 1;
}

static void _pair_list_sort_split(VALUE_PAIR *source, VALUE_PAIR **front, VALUE_PAIR **back)
{
	VALUE_PAIR *fast;
	VALUE_PAIR *slow;

	/*
	 *	Stopping condition - no more elements left to split
	 */
	if (!source || !source->next) {
		*front = source;
		*back = NULL;

		return;
	}

	/*
	 *	Fast advances twice as fast as slow, so when it gets to the end,
	 *	slow will point to the middle of the linked list.
	 */
	slow = source;
	fast = source->next;

	while (fast) {
		fast = fast->next;
		if (fast) {
			slow = slow->next;
			fast = fast->next;
		}
	}

	*front = source;
	*back = slow->next;
	slow->next = NULL;
}

static VALUE_PAIR *_pair_list_sort_merge(VALUE_PAIR *a, VALUE_PAIR *b, fr_cmp_t cmp)
{
	VALUE_PAIR *result = NULL;

	if (!a) return b;
	if (!b) return a;

	/*
	 *	Compare the fr_dict_attr_ts and tags
	 */
	if (cmp(a, b) <= 0) {
		result = a;
		result->next = _pair_list_sort_merge(a->next, b, cmp);
	} else {
		result = b;
		result->next = _pair_list_sort_merge(a, b->next, cmp);
	}

	return result;
}

/** Sort a linked list of VALUE_PAIRs using merge sort
 *
 * @note We use a merge sort (which is a stable sort), making this
 *	suitable for use on lists with things like EAP-Message
 *	fragments where the order of EAP-Message attributes needs to
 *	be maintained.
 *
 * @param[in,out] vps List of VALUE_PAIRs to sort.
 * @param[in] cmp to sort with
 */
void fr_pair_list_sort(VALUE_PAIR **vps, fr_cmp_t cmp)
{
	VALUE_PAIR *head = *vps;
	VALUE_PAIR *a;
	VALUE_PAIR *b;

	/*
	 *	If there's 0-1 elements it must already be sorted.
	 */
	if (!head || !head->next) return;

	_pair_list_sort_split(head, &a, &b);	/* Split into sublists */
	fr_pair_list_sort(&a, cmp);		/* Traverse left */
	fr_pair_list_sort(&b, cmp);		/* Traverse right */

	/*
	 *	merge the two sorted lists together
	 */
	*vps = _pair_list_sort_merge(a, b, cmp);
}

/** Write an error to the library errorbuff detailing the mismatch
 *
 * Retrieve output with fr_strerror();
 *
 * @todo add thread specific talloc contexts.
 *
 * @param ctx a hack until we have thread specific talloc contexts.
 * @param failed pair of attributes which didn't match.
 */
void fr_pair_validate_debug(TALLOC_CTX *ctx, VALUE_PAIR const *failed[2])
{
	VALUE_PAIR const *filter = failed[0];
	VALUE_PAIR const *list = failed[1];

	char *value, *str;

	(void) fr_strerror();	/* Clear any existing messages */

	if (!fr_cond_assert(!(!filter && !list))) return;

	if (!list) {
		fr_strerror_printf("Attribute \"%s\" not found in list", filter->da->name);
		return;
	}

	if (!filter || (filter->da != list->da)) {
		fr_strerror_printf("Attribute \"%s\" not found in filter", list->da->name);
		return;
	}

	if (!ATTR_TAG_MATCH(list, filter->tag)) {
		fr_strerror_printf("Attribute \"%s\" tag \"%i\" didn't match filter tag \"%i\"",
				   list->da->name, list->tag, filter->tag);
		return;
	}

	value = fr_pair_asprint(ctx, list, '"');
	str = fr_pair_asprint(ctx, filter, '"');

	fr_strerror_printf("Attribute value \"%s\" didn't match filter: %s", value, str);

	talloc_free(str);
	talloc_free(value);

	return;
}

/** Uses fr_pair_cmp to verify all VALUE_PAIRs in list match the filter defined by check
 *
 * @note will sort both filter and list in place.
 *
 * @param failed pointer to an array to write the pointers of the filter/list attributes that didn't match.
 *	  May be NULL.
 * @param filter attributes to check list against.
 * @param list attributes, probably a request or reply
 */
bool fr_pair_validate(VALUE_PAIR const *failed[2], VALUE_PAIR *filter, VALUE_PAIR *list)
{
	fr_cursor_t filter_cursor;
	fr_cursor_t list_cursor;

	VALUE_PAIR *check, *match;

	if (!filter && !list) {
		return true;
	}

	/*
	 *	This allows us to verify the sets of validate and reply are equal
	 *	i.e. we have a validate rule which matches every reply attribute.
	 *
	 *	@todo this should be removed one we have sets and lists
	 */
	fr_pair_list_sort(&filter, fr_pair_cmp_by_da_tag);
	fr_pair_list_sort(&list, fr_pair_cmp_by_da_tag);

	check = fr_cursor_init(&filter_cursor, &filter);
	match = fr_cursor_init(&list_cursor, &list);
	while (match || check) {
		/*
		 *	Lists are of different lengths
		 */
		if (!match || !check) goto mismatch;

		/*
		 *	The lists are sorted, so if the head
		 *	attributes aren't of the same type, then we're
		 *	done.
		 */
		if (!ATTRIBUTE_EQ(check, match)) goto mismatch;

		/*
		 *	They're of the same type, but don't have the
		 *	same values.  This is a problem.
		 *
		 *	Note that the RFCs say that for attributes of
		 *	the same type, order is important.
		 */
		if (fr_pair_cmp(check, match) != 1) goto mismatch;

		check = fr_cursor_next(&filter_cursor);
		match = fr_cursor_next(&list_cursor);
	}

	return true;

mismatch:
	if (failed) {
		failed[0] = check;
		failed[1] = match;
	}
	return false;
}

/** Uses fr_pair_cmp to verify all VALUE_PAIRs in list match the filter defined by check
 *
 * @note will sort both filter and list in place.
 *
 * @param failed pointer to an array to write the pointers of the filter/list attributes that didn't match.
 *	  May be NULL.
 * @param filter attributes to check list against.
 * @param list attributes, probably a request or reply
 */
bool fr_pair_validate_relaxed(VALUE_PAIR const *failed[2], VALUE_PAIR *filter, VALUE_PAIR *list)
{
	vp_cursor_t	filter_cursor;
	vp_cursor_t	list_cursor;

	VALUE_PAIR *check, *last_check = NULL, *match = NULL;

	if (!filter && !list) {
		return true;
	}

	/*
	 *	This allows us to verify the sets of validate and reply are equal
	 *	i.e. we have a validate rule which matches every reply attribute.
	 *
	 *	@todo this should be removed one we have sets and lists
	 */
	fr_pair_list_sort(&filter, fr_pair_cmp_by_da_tag);
	fr_pair_list_sort(&list, fr_pair_cmp_by_da_tag);

	fr_pair_cursor_init(&list_cursor, &list);
	for (check = fr_pair_cursor_init(&filter_cursor, &filter);
	     check;
	     check = fr_pair_cursor_next(&filter_cursor)) {
		/*
		 *	Were processing check attributes of a new type.
		 */
		if (!ATTRIBUTE_EQ(last_check, check)) {
			/*
			 *	Record the start of the matching attributes in the pair list
			 *	For every other operator we require the match to be present
			 */
			match = fr_pair_cursor_next_by_da(&list_cursor, check->da, check->tag);
			if (!match) {
				if (check->op == T_OP_CMP_FALSE) continue;
				goto mismatch;
			}

			fr_pair_cursor_init(&list_cursor, &match);
			last_check = check;
		}

		/*
		 *	Now iterate over all attributes of the same type.
		 */
		for (match = fr_pair_cursor_head(&list_cursor);
		     ATTRIBUTE_EQ(match, check);
		     match = fr_pair_cursor_next(&list_cursor)) {
			/*
			 *	This attribute passed the filter
			 */
			if (!fr_pair_cmp(check, match)) goto mismatch;
		}
	}

	return true;

mismatch:
	if (failed) {
		failed[0] = check;
		failed[1] = match;
	}
	return false;
}

/** Read one line of attribute/value pairs into a list.
 *
 * The line may specify multiple attributes separated by commas.
 *
 * @note If the function returns #T_INVALID, an error has occurred and
 * @note the valuepair list should probably be freed.
 *
 * @param ctx for talloc
 * @param buffer to read valuepairs from.
 * @param list where the parsed VALUE_PAIRs will be appended.
 * @return the last token parsed, or #T_INVALID
 */
FR_TOKEN fr_pair_list_afrom_str(TALLOC_CTX *ctx, char const *buffer, VALUE_PAIR **list)
{
	VALUE_PAIR	*vp, *head, **tail;
	char const	*p;
	FR_TOKEN	last_token = T_INVALID;
	VALUE_PAIR_RAW	raw;

	/*
	 *	We allow an empty line.
	 */
	if (buffer[0] == 0) {
		return T_EOL;
	}

	head = NULL;
	tail = &head;

	p = buffer;
	do {
		raw.l_opand[0] = '\0';
		raw.r_opand[0] = '\0';

		last_token = fr_pair_raw_from_str(&p, &raw);

		/*
		 *	JUST a hash.  Don't try to create a VP.
		 *	Let the caller determine if an empty list is OK.
		 */
		if (last_token == T_HASH) {
			last_token = T_EOL;
			break;
		}
		if (last_token == T_INVALID) break;

		if (raw.quote == T_DOUBLE_QUOTED_STRING) {
			vp = fr_pair_make(ctx, NULL, raw.l_opand, NULL, raw.op);
			if (!vp) {
				last_token = T_INVALID;
				break;
			}
			if (fr_pair_mark_xlat(vp, raw.r_opand) < 0) {
				talloc_free(vp);
				last_token = T_INVALID;
				break;
			}
		} else {
			vp = fr_pair_make(ctx, NULL, raw.l_opand, raw.r_opand, raw.op);
			if (!vp) {
				last_token = T_INVALID;
				break;
			}
		}

		*tail = vp;
		tail = &((*tail)->next);
	} while (*p && (last_token == T_COMMA));

	if (last_token == T_INVALID) {
		fr_pair_list_free(&head);
	} else {
		fr_pair_add(list, head);
	}

	/*
	 *	And return the last token which we read.
	 */
	return last_token;
}

/*
 *	Read valuepairs from the fp up to End-Of-File.
 */
int fr_pair_list_afrom_file(TALLOC_CTX *ctx, VALUE_PAIR **out, FILE *fp, bool *pfiledone)
{
	char buf[8192];
	FR_TOKEN last_token = T_EOL;

	fr_cursor_t cursor;

	VALUE_PAIR *vp = NULL;
	fr_cursor_init(&cursor, out);

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		VALUE_PAIR *next;

		/*
		 *      If we get a '\n' by itself, we assume that's
		 *      the end of that VP list.
		 */
		if (buf[0] == '\n') {
			if (vp) {
				*pfiledone = false;
				return 0;
			}
			continue;
		}

		/*
		 *	Comments get ignored
		 */
		if (buf[0] == '#') continue;

		/*
		 *	Read all of the attributes on the current line.
		 */
		vp = NULL;
		last_token = fr_pair_list_afrom_str(ctx, buf, &vp);
		if (!vp) {
			if (last_token != T_EOL) goto error;
			break;
		}

		do {
			next = vp->next;
			fr_cursor_append(&cursor, vp);
		} while (next && (vp = next));

		buf[0] = '\0';
	}
	*pfiledone = true;

	return 0;

error:
	*pfiledone = false;
	vp = fr_cursor_head(&cursor);
	if (vp) fr_pair_list_free(&vp);

	return -1;
}

/** Duplicate a list of pairs
 *
 * Copy all pairs from 'from' regardless of tag, attribute or vendor.
 *
 * @param[in] ctx	for new #VALUE_PAIR (s) to be allocated in.
 * @param[in] to	where to copy attributes to.
 * @param[in] from	whence to copy #VALUE_PAIR (s).
 * @return
 *	- >0 the number of attributes copied.
 *	- 0 if no attributes copied.
 *	- -1 on error.
 */
int fr_pair_list_copy(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR *from)
{
	fr_cursor_t	src, dst, tmp;

	VALUE_PAIR	*head = NULL;
	VALUE_PAIR	*vp;
	int		cnt = 0;

	fr_cursor_talloc_init(&tmp, &head, VALUE_PAIR);
	for (vp = fr_cursor_talloc_init(&src, &from, VALUE_PAIR);
	     vp;
	     vp = fr_cursor_next(&src), cnt++) {
		VP_VERIFY(vp);
		vp = fr_pair_copy(ctx, vp);
		if (!vp) {
			fr_pair_list_free(&head);
			return -1;
		}
		fr_cursor_append(&tmp, vp); /* fr_pair_list_copy sets next pointer to NULL */
	}

	if (!*to) {	/* Fast Path */
		*to = head;
	} else {
		fr_cursor_talloc_init(&dst, to, VALUE_PAIR);
		fr_cursor_head(&tmp);
		fr_cursor_merge(&dst, &tmp);
	}

	return cnt;
}

/** Duplicate pairs in a list matching the specified da
 *
 * Copy all pairs from 'from' matching the specified da.
 *
 * @param[in] ctx	for new #VALUE_PAIR (s) to be allocated in.
 * @param[in] to	where to copy attributes to.
 * @param[in] from	whence to copy #VALUE_PAIR (s).
 * @param[in] da	to match.
 * @return
 *	- >0 the number of attributes copied.
 *	- 0 if no attributes copied.
 *	- -1 on error.
 */
int fr_pair_list_copy_by_da(TALLOC_CTX *ctx, VALUE_PAIR **to,
			    VALUE_PAIR *from, fr_dict_attr_t const *da)
{
	fr_cursor_t	src, dst, tmp;

	VALUE_PAIR	*head = NULL;
	VALUE_PAIR	*vp;
	int		cnt = 0;

	if (unlikely(!da)) {
		fr_strerror_printf("No search attribute provided");
		return -1;
	}

	fr_cursor_talloc_init(&tmp, &head, VALUE_PAIR);
	for (vp = fr_cursor_iter_by_da_init(&src, &from, da);
	     vp;
	     vp = fr_cursor_next(&src), cnt++) {
		VP_VERIFY(vp);
		vp = fr_pair_copy(ctx, vp);
		if (!vp) {
			fr_pair_list_free(&head);
			return -1;
		}
		fr_cursor_append(&tmp, vp); /* fr_pair_list_copy sets next pointer to NULL */
	}

	if (!*to) {	/* Fast Path */
		*to = head;
	} else {
		fr_cursor_talloc_init(&dst, to, VALUE_PAIR);
		fr_cursor_head(&tmp);
		fr_cursor_merge(&dst, &tmp);
	}

	return cnt;
}

/** Duplicate pairs in a list where the da is a descendant of parent_da
 *
 * Copy all pairs from 'from' which are descendants of the specified 'parent_da'.
 * This is particularly useful for copying attributes of a particular vendor, where the vendor
 * da is passed as parent_da.
 *
 * @param[in] ctx	for new #VALUE_PAIR (s) to be allocated in.
 * @param[in] to	where to copy attributes to.
 * @param[in] from	whence to copy #VALUE_PAIR (s).
 * @param[in] parent_da	to match.
 * @return
 *	- >0 the number of attributes copied.
 *	- 0 if no attributes copied.
 *	- -1 on error.
 */
int fr_pair_list_copy_by_ancestor(TALLOC_CTX *ctx, VALUE_PAIR **to,
				  VALUE_PAIR *from, fr_dict_attr_t const *parent_da)
{
	fr_cursor_t	src, dst, tmp;

	VALUE_PAIR	*head = NULL;
	VALUE_PAIR	*vp;
	int		cnt = 0;

	if (unlikely(!parent_da)) {
		fr_strerror_printf("No search attribute provided");
		return -1;
	}

	fr_cursor_talloc_init(&tmp, &head, VALUE_PAIR);
	for (vp = fr_cursor_iter_by_ancestor_init(&src, &from, parent_da);
	     vp;
	     vp = fr_cursor_next(&src), cnt++) {
		VP_VERIFY(vp);
		vp = fr_pair_copy(ctx, vp);
		if (!vp) {
			fr_pair_list_free(&head);
			return -1;
		}
		fr_cursor_append(&tmp, vp); /* fr_pair_list_copy sets next pointer to NULL */
	}

	if (!*to) {	/* Fast Path */
		*to = head;
	} else {
		fr_cursor_talloc_init(&dst, to, VALUE_PAIR);
		fr_cursor_head(&tmp);
		fr_cursor_merge(&dst, &tmp);
	}

	return cnt;
}

/** Move pairs from source list to destination list respecting operator
 *
 * @note This function does some additional magic that's probably not needed
 *	 in most places. Consider using radius_pairmove in server code.
 *
 * @note fr_pair_list_free should be called on the head of the source list to free
 *	 unmoved attributes (if they're no longer needed).
 *
 * @note Does not respect tags when matching.
 *
 * @param[in] ctx for talloc
 * @param[in,out] to destination list.
 * @param[in,out] from source list.
 *
 * @see radius_pairmove
 */
void fr_pair_list_move(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR **from)
{
	VALUE_PAIR *i, *found;
	VALUE_PAIR *head_new, **tail_new;
	VALUE_PAIR **tail_from;

	if (!to || !from || !*from) return;

	/*
	 *	We're editing the "to" list while we're adding new
	 *	attributes to it.  We don't want the new attributes to
	 *	be edited, so we create an intermediate list to hold
	 *	them during the editing process.
	 */
	head_new = NULL;
	tail_new = &head_new;

	/*
	 *	We're looping over the "from" list, moving some
	 *	attributes out, but leaving others in place.
	 */
	tail_from = from;
	while ((i = *tail_from) != NULL) {
		VALUE_PAIR *j;

		VP_VERIFY(i);

		/*
		 *	We never move Fall-Through.
		 */
		if (fr_dict_attr_is_top_level(i->da) && (i->da->attr == FR_FALL_THROUGH)) {
			tail_from = &(i->next);
			continue;
		}

		/*
		 *	Unlike previous versions, we treat all other
		 *	attributes as normal.  i.e. there's no special
		 *	treatment for passwords or Hint.
		 */

		switch (i->op) {
		/*
		 *	Anything else are operators which
		 *	shouldn't occur.  We ignore them, and
		 *	leave them in place.
		 */
		default:
			tail_from = &(i->next);
			continue;

		/*
		 *	Add it to the "to" list, but only if
		 *	it doesn't already exist.
		 */
		case T_OP_EQ:
			found = fr_pair_find_by_da(*to, i->da, TAG_ANY);
			if (!found) goto do_add;

			tail_from = &(i->next);
			continue;

		/*
		 *	Add it to the "to" list, and delete any attribute
		 *	of the same vendor/attr which already exists.
		 */
		case T_OP_SET:
			found = fr_pair_find_by_da(*to, i->da, TAG_ANY);
			if (!found) goto do_add;

			/*
			 *	Do NOT call fr_pair_delete_by_da() here,
			 *	due to issues with re-writing
			 *	"request->username".
			 *
			 *	Everybody calls fr_pair_move, and
			 *	expects it to work.  We can't
			 *	update request->username here,
			 *	so instead we over-write the
			 *	vp that it's pointing to.
			 */
			switch (found->vp_type) {
			default:
				j = found->next;
				memcpy(found, i, sizeof(*found));
				found->next = j;
				break;

			case FR_TYPE_OCTETS:
				fr_pair_value_memsteal(found, i->vp_octets);
				i->vp_octets = NULL;
				break;

			case FR_TYPE_STRING:
				fr_pair_value_strsteal(found, i->vp_strvalue);
				i->vp_strvalue = NULL;
				found->tag = i->tag;
				break;
			}

			/*
			 *	Delete *all* of the attributes
			 *	of the same number.
			 */
			fr_pair_delete_by_da(&found->next, found->da);

			/*
			 *	Remove this attribute from the
			 *	"from" list.
			 */
			*tail_from = i->next;
			i->next = NULL;
			fr_pair_list_free(&i);
			continue;

		/*
		 *	Move it from the old list and add it
		 *	to the new list.
		 */
		case T_OP_ADD:
	do_add:
			*tail_from = i->next;
			i->next = NULL;
			*tail_new = i;
			fr_pair_steal(ctx, i);
			tail_new = &(i->next);
			continue;
		}
	} /* loop over the "from" list. */

	/*
	 *	Take the "new" list, and append it to the "to" list.
	 */
	fr_pair_add(to, head_new);
}

/** Move a list of pairs
 *
 * Move all pairs from 'from' matching the specified da.  Pairs will be reparented
 * to the specified ctx.
 *
 * @param[in] ctx	for new #VALUE_PAIR (s) to be allocated in.
 * @param[in] to	where to move attributes to.
 * @param[in] from	whence to move #VALUE_PAIR (s).
 * @param[in] da	to match.
 * @return
 *	- >0 number of pairs moved.
 *	- 0 if no pairs were moved.
 */
int fr_pair_list_move_by_da(TALLOC_CTX *ctx, VALUE_PAIR **to,
			    VALUE_PAIR **from, fr_dict_attr_t const *da)
{
	fr_cursor_t	src, dst;

	VALUE_PAIR	*vp;
	int		cnt = 0;

	if (unlikely(!da)) {
		fr_strerror_printf("No search attribute provided");
		return -1;
	}

	fr_cursor_talloc_init(&dst, to, VALUE_PAIR);
	for (vp = fr_cursor_iter_by_da_init(&src, from, da);
	     vp;
	     vp = fr_cursor_next(&src), cnt++) {
		VP_VERIFY(vp);
		fr_pair_steal(ctx, vp);
		fr_cursor_append(&dst, vp);
	}

	return cnt;
}

/** Move pairs in a list where the da is a descendant of parent_da
 *
 * Copy all pairs from 'from' which are descendants of the specified 'parent_da'.
 * This is particularly useful for moving attributes of a particular vendor, where the vendor
 * da is passed as parent_da.
 *
 * @param[in] ctx	for new #VALUE_PAIR (s) to be allocated in.
 * @param[in] to	where to move attributes to.
 * @param[in] from	whence to move #VALUE_PAIR (s).
 * @param[in] parent_da	to match.
 * @return
 *	- >0 number of pairs moved.
 *	- 0 if no pairs were moved.
 */
int fr_pair_list_move_by_ancestor(TALLOC_CTX *ctx, VALUE_PAIR **to,
				  VALUE_PAIR **from, fr_dict_attr_t const *parent_da)
{
	fr_cursor_t	src, dst;

	VALUE_PAIR	*vp;
	int		cnt = 0;

	if (unlikely(!parent_da)) {
		fr_strerror_printf("No search attribute provided");
		return -1;
	}

	fr_cursor_talloc_init(&dst, to, VALUE_PAIR);
	for (vp = fr_cursor_iter_by_ancestor_init(&src, from, parent_da);
	     vp;
	     vp = fr_cursor_next(&src), cnt++) {
		VP_VERIFY(vp);
		fr_pair_steal(ctx, vp);
		fr_cursor_append(&dst, vp);
	}

	return cnt;
}

/** Convert string value to native attribute value
 *
 * @param[in] vp	to assign value to.
 * @param[in] value	string to convert. Binary safe for variable
 *			length values if len is provided.
 * @param[in] inlen	may be < 0 in which case strlen(len) is used
 *			to determine length, else inlen should be the
 *			length of the string or sub string to parse.
 * @param[in] quote	character used set unescape mode.  @see value_str_unescape.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_from_str(VALUE_PAIR *vp, char const *value, ssize_t inlen, char quote, bool tainted)
{
	fr_type_t type;

	if (!value) return -1;

	type = vp->da->type;

	/*
	 *	We presume that the input data is from a double quoted
	 *	string, and needs unescaping
	 */
	if (fr_value_box_from_str(vp, &vp->data, &type, vp->da, value, inlen, quote, tainted) < 0) return -1;

	/*
	 *	If we parsed to a different type than the DA associated with
	 *	the VALUE_PAIR we now need to fixup the DA.
	 *
	 *	This is for types COMBO_IP.  VALUE_PAIRs have a fixed
	 *	data type, and not a polymorphic one.  So instead of
	 *	hacking polymorphic crap through the entire server
	 *	code, we have this hack to make them static.
	 */
	if (type != vp->da->type) {
		fr_dict_attr_t const *da;

		da = fr_dict_attr_by_type(vp->da, type);
		if (!da) {
			fr_strerror_printf("Cannot find %s variant of attribute \"%s\"",
					   fr_int2str(dict_attr_types, type, "<INVALID>"), vp->da->name);
			return -1;
		}
		vp->da = da;
		vp->data.enumv = da;
	}
	vp->type = VT_DATA;

	VP_VERIFY(vp);

	return 0;
}

/** Copy data into an "octets" data type.
 *
 * @param[in,out] vp	to update
 * @param[in] src	data to copy
 * @param[in] size	of the data.
 */
void fr_pair_value_memcpy(VALUE_PAIR *vp, uint8_t const *src, size_t size)
{
	uint8_t *p = NULL;

	if (size) {
		p = talloc_memdup(vp, src, size);
		if (!p) return;
		talloc_set_type(p, uint8_t);
	}

	fr_value_box_clear(&vp->data);

	vp->vp_octets = p;
	vp->vp_length = size;
	vp->vp_type = FR_TYPE_OCTETS;

	vp->type = VT_DATA;

	VP_VERIFY(vp);
}

/** Reparent an allocated octet buffer to a VALUE_PAIR
 *
 * @param[in,out] vp	to update
 * @param[in] src	buffer to steal.
 */
void fr_pair_value_memsteal(VALUE_PAIR *vp, uint8_t const *src)
{
	fr_value_box_clear(&vp->data);

	vp->vp_octets = talloc_steal(vp, src);
	vp->vp_length = talloc_array_length(vp->vp_octets);
	vp->vp_type = FR_TYPE_OCTETS;
	talloc_set_type(vp->vp_ptr, uint8_t);

	vp->type = VT_DATA;

	VP_VERIFY(vp);
}

/** Reparent an allocated char buffer to a VALUE_PAIR
 *
 * @param[in,out] vp	to update
 * @param[in] src	buffer to steal.
 */
void fr_pair_value_strsteal(VALUE_PAIR *vp, char const *src)
{
	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return;

	fr_value_box_clear(&vp->data);

	vp->vp_strvalue = talloc_steal(vp, src);
	vp->vp_length = talloc_array_length(vp->vp_strvalue) - 1;
	vp->vp_type = FR_TYPE_STRING;
	talloc_set_type(vp->vp_ptr, char);

	vp->type = VT_DATA;

	VP_VERIFY(vp);
}

/** Copy data into an "string" data type.
 *
 * @note vp->da must be of type FR_TYPE_STRING.
 *
 * @param[in,out] vp to update
 * @param[in] src data to copy
 */
void fr_pair_value_strcpy(VALUE_PAIR *vp, char const *src)
{
	char *p;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return;

	p = talloc_strdup(vp, src);
	if (!p) return;

	fr_value_box_clear(&vp->data);

	vp->vp_strvalue = p;
	vp->type = VT_DATA;
	vp->vp_length = talloc_array_length(vp->vp_strvalue) - 1;
	vp->vp_type = FR_TYPE_STRING;
	talloc_set_type(vp->vp_ptr, char);

	VP_VERIFY(vp);
}

/** Copy data into an "string" data type.
 *
 * @note unlike the original strncpy, this function does not stop
 *	if it finds \0 bytes embedded in the string.
 *
 * @note vp->da must be of type FR_TYPE_STRING.
 *
 * @param[in,out] vp to update.
 * @param[in] src data to copy.
 * @param[in] len of data to copy.
 */
void fr_pair_value_bstrncpy(VALUE_PAIR *vp, void const *src, size_t len)
{
	char *p;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return;

	p = talloc_array(vp, char, len + 1);
	if (!p) return;

	memcpy(p, src, len);	/* embdedded \0 safe */
	p[len] = '\0';

	fr_value_box_clear(&vp->data);

	vp->vp_strvalue = p;
	vp->vp_length = len;
	vp->vp_type = FR_TYPE_STRING;
	talloc_set_type(vp->vp_ptr, char);

	vp->type = VT_DATA;

	VP_VERIFY(vp);
}

/** Reparent an allocated char buffer to a VALUE_PAIR reallocating the buffer to the correct size
 *
 * If len is larger than the current buffer, the additional space will be filled with '\0'
 *
 * @note vp->da must be of type FR_TYPE_STRING.
 *
 * @param[in,out] vp	to update
 * @param[in] src	buffer to steal.
 * @param[in] len	of data in buffer.
 */
void fr_pair_value_bstrnsteal(VALUE_PAIR *vp, char *src, size_t len)
{
	char	*p;
	size_t	buf_len;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return;

	fr_value_box_clear(&vp->data);

	buf_len = talloc_array_length(src);
	if (buf_len > (len + 1)) {
		vp->vp_strvalue = talloc_realloc_size(vp, src, len + 1);
	} else if (buf_len < (len + 1)) {
		vp->vp_strvalue = p = talloc_realloc_size(vp, src, len + 1);
		memset(p + (buf_len - 1), '\0', (len + 1) - (buf_len - 1));
	} else {
		vp->vp_strvalue = talloc_steal(vp, src);
	}
	vp->vp_length = len;
	vp->vp_type = FR_TYPE_STRING;
	talloc_set_type(vp->vp_ptr, char);

	vp->type = VT_DATA;

	VP_VERIFY(vp);
}

/** Print data into an "string" data type.
 *
 * @note vp->da must be of type FR_TYPE_STRING.
 *
 * @param[in,out] vp to update
 * @param[in] fmt the format string
 */
void fr_pair_value_snprintf(VALUE_PAIR *vp, char const *fmt, ...)
{
	va_list ap;
	char *p;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return;

	va_start(ap, fmt);
	p = talloc_vasprintf(vp, fmt, ap);
	va_end(ap);
	if (!p) return;

	fr_value_box_clear(&vp->data);

	vp->vp_strvalue = p;
	vp->vp_length = talloc_array_length(vp->vp_strvalue) - 1;
	vp->vp_type = FR_TYPE_STRING;
	talloc_set_type(vp->vp_ptr, char);

	vp->type = VT_DATA;

	VP_VERIFY(vp);
}

/** Print the value of an attribute to a string
 *
 * @param[out] out Where to write the string.
 * @param[in] outlen Size of outlen (must be at least 3 bytes).
 * @param[in] vp to print.
 * @param[in] quote Char to add before and after printed value, if 0 no char will be added, if < 0
 *	raw string will be added.
 * @return
 *	- Length of data written to out.
 *	- Value >= outlen on truncation.
 */
size_t fr_pair_value_snprint(char *out, size_t outlen, VALUE_PAIR const *vp, char quote)
{
	VP_VERIFY(vp);

	if (vp->type == VT_XLAT) return snprintf(out, outlen, "%c%s%c", quote, vp->xlat, quote);

	return fr_value_box_snprint(out, outlen, &vp->data, quote);
}

/** Print one attribute value to a string
 *
 * @param ctx to allocate string in.
 * @param vp to print.
 * @param[in] quote the quotation character
 * @return a talloced buffer with the attribute operator and value.
 */
char *fr_pair_value_asprint(TALLOC_CTX *ctx, VALUE_PAIR const *vp, char quote)
{
	VP_VERIFY(vp);

	if (vp->type == VT_XLAT) return fr_asprint(ctx, vp->xlat, talloc_array_length(vp->xlat) - 1, quote);

	return fr_value_box_asprint(ctx, &vp->data, quote);
}

/** Return a const buffer for an enum type attribute
 *
 * Where the vp type is numeric but does not have any enumv, or its value
 * does not map to an enumv, the integer value of the pair will be printed
 * to buff, and a pointer to buff will be returned.
 *
 * @param[in] vp	to print.
 * @param[in] buff	to print integer value to.
 * @return a talloced buffer.
 */
char const *fr_pair_value_enum(VALUE_PAIR const *vp, char buff[20])
{
	char const		*str;
	fr_dict_enum_t const	*enumv = NULL;

	switch (vp->vp_type) {
	case FR_TYPE_NUMERIC:
		break;

	default:
		fr_strerror_printf("Pair %s is not numeric", vp->da->name);
		return NULL;
	}

	if (vp->da->flags.has_value) switch (vp->vp_type) {
	case FR_TYPE_BOOL:
		return vp->vp_bool ? "yes" : "no";

	default:
		enumv = fr_dict_enum_by_value(vp->da, &vp->data);
		break;
	}

	if (!enumv) {
		fr_pair_value_snprint(buff, 20, vp, '\0');
		str = buff;
	} else {
		str = enumv->alias;
	}

	return str;
}

char *fr_pair_type_asprint(TALLOC_CTX *ctx, fr_type_t type)
{
	switch (type) {
	case FR_TYPE_STRING :
		return talloc_typed_strdup(ctx, "_");

	case FR_TYPE_UINT64:
	case FR_TYPE_SIZE:
	case FR_TYPE_INT32:
	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_DATE :
		return talloc_typed_strdup(ctx, "0");

	case FR_TYPE_IPV4_ADDR :
		return talloc_typed_strdup(ctx, "?.?.?.?");

	case FR_TYPE_IPV4_PREFIX:
		return talloc_typed_strdup(ctx, "?.?.?.?/?");

	case FR_TYPE_IPV6_ADDR:
		return talloc_typed_strdup(ctx, "[:?:]");

	case FR_TYPE_IPV6_PREFIX:
		return talloc_typed_strdup(ctx, "[:?:]/?");

	case FR_TYPE_OCTETS:
		return talloc_typed_strdup(ctx, "??");

	case FR_TYPE_ETHERNET:
		return talloc_typed_strdup(ctx, "??:??:??:??:??:??:??:??");

#ifdef WITH_ASCEND_BINARY
	case FR_TYPE_ABINARY:
		return talloc_typed_strdup(ctx, "??");
#endif

	default :
		break;
	}

	return talloc_typed_strdup(ctx, "<UNKNOWN-TYPE>");
}

/** Print one attribute and value to a string
 *
 * Print a VALUE_PAIR in the format:
@verbatim
	<attribute_name>[:tag] <op> <value>
@endverbatim
 * to a string.
 *
 * @param out Where to write the string.
 * @param outlen Length of output buffer.
 * @param vp to print.
 * @return
 *	- Length of data written to out.
 *	- value >= outlen on truncation.
 */
size_t fr_pair_snprint(char *out, size_t outlen, VALUE_PAIR const *vp)
{
	char const	*token = NULL;
	size_t		len, freespace = outlen;

	if (!out) return 0;

	*out = '\0';
	if (!vp || !vp->da) return 0;

	VP_VERIFY(vp);

	if ((vp->op > T_INVALID) && (vp->op < T_TOKEN_LAST)) {
		token = fr_tokens[vp->op];
	} else {
		token = "<INVALID-TOKEN>";
	}

	if (vp->da->flags.has_tag && (vp->tag != TAG_ANY)) {
		len = snprintf(out, freespace, "%s:%d %s ", vp->da->name, vp->tag, token);
	} else {
		len = snprintf(out, freespace, "%s %s ", vp->da->name, token);
	}

	if (is_truncated(len, freespace)) return len;
	out += len;
	freespace -= len;

	len = fr_pair_value_snprint(out, freespace, vp, '"');
	if (is_truncated(len, freespace)) return (outlen - freespace) + len;
	freespace -= len;

	return (outlen - freespace);
}

/** Print one attribute and value to FP
 *
 * Complete string with '\\t' and '\\n' is written to buffer before printing to
 * avoid issues when running with multiple threads.
 *
 * @param fp to output to.
 * @param vp to print.
 */
void fr_pair_fprint(FILE *fp, VALUE_PAIR const *vp)
{
	char	buf[1024];
	char	*p = buf;
	size_t	len;

	if (!fp) return;
	VP_VERIFY(vp);

	*p++ = '\t';
	len = fr_pair_snprint(p, sizeof(buf) - 1, vp);
	if (!len) {
		return;
	}
	p += len;

	/*
	 *	Deal with truncation gracefully
	 */
	if (((size_t) (p - buf)) >= (sizeof(buf) - 2)) {
		p = buf + (sizeof(buf) - 2);
	}

	*p++ = '\n';
	*p = '\0';

	fputs(buf, fp);
}


/** Print a list of attributes and enumv
 *
 * @param fp to output to.
 * @param const_vp to print.
 */
void fr_pair_list_fprint(FILE *fp, VALUE_PAIR const *const_vp)
{
	VALUE_PAIR *vp;
	fr_cursor_t cursor;

	memcpy(&vp, &const_vp, sizeof(vp)); /* const work-arounds */

	for (vp = fr_cursor_init(&cursor, &vp); vp; vp = fr_cursor_next(&cursor)) {
		fr_pair_fprint(fp, vp);
	}
}

/** Print one attribute and value to a string
 *
 * Print a VALUE_PAIR in the format:
@verbatim
	<attribute_name>[:tag] <op> <value>
@endverbatim
 * to a string.
 *
 * @param ctx to allocate string in.
 * @param vp to print.
 * @param[in] quote the quotation character
 * @return a talloced buffer with the attribute operator and value.
 */
char *fr_pair_asprint(TALLOC_CTX *ctx, VALUE_PAIR const *vp, char quote)
{
	char const	*token = NULL;
	char 		*str, *value;

	if (!vp || !vp->da) return 0;

	VP_VERIFY(vp);

	if ((vp->op > T_INVALID) && (vp->op < T_TOKEN_LAST)) {
		token = fr_tokens[vp->op];
	} else {
		token = "<INVALID-TOKEN>";
	}

	value = fr_pair_value_asprint(ctx, vp, quote);

	if (vp->da->flags.has_tag) {
		if (quote && (vp->vp_type == FR_TYPE_STRING)) {
			str = talloc_typed_asprintf(ctx, "%s:%d %s %c%s%c", vp->da->name, vp->tag, token, quote, value, quote);
		} else {
			str = talloc_typed_asprintf(ctx, "%s:%d %s %s", vp->da->name, vp->tag, token, value);
		}
	} else {
		if (quote && (vp->vp_type == FR_TYPE_STRING)) {
			str = talloc_typed_asprintf(ctx, "%s %s %c%s%c", vp->da->name, token, quote, value, quote);
		} else {
			str = talloc_typed_asprintf(ctx, "%s %s %s", vp->da->name, token, value);
		}
	}

	talloc_free(value);

	return str;
}

/** Read a single valuepair from a buffer, and advance the pointer
 *
 *  Returns T_EOL if end of line was encountered.
 *
 * @param[in,out] ptr to read from and update.
 * @param[out] raw The struct to write the raw VALUE_PAIR to.
 * @return the last token read.
 */
FR_TOKEN fr_pair_raw_from_str(char const **ptr, VALUE_PAIR_RAW *raw)
{
	char const	*p;
	char *q;
	FR_TOKEN	ret = T_INVALID, next, quote;
	char		buf[8];

	if (!ptr || !*ptr || !raw) {
		fr_strerror_printf("Invalid arguments");
		return T_INVALID;
	}

	/*
	 *	Skip leading spaces
	 */
	p = *ptr;
	while ((*p == ' ') || (*p == '\t')) p++;

	if (!*p) {
		fr_strerror_printf("No token read where we expected "
				   "an attribute name");
		return T_INVALID;
	}

	if (*p == '#') return T_HASH;

	/*
	 *	Try to get the attribute name.
	 */
	q = raw->l_opand;
	*q = '\0';
	while (*p) {
		uint8_t const *t = (uint8_t const *) p;

		if (q >= (raw->l_opand + sizeof(raw->l_opand))) {
		too_long:
			fr_strerror_printf("Attribute name too long");
			return T_INVALID;
		}

		/*
		 *	This is arguably easier than trying to figure
		 *	out which operators come after the attribute
		 *	name.  Yes, our "lexer" is bad.
		 */
		if (!fr_dict_attr_allowed_chars[(uint8_t)*t]) break;

		/*
		 *	Attribute:=value is NOT
		 *
		 *	Attribute:
		 *	=
		 *	value
		 */
		if ((*p == ':') && (!isdigit((int) p[1]))) break;

		*(q++) = *(p++);
	}

	/*
	 *	Haven't found any valid characters in the name.
	 */
	if (!*raw->l_opand) {
		fr_strerror_printf("Invalid attribute name");
		return T_INVALID;
	}

	/*
	 *	Look for tag (:#).  This is different from :=, which
	 *	is an operator.
	 */
	if ((*p == ':') && (isdigit((int) p[1]))) {
		if (q >= (raw->l_opand + sizeof(raw->l_opand))) {
			goto too_long;
		}
		*(q++) = *(p++);

		while (isdigit((int) *p)) {
			if (q >= (raw->l_opand + sizeof(raw->l_opand))) {
				goto too_long;
			}
			*(q++) = *(p++);
		}
	}

	*q = '\0';
	*ptr = p;

	/* Now we should have an operator here. */
	raw->op = gettoken(ptr, buf, sizeof(buf), false);
	if (raw->op  < T_EQSTART || raw->op  > T_EQEND) {
		fr_strerror_printf("Expecting operator");

		return T_INVALID;
	}

	/*
	 *	Read value.  Note that empty string values are allowed
	 */
	quote = gettoken(ptr, raw->r_opand, sizeof(raw->r_opand), false);
	if (quote == T_EOL) {
		fr_strerror_printf("Failed to get value");

		return T_INVALID;
	}

	/*
	 *	Peek at the next token. Must be T_EOL, T_COMMA, or T_HASH
	 */
	p = *ptr;

	next = gettoken(&p, buf, sizeof(buf), false);
	switch (next) {
	case T_HASH:
		next = T_EOL;
		break;

	case T_EOL:
		break;

	case T_COMMA:
		*ptr = p;
		break;

	default:
		fr_strerror_printf("Expected end of line or comma");
		return T_INVALID;
	}
	ret = next;

	switch (quote) {
	/*
	 *	Perhaps do xlat's
	 */
	case T_DOUBLE_QUOTED_STRING:
		/*
		 *	Only report as double quoted if it contained valid
		 *	a valid xlat expansion.
		 */
		p = strchr(raw->r_opand, '%');
		if (p && (p[1] == '{')) {
			raw->quote = quote;
		} else {
			raw->quote = T_SINGLE_QUOTED_STRING;
		}

		break;

	case T_SINGLE_QUOTED_STRING:
	case T_BACK_QUOTED_STRING:
	case T_BARE_WORD:
		raw->quote = quote;
		break;

	default:
		fr_strerror_printf("Failed to find expected value on right hand side");
		return T_INVALID;
	}

	return ret;
}

#ifdef WITH_VERIFY_PTR
/*
 *	Verify a VALUE_PAIR
 */
inline void fr_pair_verify(char const *file, int line, VALUE_PAIR const *vp)
{
	if (!vp) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR pointer was NULL", file, line);
		if (!fr_cond_assert(0)) fr_exit_now(1);
	}

	(void) talloc_get_type_abort_const(vp, VALUE_PAIR);

	if (!vp->da) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR da pointer was NULL", file, line);
		if (!fr_cond_assert(0)) fr_exit_now(1);
	}

	fr_dict_verify(file, line, vp->da);
	if (vp->data.enumv) fr_dict_verify(file, line, vp->data.enumv);

	if (vp->vp_ptr) switch (vp->vp_type) {
	case FR_TYPE_OCTETS:
	{
		size_t len;
		TALLOC_CTX *parent;

		if (!talloc_get_type(vp->vp_ptr, uint8_t)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" data buffer type should be "
				     "uint8_t but is %s\n", file, line, vp->da->name, talloc_get_name(vp->vp_ptr));
			(void) talloc_get_type_abort(vp->vp_ptr, uint8_t);
		}

		len = talloc_array_length(vp->vp_octets);
		if (vp->vp_length > len) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" length %zu is greater than "
				     "uint8_t data buffer length %zu\n", file, line, vp->da->name, vp->vp_length, len);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

		parent = talloc_parent(vp->vp_ptr);
		if (parent != vp) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" char buffer is not "
				     "parented by VALUE_PAIR %p, instead parented by %p (%s)\n",
				     file, line, vp->da->name,
				     vp, parent, parent ? talloc_get_name(parent) : "NULL");
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
	}
		break;

	case FR_TYPE_STRING:
	{
		size_t len;
		TALLOC_CTX *parent;

		if (!talloc_get_type(vp->vp_ptr, char)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" data buffer type should be "
				     "char but is %s\n", file, line, vp->da->name, talloc_get_name(vp->vp_ptr));
			(void) talloc_get_type_abort(vp->vp_ptr, char);
		}

		len = (talloc_array_length(vp->vp_strvalue) - 1);
		if (vp->vp_length > len) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" length %zu is greater than "
				     "char buffer length %zu\n", file, line, vp->da->name, vp->vp_length, len);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

		if (vp->vp_strvalue[vp->vp_length] != '\0') {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" char buffer not \\0 "
				     "terminated\n", file, line, vp->da->name);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

		parent = talloc_parent(vp->vp_ptr);
		if (parent != vp) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" char buffer is not "
				     "parented by VALUE_PAIR %p, instead parented by %p (%s)\n",
				     file, line, vp->da->name,
				     vp, parent, parent ? talloc_get_name(parent) : "NULL");
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
	}
		break;

	case FR_TYPE_IPV4_ADDR:
		if (vp->vp_ip.af != AF_INET) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" address family is not "
				     "set correctly for IPv4 address.  Expected %i got %i\n",
				     file, line, vp->da->name,
				     AF_INET, vp->vp_ip.af);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
		if (vp->vp_ip.prefix != 32) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" address prefix "
				     "set correctly for IPv4 address.  Expected %i got %i\n",
				     file, line, vp->da->name,
				     32, vp->vp_ip.prefix);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
		break;

	case FR_TYPE_IPV6_ADDR:
		if (vp->vp_ip.af != AF_INET6) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" address family is not "
				     "set correctly for IPv6 address.  Expected %i got %i\n",
				     file, line, vp->da->name,
				     AF_INET6, vp->vp_ip.af);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
		if (vp->vp_ip.prefix != 128) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" address prefix "
				     "set correctly for IPv6 address.  Expected %i got %i\n",
				     file, line, vp->da->name,
				     128, vp->vp_ip.prefix);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
		break;

	default:
		break;
	}

	if (vp->da->flags.is_unknown) {
		(void) talloc_get_type_abort_const(vp->da, fr_dict_attr_t);
	} else {
		fr_dict_attr_t const *da;

		/*
		 *	Attribute may be present with multiple names
		 */
		da = fr_dict_attr_by_name(NULL, vp->da->name);
		if (!da) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR attribute %p \"%s\" (%s) "
				     "not found in global dictionary",
				     file, line, vp->da, vp->da->name,
				     fr_int2str(dict_attr_types, vp->vp_type, "<INVALID>"));
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

		if (da->type == FR_TYPE_COMBO_IP_ADDR) {
			da = fr_dict_attr_by_type(vp->da, vp->da->type);
			if (!da) {
				FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR attribute %p \"%s\" "
					     "variant (%s) not found in global dictionary",
					     file, line, vp->da, vp->da->name,
					     fr_int2str(dict_attr_types, vp->da->type, "<INVALID>"));
				if (!fr_cond_assert(0)) fr_exit_now(1);
			}
		}


		if (da != vp->da) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR "
				     "dictionary pointer %p \"%s\" (%s) "
				     "and global dictionary pointer %p \"%s\" (%s) differ",
				     file, line, vp->da, vp->da->name,
				     fr_int2str(dict_attr_types, vp->da->type, "<INVALID>"),
				     da, da->name, fr_int2str(dict_attr_types, da->type, "<INVALID>"));
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
	}

	if (vp->da->flags.is_raw || vp->da->flags.is_unknown) {
		if (vp->data.type != FR_TYPE_OCTETS) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR (raw/unknown) attribute %p \"%s\" "
				     "data type incorrect.  Expected %s, got %s",
				     file, line, vp->da, vp->da->name,
				     fr_int2str(dict_attr_types, FR_TYPE_OCTETS, "<INVALID>"),
				     fr_int2str(dict_attr_types, vp->data.type, "<INVALID>"));
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
	} else if (vp->da->type != vp->data.type) {
		char data_type_int[10], da_type_int[10];

		snprintf(data_type_int, sizeof(data_type_int), "%i", vp->data.type);
		snprintf(da_type_int, sizeof(da_type_int), "%i", vp->da->type);

		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR attribute %p \"%s\" "
			     "data type (%s) does not match da type (%s)",
			     file, line, vp->da, vp->da->name,
			     fr_int2str(dict_attr_types, vp->data.type, data_type_int),
			     fr_int2str(dict_attr_types, vp->da->type, da_type_int));
		if (!fr_cond_assert(0)) fr_exit_now(1);
	}
}

/*
 *	Verify a pair list
 */
void fr_pair_list_verify(char const *file, int line, TALLOC_CTX const *expected, VALUE_PAIR *vps)
{
	fr_cursor_t		slow_cursor, fast_cursor;
	VALUE_PAIR		*slow, *fast;
	TALLOC_CTX		*parent;

	if (!vps) return;	/* Fast path */

	fr_cursor_init(&fast_cursor, &vps);

	for (slow = fr_cursor_init(&slow_cursor, &vps), fast = fr_cursor_init(&fast_cursor, &vps);
	     slow && fast;
	     slow = fr_cursor_next(&fast_cursor), fast = fr_cursor_next(&fast_cursor)) {
		VP_VERIFY(slow);

		/*
		 *	Advances twice as fast as slow...
		 */
		fast = fr_cursor_next(&fast_cursor);
		if (fast == slow) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: Looping list found.  Fast pointer hit "
				     "slow pointer at \"%s\"", file, line, slow->da->name);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}

		parent = talloc_parent(slow);
		if (expected && (parent != expected)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: Expected VALUE_PAIR \"%s\" to be parented "
				     "by %p (%s), instead parented by %p (%s)\n",
				     file, line, slow->da->name,
				     expected, talloc_get_name(expected),
				     parent, parent ? talloc_get_name(parent) : "NULL");

			fr_log_talloc_report(expected);
			if (parent) fr_log_talloc_report(parent);
			if (!fr_cond_assert(0)) fr_exit_now(1);
		}
	}
}
#endif

/** Mark up a list of VPs as tainted.
 *
 */
void fr_pair_list_tainted(VALUE_PAIR *vps)
{
	VALUE_PAIR	*vp;
	fr_cursor_t	cursor;

	if (!vps) return;

	for (vp = fr_cursor_init(&cursor, &vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		VP_VERIFY(vp);
		vp->vp_tainted = true;
	}
}
