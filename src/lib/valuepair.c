/*
 * valuepair.c	Functions to handle VALUE_PAIRs
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
 * Copyright 2000,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>

#include <ctype.h>

#ifdef HAVE_PCREPOSIX_H
#  define WITH_REGEX
#  include <pcreposix.h>
#elif defined(HAVE_REGEX_H)
#  include <regex.h>
#  define WITH_REGEX

/*
 *  For POSIX Regular expressions.
 *  (0) Means no extended regular expressions.
 *  REG_EXTENDED means use extended regular expressions.
 */
#  ifndef REG_EXTENDED
#    define REG_EXTENDED (0)
#  endif

#  ifndef REG_NOSUB
#    define REG_NOSUB (0)
#  endif
#endif

#define attribute_eq(_x, _y) ((_x && _y) && (_x->da == _y->da) && (_x->tag == _y->tag))

/** Free a VALUE_PAIR
 *
 * @note Do not call directly, use talloc_free instead.
 *
 * @param vp to free.
 * @return 0
 */
static int _pairfree(VALUE_PAIR *vp) {
	/*
	 *	The lack of DA means something has gone wrong
	 */
	if (!vp->da) {
		fr_strerror_printf("VALUE_PAIR has NULL DICT_ATTR pointer (probably already freed)");
	/*
	 *	Only free the DICT_ATTR if it was dynamically allocated
	 *	and was marked for free when the VALUE_PAIR is freed.
	 *
	 *	@fixme This is an awful hack and needs to be removed once DICT_ATTRs are allocated by talloc.
	 */
	} else if (vp->da->flags.vp_free) {
		dict_attr_free(&(vp->da));
	}

#ifndef NDEBUG
	vp->vp_integer = FREE_MAGIC;
#endif

#ifdef TALLOC_DEBUG
	talloc_report_depth_cb(NULL, 0, -1, fr_talloc_verify_cb, NULL);
#endif
	return 0;
}

/** Dynamically allocate a new attribute
 *
 * Allocates a new attribute and a new dictionary attr if no DA is provided.
 *
 * @param[in] ctx for allocated memory, usually a pointer to a RADIUS_PACKET
 * @param[in] da Specifies the dictionary attribute to build the VP from.
 * @return a new value pair or NULL if an error occurred.
 */
VALUE_PAIR *pairalloc(TALLOC_CTX *ctx, DICT_ATTR const *da)
{
	VALUE_PAIR *vp;

	/*
	 *	Caller must specify a da else we don't know what the attribute type is.
	 */
	if (!da) return NULL;

	vp = talloc_zero(ctx, VALUE_PAIR);
	if (!vp) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}

	vp->da = da;
	vp->op = T_OP_EQ;
	vp->type = VT_NONE;

	vp->length = da->flags.length;

	talloc_set_destructor(vp, _pairfree);

	return vp;
}

/** Create a new valuepair
 *
 * If attr and vendor match a dictionary entry then a VP with that DICT_ATTR
 * will be returned.
 *
 * If attr or vendor are uknown will call dict_attruknown to create a dynamic
 * DICT_ATTR of PW_TYPE_OCTETS.
 *
 * Which type of DICT_ATTR the VALUE_PAIR was created with can be determined by
 * checking @verbatim vp->da->flags.is_unknown @endverbatim.
 *
 * @param[in] ctx for allocated memory, usually a pointer to a RADIUS_PACKET
 * @param[in] attr number.
 * @param[in] vendor number.
 * @return the new valuepair or NULL on error.
 */
VALUE_PAIR *paircreate(TALLOC_CTX *ctx, unsigned int attr, unsigned int vendor)
{
	DICT_ATTR const *da;

	da = dict_attrbyvalue(attr, vendor);
	if (!da) {
		da = dict_attrunknown(attr, vendor, true);
		if (!da) {
			return NULL;
		}
	}

	return pairalloc(ctx, da);
}

/** Free memory used by a valuepair list.
 *
 * @todo TLV: needs to free all dependents of each VP freed.
 */
void pairfree(VALUE_PAIR **vps)
{
	VALUE_PAIR	*vp;
	vp_cursor_t	cursor;

	if (!vps || !*vps) {
		return;
	}

	for (vp = fr_cursor_init(&cursor, vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		VERIFY_VP(vp);
		talloc_free(vp);
	}

	*vps = NULL;
}

/** Mark malformed or unrecognised attributed as unknown
 *
 * @param vp to change DICT_ATTR of.
 * @return 0 on success (or if already unknown) else -1 on error.
 */
int pair2unknown(VALUE_PAIR *vp)
{
	DICT_ATTR const *da;

	VERIFY_VP(vp);
	if (vp->da->flags.is_unknown) {
		return 0;
	}

	da = dict_attrunknown(vp->da->attr, vp->da->vendor, true);
	if (!da) {
		return -1;
	}

	vp->da = da;

	return 0;
}
/** Find the pair with the matching DAs
 *
 */
VALUE_PAIR *pairfind_da(VALUE_PAIR *vp, DICT_ATTR const *da, int8_t tag)
{
	vp_cursor_t 	cursor;
	VALUE_PAIR	*i;

	if(!fr_assert(da)) {
		 return NULL;
	}

	for (i = fr_cursor_init(&cursor, &vp);
	     i;
	     i = fr_cursor_next(&cursor)) {
		VERIFY_VP(i);
		if ((i->da == da) && (!i->da->flags.has_tag || (tag == TAG_ANY) || (i->tag == tag))) {
			return i;
		}
	}

	return NULL;
}


/** Find the pair with the matching attribute
 *
 * @todo should take DAs and do a pointer comparison.
 */
VALUE_PAIR *pairfind(VALUE_PAIR *vp, unsigned int attr, unsigned int vendor, int8_t tag)
{
	vp_cursor_t 	cursor;
	VALUE_PAIR	*i;

	for (i = fr_cursor_init(&cursor, &vp);
	     i;
	     i = fr_cursor_next(&cursor)) {
		VERIFY_VP(i);
		if ((i->da->attr == attr) && (i->da->vendor == vendor) && \
		    (!i->da->flags.has_tag || (tag == TAG_ANY) || (i->tag == tag))) {
			return i;
		}
	}

	return NULL;
}

/** Delete matching pairs
 *
 * Delete matching pairs from the attribute list.
 *
 * @param[in,out] first VP in list.
 * @param[in] attr to match.
 * @param[in] vendor to match.
 * @param[in] tag to match. TAG_ANY matches any tag, TAG_UNUSED matches tagless VPs.
 *
 * @todo should take DAs and do a point comparison.
 */
void pairdelete(VALUE_PAIR **first, unsigned int attr, unsigned int vendor,
		int8_t tag)
{
	VALUE_PAIR *i, *next;
	VALUE_PAIR **last = first;

	for(i = *first; i; i = next) {
		VERIFY_VP(i);
		next = i->next;
		if ((i->da->attr == attr) && (i->da->vendor == vendor) &&
		    ((tag == TAG_ANY) ||
		     (i->da->flags.has_tag && (i->tag == tag)))) {
			*last = next;
			talloc_free(i);
		} else {
			last = &i->next;
		}
	}
}

/** Add a VP to the end of the list.
 *
 * Locates the end of 'first', and links an additional VP 'add' at the end.
 *
 * @param[in] first VP in linked list. Will add new VP to the end of this list.
 * @param[in] add VP to add to list.
 */
void pairadd(VALUE_PAIR **first, VALUE_PAIR *add)
{
	VALUE_PAIR *i;

	if (!add) return;

	VERIFY_VP(add);

	if (*first == NULL) {
		*first = add;
		return;
	}
	for(i = *first; i->next; i = i->next)
		VERIFY_VP(i);
	i->next = add;
}

/** Replace all matching VPs
 *
 * Walks over 'first', and replaces the first VP that matches 'replace'.
 *
 * @note Memory used by the VP being replaced will be freed.
 * @note Will not work with unknown attributes.
 *
 * @param[in,out] first VP in linked list. Will search and replace in this list.
 * @param[in] replace VP to replace.
 */
void pairreplace(VALUE_PAIR **first, VALUE_PAIR *replace)
{
	VALUE_PAIR *i, *next;
	VALUE_PAIR **prev = first;

	VERIFY_VP(replace);

	if (*first == NULL) {
		*first = replace;
		return;
	}

	/*
	 *	Not an empty list, so find item if it is there, and
	 *	replace it. Note, we always replace the first one, and
	 *	we ignore any others that might exist.
	 */
	for(i = *first; i; i = next) {
		VERIFY_VP(i);
		next = i->next;

		/*
		 *	Found the first attribute, replace it,
		 *	and return.
		 */
		if ((i->da == replace->da) &&
		    (!i->da->flags.has_tag || (i->tag == replace->tag))
		) {
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

static void pairsort_split(VALUE_PAIR *source, VALUE_PAIR **front, VALUE_PAIR **back)
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

static VALUE_PAIR *pairsort_merge(VALUE_PAIR *a, VALUE_PAIR *b, bool with_tag)
{
	VALUE_PAIR *result = NULL;

	if (!a) return b;
	if (!b) return a;

 	/*
 	 *	Compare the DICT_ATTRs and tags
 	 */
	if ((with_tag && (a->tag < b->tag)) || (a->da <= b->da)) {
		result = a;
     		result->next = pairsort_merge(a->next, b, with_tag);
  	} else {
		result = b;
		result->next = pairsort_merge(a, b->next, with_tag);
	}

	return result;
}

/** Sort a linked list of VALUE_PAIRs using merge sort
 *
 * @param[in,out] vps List of VALUE_PAIRs to sort.
 * @param[in] with_tag sort by tag then by DICT_ATTR
 */
void pairsort(VALUE_PAIR **vps, bool with_tag)
{
	VALUE_PAIR *head = *vps;
	VALUE_PAIR *a;
	VALUE_PAIR *b;

	/*
	 *	If there's 0-1 elements it must already be sorted.
	 */
	if (!head || !head->next) {
		return;
	}

	pairsort_split(head, &a, &b);	/* Split into sublists */
	pairsort(&a, with_tag);		/* Traverse left */
	pairsort(&b, with_tag);		/* Traverse right */

  	/*
  	 *	merge the two sorted lists together
  	 */
  	*vps = pairsort_merge(a, b, with_tag);
}

/** Uses paircmp to verify all VALUE_PAIRs in list match the filter defined by check
 *
 * @param filter attributes to check list against.
 * @param list attributes, probably a request or reply
 */
bool pairvalidate(VALUE_PAIR *filter, VALUE_PAIR *list)
{
	vp_cursor_t filter_cursor;
	vp_cursor_t list_cursor;

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
	pairsort(&filter, true);
	pairsort(&list, true);

	match = fr_cursor_init(&list_cursor, &list);
	check = fr_cursor_init(&filter_cursor, &filter);

	while (true) {
		/*
		 *	The lists are sorted, so if the first
		 *	attributes aren't of the same type, then we're
		 *	done.
		 */
		if (!attribute_eq(check, match)) {
			return false;
		}

		/*
		 *	They're of the same type, but don't have the
		 *	same values.  This is a problem.
		 *
		 *	Note that the RFCs say that for attributes of
		 *	the same type, order is important.
		 */
		if (!paircmp(check, match)) {
			return false;
		}

		match = fr_cursor_next(&list_cursor);
		check = fr_cursor_next(&filter_cursor);

		if (!match && !check) break;

		/*
		 *	One list ended earlier than the others, they
		 *	didn't match.
		 */
		if (!match || !check) {
			return false;
		}
	}

	return true;
}

/** Uses paircmp to verify all VALUE_PAIRs in list match the filter defined by check
 *
 * @param filter attributes to check list against.
 * @param list attributes, probably a request or reply
 */
bool pairvalidate_relaxed(VALUE_PAIR *filter, VALUE_PAIR *list)
{
	vp_cursor_t filter_cursor;
	vp_cursor_t list_cursor;

	VALUE_PAIR *check, *match, *last_check = NULL, *last_match;

	if (!filter && !list) {
		return true;
	}

	/*
	 *	This allows us to verify the sets of validate and reply are equal
	 *	i.e. we have a validate rule which matches every reply attribute.
	 *
	 *	@todo this should be removed one we have sets and lists
	 */
	pairsort(&filter, true);
	pairsort(&list, true);

	fr_cursor_init(&list_cursor, &list);
	for (check = fr_cursor_init(&filter_cursor, &filter);
	     check;
	     check = fr_cursor_next(&filter_cursor)) {
	     	/*
	     	 *	Were processing check attributes of a new type.
	     	 */
	     	if (!attribute_eq(last_check, check)) {
			/*
			 *	Record the start of the matching attributes in the pair list
			 *	For every other operator we require the match to be present
			 */
	     		last_match = fr_cursor_next_by_da(&list_cursor, check->da, check->tag);
	     		if (!last_match) {
	     			if (check->op == T_OP_CMP_FALSE) {
	     				continue;
	     			}
	     			return false;
	     		}

	     		fr_cursor_init(&list_cursor, &last_match);
	     		last_check = check;
	     	}

		/*
		 *	Now iterate over all attributes of the same type.
		 */
		for (match = fr_cursor_first(&list_cursor);
	     	     attribute_eq(match, check);
	             match = fr_cursor_next(&list_cursor)) {
	             	/*
	             	 *	This attribute passed the filter
	             	 */
	             	if (!paircmp(check, match)) {
	             		return false;
	             	}
	        }
	}

	return true;
}

/** Copy a single valuepair
 *
 * Allocate a new valuepair and copy the da from the old vp.
 *
 * @param[in] ctx for talloc
 * @param[in] vp to copy.
 * @return a copy of the input VP or NULL on error.
 */
VALUE_PAIR *paircopyvp(TALLOC_CTX *ctx, VALUE_PAIR const *vp)
{
	VALUE_PAIR *n;

	if (!vp) return NULL;

	VERIFY_VP(vp);

	n = pairalloc(ctx, vp->da);
	if (!n) {
		fr_strerror_printf("out of memory");
		return NULL;
	}

	memcpy(n, vp, sizeof(*n));

	/*
	 *	Now copy the value
	 */
	if (vp->type == VT_XLAT) {
		n->value.xlat = talloc_strdup(n, n->value.xlat);
	}

	n->da = dict_attr_copy(vp->da, true);
	if (!n->da) {
		talloc_free(n);
		return NULL;
	}

	n->next = NULL;

	if ((n->da->type == PW_TYPE_TLV) ||
	    (n->da->type == PW_TYPE_OCTETS)) {
		if (n->vp_octets != NULL) {
			n->vp_octets = talloc_memdup(n, vp->vp_octets, n->length);
		}

	} else if (n->da->type == PW_TYPE_STRING) {
		if (n->vp_strvalue != NULL) {
			/*
			 *	Equivalent to, and faster than strdup.
			 */
			n->vp_strvalue = talloc_memdup(n, vp->vp_octets, n->length + 1);
		}
	}

	return n;
}

/** Copy data from one VP to another
 *
 * Allocate a new pair using da, and copy over the value from the specified
 * vp.
 *
 * @todo Should be able to do type conversions.
 *
 * @param[in] ctx for talloc
 * @param[in] da of new attribute to alloc.
 * @param[in] vp to copy data from.
 * @return the new valuepair.
 */
VALUE_PAIR *paircopyvpdata(TALLOC_CTX *ctx, DICT_ATTR const *da, VALUE_PAIR const *vp)
{
	VALUE_PAIR *n;

	if (!vp) return NULL;

	VERIFY_VP(vp);

	/*
	 *	The types have to be identical, OR the "from" VP has
	 *	to be octets.
	 */
	if (da->type != vp->da->type) {
		int length;
		uint8_t *p;
		VALUE_PAIR const **pvp;

		if (vp->da->type == PW_TYPE_OCTETS) {
			/*
			 *	Decode the data.  It may be wrong!
			 */
			if (rad_data2vp(da->attr, da->vendor, vp->vp_octets, vp->length, &n) < 0) {
				return NULL;
			}

			n->type = VT_DATA;
			return n;
		}

		/*
		 *	Else the destination type is octets
		 */
		switch (vp->da->type) {
		default:
			return NULL; /* can't do it */

		case PW_TYPE_INTEGER:
		case PW_TYPE_IPADDR:
		case PW_TYPE_DATE:
		case PW_TYPE_IFID:
		case PW_TYPE_IPV6ADDR:
		case PW_TYPE_IPV6PREFIX:
		case PW_TYPE_BYTE:
		case PW_TYPE_SHORT:
		case PW_TYPE_ETHERNET:
		case PW_TYPE_SIGNED:
		case PW_TYPE_INTEGER64:
		case PW_TYPE_IPV4PREFIX:
			break;
		}

		n = pairalloc(ctx, da);
		if (!n) return NULL;

		p = talloc_array(n, uint8_t, dict_attr_sizes[vp->da->type][1] + 2);

		pvp = &vp;
		length = rad_vp2attr(NULL, NULL, NULL, pvp, p, dict_attr_sizes[vp->da->type][1]);
		if (length < 0) {
			pairfree(&n);
			return NULL;
		}

		pairmemcpy(n, p + 2, length - 2);
		talloc_free(p);
		return n;
	}

	n = pairalloc(ctx, da);
	if (!n) {
		return NULL;
	}

	memcpy(n, vp, sizeof(*n));
	n->da = da;

	if (n->type == VT_XLAT) {
		n->value.xlat = talloc_strdup(n, n->value.xlat);
	}

	switch (n->da->type) {
		case PW_TYPE_TLV:
		case PW_TYPE_OCTETS:
			if (n->vp_octets != NULL) {
				n->vp_octets = talloc_memdup(n, vp->vp_octets, n->length);
			}
			break;

		case PW_TYPE_STRING:
			if (n->vp_strvalue != NULL) {
				n->vp_strvalue = talloc_memdup(n, vp->vp_strvalue, n->length + 1);	/* NULL byte */
			}
			break;
		default:
			fr_assert(0);
			return NULL;
	}

	n->next = NULL;

	return n;
}


/** Copy a pairlist.
 *
 * Copy all pairs from 'from' regardless of tag, attribute or vendor.
 *
 * @param[in] ctx for new VALUE_PAIRs to be allocated in.
 * @param[in] from whence to copy VALUE_PAIRs.
 * @return the head of the new VALUE_PAIR list or NULL on error.
 */
VALUE_PAIR *paircopy(TALLOC_CTX *ctx, VALUE_PAIR *from)
{
	vp_cursor_t src, dst;

	VALUE_PAIR *out = NULL, *vp;

	fr_cursor_init(&dst, &out);
	for (vp = fr_cursor_init(&src, &from);
	     vp;
	     vp = fr_cursor_next(&src)) {
	     	VERIFY_VP(vp);
	     	vp = paircopyvp(ctx, vp);
	     	if (!vp) {
	     		pairfree(&out);
	     		return NULL;
	     	}
		fr_cursor_insert(&dst, vp); /* paircopy sets next pointer to NULL */
	}

	return out;
}

/** Copy matching pairs
 *
 * Copy pairs of a matching attribute number, vendor number and tag from the
 * the input list to a new list, and returns the head of this list.
 *
 * @param[in] ctx for talloc
 * @param[in] from whence to copy VALUE_PAIRs.
 * @param[in] attr to match, if 0 input list will not be filtered by attr.
 * @param[in] vendor to match.
 * @param[in] tag to match, TAG_ANY matches any tag, TAG_UNUSED matches tagless VPs.
 * @return the head of the new VALUE_PAIR list or NULL on error.
 */
VALUE_PAIR *paircopy2(TALLOC_CTX *ctx, VALUE_PAIR *from,
		      unsigned int attr, unsigned int vendor, int8_t tag)
{
	vp_cursor_t src, dst;

	VALUE_PAIR *out = NULL, *vp;

	fr_cursor_init(&dst, &out);
	for (vp = fr_cursor_init(&src, &from);
	     vp;
	     vp = fr_cursor_next(&src)) {
	     	VERIFY_VP(vp);

		if ((vp->da->attr != attr) || (vp->da->vendor != vendor)) {
			continue;
		}

		if ((tag != TAG_ANY) && vp->da->flags.has_tag && (vp->tag != tag)) {
			continue;
		}

		vp = paircopyvp(ctx, vp);
		if (!vp) {
			pairfree(&out);
			return NULL;
		}
		fr_cursor_insert(&dst, vp);
	}

	return out;
}

/** Steal all members of a VALUE_PAIR list
 *
 * @param[in] ctx to move VALUE_PAIRs into
 * @param[in] from VALUE_PAIRs to move into the new context.
 */
VALUE_PAIR *pairsteal(TALLOC_CTX *ctx, VALUE_PAIR *from)
{
	vp_cursor_t cursor;
	VALUE_PAIR *vp;

	for (vp = fr_cursor_init(&cursor, &from);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		(void) talloc_steal(ctx, vp);
	}

	return from;
}

/** Move pairs from source list to destination list respecting operator
 *
 * @note This function does some additional magic that's probably not needed
 *	 in most places. Consider using radius_pairmove in server code.
 *
 * @note pairfree should be called on the head of the source list to free
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
void pairmove(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR **from)
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
		VERIFY_VP(i);

		/*
		 *	We never move Fall-Through.
		 */
		if (!i->da->vendor && i->da->attr == PW_FALL_THROUGH) {
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
				found = pairfind(*to, i->da->attr, i->da->vendor,
						 TAG_ANY);
				if (!found) goto do_add;

				tail_from = &(i->next);
				continue;

			/*
			 *	Add it to the "to" list, and delete any attribute
			 *	of the same vendor/attr which already exists.
			 */
			case T_OP_SET:
				found = pairfind(*to, i->da->attr, i->da->vendor,
						 TAG_ANY);
				if (!found) goto do_add;

				/*
				 *	Do NOT call pairdelete() here,
				 *	due to issues with re-writing
				 *	"request->username".
				 *
				 *	Everybody calls pairmove, and
				 *	expects it to work.  We can't
				 *	update request->username here,
				 *	so instead we over-write the
				 *	vp that it's pointing to.
				 */
				switch (found->da->type) {
					VALUE_PAIR *j;

					default:
						j = found->next;
						memcpy(found, i, sizeof(*found));
						found->next = j;
						break;

					case PW_TYPE_TLV:
						pairmemsteal(found, i->vp_tlv);
						i->vp_tlv = NULL;
						break;

					case PW_TYPE_OCTETS:
						pairmemsteal(found, i->vp_octets);
						i->vp_octets = NULL;
						break;

					case PW_TYPE_STRING:
						pairstrsteal(found, i->vp_strvalue);
						i->vp_strvalue = NULL;
						found->tag = i->tag;
						break;
				}

				/*
				 *	Delete *all* of the attributes
				 *	of the same number.
				 */
				pairdelete(&found->next,
					   found->da->attr,
					   found->da->vendor, TAG_ANY);

				/*
				 *	Remove this attribute from the
				 *	"from" list.
				 */
				*tail_from = i->next;
				i->next = NULL;
				pairfree(&i);
				continue;

			/*
			 *	Move it from the old list and add it
			 *	to the new list.
			 */
			case T_OP_ADD:
		do_add:
				*tail_from = i->next;
				i->next = NULL;
				*tail_new = talloc_steal(ctx, i);
				tail_new = &(i->next);
				continue;
		}
	} /* loop over the "from" list. */

	/*
	 *	Take the "new" list, and append it to the "to" list.
	 */
	pairadd(to, head_new);
}

/** Move matching pairs between VALUE_PAIR lists
 *
 * Move pairs of a matching attribute number, vendor number and tag from the
 * the input list to the output list.
 *
 * @note pairfree should be called on the head of the old list to free unmoved
 	 attributes (if they're no longer needed).
 *
 * @param[in] ctx for talloc
 * @param[in,out] to destination list.
 * @param[in,out] from source list.
 * @param[in] attr to match, if PW_VENDOR_SPECIFIC and vendor 0, only VSAs will
 *	      be copied.  If 0 and 0, all attributes will match
 * @param[in] vendor to match.
 * @param[in] tag to match, TAG_ANY matches any tag, TAG_UNUSED matches tagless VPs.
 */
void pairfilter(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR **from, unsigned int attr, unsigned int vendor, int8_t tag)
{
	VALUE_PAIR *to_tail, *i, *next;
	VALUE_PAIR *iprev = NULL;

	/*
	 *	Find the last pair in the "to" list and put it in "to_tail".
	 *
	 *	@todo: replace the "if" with "VALUE_PAIR **tail"
	 */
	if (*to != NULL) {
		to_tail = *to;
		for(i = *to; i; i = i->next) {
			VERIFY_VP(i);
			to_tail = i;
		}
	} else
		to_tail = NULL;

	/*
	 *	Attr/vendor of 0 means "move them all".
	 *	It's better than "pairadd(foo,bar);bar=NULL"
	 */
	if ((vendor == 0) && (attr == 0)) {
		if (*to) {
			to_tail->next = *from;
		} else {
			*to = *from;
		}

		for (i = *from; i; i = i->next) {
			(void) talloc_steal(ctx, i);
		}

		*from = NULL;
		return;
	}

	for(i = *from; i; i = next) {
		VERIFY_VP(i);
		next = i->next;

		if ((tag != TAG_ANY) && i->da->flags.has_tag &&
		    (i->tag != tag)) {
			continue;
		}

		/*
		 *	vendor=0, attr = PW_VENDOR_SPECIFIC means
		 *	"match any vendor attribute".
		 */
		if ((vendor == 0) && (attr == PW_VENDOR_SPECIFIC)) {
			/*
			 *	It's a VSA: move it over.
			 */
			if (i->da->vendor != 0) goto move;

			/*
			 *	It's Vendor-Specific: move it over.
			 */
			if (i->da->attr == attr) goto move;

			/*
			 *	It's not a VSA: ignore it.
			 */
			iprev = i;
			continue;
		}

		/*
		 *	If it isn't an exact match, ignore it.
		 */
		if (!((i->da->vendor == vendor) && (i->da->attr == attr))) {
			iprev = i;
			continue;
		}

	move:
		/*
		 *	Remove the attribute from the "from" list.
		 */
		if (iprev)
			iprev->next = next;
		else
			*from = next;

		/*
		 *	Add the attribute to the "to" list.
		 */
		if (to_tail)
			to_tail->next = i;
		else
			*to = i;
		to_tail = i;
		i->next = NULL;
		(void) talloc_steal(ctx, i);
	}
}

static char const *hextab = "0123456789abcdef";

bool pairparsevalue(VALUE_PAIR *vp, char const *value)
{
	char		*p;
	char const	*cp, *cs;
	int		x;
	uint64_t	y;
	size_t		length;
	DICT_VALUE	*dval;

	if (!value) return false;
	VERIFY_VP(vp);

	/*
	 *	It's a comparison, not a real VALUE_PAIR, copy the string over verbatim
	 */
	if ((vp->op == T_OP_REG_EQ) || (vp->op == T_OP_REG_NE)) {
		pairstrcpy(vp, value);	/* Icky hacky ewww */
		goto finish;
	}

	switch(vp->da->type) {
	case PW_TYPE_STRING:
		/*
		 *	Do escaping here
		 */
		p = talloc_strdup(vp, value);
		vp->vp_strvalue = p;
		cp = value;
		length = 0;

		while (*cp) {
			char c = *cp++;

			if (c == '\\') {
				switch (*cp) {
				case 'r':
					c = '\r';
					cp++;
					break;
				case 'n':
					c = '\n';
					cp++;
					break;
				case 't':
					c = '\t';
					cp++;
					break;
				case '"':
					c = '"';
					cp++;
					break;
				case '\'':
					c = '\'';
					cp++;
					break;
				case '\\':
					c = '\\';
					cp++;
					break;
				case '`':
					c = '`';
					cp++;
					break;
				case '\0':
					c = '\\'; /* no cp++ */
					break;
				default:
					if ((cp[0] >= '0') &&
					    (cp[0] <= '9') &&
					    (cp[1] >= '0') &&
					    (cp[1] <= '9') &&
					    (cp[2] >= '0') &&
					    (cp[2] <= '9') &&
					    (sscanf(cp, "%3o", &x) == 1)) {
						c = x;
						cp += 3;
					} /* else just do '\\' */
				}
			}
			*p++ = c;
			length++;
		}
		*p = '\0';
		vp->length = length;
		break;

	case PW_TYPE_IPADDR:
		/*
		 *	FIXME: complain if hostname
		 *	cannot be resolved, or resolve later!
		 */
		p = NULL;
		{
			fr_ipaddr_t ipaddr;
			char ipv4[16];

			/*
			 *	Convert things which are obviously integers to IP addresses
			 *
			 *	We assume the number is the bigendian representation of the
			 *	IP address.
			 */
			if (fr_integer_check(value)) {
				vp->vp_ipaddr = htonl(atol(value));
				break;
			}

			/*
			 *	Certain applications/databases print IPv4 addresses with a
			 *	/32 suffix. Strip it off if the mask is 32, else error out.
			 */
			p = strchr(value, '/');
			if (p) {
				if ((p[1] != '3') || (p[2] != '2') || (p[3] != '\0')) {
					fr_strerror_printf("Invalid IP address suffix \"%s\".  Only '/32' permitted "
							   "for non-prefix types", p);
					return false;
				}

				strlcpy(ipv4, value, sizeof(ipv4));
				ipv4[p - value] = '\0';
				cs = ipv4;
			} else {
				cs = value;
			}

			if (ip_hton(cs, AF_INET, &ipaddr) < 0) {
				fr_strerror_printf("Failed to find IP address for %s", cs);
				return false;
			}

			vp->vp_ipaddr = ipaddr.ipaddr.ip4addr.s_addr;
		}
		vp->length = 4;
		break;

	case PW_TYPE_BYTE:
		vp->length = 1;

		/*
		 *	Note that ALL integers are unsigned!
		 */
		vp->vp_integer = fr_strtoul(value, &p);
		if (!*p) {
			if (vp->vp_integer > 255) {
				fr_strerror_printf("Byte value \"%s\" is larger than 255", value);
				return false;
			}
			break;
		}
		if (fr_whitespace_check(p)) break;
		goto check_for_value;

	case PW_TYPE_SHORT:
		/*
		 *	Note that ALL integers are unsigned!
		 */
		vp->vp_integer = fr_strtoul(value, &p);
		vp->length = 2;
		if (!*p) {
			if (vp->vp_integer > 65535) {
				fr_strerror_printf("Byte value \"%s\" is larger than 65535", value);
				return false;
			}
			break;
		}
		if (fr_whitespace_check(p)) break;
		goto check_for_value;

	case PW_TYPE_INTEGER:
		/*
		 *	Note that ALL integers are unsigned!
		 */
		vp->vp_integer = fr_strtoul(value, &p);
		vp->length = 4;
		if (!*p) break;
		if (fr_whitespace_check(p)) break;

	check_for_value:
		/*
		 *	Look for the named value for the given
		 *	attribute.
		 */
		if ((dval = dict_valbyname(vp->da->attr, vp->da->vendor, value)) == NULL) {
			fr_strerror_printf("Unknown value '%s' for attribute '%s'", value, vp->da->name);
			return false;
		}
		vp->vp_integer = dval->value;
		break;

	case PW_TYPE_INTEGER64:
		/*
		 *	Note that ALL integers are unsigned!
		 */
		if (sscanf(value, "%" PRIu64, &y) != 1) {
			fr_strerror_printf("Invalid value '%s' for attribute '%s'",
					   value, vp->da->name);
			return false;
		}
		vp->vp_integer64 = y;
		vp->length = 8;
		length = strspn(value, "0123456789");
		if (fr_whitespace_check(value + length)) break;
		break;

	case PW_TYPE_DATE:
		{
			/*
			 *	time_t may be 64 bits, whule vp_date
			 *	MUST be 32-bits.  We need an
			 *	intermediary variable to handle
			 *	the conversions.
			 */
			time_t date;

			if (fr_get_time(value, &date) < 0) {
				fr_strerror_printf("failed to parse time string "
					   "\"%s\"", value);
				return false;
			}

			vp->vp_date = date;
		}
		vp->length = 4;
		break;

	case PW_TYPE_ABINARY:
#ifdef WITH_ASCEND_BINARY
		if (strncasecmp(value, "0x", 2) == 0) {
			goto do_octets;
		}

		if (ascend_parse_filter(vp, value) < 0 ) {
			/* Allow ascend_parse_filter's strerror to bubble up */
			return false;
		}
		break;

		/*
		 *	If Ascend binary is NOT defined,
		 *	then fall through to raw octets, so that
		 *	the user can at least make them by hand...
		 */
#endif
	/* raw octets: 0x01020304... */
	case PW_TYPE_VSA:
		if (strcmp(value, "ANY") == 0) {
			vp->length = 0;
			break;
		} /* else it's hex */

	case PW_TYPE_OCTETS:
		if (strncasecmp(value, "0x", 2) == 0) {
			size_t size;
			uint8_t *us;

#ifdef WITH_ASCEND_BINARY
		do_octets:
#endif
			cp = value + 2;
			size = strlen(cp);
			vp->length = size >> 1;
			us = talloc_array(vp, uint8_t, vp->length);

			/*
			 *	Invalid.
			 */
			if ((size & 0x01) != 0) {
				fr_strerror_printf("Hex string is not an even length string");
				return false;
			}

			if (fr_hex2bin(us, cp, vp->length) != vp->length) {
				fr_strerror_printf("Invalid hex data");
				return false;
			}
			vp->vp_octets = us;
		} else {
			pairstrcpy(vp, value);
		}
		break;

	case PW_TYPE_IFID:
		if (ifid_aton(value, (void *) &vp->vp_ifid) == NULL) {
			fr_strerror_printf("Failed to parse interface-id string \"%s\"", value);
			return false;
		}
		vp->length = 8;
		break;

	case PW_TYPE_IPV6ADDR:
		{
			fr_ipaddr_t ipaddr;

			if (ip_hton(value, AF_INET6, &ipaddr) < 0) {
				char buffer[1024];

				strlcpy(buffer, fr_strerror(), sizeof(buffer));

				fr_strerror_printf("failed to parse IPv6 address "
						   "string \"%s\": %s", value, buffer);
				return false;
			}
			vp->vp_ipv6addr = ipaddr.ipaddr.ip6addr;
			vp->length = 16; /* length of IPv6 address */
		}
		break;

	case PW_TYPE_IPV6PREFIX:
		p = strchr(value, '/');
		if (!p || ((p - value) >= 256)) {
			fr_strerror_printf("invalid IPv6 prefix string \"%s\"", value);
			return false;
		} else {
			unsigned int prefix;
			char buffer[256], *eptr;

			memcpy(buffer, value, p - value);
			buffer[p - value] = '\0';

			if (inet_pton(AF_INET6, buffer, vp->vp_ipv6prefix + 2) <= 0) {
				fr_strerror_printf("failed to parse IPv6 address string \"%s\"", value);
				return false;
			}

			prefix = strtoul(p + 1, &eptr, 10);
			if ((prefix > 128) || *eptr) {
				fr_strerror_printf("failed to parse IPv6 address string \"%s\"", value);
				return false;
			}
			vp->vp_ipv6prefix[1] = prefix;

			if (prefix < 128) {
				struct in6_addr addr;

				addr = fr_ipaddr_mask6((struct in6_addr *)(&vp->vp_ipv6prefix[2]), prefix);
				memcpy(vp->vp_ipv6prefix + 2, &addr, sizeof(addr));
			}
		}
		vp->length = 16 + 2;
		break;

	case PW_TYPE_IPV4PREFIX:
		p = strchr(value, '/');

		/*
		 *	192.0.2.2 is parsed as if it was /32
		 */
		if (!p) {
			vp->vp_ipv4prefix[1] = 32;

			if (inet_pton(AF_INET, value, vp->vp_ipv4prefix + 2) <= 0) {
				fr_strerror_printf("failed to parse IPv4 address string \"%s\"", value);
				return false;
			}
			vp->length = sizeof(vp->vp_ipv4prefix);
			break;
		}

		/*
		 *	Otherwise parse the prefix
		 */
		if ((p - value) >= 256) {
			fr_strerror_printf("invalid IPv4 prefix string \"%s\"", value);
			return false;
		} else {
			unsigned int prefix;
			char buffer[256], *eptr;

			memcpy(buffer, value, p - value);
			buffer[p - value] = '\0';

			if (inet_pton(AF_INET, buffer, vp->vp_ipv4prefix + 2) <= 0) {
				fr_strerror_printf("failed to parse IPv4 address string \"%s\"", value);
				return false;
			}

			prefix = strtoul(p + 1, &eptr, 10);
			if ((prefix > 32) || *eptr) {
				fr_strerror_printf("failed to parse IPv4 address string \"%s\"", value);
				return false;
			}
			vp->vp_ipv4prefix[1] = prefix;

			if (prefix < 32) {
				struct in_addr addr;

				addr = fr_ipaddr_mask((struct in_addr *)(&vp->vp_ipv4prefix[2]), prefix);
				memcpy(vp->vp_ipv4prefix + 2, &addr, sizeof(addr));
			}
		}
		vp->length = sizeof(vp->vp_ipv4prefix);
		break;

	case PW_TYPE_ETHERNET:
		{
			char const *c1, *c2;

			/*
			 *	Convert things which are obviously integers to Ethernet addresses
			 *
			 *	We assume the number is the bigendian representation of the
			 *	ethernet address.
			 */
			if (fr_integer_check(value)) {
				uint64_t integer = htonll(atoll(value));

				memcpy(&vp->vp_ether, &integer, sizeof(vp->vp_ether));
				break;
			}

			length = 0;
			cp = value;
			while (*cp) {
				if (cp[1] == ':') {
					c1 = hextab;
					c2 = memchr(hextab, tolower((int) cp[0]), 16);
					cp += 2;
				} else if ((cp[1] != '\0') &&
					   ((cp[2] == ':') ||
					    (cp[2] == '\0'))) {
					   c1 = memchr(hextab, tolower((int) cp[0]), 16);
					   c2 = memchr(hextab, tolower((int) cp[1]), 16);
					   cp += 2;
					   if (*cp == ':') cp++;
				} else {
					c1 = c2 = NULL;
				}
				if (!c1 || !c2 || (length >= sizeof(vp->vp_ether))) {
					fr_strerror_printf("failed to parse Ethernet address \"%s\"", value);
					return false;
				}
				vp->vp_ether[length] = ((c1-hextab)<<4) + (c2-hextab);
				length++;
			}
		}
		vp->length = 6;
		break;

	/*
	 *	Crazy polymorphic (IPv4/IPv6) attribute type for WiMAX.
	 *
	 *	We try and make is saner by replacing the original
	 *	da, with either an IPv4 or IPv6 da type.
	 *
	 *	These are not dynamic da, and will have the same vendor
	 *	and attribute as the original.
	 */
	case PW_TYPE_COMBO_IP:
		{
			DICT_ATTR const *da;

			if (inet_pton(AF_INET6, value, &vp->vp_ipv6addr) > 0) {
				da = dict_attrbytype(vp->da->attr, vp->da->vendor,
						     PW_TYPE_IPV6ADDR);
				if (!da) {
					fr_strerror_printf("Cannot find ipv6addr for %s", vp->da->name);
					return false;
				}

				vp->length = 16; /* length of IPv6 address */
			} else {
				fr_ipaddr_t ipaddr;

				da = dict_attrbytype(vp->da->attr, vp->da->vendor,
						     PW_TYPE_IPADDR);
				if (!da) {
					fr_strerror_printf("Cannot find ipaddr for %s", vp->da->name);
					return false;
				}

				if (ip_hton(value, AF_INET, &ipaddr) < 0) {
					fr_strerror_printf("Failed to find IPv4 address for %s", value);
					return false;
				}

				vp->vp_ipaddr = ipaddr.ipaddr.ip4addr.s_addr;
				vp->length = 4;
			}

			vp->da = da;
		}
		break;

	case PW_TYPE_SIGNED: /* Damned code for 1 WiMAX attribute */
		vp->vp_signed = (int32_t) strtol(value, &p, 10);
		vp->length = 4;
		break;

	case PW_TYPE_TLV: /* don't use this! */
		if (strncasecmp(value, "0x", 2) != 0) {
			fr_strerror_printf("Invalid TLV specification");
			return false;
		}
		length = strlen(value + 2) / 2;
		if (vp->length < length) {
			TALLOC_FREE(vp->vp_tlv);
		}
		vp->vp_tlv = talloc_array(vp, uint8_t, length);
		if (!vp->vp_tlv) {
			fr_strerror_printf("No memory");
			return false;
		}
		if (fr_hex2bin(vp->vp_tlv, value + 2, length) != length) {
			fr_strerror_printf("Invalid hex data in TLV");
			return false;
		}
		vp->length = length;
		break;

		/*
		 *  Anything else.
		 */
	default:
		fr_strerror_printf("unknown attribute type %d", vp->da->type);
		return false;
	}

	finish:
	vp->type = VT_DATA;
	return true;
}

/** Use simple heuristics to create an VALUE_PAIR from an unknown address string
 *
 * If a DICT_ATTR is not provided for the address type, parsing will fail with
 * and error.
 *
 * @param ctx to allocate VP in.
 * @param value IPv4/IPv6 address/prefix string.
 * @param ipv4 dictionary attribute to use for an IPv4 address.
 * @param ipv6 dictionary attribute to use for an IPv6 address.
 * @param ipv4_prefix dictionary attribute to use for an IPv4 prefix.
 * @param ipv6_prefix dictionary attribute to use for an IPv6 prefix.
 * @return NULL on error, or new VALUE_PAIR.
 */
VALUE_PAIR *pairmake_ip(TALLOC_CTX *ctx, char const *value, DICT_ATTR *ipv4, DICT_ATTR *ipv6,
			DICT_ATTR *ipv4_prefix, DICT_ATTR *ipv6_prefix)
{
	VALUE_PAIR *vp;
	DICT_ATTR *da;

	if (!fr_assert(ipv4 || ipv6 || ipv4_prefix || ipv6_prefix)) {
		return NULL;
	}

	/* No point in repeating the work of pairparsevalue */
	if (strchr(value, ':')) {
		if (strchr(value, '/')) {
			da = ipv6_prefix;
			goto finish;
		}

		da = ipv6;
		goto finish;
	}

	if (strchr(value, '/')) {
		da = ipv4_prefix;
		goto finish;
	}
	da = ipv4;

	if (!da) {
		fr_strerror_printf("Invalid IP value specified, allowed types are %s%s%s%s",
				   ipv4 ? "ipaddr " : "", ipv6 ? "ipv6addr " : "",
				   ipv4_prefix ? "ipv4prefix " : "", ipv6_prefix ? "ipv6prefix" : "");
	}
	finish:
	vp = pairalloc(ctx, da);
	if (!pairparsevalue(vp, value)) {
		talloc_free(vp);
		return NULL;
	}

	return vp;
}


/** Create a valuepair from an ASCII attribute and value
 *
 * Where the attribute name is in the form:
 *  - Attr-%d
 *  - Attr-%d.%d.%d...
 *  - Vendor-%d-Attr-%d
 *  - VendorName-Attr-%d
 *
 * @param ctx for talloc
 * @param attribute name to parse.
 * @param value to parse (must be a hex string).
 * @param op to assign to new valuepair.
 * @return new valuepair or NULL on error.
 */
static VALUE_PAIR *pairmake_any(TALLOC_CTX *ctx,
				char const *attribute, char const *value,
				FR_TOKEN op)
{
	VALUE_PAIR	*vp;
	DICT_ATTR const *da;

	uint8_t 	*data;
	size_t		size;

	da = dict_attrunknownbyname(attribute, true);
	if (!da) return NULL;

	/*
	 *	Unknown attributes MUST be of type 'octets'
	 */
	if (value && (strncasecmp(value, "0x", 2) != 0)) {
		fr_strerror_printf("Unknown attribute \"%s\" requires a hex "
				   "string, not \"%s\"", attribute, value);

		dict_attr_free(&da);
		return NULL;
	}

	/*
	 *	We've now parsed the attribute properly, Let's create
	 *	it.  This next stop also looks the attribute up in the
	 *	dictionary, and creates the appropriate type for it.
	 */
	vp = pairalloc(ctx, da);
	if (!vp) {
		dict_attr_free(&da);
		return NULL;
	}

	vp->op = (op == 0) ? T_OP_EQ : op;

	if (!value) return vp;

	size = strlen(value + 2);
	vp->length = size >> 1;
	data = talloc_array(vp, uint8_t, vp->length);

	if (fr_hex2bin(data, value + 2, size) != vp->length) {
		fr_strerror_printf("Invalid hex string");
		talloc_free(vp);
		return NULL;
	}

	vp->vp_octets = data;
	vp->type = VT_DATA;
	return vp;
}


/** Create a VALUE_PAIR from ASCII strings
 *
 * Converts an attribute string identifier (with an optional tag qualifier)
 * and value string into a VALUE_PAIR.
 *
 * The string value is parsed according to the type of VALUE_PAIR being created.
 *
 * @param[in] ctx for talloc
 * @param[in] vps list where the attribute will be added (optional)
 * @param[in] attribute name.
 * @param[in] value attribute value (may be NULL if value will be set later).
 * @param[in] op to assign to new VALUE_PAIR.
 * @return a new VALUE_PAIR.
 */
VALUE_PAIR *pairmake(TALLOC_CTX *ctx, VALUE_PAIR **vps,
		     char const *attribute, char const *value, FR_TOKEN op)
{
	DICT_ATTR const *da;
	VALUE_PAIR	*vp;
	char		*tc, *ts;
	int8_t		tag;
	int		found_tag;
	char		buffer[256];
	char const	*attrname = attribute;

	/*
	 *    Check for tags in 'Attribute:Tag' format.
	 */
	found_tag = 0;
	tag = 0;

	ts = strrchr(attribute, ':');
	if (ts && !ts[1]) {
		fr_strerror_printf("Invalid tag for attribute %s", attribute);
		return NULL;
	}

	if (ts && ts[1]) {
		strlcpy(buffer, attribute, sizeof(buffer));
		attrname = buffer;
		ts = strrchr(attrname, ':');
		if (!ts) return NULL;

		 /* Colon found with something behind it */
		 if (ts[1] == '*' && ts[2] == 0) {
			 /* Wildcard tag for check items */
			 tag = TAG_ANY;
			 *ts = 0;
		 } else if ((ts[1] >= '0') && (ts[1] <= '9')) {
			 /* It's not a wild card tag */
			 tag = strtol(ts + 1, &tc, 0);
			 if (tc && !*tc && TAG_VALID_ZERO(tag))
				 *ts = 0;
			 else tag = 0;
		 } else {
			 fr_strerror_printf("Invalid tag for attribute %s", attribute);
			 return NULL;
		 }
		 found_tag = 1;
	}

	/*
	 *	It's not found in the dictionary, so we use
	 *	another method to create the attribute.
	 */
	da = dict_attrbyname(attrname);
	if (!da) {
		vp = pairmake_any(ctx, attrname, value, op);
		if (vp && vps) pairadd(vps, vp);
		return vp;
	}

	/*      Check for a tag in the 'Merit' format of:
	 *      :Tag:Value.  Print an error if we already found
	 *      a tag in the Attribute.
	 */

	if (value && (*value == ':' && da->flags.has_tag)) {
		/* If we already found a tag, this is invalid */
		if(found_tag) {
			fr_strerror_printf("Duplicate tag %s for attribute %s",
				   value, da->name);
			DEBUG("Duplicate tag %s for attribute %s\n",
				   value, da->name);
			return NULL;
		}
		/* Colon found and attribute allows a tag */
		if (value[1] == '*' && value[2] == ':') {
		       /* Wildcard tag for check items */
		       tag = TAG_ANY;
		       value += 3;
		} else {
		       /* Real tag */
		       tag = strtol(value + 1, &tc, 0);
		       if (tc && *tc==':' && TAG_VALID_ZERO(tag))
			    value = tc + 1;
		       else tag = 0;
		}
	}

	vp = pairalloc(ctx, da);
	if (!vp) {
		return NULL;
	}

	vp->op = (op == 0) ? T_OP_EQ : op;
	vp->tag = tag;

	switch (vp->op) {
	default:
		break;

	case T_OP_CMP_TRUE:
	case T_OP_CMP_FALSE:
		vp->vp_strvalue = NULL;
		vp->length = 0;
		value = NULL;	/* ignore it! */
		break;

		/*
		 *	Regular expression comparison of integer attributes
		 *	does a STRING comparison of the names of their
		 *	integer attributes.
		 */
	case T_OP_REG_EQ:	/* =~ */
	case T_OP_REG_NE:	/* !~ */
#ifndef WITH_REGEX
		fr_strerror_printf("Regular expressions are not supported");
		return NULL;

#else

		/*
		 *	Someone else will fill in the value.
		 */
		if (!value) break;

		talloc_free(vp);

		if (1) {
			int compare;
			regex_t reg;

			compare = regcomp(&reg, value, REG_EXTENDED);
			if (compare != 0) {
				regerror(compare, &reg, buffer, sizeof(buffer));
				fr_strerror_printf("Illegal regular expression in attribute: %s: %s",
					   attribute, buffer);
				return NULL;
			}
		}

		vp = pairmake(ctx, NULL, attribute, NULL, op);
		if (!vp) return NULL;

		if (pairmark_xlat(vp, value) < 0) {
			talloc_free(vp);
			return NULL;
		}

		value = NULL;	/* ignore it */
		break;
#endif
	}

	/*
	 *	FIXME: if (strcasecmp(attribute, vp->da->name) != 0)
	 *	then the user MAY have typed in the attribute name
	 *	as Vendor-%d-Attr-%d, and the value MAY be octets.
	 *
	 *	We probably want to fix pairparsevalue to accept
	 *	octets as values for any attribute.
	 */
	if (value && !pairparsevalue(vp, value)) {
		talloc_free(vp);
		return NULL;
	}

	if (vps) pairadd(vps, vp);
	return vp;
}

/** Mark a valuepair for xlat expansion
 *
 * Copies xlat source (unprocessed) string to valuepair value,
 * and sets value type.
 *
 * @param vp to mark for expansion.
 * @param value to expand.
 * @return 0 if marking succeeded or -1 if vp already had a value, or OOM.
 */
int pairmark_xlat(VALUE_PAIR *vp, char const *value)
{
	char *raw;

	/*
	 *	valuepair should not already have a value.
	 */
	if (vp->type != VT_NONE) {
		return -1;
	}

	raw = talloc_strdup(vp, value);
	if (!raw) {
		return -1;
	}

	vp->type = VT_XLAT;
	vp->value.xlat = raw;
	vp->length = 0;

	return 0;
}

/** Read a single valuepair from a buffer, and advance the pointer
 *
 * Sets *eol to T_EOL if end of line was encountered.
 *
 * @param[in,out] ptr to read from and update.
 * @param[out] raw The struct to write the raw VALUE_PAIR to.
 * @return the last token read.
 */
FR_TOKEN pairread(char const **ptr, VALUE_PAIR_RAW *raw)
{
	char const	*p;
	char *q;
	FR_TOKEN	ret = T_OP_INVALID, next, quote;
	char		buf[8];

	if (!ptr || !*ptr || !raw) {
		fr_strerror_printf("Invalid arguments");
		return T_OP_INVALID;
	}

	/*
	 *	Skip leading spaces
	 */
	p = *ptr;
	while ((*p == ' ') || (*p == '\t')) p++;

	if (!*p) {
		fr_strerror_printf("No token read where we expected "
				   "an attribute name");
		return T_OP_INVALID;
	}

	if (*p == '#') {
		fr_strerror_printf("Read a comment instead of a token");

		return T_HASH;
	}

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
			return T_OP_INVALID;
		}

		/*
		 *	Only ASCII is allowed, and only a subset of that.
		 */
		if ((*t < 32) || (*t >= 128)) {
		invalid:
			fr_strerror_printf("Invalid attribute name");
			return T_OP_INVALID;
		}

		/*
		 *	This is arguably easier than trying to figure
		 *	out which operators come after the attribute
		 *	name.  Yes, our "lexer" is bad.
		 */
		if (!dict_attr_allowed_chars[(int) *t]) {
			break;
		}

		*(q++) = *(p++);
	}

	/*
	 *	ASCII, but not a valid attribute name.
	 */
	if (!*raw->l_opand) goto invalid;

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
	raw->op = gettoken(ptr, buf, sizeof(buf));
	if (raw->op  < T_EQSTART || raw->op  > T_EQEND) {
		fr_strerror_printf("Expecting operator");

		return T_OP_INVALID;
	}

	/*
	 *	Read value.  Note that empty string values are allowed
	 */
	quote = gettoken(ptr, raw->r_opand, sizeof(raw->r_opand));
	if (quote == T_EOL) {
		fr_strerror_printf("Failed to get value");

		return T_OP_INVALID;
	}

	/*
	 *	Peek at the next token. Must be T_EOL, T_COMMA, or T_HASH
	 */
	p = *ptr;

	next = gettoken(&p, buf, sizeof(buf));
	switch (next) {
	case T_EOL:
	case T_HASH:
		break;

	case T_COMMA:
		*ptr = p;
		break;

	default:
		fr_strerror_printf("Expected end of line or comma");
		return T_OP_INVALID;
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
	default:
		raw->quote = quote;

		break;
	}

	return ret;
}

/** Read one line of attribute/value pairs into a list.
 *
 * The line may specify multiple attributes separated by commas.
 *
 * @note If the function returns T_OP_INVALID, an error has occurred and
 * @note the valuepair list should probably be freed.
 *
 * @param ctx for talloc
 * @param buffer to read valuepairs from.
 * @param list where the parsed VALUE_PAIRs will be appended.
 * @return the last token parsed, or T_OP_INVALID
 */
FR_TOKEN userparse(TALLOC_CTX *ctx, char const *buffer, VALUE_PAIR **list)
{
	VALUE_PAIR	*vp, *head, **tail;
	char const	*p;
	FR_TOKEN	last_token = T_OP_INVALID;
	FR_TOKEN	previous_token;
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

		previous_token = last_token;

		last_token = pairread(&p, &raw);
		if (last_token == T_OP_INVALID) break;

		if (raw.quote == T_DOUBLE_QUOTED_STRING) {
			vp = pairmake(ctx, NULL, raw.l_opand, NULL, raw.op);
			if (!vp) {
				last_token = T_OP_INVALID;
				break;
			}
			if (pairmark_xlat(vp, raw.r_opand) < 0) {
				talloc_free(vp);
				last_token = T_OP_INVALID;
				break;
			}
		} else {
			vp = pairmake(ctx, NULL, raw.l_opand, raw.r_opand, raw.op);
			if (!vp) {
				last_token = T_OP_INVALID;
				break;
			}
		}

		*tail = vp;
		tail = &((*tail)->next);
	} while (*p && (last_token == T_COMMA));

	/*
	 *	Don't tell the caller that there was a comment.
	 */
	if (last_token == T_HASH) {
		last_token = previous_token;
	}

	if (last_token == T_OP_INVALID) {
		pairfree(&head);
	} else {
		pairadd(list, head);
	}

	/*
	 *	And return the last token which we read.
	 */
	return last_token;
}

/*
 *	Read valuepairs from the fp up to End-Of-File.
 *
 *	Hmm... this function is only used by radclient..
 */
VALUE_PAIR *readvp2(TALLOC_CTX *ctx, FILE *fp, bool *pfiledone, char const *errprefix)
{
	char buf[8192];
	FR_TOKEN last_token = T_EOL;
	VALUE_PAIR *vp;
	VALUE_PAIR *list;
	bool error = false;

	list = NULL;

	while (!error && fgets(buf, sizeof(buf), fp) != NULL) {
		/*
		 *      If we get a '\n' by itself, we assume that's
		 *      the end of that VP
		 */
		if ((buf[0] == '\n') && (list)) {
			return list;
		}
		if ((buf[0] == '\n') && (!list)) {
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
		last_token = userparse(ctx, buf, &vp);
		if (!vp) {
			if (last_token != T_EOL) {
				fr_perror("%s", errprefix);
				error = false;
				break;
			}
			break;
		}

		pairadd(&list, vp);
		buf[0] = '\0';
	}

	if (error) pairfree(&list);

	*pfiledone = true;

	return list;
}

/** Compare two attribute values
 *
 * @param[in] one the first attribute.
 * @param[in] two the second attribute.
 * @return -1 if one is less than two, 0 if both are equal, 1 if one is more than two, < -1 on error.
 */
int8_t paircmp_value(VALUE_PAIR const *one, VALUE_PAIR const *two)
{
	int64_t compare = 0;

	VERIFY_VP(one);
	VERIFY_VP(two);

	if (one->da->type != two->da->type) {
		fr_strerror_printf("Can't compare attribute values of different types");
		return -2;
	}

	/*
	 *	After doing the previous check for special comparisons,
	 *	do the per-type comparison here.
	 */
	switch (one->da->type) {
	case PW_TYPE_ABINARY:
	case PW_TYPE_OCTETS:
	{
		size_t length;

		if (one->length > two->length) {
			length = one->length;
		} else {
			length = two->length;
		}

		if (length) {
			compare = memcmp(one->vp_octets, two->vp_octets, length);
			if (compare != 0) break;
		}

		/*
		 *	Contents are the same.  The return code
		 *	is therefore the difference in lengths.
		 *
		 *	i.e. "0x00" is smaller than "0x0000"
		 */
		compare = one->length - two->length;
	}
		break;

	case PW_TYPE_STRING:
		fr_assert(one->vp_strvalue);
		fr_assert(two->vp_strvalue);
		compare = strcmp(one->vp_strvalue, two->vp_strvalue);
		break;

	case PW_TYPE_BYTE:
	case PW_TYPE_SHORT:
	case PW_TYPE_INTEGER:
	case PW_TYPE_DATE:
		compare = (int64_t) one->vp_integer - (int64_t) two->vp_integer;
		break;

	case PW_TYPE_SIGNED:
		compare = one->vp_signed - two->vp_signed;
		break;

	case PW_TYPE_INTEGER64:
		/*
		 *	Don't want integer overflow!
		 */
		if (one->vp_integer64 < two->vp_integer64) {
			compare = -1;
		} else if (one->vp_integer64 > two->vp_integer64) {
			compare = 1;
		}
		break;

	case PW_TYPE_ETHERNET:
		compare = memcmp(&one->vp_ether, &two->vp_ether, sizeof(one->vp_ether));
		break;

	case PW_TYPE_IPADDR:
		compare = (int64_t) ntohl(one->vp_ipaddr) - (int64_t) ntohl(two->vp_ipaddr);
		break;

	case PW_TYPE_IPV6ADDR:
		compare = memcmp(&one->vp_ipv6addr, &two->vp_ipv6addr, sizeof(one->vp_ipv6addr));
		break;

	case PW_TYPE_IPV6PREFIX:
		compare = memcmp(&one->vp_ipv6prefix, &two->vp_ipv6prefix, sizeof(one->vp_ipv6prefix));
		break;

	case PW_TYPE_IPV4PREFIX:
		compare = memcmp(&one->vp_ipv4prefix, &two->vp_ipv4prefix, sizeof(one->vp_ipv4prefix));
		break;

	case PW_TYPE_IFID:
		compare = memcmp(&one->vp_ifid, &two->vp_ifid, sizeof(one->vp_ifid));
		break;

	/*
	 *	None of the types below should be in the REQUEST
	 */
	case PW_TYPE_COMBO_IP:		/* This should of been converted into IPADDR/IPV6ADDR */
	case PW_TYPE_TLV:
	case PW_TYPE_EXTENDED:
	case PW_TYPE_LONG_EXTENDED:
	case PW_TYPE_EVS:
	case PW_TYPE_VSA:
	case PW_TYPE_INVALID:		/* We should never see these */
	case PW_TYPE_MAX:
		fr_assert(0);	/* unknown type */
		return -2;

	/*
	 *	Do NOT add a default here, as new types are added
	 *	static analysis will warn us they're not handled
	 */
	}

	if (compare > 0) {
		return 1;
	} else if (compare < 0) {
		return -1;
	}
	return 0;
}

/*
 *	We leverage the fact that IPv4 and IPv6 prefixes both
 *	have the same format:
 *
 *	reserved, prefix-len, data...
 */
static int paircmp_op_cidr(FR_TOKEN op, int bytes,
			   uint8_t one_net, uint8_t const *one,
			   uint8_t two_net, uint8_t const *two)
{
	int i, common;
	uint32_t mask;

	/*
	 *	Handle the case of netmasks being identical.
	 */
	if (one_net == two_net) {
		int compare;

		compare = memcmp(one, two, bytes);

		/*
		 *	If they're identical return true for
		 *	identical.
		 */
		if ((compare == 0) &&
		    ((op == T_OP_CMP_EQ) ||
		     (op == T_OP_LE) ||
		     (op == T_OP_GE))) {
			return true;
		}

		/*
		 *	Everything else returns false.
		 *
		 *	10/8 == 24/8  --> false
		 *	10/8 <= 24/8  --> false
		 *	10/8 >= 24/8  --> false
		 */
		return false;
	}

	/*
	 *	Netmasks are different.  That limits the
	 *	possible results, based on the operator.
	 */
	switch (op) {
	case T_OP_CMP_EQ:
		return false;

	case T_OP_NE:
		return true;

	case T_OP_LE:
	case T_OP_LT:	/* 192/8 < 192.168/16 --> false */
		if (one_net < two_net) {
			return false;
		}
		break;

	case T_OP_GE:
	case T_OP_GT:	/* 192/16 > 192.168/8 --> false */
		if (one_net > two_net) {
			return false;
		}
		break;

	default:
		return false;
	}

	if (one_net < two_net) {
		common = one_net;
	} else {
		common = two_net;
	}

	/*
	 *	Do the check byte by byte.  If the bytes are
	 *	identical, it MAY be a match.  If they're different,
	 *	it is NOT a match.
	 */
	i = 0;
	while (i < bytes) {
		/*
		 *	All leading bytes are identical.
		 */
		if (common == 0) return true;

		/*
		 *	Doing bitmasks takes more work.
		 */
		if (common < 8) break;

		if (one[i] != two[i]) return false;

		common -= 8;
		i++;
		continue;
	}

	mask = 1;
	mask <<= (8 - common);
	mask--;
	mask = ~mask;

	if ((one[i] & mask) == ((two[i] & mask))) {
		return true;
	}

	return false;
}

/** Compare two attributes using an operator
 *
 * @param[in] one the first attribute
 * @param[in] op the operator for comparison.
 * @param[in] two the second attribute
 * @return 1 if true, 0 if false, -1 on error.
 */
int8_t paircmp_op(VALUE_PAIR const *one, FR_TOKEN op, VALUE_PAIR const *two)
{
	int compare;

	switch (one->da->type) {
	case PW_TYPE_IPADDR:
		switch (two->da->type) {
		case PW_TYPE_IPADDR:		/* IPv4 and IPv4 */
			goto cmp;

		case PW_TYPE_IPV4PREFIX:	/* IPv4 and IPv4 Prefix */
			return paircmp_op_cidr(op, 4, 32, (uint8_t const *) &one->vp_ipaddr,
					       two->vp_ipv4prefix[1], (uint8_t const *) &two->vp_ipv4prefix + 2);

		default:
			fr_strerror_printf("Cannot compare IPv4 with IPv6 address");
			return -1;
		}
		break;

	case PW_TYPE_IPV4PREFIX:		/* IPv4 and IPv4 Prefix */
		switch (two->da->type) {
		case PW_TYPE_IPADDR:
			return paircmp_op_cidr(op, 4, one->vp_ipv4prefix[1],
					       (uint8_t const *) &one->vp_ipv4prefix + 2,
					       32, (uint8_t const *) &two->vp_ipaddr);

		case PW_TYPE_IPV4PREFIX:	/* IPv4 Prefix and IPv4 Prefix */
			return paircmp_op_cidr(op, 4, one->vp_ipv4prefix[1],
					       (uint8_t const *) &one->vp_ipv4prefix + 2,
					       two->vp_ipv4prefix[1], (uint8_t const *) &two->vp_ipv4prefix + 2);

		default:
			fr_strerror_printf("Cannot compare IPv4 with IPv6 address");
			return -1;
		}
		break;

	case PW_TYPE_IPV6ADDR:
		switch (two->da->type) {
		case PW_TYPE_IPV6ADDR:		/* IPv6 and IPv6 */
			goto cmp;

		case PW_TYPE_IPV6PREFIX:	/* IPv6 and IPv6 Preifx */
			return paircmp_op_cidr(op, 16, 128, (uint8_t const *) &one->vp_ipv6addr,
					       two->vp_ipv6prefix[1], (uint8_t const *) &two->vp_ipv6prefix + 2);
			break;

		default:
			fr_strerror_printf("Cannot compare IPv6 with IPv4 address");
			return -1;
		}
		break;

	case PW_TYPE_IPV6PREFIX:
		switch (two->da->type) {
		case PW_TYPE_IPV6ADDR:		/* IPv6 Prefix and IPv6 */
			return paircmp_op_cidr(op, 16, one->vp_ipv6prefix[1],
					       (uint8_t const *) &one->vp_ipv6prefix + 2,
					       128, (uint8_t const *) &two->vp_ipv6addr);

		case PW_TYPE_IPV6PREFIX:	/* IPv6 Prefix and IPv6 */
			return paircmp_op_cidr(op, 16, one->vp_ipv6prefix[1],
					       (uint8_t const *) &one->vp_ipv6prefix + 2,
					       two->vp_ipv6prefix[1], (uint8_t const *) &two->vp_ipv6prefix + 2);

		default:
			fr_strerror_printf("Cannot compare IPv6 with IPv4 address");
			return -1;
		}
		break;

	default:
	cmp:
		compare = paircmp_value(one, two);
		if (compare < -1) {	/* comparison error */
			return -1;
		}
	}

	/*
	 *	Now do the operator comparison.
	 */
	switch (op) {
	case T_OP_CMP_EQ:
		return (compare == 0);

	case T_OP_NE:
		return (compare != 0);

	case T_OP_LT:
		return (compare < 0);

	case T_OP_GT:
		return (compare > 0);

	case T_OP_LE:
		return (compare <= 0);

	case T_OP_GE:
		return (compare >= 0);

	default:
		return 0;
	}
}


/** Compare two pairs, using the operator from "one"
 *
 *	i.e. given two attributes, it does:
 *
 *	(two->data) (one->operator) (one->data)
 *
 *	e.g. "foo" != "bar"
 *
 * @param[in] one the first attribute
 * @param[in] two the second attribute
 * @return 1 if true, 0 if false, -1 on error.
 */
int8_t paircmp(VALUE_PAIR *one, VALUE_PAIR *two)
{
	int compare;

	VERIFY_VP(one);
	VERIFY_VP(two);

	switch (one->op) {
	case T_OP_CMP_TRUE:
		return (two != NULL);

	case T_OP_CMP_FALSE:
		return (two == NULL);

		/*
		 *	One is a regex, compile it, print two to a string,
		 *	and then do string comparisons.
		 */
	case T_OP_REG_EQ:
	case T_OP_REG_NE:
#ifndef WITH_REGEX
		return -1;
#else
		{
			regex_t reg;
			char buffer[MAX_STRING_LEN * 4 + 1];

			compare = regcomp(&reg, one->vp_strvalue, REG_EXTENDED);
			if (compare != 0) {
				regerror(compare, &reg, buffer, sizeof(buffer));
				fr_strerror_printf("Illegal regular expression in attribute: %s: %s",
					   	   one->da->name, buffer);
				return -1;
			}

			vp_prints_value(buffer, sizeof(buffer), two, 0);

			/*
			 *	Don't care about substring matches,
			 *	oh well...
			 */
			compare = regexec(&reg, buffer, 0, NULL, 0);

			regfree(&reg);
			if (one->op == T_OP_REG_EQ) {
				return (compare == 0);
			}

			return (compare != 0);
		}
#endif

	default:		/* we're OK */
		break;
	}

	return paircmp_op(two, one->op, one);
}

/** Determine equality of two lists
 *
 * This is useful for comparing lists of attributes inserted into a binary tree.
 *
 * @param a first list of VALUE_PAIRs.
 * @param b second list of VALUE_PAIRs.
 * @return -1 if a < b, 0 if the two lists are equal, 1 if a > b, -2 on error.
 */
int8_t pairlistcmp(VALUE_PAIR *a, VALUE_PAIR *b)
{
	vp_cursor_t a_cursor, b_cursor;
	VALUE_PAIR *a_p, *b_p;
	int ret;

	for (a_p = fr_cursor_init(&a_cursor, &a), b_p = fr_cursor_init(&b_cursor, &b);
	     a_p && b_p;
	     a_p = fr_cursor_next(&a_cursor), b_p = fr_cursor_next(&b_cursor)) {
	     	/* Same VP, no point doing expensive checks */
	     	if (a_p == b_p) {
			continue;
	     	}

		if (a_p->da < b_p->da) {
			return -1;
		}
		if (a_p->da > b_p->da) {
			return 1;
		}

		if (a_p->tag < b_p->tag) {
			return -1;
		}
		if (a_p->tag > b_p->tag) {
			return 1;
		}

		ret = paircmp_value(a_p, b_p);
		if (ret != 0) {
			fr_assert(ret >= -1); 	/* Comparison error */
			return ret;
		}
	}

	if (!a_p && !b_p) {
		return 0;
	}

	if (!a_p) {
		return -1;
	}

	if (!b_p) {
		return 1;
	}

	return 0;
}

/** Copy data into an "octets" data type.
 *
 * @param[in,out] vp to update
 * @param[in] src data to copy
 * @param[in] size of the data
 */
void pairmemcpy(VALUE_PAIR *vp, uint8_t const *src, size_t size)
{
	uint8_t *p, *q;

	VERIFY_VP(vp);

	p = talloc_memdup(vp, src, size);
	if (!p) return;

	memcpy(&q, &vp->vp_octets, sizeof(q));
	talloc_free(q);

	vp->vp_octets = p;
	vp->length = size;
}

/** Reparent an allocated octet buffer to a VALUE_PAIR
 *
 * @param[in,out] vp to update
 * @param[in] src buffer to steal.
 */
void pairmemsteal(VALUE_PAIR *vp, uint8_t const *src)
{
	uint8_t *q;
	VERIFY_VP(vp);

	memcpy(&q, &vp->vp_octets, sizeof(q));
	talloc_free(q);

	vp->vp_octets = talloc_steal(vp, src);
	vp->type = VT_DATA;
	vp->length = talloc_array_length(vp->vp_strvalue);
}

/** Reparent an allocated char buffer to a VALUE_PAIR
 *
 * @param[in,out] vp to update
 * @param[in] src buffer to steal.
 */
void pairstrsteal(VALUE_PAIR *vp, char const *src)
{
	uint8_t *q;
	VERIFY_VP(vp);

	memcpy(&q, &vp->vp_octets, sizeof(q));
	talloc_free(q);

	vp->vp_strvalue = talloc_steal(vp, src);
	vp->type = VT_DATA;
	vp->length = talloc_array_length(vp->vp_strvalue) - 1;
}

/** Copy data into an "string" data type.
 *
 * @param[in,out] vp to update
 * @param[in] src data to copy
 */
void pairstrcpy(VALUE_PAIR *vp, char const *src)
{
	char *p, *q;

	VERIFY_VP(vp);

	p = talloc_strdup(vp, src);
	if (!p) return;

	memcpy(&q, &vp->vp_strvalue, sizeof(q));
	talloc_free(q);

	vp->vp_strvalue = p;
	vp->type = VT_DATA;
	vp->length = talloc_array_length(vp->vp_strvalue) - 1;
}


/** Print data into an "string" data type.
 *
 * @param[in,out] vp to update
 * @param[in] fmt the format string
 */
void pairsprintf(VALUE_PAIR *vp, char const *fmt, ...)
{
	va_list ap;
	char *p, *q;

	VERIFY_VP(vp);

	va_start(ap, fmt);
	p = talloc_vasprintf(vp, fmt, ap);
	va_end(ap);

	if (!p) return;

	memcpy(&q, &vp->vp_strvalue, sizeof(q));
	talloc_free(q);

	vp->vp_strvalue = p;
	vp->type = VT_DATA;

	vp->length = talloc_array_length(vp->vp_strvalue) - 1;
}

