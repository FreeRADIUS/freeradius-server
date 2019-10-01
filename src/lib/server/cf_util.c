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

/**
 * $Id$
 * @file cf_util.c
 * @brief Functions for building and managing the structure of internal format config items.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <string.h>

#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/cf_priv.h>
#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/rad_assert.h>

#include <freeradius-devel/util/cursor.h>

static inline int cf_ident2_cmp(void const *a, void const *b);
static int _cf_ident1_cmp(void const *a, void const *b);
static int _cf_ident2_cmp(void const *a, void const *b);

/** Return the next child that's of the specified type
 *
 * @param[in] parent	to return children from.
 * @param[in] prev	child to start searching from.
 * @param[in] type	to search for.
 * @return
 *	- The next #CONF_ITEM that's a child of ci matching type.
 *	- NULL if no #CONF_ITEM matches that criteria.
 */
static CONF_ITEM *cf_next(CONF_ITEM const *parent, CONF_ITEM const *prev, CONF_ITEM_TYPE type)
{
	CONF_ITEM *ci;

	for (ci = prev ? prev->next : parent->child;
	     ci;
	     ci = ci->next) {
		if (ci->type == type) return ci;
	}

	return NULL;
}

#define IS_WILDCARD(_ident) (_ident == CF_IDENT_ANY)

/** Return the next child that's of the specified type with the specified identifiers
 *
 * @param[in] parent	The section we're searching in.
 * @param[in] type	of #CONF_ITEM we're searching for.
 * @param[in] ident1	The first identifier.
 * @param[in] ident2	The second identifier. Special value CF_IDENT_ANY
 *			can be used to match any ident2 value.
 * @return
 *	- The first matching item.
 *	- NULL if no items matched.
 */
static CONF_ITEM *cf_find(CONF_ITEM const *parent, CONF_ITEM_TYPE type, char const *ident1, char const *ident2)
{
	CONF_SECTION	cs_find;
	CONF_PAIR	cp_find;
	CONF_DATA	cd_find;
	CONF_ITEM	*find;

	if (!parent) return NULL;
	if (!parent->child) return NULL;	/* No children */

	if (!ident1) return cf_next(parent, NULL, type);

	switch (type) {
	case CONF_ITEM_SECTION:
		memset(&cs_find, 0, sizeof(cs_find));
		cs_find.item.type = CONF_ITEM_SECTION;
		cs_find.name1 = ident1;
		if (!IS_WILDCARD(ident2)) cs_find.name2 = ident2;

		find = (CONF_ITEM *)&cs_find;
		break;

	case CONF_ITEM_PAIR:
		rad_assert((ident2 == NULL) || IS_WILDCARD(ident2));

		memset(&cp_find, 0, sizeof(cp_find));
		cp_find.item.type = CONF_ITEM_PAIR;
		cp_find.attr = ident1;

		find = (CONF_ITEM *)&cp_find;
		break;

	case CONF_ITEM_DATA:
		memset(&cd_find, 0, sizeof(cd_find));
		cd_find.item.type = CONF_ITEM_DATA;
		cd_find.type = ident1;
		if (!IS_WILDCARD(ident2)) cd_find.name = ident2;

		find = (CONF_ITEM *)&cd_find;
		break;

	default:
		fr_assert_fail(NULL);
		return NULL;
	}

	/*
	 *	No ident1, iterate over the child list
	 */
	if (IS_WILDCARD(ident1)) {
		CONF_ITEM *ci;

		for (ci = parent->child;
		     ci != NULL;
		     ci = ci->next) {
			if (find->type != ci->type) continue;

			if (cf_ident2_cmp(find, ci) == 0) break;
		}

		return ci;
	}

	/*
	 *	No ident2, use the ident1 tree.
	 */
	if (IS_WILDCARD(ident2)) return rbtree_finddata(parent->ident1, find);

	/*
	 *	Both ident1 and ident2 use the ident2 tree.
	 */
	return rbtree_finddata(parent->ident2, find);
}

/** Return the next child that's of the specified type with the specified identifiers
 *
 * @param[in] parent	The section we're searching in.
 * @param[in] prev	item we found, or NULL to start from the beginning.
 * @param[in] type	of #CONF_ITEM we're searching for.
 * @param[in] ident1	The first identifier.
 * @param[in] ident2	The second identifier. Special value CF_IDENT_ANY
 *			can be used to match any ident2 value.
 * @return
 *	- The first matching item.
 *	- NULL if no items matched.
 */
static CONF_ITEM *cf_find_next(CONF_ITEM const *parent, CONF_ITEM const *prev,
			       CONF_ITEM_TYPE type, char const *ident1, char const *ident2)
{
	CONF_SECTION	cs_find;
	CONF_PAIR	cp_find;
	CONF_DATA	cd_find;
	CONF_ITEM	*find;
	CONF_ITEM	*ci;

	if (!parent) return NULL;

	if (!prev) {
		if (!ident1) return cf_next(parent, NULL, type);
		return cf_find(parent, type, ident1, ident2);
	}
	if (!ident1) return cf_next(parent, prev, type);

	switch (type) {
	case CONF_ITEM_SECTION:
		memset(&cs_find, 0, sizeof(cs_find));
		cs_find.item.type = CONF_ITEM_SECTION;
		cs_find.name1 = ident1;
		if (!IS_WILDCARD(ident2)) cs_find.name2 = ident2;

		find = (CONF_ITEM *)&cs_find;
		break;

	case CONF_ITEM_PAIR:
		rad_assert((ident2 == NULL) || IS_WILDCARD(ident2));

		memset(&cp_find, 0, sizeof(cp_find));
		cp_find.item.type = CONF_ITEM_PAIR;
		cp_find.attr = ident1;

		find = (CONF_ITEM *)&cp_find;
		break;

	case CONF_ITEM_DATA:
		memset(&cd_find, 0, sizeof(cd_find));
		cd_find.item.type = CONF_ITEM_DATA;
		cd_find.type = ident1;
		if (!IS_WILDCARD(ident2)) cd_find.name = ident2;

		find = (CONF_ITEM *)&cd_find;
		break;

	default:
		fr_assert_fail(NULL);
		return NULL;
	}

	if (IS_WILDCARD(ident1)) {
		for (ci = prev->next;
		     ci && (cf_ident2_cmp(ci, find) != 0);
		     ci = ci->next);

		return ci;
	}

	if (IS_WILDCARD(ident2)) {
		for (ci = prev->next;
		     ci && (_cf_ident1_cmp(ci, find) != 0);
		     ci = ci->next) {
			rad_assert(ci->next != ci);
		}

		return ci;
	}

	for (ci = prev->next;
	     ci && (_cf_ident2_cmp(ci, find) != 0);
	     ci = ci->next);

	return ci;
}

/** Compare the first identifier of a child
 *
 * For CONF_ITEM_PAIR this is 'attr'.
 * For CONF_ITEM_SECTION this is 'name1'.
 * For CONF_ITEM_DATA this is 'type'.
 *
 * @param[in] a	First CONF_ITEM to compare.
 * @param[in] b Second CONF_ITEM to compare.
 * @return
 *	- >0 if a > b.
 *	- <0 if a < b.
 *	- 0 if a == b.
 */
static inline int _cf_ident1_cmp(void const *a, void const *b)
{
	CONF_ITEM_TYPE type;

	{
		CONF_ITEM const *one = a;
		CONF_ITEM const *two = b;

		if (one->type > two->type) return +1;
		if (one->type < two->type) return -1;

		type = one->type;
	}

	switch (type) {
	case CONF_ITEM_PAIR:
	{
		CONF_PAIR const *one = a;
		CONF_PAIR const *two = b;

		return strcmp(one->attr, two->attr);
	}

	case CONF_ITEM_SECTION:
	{
		CONF_SECTION const *one = a;
		CONF_SECTION const *two = b;

		return strcmp(one->name1, two->name1);
	}

	case CONF_ITEM_DATA:
	{
		CONF_DATA const *one = a;
		CONF_DATA const *two = b;

		return strcmp(one->type, two->type);
	}

	default:
		fr_assert_fail(NULL);
		return 0;
	}
}

/** Compare only the second identifier of a child
 *
 * For CONF_ITEM_SECTION this is 'name2'.
 * For CONF_ITEM_DATA this is 'name'.
 *
 * @param[in] a	First CONF_ITEM to compare.
 * @param[in] b Second CONF_ITEM to compare.
 * @return
 *	- >0 if a > b.
 *	- <0 if a < b.
 *	- 0 if a == b.
 */
static inline int cf_ident2_cmp(void const *a, void const *b)
{
	CONF_ITEM const *ci = a;

	switch (ci->type) {
	case CONF_ITEM_PAIR:
		return 0;

	case CONF_ITEM_SECTION:
	{
		CONF_SECTION const *one = a;
		CONF_SECTION const *two = b;

		if (!two->name2 && one->name2) return +1;
		if (two->name2 && !one->name2) return -1;
		if (!two->name2 && !one->name2) return 0;

		return strcmp(one->name2, two->name2);
	}

	case CONF_ITEM_DATA:
	{
		CONF_DATA const *one = a;
		CONF_DATA const *two = b;

		if (!two->name && one->name) return +1;
		if (two->name && !one->name) return -1;
		if (!two->name && !one->name) return 0;

		return strcmp(one->name, two->name);
	}

	default:
		fr_assert_fail(NULL);
		return 0;
	}
}

/** Compare the first and second identifiers of a child
 *
 * For CONF_ITEM_SECTION this is 'name2'.
 * For CONF_ITEM_DATA this is 'name'.
 *
 * @param[in] a	First CONF_ITEM to compare.
 * @param[in] b Second CONF_ITEM to compare.
 * @return
 *	- >0 if a > b.
 *	- <0 if a < b.
 *	- 0 if a == b.
 */
static int _cf_ident2_cmp(void const *a, void const *b)
{
	int ret;

	ret = _cf_ident1_cmp(a, b);
	if (ret != 0) return ret;

	return cf_ident2_cmp(a, b);
}

/** Add a child
 *
 * @param[in] parent	to add child to.
 * @param[in] child	to add.
 */
void _cf_item_add(CONF_ITEM *parent, CONF_ITEM *child)
{
	fr_cursor_t	to_merge;
	CONF_ITEM	*ci;

	rad_assert(parent != child);

	if (!parent || !child) return;

	/*
	 *	New child, add child trees.
	 */
	if (!parent->ident1) parent->ident1 = rbtree_create(parent, _cf_ident1_cmp, NULL, RBTREE_FLAG_NONE);
	if (!parent->ident2) parent->ident2 = rbtree_create(parent, _cf_ident2_cmp, NULL, RBTREE_FLAG_NONE);

	fr_cursor_init(&to_merge, &child);

	for (ci = fr_cursor_head(&to_merge);
	     ci;
	     ci = fr_cursor_next(&to_merge)) {
		rbtree_insert(parent->ident1, ci);
		rbtree_insert(parent->ident2, ci);	/* NULL ident2 is still a value */
	 	fr_cursor_append(&parent->cursor, ci);	/* Append to the list of children */
	}
}

/** Remove item from parent and fixup trees
 *
 * @param[in] parent	to remove child from.
 * @param[in] child	to remove.
 * @return
 *	- The item removed.
 *	- NULL if the item wasn't set.
 */
CONF_ITEM *cf_remove(CONF_ITEM *parent, CONF_ITEM *child)
{
	CONF_ITEM	*found;
	bool		in_ident1, in_ident2;

	if (!parent || !parent->child) return NULL;
	if (parent != child->parent) return NULL;

	for (found = fr_cursor_head(&parent->cursor);
	     found && (child != found);
	     found = fr_cursor_next(&parent->cursor));

	if (!found) return NULL;

	/*
	 *	Fixup the linked list
	 */
	found = fr_cursor_remove(&parent->cursor);
	if (!fr_cond_assert(found == child)) return NULL;

	in_ident1 = (rbtree_finddata(parent->ident1, child) == child);
	if (in_ident1 && (!rbtree_deletebydata(parent->ident1, child))) {
		rad_assert(0);
		return NULL;
	}

	in_ident2 = (rbtree_finddata(parent->ident2, child) == child);
	if (in_ident2 && (!rbtree_deletebydata(parent->ident2, child))) {
		rad_assert(0);
		return NULL;
	}

	/*
	 *	Look for twins
	 */
	for (found = fr_cursor_head(&parent->cursor);
	     found && (in_ident1 || in_ident2);
	     found = fr_cursor_next(&parent->cursor)) {
		if (in_ident1 && (_cf_ident1_cmp(found, child) == 0)) {
			rbtree_insert(parent->ident1, child);
			in_ident1 = false;
		}

		if (in_ident2 && (_cf_ident2_cmp(found, child) == 0)) {
			rbtree_insert(parent->ident2, child);
			in_ident2 = false;
		}
	}

	return child;
}

/** Return the next child of cs
 *
 * @param[in] ci	to return children from.
 * @param[in] prev	child to start searching from.
 * @return
 *	- The next #CONF_ITEM that's a child of cs.
 *	- NULL if no more #CONF_ITEM.
 */
CONF_ITEM *_cf_item_next(CONF_ITEM const *ci, CONF_ITEM const *prev)
{
	if (!ci) return NULL;

	return prev ? prev->next : ci->child;
}

/** Return the top level #CONF_SECTION holding all other #CONF_ITEM
 *
 * @param[in] ci	to traverse up from.
 * @return
 *	- NULL if ci was NULL.
 *	- The top level #CONF_SECTION
 */
CONF_SECTION *_cf_root(CONF_ITEM const *ci)
{
	CONF_ITEM const *ci_p;

	if (!ci) return NULL;

	for (ci_p = ci; ci_p->parent; ci_p = ci_p->parent);

	return cf_item_to_section(ci_p);
}

/** Return the parent of a #CONF_ITEM
 *
 * @param[in] ci	to return the parent of.
 * @return
 *	- NULL if ci was NULL or it has no parents.
 *	- The parent of ci.
 */
CONF_ITEM *_cf_parent(CONF_ITEM const *ci)
{
	if (!ci) return NULL;

	return ci->parent;
}

/** Return the lineno the #CONF_ITEM was parsed at
 *
 * @param[in] ci	to return the location of.
 * @return
 *	- -1 if the #CONF_ITEM was created programatically.
 *	- >= 0 where in the config file the line was parsed from.
 */
int _cf_lineno(CONF_ITEM const *ci)
{
	if (!ci) return -1;

	return ci->lineno;
}

/** Return the filename the #CONF_ITEM was parsed in
 *
 * @param[in] ci	to return the location of.
 * @return
 *	- NULL if the #CONF_ITEM was created programatically.
 *	- The path of the config file the #CONF_ITEM was located in.
 */
char const *_cf_filename(CONF_ITEM const *ci)
{
	if (!ci) return NULL;

	return ci->filename;
}

/** Determine if #CONF_ITEM is a #CONF_SECTION
 *
 * @param[in] ci	to check.
 * @return
 *	- true if ci is a #CONF_SECTION.
 *	- false if ci is another specialisation.
 */
bool cf_item_is_section(CONF_ITEM const *ci)
{
	if (!ci) return false;

	return ci->type == CONF_ITEM_SECTION;
}

/** Determine if #CONF_ITEM is a #CONF_PAIR
 *
 * @param[in] ci	to check.
 * @return
 *	- true if ci is a #CONF_PAIR.
 *	- false if ci is another specialisation.
 */
bool cf_item_is_pair(CONF_ITEM const *ci)
{
	if (!ci) return false;

	return ci->type == CONF_ITEM_PAIR;
}

/** Determine if #CONF_ITEM is #CONF_DATA
 *
 * @param[in] ci	to check.
 * @return
 *	- true if ci is #CONF_DATA.
 *	- false if ci is another specialisation.
 */
bool cf_item_is_data(CONF_ITEM const *ci)
{
	if (!ci) return false;

	return ci->type == CONF_ITEM_DATA;
}

/** Cast a #CONF_ITEM to a #CONF_PAIR
 *
 * @note Will assert if ci does not contain #CONF_PAIR.
 *
 * @param[in] ci	to cast.
 * @return
 *	- #CONF_PAIR.
 *	- NULL if ci was NULL.
 */
CONF_PAIR *cf_item_to_pair(CONF_ITEM const *ci)
{
	CONF_PAIR *out;

	if (ci == NULL) return NULL;

	rad_assert(ci->type == CONF_ITEM_PAIR);

	memcpy(&out, &ci, sizeof(out));
	return out;
}

/** Cast a #CONF_ITEM to a #CONF_SECTION
 *
 * @note Will assert if ci does not contain #CONF_SECTION.
 *
 * @param[in] ci	to cast.
 * @return
 *	- #CONF_SECTION.
 *	- NULL if ci was NULL.
 */
CONF_SECTION *cf_item_to_section(CONF_ITEM const *ci)
{
	CONF_SECTION *out;

	if (ci == NULL) return NULL;

	rad_assert(ci->type == CONF_ITEM_SECTION);

	memcpy(&out, &ci, sizeof(out));
	return out;
}

/** Cast #CONF_ITEM to #CONF_DATA performing a type check
 *
 * @note Will assert if ci does not contain #CONF_DATA.
 *
 * @param[in] ci	to cast.
 * @return
 *	- #CONF_DATA.
 *	- NULL if ci was NULL.
 */
CONF_DATA *cf_item_to_data(CONF_ITEM const *ci)
{
	CONF_DATA *out;

	if (ci == NULL) return NULL;

	rad_assert(ci->type == CONF_ITEM_DATA);

	memcpy(&out, &ci, sizeof(out));
	return out;
}

/** Cast a #CONF_PAIR to a #CONF_ITEM
 *
 * @param[in] cp	to cast.
 * @return
 *	- The common #CONF_ITEM header.
 *	- NULL if cp was NULL.
 */
CONF_ITEM *cf_pair_to_item(CONF_PAIR const *cp)
{
	CONF_ITEM *out;

	if (cp == NULL) return NULL;

	memcpy(&out, &cp, sizeof(out));
	return out;
}

/** Cast a #CONF_SECTION to a #CONF_ITEM
 *
 * @param[in] cs	to cast.
 * @return
 *	- The common #CONF_ITEM header.
 *	- NULL if cs was NULL.
 */
CONF_ITEM *cf_section_to_item(CONF_SECTION const *cs)
{
	CONF_ITEM *out;

	if (cs == NULL) return NULL;

	memcpy(&out, &cs, sizeof(out));
	return out;
}

/** Cast #CONF_DATA to a #CONF_ITEM
 *
 * @param[in] cd	to cast.
 * @return
 *	- The common #CONF_ITEM header.
 *	- NULL if cd was NULL.
 */
CONF_ITEM *cf_data_to_item(CONF_DATA const *cd)
{
	CONF_ITEM *out;

	if (cd == NULL) return NULL;

	memcpy(&out, &cd, sizeof(out));
	return out;
}

/** Free a section and associated trees
 *
 * @param[in] cs	to free.
 * @return 0
 */
static int _cf_section_free(CONF_SECTION *cs)
{
	if (cs->item.ident1) TALLOC_FREE(cs->item.ident1);
	if (cs->item.ident2) TALLOC_FREE(cs->item.ident2);

	return 0;
}

/** Allocate a #CONF_SECTION
 *
 * @param[in] ctx	to allocate
 * @param[in] parent	#CONF_SECTION to hang this #CONF_SECTION off of.
 *			If parent is not NULL, the new section will be added as a child.
 * @param[in] name1	Primary name.
 * @param[in] name2	Secondary name.
 * @param[in] filename	Caller file name for debugging.  May be overridden later.
 * @param[in] lineno	Caller line number for debugging.  May be overridden later.
 * @return
 *	- NULL on error.
 *	- A new #CONF_SECTION parented by parent.
 */
CONF_SECTION *_cf_section_alloc(TALLOC_CTX *ctx, CONF_SECTION *parent,
				char const *name1, char const *name2,
				char const *filename, int lineno)
{
	CONF_SECTION	*cs;
	char		buffer[1024];

	if (!name1) return NULL;

	if (name2 && parent) {
		char const *p;

		p = strchr(name2, '$');
		if (p && (p[1] != '{')) p = NULL;

		if (p) {
			name2 = cf_expand_variables(parent->item.filename,
						    parent->item.lineno,
						    parent,
						    buffer, sizeof(buffer), name2, -1, NULL);

			if (!name2) {
				ERROR("Failed expanding section name");
				return NULL;
			}
		}
	}

	cs = talloc_zero(ctx, CONF_SECTION);
	if (!cs) return NULL;

	cs->item.type = CONF_ITEM_SECTION;
	cs->item.parent = cf_section_to_item(parent);
	fr_cursor_init(&cs->item.cursor, &cs->item.child);
	if (filename) cf_filename_set(cs, filename);
	if (lineno) cf_lineno_set(cs, lineno);

	MEM(cs->name1 = talloc_typed_strdup(cs, name1));
	if (name2) {
		MEM(cs->name2 = talloc_typed_strdup(cs, name2));
		cs->name2_quote = T_BARE_WORD;
	}
	talloc_set_destructor(cs, _cf_section_free);

	if (parent) {
		CONF_DATA const *cd;
		CONF_PARSER *rule;

		cs->depth = parent->depth + 1;
		cf_item_add(parent, &(cs->item));

		cd = cf_data_find(CF_TO_ITEM(parent), CONF_PARSER, cf_section_name1(parent));
		if (cd) {
			rule = cf_data_value(cd);

			/*
			 *	The parent has an ON_READ rule.  Check
			 *	if that rule has a child which matches
			 *	this section.
			 */
			if ((FR_BASE_TYPE(rule->type) == FR_TYPE_SUBSECTION) &&
			    ((rule->type & FR_TYPE_ON_READ) != 0) &&
			    rule->subcs) {
				CONF_PARSER const *rule_p;

				for (rule_p = rule->subcs; rule_p->name; rule_p++) {
					if ((FR_BASE_TYPE(rule_p->type) == FR_TYPE_SUBSECTION) &&
					    ((rule_p->type & FR_TYPE_ON_READ) != 0) &&
					    (strcmp(rule_p->name, name1) == 0)) {
						if (_cf_section_rule_push(cs, rule_p,
									  cd->item.filename, cd->item.lineno) < 0) {
						error:
							talloc_free(cs);
							return NULL;
						}

						if (rule_p->func(ctx, NULL, NULL,
								 cf_section_to_item(cs), rule_p) < 0) goto error;
						return cs;
					}
				}
			}
		}

		/*
		 *	Call any ON_READ callback.  And push this rule
		 *	to the child section, so that the child can
		 *	pick it up.
		 */
		cd = cf_data_find(CF_TO_ITEM(parent), CONF_PARSER, name1);
		if (cd) {
			rule = cf_data_value(cd);
			if (rule->func &&
			    (FR_BASE_TYPE(rule->type) == FR_TYPE_SUBSECTION) &&
			    ((rule->type & FR_TYPE_ON_READ) != 0)) {
				if (cf_section_rules_push(cs, rule) < 0) goto error;
				if (rule->func(ctx, NULL, NULL, cf_section_to_item(cs), rule) < 0) goto error;
			}
		}
	}

	return cs;
}

/** Set the filename of a #CONF_ITEM
 *
 * @param[in] ci	to set filename on.
 * @param[in] filename	to set.
 */
void _cf_filename_set(CONF_ITEM *ci, char const *filename)
{
	talloc_const_free(ci->filename);

	ci->filename = talloc_typed_strdup(ci, filename);
}

/** Set the line number of a #CONF_ITEM
 *
 * @param[in] ci	to set the lineno for.
 * @param[in] lineno	to set.
 */
void _cf_lineno_set(CONF_ITEM *ci, int lineno)
{
	ci->lineno = lineno;
}

/** Duplicate a configuration section
 *
 * @note recursively duplicates any child sections.
 * @note does not duplicate any data associated with a section, or its child sections.
 *
 * @param[in] ctx	to allocate memory in.
 * @param[in] parent	section (may be NULL).
 * @param[in] cs	to duplicate.
 * @param[in] name1	of new section.
 * @param[in] name2	of new section.
 * @param[in] copy_meta	Copy additional meta data for a section
 *			(like template, base, depth and variables).
 * @return
 *	- A duplicate of the existing section.
 *	- NULL on error.
 */
CONF_SECTION *cf_section_dup(TALLOC_CTX *ctx, CONF_SECTION *parent, CONF_SECTION const *cs,
			     char const *name1, char const *name2, bool copy_meta)
{
	CONF_SECTION	*new, *subcs;
	CONF_PAIR	*cp;
	CONF_ITEM	*ci;
	fr_cursor_t	cursor;

	new = cf_section_alloc(ctx, parent, name1, name2);

	if (copy_meta) {
		new->template = cs->template;
		new->base = cs->base;
		new->depth = cs->depth;
	}

	new->item.lineno = cs->item.lineno;
	new->item.filename = cs->item.filename;

	fr_cursor_copy(&cursor, &cs->item.cursor);	/* Mutable cursor */
	for (ci = fr_cursor_head(&cursor);
	     ci;
	     ci = fr_cursor_next(&cursor)) {
		switch (ci->type) {
		case CONF_ITEM_SECTION:
			subcs = cf_item_to_section(ci);
			subcs = cf_section_dup(new, new, subcs,
					       cf_section_name1(subcs), cf_section_name2(subcs),
					       copy_meta);
			if (!subcs) {
				talloc_free(new);
				return NULL;
			}
			cf_section_add(new, subcs);
			break;

		case CONF_ITEM_PAIR:
			cp = cf_pair_dup(new, cf_item_to_pair(ci));
			if (!cp) {
				talloc_free(new);
				return NULL;
			}
			cf_pair_add(new, cp);
			break;

		case CONF_ITEM_DATA: /* Skip data */
			break;

		case CONF_ITEM_INVALID:
			rad_assert(0);
		}
	}

	return new;
}

/** Add a section as a child of another section
 *
 * @param[in] parent	section we're adding to.
 * @param[in] cs	we're adding.
 */
void cf_section_add(CONF_SECTION *parent, CONF_SECTION *cs)
{
	cf_item_add(parent, &(cs->item));
}

/** Return the next child that's a #CONF_SECTION
 *
 * @param[in] cs	to return children from.
 * @param[in] prev	child to start searching from.
 * @return
 *	- The next #CONF_ITEM that's a child of cs and a CONF_SECTION.
 *	- NULL if no #CONF_ITEM matches that criteria.
 */
CONF_SECTION *cf_section_next(CONF_SECTION const *cs, CONF_SECTION const *prev)
{
	return cf_item_to_section(cf_next(cf_section_to_item(cs), cf_section_to_item(prev), CONF_ITEM_SECTION));
}

/** Find a CONF_SECTION with name1 and optionally name2.
 *
 * @param[in] cs	The section we're searching in.
 * @param[in] name1	of the section we're searching for. Special value CF_IDENT_ANY
 *			can be used to match any name1 value.
 * @param[in] name2	of the section we're searching for. Special value CF_IDENT_ANY
 *			can be used to match any name2 value.
 * @return
 *	- The first matching subsection.
 *	- NULL if no subsections match.
 */
CONF_SECTION *cf_section_find(CONF_SECTION const *cs,
			      char const *name1, char const *name2)
{
	return cf_item_to_section(cf_find(cf_section_to_item(cs), CONF_ITEM_SECTION, name1, name2));
}

/** Return the next matching section
 *
 * @param[in] cs	The section we're searching in.
 * @param[in] prev	section we found.  May be NULL in which case
 *			we just return the next section after prev.
 * @param[in] name1	of the section we're searching for.  Special value CF_IDENT_ANY
 *			can be used to match any name1 value.
 * @param[in] name2	of the section we're searching for.  Special value CF_IDENT_ANY
 *			can be used to match any name2 value.
 * @return
 *	- The next CONF_SECTION.
 *	- NULL if there are no more CONF_SECTIONs
 */
CONF_SECTION *cf_section_find_next(CONF_SECTION const *cs, CONF_SECTION const *prev,
				   char const *name1, char const *name2)
{
	return cf_item_to_section(cf_find_next(cf_section_to_item(cs), cf_section_to_item(prev),
					       CONF_ITEM_SECTION, name1, name2));
}

/** Find a CONF_SECTION with name1 and optionally name2 in the specified conf section of one of its parents
 *
 * @param[in] cs	The section we're searching in.
 * @param[in] name1	of the section we're searching for. Special value CF_IDENT_ANY
 *			can be used to match any name1 value.
 * @param[in] name2	of the section we're searching for. Special value CF_IDENT_ANY
 *			can be used to match any name2 value.
 * @return
 *	- The first matching subsection.
 *	- NULL if no subsections match.
 */
CONF_SECTION *cf_section_find_in_parent(CONF_SECTION const *cs,
			      		char const *name1, char const *name2)
{
	CONF_ITEM const *parent = cf_section_to_item(cs);

	do {
		CONF_ITEM *found;

		found = cf_find(parent, CONF_ITEM_SECTION, name1, name2);
		if (found) return cf_item_to_section(found);
	} while ((parent = cf_parent(parent)));

	return NULL;
}

/** Find a pair in a #CONF_SECTION
 *
 * @param[in] cs	the #CONF_SECTION to search in.
 * @param[in] attr	to search for.
 * @return
 *	- NULL if no pair can be found.
 *	- The value of the pair found.
 */
char const *cf_section_value_find(CONF_SECTION const *cs, char const *attr)
{
	CONF_PAIR	*cp;

	cp = cf_pair_find(cs, attr);

	return (cp ? cp->value : NULL);
}

/** Return the second identifier of a #CONF_SECTION
 *
 * @param[in] cs	to return identifiers for.
 * @return
 *	- The first identifier.
 *	- NULL if cs was NULL or no name1 set.
 */
char const *cf_section_name1(CONF_SECTION const *cs)
{
	return (cs ? cs->name1 : NULL);
}

/** Return the second identifier of a #CONF_SECTION
 *
 * @param[in] cs	to return identifiers for.
 * @return
 *	- The second identifier.
 *	- NULL if cs was NULL or no name2 set.
 */
char const *cf_section_name2(CONF_SECTION const *cs)
{
	return (cs ? cs->name2 : NULL);
}

/** Return name2 if set, else name1
 *
 * @param[in] cs	to return identifiers for.
 * @return name1 or name2 identifier.
 */
char const *cf_section_name(CONF_SECTION const *cs)
{
	char const *name;

	name = cf_section_name2(cs);
	if (name) return name;

	return cf_section_name1(cs);
}

/** Return variadic argument at the specified index
 *
 * @param[in] cs	containing the arguments.
 * @param[in] argc	Argument index. Note name1 and name2 are not counted in this index.
 * @return the argument value or NULL.
 */
char const *cf_section_argv(CONF_SECTION const *cs, int argc)
{
	if (!cs || !cs->argv || (argc < 0) || (argc > cs->argc)) return NULL;

	return cs->argv[argc];
}

/** Return the quoting of the name2 identifier
 *
 * @param[in] cs	containing name2.
 * @return
 *	- #T_BARE_WORD.
 *	- #T_SINGLE_QUOTED_STRING.
 *	- #T_BACK_QUOTED_STRING.
 *	- #T_DOUBLE_QUOTED_STRING.
 *	- #T_INVALID if cs was NULL.
 */
FR_TOKEN cf_section_name2_quote(CONF_SECTION const *cs)
{
	if (!cs) return T_INVALID;

	return cs->name2_quote;
}

/** Return the quoting for one of the variadic arguments
 *
 * @param[in] cs	containing the arguments.
 * @param[in] argc	Argument index.  Note name1 and name2 are not counted in this index.
 * @return
 *	- #T_BARE_WORD.
 *	- #T_SINGLE_QUOTED_STRING.
 *	- #T_BACK_QUOTED_STRING.
 *	- #T_DOUBLE_QUOTED_STRING.
 *	- #T_INVALID if cs was NULL or the index was invalid.
 */
FR_TOKEN cf_section_argv_quote(CONF_SECTION const *cs, int argc)
{
	if (!cs || !cs->argv_quote || (argc < 0) || (argc > cs->argc)) return T_INVALID;

	return cs->argv_quote[argc];
}

/** Allocate a #CONF_PAIR
 *
 * @param[in] parent		#CONF_SECTION to hang this #CONF_PAIR off of.
 * @param[in] attr		name.
 * @param[in] value		of #CONF_PAIR.
 * @param[in] op		#T_OP_EQ, #T_OP_SET etc.
 * @param[in] lhs_quote		#T_BARE_WORD, #T_DOUBLE_QUOTED_STRING, #T_BACK_QUOTED_STRING.
 * @param[in] rhs_quote		#T_BARE_WORD, #T_DOUBLE_QUOTED_STRING, #T_BACK_QUOTED_STRING.
 * @return
 *	- NULL on error.
 *	- A new #CONF_SECTION parented by parent.
 */
CONF_PAIR *cf_pair_alloc(CONF_SECTION *parent, char const *attr, char const *value,
			 FR_TOKEN op, FR_TOKEN lhs_quote, FR_TOKEN rhs_quote)
{
	CONF_PAIR *cp;

	rad_assert(fr_equality_op[op] || fr_assignment_op[op]);
	if (!attr) return NULL;

	cp = talloc_zero(parent, CONF_PAIR);
	if (!cp) return NULL;

	cp->item.type = CONF_ITEM_PAIR;
	cp->item.parent = cf_section_to_item(parent);
	cp->lhs_quote = lhs_quote;
	cp->rhs_quote = rhs_quote;
	cp->op = op;
	cp->item.filename = "";		/* will be over-written if necessary */
	fr_cursor_init(&cp->item.cursor, &cp->item.child);

	cp->attr = talloc_typed_strdup(cp, attr);
	if (!cp->attr) {
	error:
		talloc_free(cp);
		return NULL;
	}

	if (value) {
		cp->value = talloc_typed_strdup(cp, value);
		if (!cp->value) goto error;
	}

	return cp;
}

/** Duplicate a #CONF_PAIR
 *
 * @param parent	to allocate new pair in.
 * @param cp		to duplicate.
 * @return
 *	- NULL on error.
 *	- A duplicate of the input pair.
 */
CONF_PAIR *cf_pair_dup(CONF_SECTION *parent, CONF_PAIR *cp)
{
	CONF_PAIR *new;

	rad_assert(parent);
	rad_assert(cp);

	new = cf_pair_alloc(parent, cp->attr, cf_pair_value(cp),
			    cp->op, cp->lhs_quote, cp->rhs_quote);
	if (!new) return NULL;

	new->parsed = cp->parsed;
	new->item.lineno = cp->item.lineno;
	new->item.filename = cp->item.filename;

	return new;
}

/** Replace pair in a given section with a new pair, of the given value.
 *
 * @note A new pair with the same metadata as the #CONF_PAIR will be added
 *	even if the #CONF_PAIR can't be found inside the #CONF_SECTION.
 *
 * @param[in] cs	to replace pair in.
 * @param[in] cp	to replace.
 * @param[in] value	New value to assign to cp.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int cf_pair_replace(CONF_SECTION *cs, CONF_PAIR *cp, char const *value)
{
	CONF_PAIR *new_cp;
	CONF_ITEM *ci;

	if (!cs || !cp || !value) return -1;

	MEM(new_cp = cf_pair_alloc(cs, cp->attr, value, cp->op, cp->lhs_quote, cp->rhs_quote));

	/*
	 *	Remove the old CONF_PAIR
	 */
	ci = cf_remove(cf_section_to_item(cs), cf_pair_to_item(cp));
	if (!fr_cond_assert(!ci || (ci == cf_pair_to_item(cp)))) return -1;

	/*
	 *	Add the new CONF_PAIR
	 */
	cf_item_add(cf_section_to_item(cs), cf_pair_to_item(new_cp));

	return 0;
}

/** Add a configuration pair to a section
 *
 * @param[in] parent section to add pair to.
 * @param[in] cp to add.
 */
void cf_pair_add(CONF_SECTION *parent, CONF_PAIR *cp)
{
	cf_item_add(parent, cf_pair_to_item(cp));
}

/** Mark a pair as parsed
 *
 * @param[in] cp	to mark as parsed.
 */
void cf_pair_mark_parsed(CONF_PAIR *cp)
{
	cp->parsed = true;
}

/** Return the next child that's a #CONF_PAIR
 *
 * @param[in] cs	to return children from.
 * @param[in] prev	child to start searching from.
 * @return
 *	- The next #CONF_ITEM that's a child of cs and a CONF_PAIR.
 *	- NULL if no #CONF_ITEM matches that criteria.
 */
CONF_PAIR *cf_pair_next(CONF_SECTION const *cs, CONF_PAIR const *prev)
{
	return cf_item_to_pair(cf_next(cf_section_to_item(cs), cf_pair_to_item(prev), CONF_ITEM_PAIR));
}

/** Search for a #CONF_PAIR with a specific name
 *
 * @param[in] cs	to search in.
 * @param[in] attr	to find.
 * @return
 *	- The next matching #CONF_PAIR.
 *	- NULL if none matched.
 */
CONF_PAIR *cf_pair_find(CONF_SECTION const *cs, char const *attr)
{
	return cf_item_to_pair(cf_find(cf_section_to_item(cs), CONF_ITEM_PAIR, attr, NULL));
}

/** Find a pair with a name matching attr, after specified pair
 *
 * @param[in] cs	to search in.
 * @param[in] prev	Pair to search from (may be NULL).
 * @param[in] attr	to find (may be NULL in which case any attribute matches).
 * @return
 *	- The next matching #CONF_PAIR
 *	- NULL if none matched.
 */
CONF_PAIR *cf_pair_find_next(CONF_SECTION const *cs, CONF_PAIR const *prev, char const *attr)
{
	return cf_item_to_pair(cf_find_next(cf_section_to_item(cs), cf_pair_to_item(prev), CONF_ITEM_PAIR, attr, NULL));
}

/** Find a pair with a name matching attr in the specified section or one of its parents
 *
 * @param[in] cs	to search in.  Will start in the current section
 *			and work upwards.
 * @param[in] attr	to find.
 * @return
 *	- A matching #CONF_PAIR.
 *	- NULL if none matched.
 */
CONF_PAIR *cf_pair_find_in_parent(CONF_SECTION const *cs, char const *attr)
{
	CONF_ITEM const *parent = cf_section_to_item(cs);

	do {
		CONF_ITEM *found;

		found = cf_find(parent, CONF_ITEM_PAIR, attr, NULL);
		if (found) return cf_item_to_pair(found);
	} while ((parent = cf_parent(parent)));

	return NULL;
}

/** Callback to determine the number of pairs in a section
 *
 * @param[out] count	Where we store the number of pairs found.
 * @param[in] cs	we're currently searching in.
 */
static void _pair_count(int *count, CONF_SECTION const *cs)
{
	CONF_ITEM const *ci = NULL;

	while ((ci = cf_item_next(cs, ci))) {
		if (cf_item_is_section(ci)) {
			_pair_count(count, cf_item_to_section(ci));
			continue;
		}

		(*count)++;
	}
}

/** Count the number of conf pairs beneath a section
 *
 * @param[in] cs to search for items in.
 * @return The number of pairs nested within section.
 */
int cf_pair_count(CONF_SECTION const *cs)
{
	int count = 0;

	_pair_count(&count, cs);

	return count;
}

/** Return the attr of a #CONF_PAIR
 *
 * Return the LHS value of a pair (the attribute).
 *
 * @param[in] pair	to return the attribute for.
 * @return
 *	- NULL if the pair was NULL.
 *	- The attribute name of the pair.
 */
char const *cf_pair_attr(CONF_PAIR const *pair)
{
	return (pair ? pair->attr : NULL);
}

/** Return the value of a #CONF_PAIR
 *
 * Return the RHS value of a pair (the value).
 *
 * @param[in]	pair to return the value of.
 * @return
 *	- NULL if pair was NULL or the pair has no value.
 *	- The string value of the pair.
 */
char const *cf_pair_value(CONF_PAIR const *pair)
{
	return (pair ? pair->value : NULL);
}

/** Return the operator of a pair
 *
 * @param[in] pair	to return the operator of.
 * @return
 *	- T_INVALID if pair was NULL.
 *	- T_OP_* (one of the operator constants).
 */
FR_TOKEN cf_pair_operator(CONF_PAIR const *pair)
{
	return (pair ? pair->op : T_INVALID);
}

/** Return the value (lhs) quoting of a pair
 *
 * @param pair to extract value type from.
 * @return
 *	- #T_BARE_WORD.
 *	- #T_SINGLE_QUOTED_STRING.
 *	- #T_BACK_QUOTED_STRING.
 *	- #T_DOUBLE_QUOTED_STRING.
 *	- #T_INVALID if the pair is NULL.
 */
FR_TOKEN cf_pair_attr_quote(CONF_PAIR const *pair)
{
	return (pair ? pair->lhs_quote : T_INVALID);
}

/** Return the value (rhs) quoting of a pair
 *
 * @param pair to extract value type from.
 * @return
 *	- #T_BARE_WORD.
 *	- #T_SINGLE_QUOTED_STRING.
 *	- #T_BACK_QUOTED_STRING.
 *	- #T_DOUBLE_QUOTED_STRING.
 *	- #T_INVALID if the pair is NULL.
 */
FR_TOKEN cf_pair_value_quote(CONF_PAIR const *pair)
{
	return (pair ? pair->rhs_quote : T_INVALID);
}

/** Free user data associated with #CONF_DATA
 *
 * @param[in] cd	being freed.
 * @return 0
 */
static int _cd_free(CONF_DATA *cd)
{
	void *to_free;

	memcpy(&to_free, &cd->data, sizeof(to_free));

	if (cd->free) talloc_decrease_ref_count(to_free);	/* Also works OK for non-reference counted chunks */

	return 0;
}

/** Allocate a new user data container
 *
 * @param[in] parent	#CONF_PAIR, or #CONF_SECTION to hang CONF_DATA off of.
 * @param[in] data	being added.
 * @param[in] type	of data being added.
 * @param[in] name	String identifier of the user data.
 * @param[in] do_free	function, called when the parent #CONF_SECTION is being freed.
 * @return
 *	- CONF_DATA on success.
 *	- NULL on error.
 */
static CONF_DATA *cf_data_alloc(CONF_ITEM *parent, void const *data, char const *type, char const *name, bool do_free)
{
	CONF_DATA *cd;

	cd = talloc_zero(parent, CONF_DATA);
	if (!cd) return NULL;

	cd->item.type = CONF_ITEM_DATA;
	cd->item.parent = parent;
	fr_cursor_init(&cd->item.cursor, &cd->item.child);

	/*
	 *	strdup so if the data is freed, we can
	 *	still remove it from the section without
	 *	explosions.
	 */
	if (data) {
		cd->type = talloc_typed_strdup(cd, type);
		cd->data = data;
	}
	if (name) cd->name = talloc_typed_strdup(cd, name);

	if (do_free) {
		cd->free = true;
		talloc_set_destructor(cd, _cd_free);
	}

	return cd;
}

/** Find user data in a config section
 *
 * @param[in] ci	The section to search for data in.
 * @param[in] type	of user data.  Used for name spacing and walking over a specific
 *			type of user data.
 * @param[in] name	String identifier of the user data.  Special value CF_IDENT_ANY
 *			may be used to match on type only.
 * @return
 *	- The user data.
 *	- NULL if no user data exists.
 */
CONF_DATA const *_cf_data_find(CONF_ITEM const *ci, char const *type, char const *name)
{
	return cf_item_to_data(cf_find(ci, CONF_ITEM_DATA, type, name));
}

/** Return the next item of user data
 *
 * @param[in] ci	The section to search for data in.
 * @param[in] prev	section we found.  May be NULL in which case
 *			we just return the next section after prev.
 * @param[in] type	of user data.  Used for name spacing and walking over a specific
 *			type of user data.
 * @param[in] name	String identifier of the user data.  Special value CF_IDENT_ANY
 *			can be used to match any name2 value.
 * @return
 *	- The next matching #CONF_DATA.
 *	- NULL if there is no more matching #CONF_DATA.
 */
CONF_DATA const *_cf_data_find_next(CONF_ITEM const *ci, CONF_ITEM const *prev, char const *type, char const *name)
{
	return cf_item_to_data(cf_find_next(ci, prev, CONF_ITEM_DATA, type, name));
}

/** Find matching data in the specified section or one of its parents
 *
 * @param[in] ci	The section to search for data in.
 * @param[in] type	of user data.  Used for name spacing and walking over a specific
 *			type of user data.
 * @param[in] name	String identifier of the user data.  Special value CF_IDENT_ANY
 *			may be used to match on type only.
 * @return
 *	- The next matching #CONF_DATA.
 *	- NULL if there is no more matching #CONF_DATA.
 */
CONF_DATA *_cf_data_find_in_parent(CONF_ITEM const *ci, char const *type, char const *name)
{
	CONF_ITEM const *parent = ci;

	do {
		CONF_ITEM *found;

		found = cf_find(parent, CONF_ITEM_DATA, type, name);
		if (found) return cf_item_to_data(found);
	} while ((parent = cf_parent(parent)));

	return NULL;
}

/** Return the user assigned value of #CONF_DATA
 *
 * @param[in] cd	to return value of.
 * @return the user data stored within the #CONF_DATA.
 */
void *cf_data_value(CONF_DATA const *cd)
{
	void *to_return;

	if (!cd) return NULL;

	memcpy(&to_return, &cd->data, sizeof(to_return));

	return to_return;
}

/** Add talloced user data to a config section
 *
 * @param[in] ci	to add data to.
 * @param[in] data	to add.
 * @param[in] name	String identifier of the user data.
 * @param[in] do_free	Function to free user data when the CONF_SECTION is freed.
 * @param[in] filename	Source file the #CONF_DATA was added in.
 * @param[in] lineno	the #CONF_DATA was added at.
 * @return
 *	- #CONF_DATA  - opaque handle to the stored data - on success.
 *	- NULL error.
 */
CONF_DATA const *_cf_data_add(CONF_ITEM *ci, void const *data, char const *name, bool do_free,
			      char const *filename, int lineno)
{
	CONF_DATA	*cd;
	CONF_DATA const *found;
	char const	*type = NULL;

	if (!ci) return NULL;

	if (data) type = talloc_get_name(data);

	/*
	 *	Already exists.  Can't add it.
	 */
	found = _cf_data_find(ci, type, name);
	if (found) {
		return NULL;
	}

	cd = cf_data_alloc(ci, data, type, name, do_free);
	if (!cd) {
		cf_log_err(ci, "Failed allocating data");
		return NULL;
	}
	cd->is_talloced = true;
	cd->item.filename = filename;
	cd->item.lineno = lineno;

	cf_item_add(ci, cd);

	return cd;
}

/** Add non-talloced user data to a config section
 *
 * @param[in] ci	to add data to.
 * @param[in] data	to add.
 * @param[in] type	identifier of the user data.
 * @param[in] name	String identifier of the user data.
 * @param[in] filename	Source file the #CONF_DATA was added in.
 * @param[in] lineno	the #CONF_DATA was added at.
 *	- #CONF_DATA  - opaque handle to the stored data - on success.
 *	- NULL error.
 */
CONF_DATA const *_cf_data_add_static(CONF_ITEM *ci, void const *data, char const *type, char const *name,
				     char const *filename, int lineno)
{
	CONF_DATA *cd;
	CONF_DATA const *found;

	/*
	 *	Already exists.  Can't add it.
	 */
	found = _cf_data_find(ci, type, name);
	if (found) {
		/*
		 *	Suppress these, as it's OK for the CONF_PARSER in main_config.c
       		 */
		if (strcmp(type, "CONF_PARSER") == 0) return NULL;

		cf_log_err(ci, "Data of type %s with name \"%s\" already exists.  Existing data added %s[%i]", type,
			   name, found->item.filename, found->item.lineno);
		return NULL;
	}

	cd = cf_data_alloc(ci, data, type, name, false);
	if (!cd) {
		cf_log_err(ci, "Failed allocating data");
		return NULL;
	}
	cd->is_talloced = false;
	cd->item.filename = filename;
	cd->item.lineno = lineno;

	cf_item_add(ci, cd);

	return cd;
}

/** Remove data from a configuration section
 *
 * @note If cd was not found it will not be freed, and it is the caller's responsibility
 *	to free it explicitly, or free the section it belongs to.
 *
 * @param[in] parent	to remove data from.
 * @param[in] cd	opaque handle of the stored data.
 * @return
 *	- The value stored within the data (if cd is valid and was found and removed).
 *	- NULL if not found.
 */
void *_cf_data_remove(CONF_ITEM *parent, CONF_DATA const *cd)
{
	void *data;
	CONF_ITEM *ci;

	if (!cd) return NULL;

	ci = cf_remove(parent, cf_data_to_item(cd));
	if (!fr_cond_assert(!ci || (ci == cf_data_to_item(cd)))) return NULL;
	if (!ci) return NULL;

	talloc_set_destructor(cd, NULL);	/* Disarm the destructor */
	memcpy(&data, &cd->data, sizeof(data));
	talloc_const_free(cd);

	return data;
}

/** ctx data for a _cf_data_walk_call
 *
 */
typedef struct {
	char const 	*type;		//!< of CONF_DATA we're iterating over.
	cf_walker_t	cb;		//!< cb to process CONF_DATA.
	void		*ctx;		//!< to pass to cb.
} cf_data_walk_ctx_t;

/** Wrap a cf_walker_t in an rb_walker_t
 *
 * @param[in] data	A CONF_DATA entry.
 * @param[in] uctx	A cf_data_walk_ctx_t.
 */
static int _cf_data_walk_cb(void *data, void *uctx)
{
	cf_data_walk_ctx_t	*cd_ctx = uctx;
	CONF_DATA		*cd = data;
	CONF_ITEM		*ci = data;
	void			*mutable;
	int			ret;

	/*
	 *	We're walking ident2, not all of the items will be data
	 */
	if (ci->type != CONF_ITEM_DATA) return 0;

	if ((cd->type != cd_ctx->type) && (strcmp(cd->type, cd_ctx->type) != 0)) return 0;

	memcpy(&mutable, &cd->data, sizeof(data));
	ret = cd_ctx->cb(mutable, cd_ctx->ctx);

	return ret;
}

/** Walk over a specific type of CONF_DATA
 *
 * @param[in] ci	containing the CONF_DATA to walk over.
 * @param[in] type	of CONF_DATA to walk over.
 * @param[in] cb	to call when we find CONF_DATA of the specified type.
 * @param[in] ctx	to pass to cb.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int _cf_data_walk(CONF_ITEM *ci, char const *type, cf_walker_t cb, void *ctx)
{
	cf_data_walk_ctx_t cd_ctx = {
		.type = type,
		.cb = cb,
		.ctx = ctx
	};

	if (!ci->ident2) return 0;

	return rbtree_walk(ci->ident2, RBTREE_IN_ORDER, _cf_data_walk_cb, &cd_ctx);
}

static inline void truncate_filename(char const **e, char const **p, int *len, char const *filename)
{
	size_t flen;
	char const *q;

	#define FILENAME_TRUNCATE	60

	*p = filename;
	*e = "";

	if (!filename || !*filename) {
		*len = 0;
		return;
	}

	flen = talloc_array_length(filename) - 1;
	if (flen <= FILENAME_TRUNCATE) {
		*len = (int)flen;
		return;
	}

	*p += flen - FILENAME_TRUNCATE;
	*len = FILENAME_TRUNCATE;

	q = strchr(*p, FR_DIR_SEP);
	if (q) {
		q++;
		*p += (q - *p);
		*len -= (q - *p);
	}

	*e = "...";
}

/** Check to see if the CONF_PAIR value is present in the specified table
 *
 * If it's not present, return an error and produce a helpful log message
 *
 * @param[out] out	The result of parsing the pair value.
 * @param[in] table	to look for string values in.
 * @param[in] table_len	Length of the table.
 * @param[in] cp	to parse.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int cf_pair_in_table(int32_t *out, fr_table_num_sorted_t const *table, size_t table_len, CONF_PAIR *cp)
{
	char				*list = NULL;
	int32_t				res;
	size_t				i;

	res = fr_table_value_by_str(table, cf_pair_value(cp), FR_TABLE_NOT_FOUND);
	if (res != FR_TABLE_NOT_FOUND) {
		*out = res;
		return 0;
	}

	for (i = 0; i < table_len; i++) MEM(list = talloc_asprintf_append_buffer(list, "'%s', ", table[i].name));

	if (!list) {
		cf_log_err(cp, "Internal error parsing %s: Table was empty", cf_pair_attr(cp));
		return -1;
	}

	/*
	 *	Trim the final ", "
	 */
	MEM(list = talloc_bstr_realloc(NULL, list, talloc_array_length(list) - 3));

	cf_log_err(cp, "Invalid value \"%s\". Expected one of %s", cf_pair_value(cp), list);

	talloc_free(list);

	return -1;
}

/** Log an error message relating to a #CONF_ITEM
 *
 * @param[in] type	of log message.
 * @param[in] ci	#CONF_ITEM to print file/lineno for.
 * @param[in] file	src file the log message was generated in.
 * @param[in] line	number the log message was generated on.
 * @param[in] fmt	of the message.
 * @param[in] ap	Message args.
 */
void _cf_vlog(fr_log_type_t type, CONF_ITEM const *ci, char const *file, int line, char const *fmt, va_list ap)
{
	va_list	aq;

	if ((type == L_DBG) && !DEBUG_ENABLED) return;

	if (!ci || !ci->filename || !*ci->filename || (*ci->filename == '<') ||
	    (((type == L_DBG) || (type == L_INFO)) && !DEBUG_ENABLED4)) {
		va_copy(aq, ap);
		fr_vlog(LOG_DST, type, file, line, fmt, ap);
		va_end(aq);
		return;
	}

	{
		char const	*e, *p;
		int		len;
		char		*msg;

		truncate_filename(&e, &p, &len, ci->filename);

		va_copy(aq, ap);
		msg = fr_vasprintf(NULL, fmt, ap);
		va_end(aq);

		fr_log(LOG_DST, type, file, line, "%s%.*s[%d]: %s", e, len, p, ci->lineno, msg);
		talloc_free(msg);
	}
}

/** Log an error message relating to a #CONF_ITEM
 *
 * @param[in] type	of log message.
 * @param[in] file	src file the log message was generated in.
 * @param[in] line	number the log message was generated on.
 * @param[in] ci	#CONF_ITEM to print file/lineno for.
 * @param[in] fmt	of the message.
 * @param[in] ...	Message args.
 */
void _cf_log(fr_log_type_t type, CONF_ITEM const *ci, char const *file, int line, char const *fmt, ...)
{
	va_list ap;

	if ((type == L_DBG) && !DEBUG_ENABLED) return;

	va_start(ap, fmt);
	_cf_vlog(type, ci, file, line, fmt, ap);
	va_end(ap);
}

/** Log an error message relating to a #CONF_ITEM
 *
 * Drains the fr_strerror() stack emitting one or more error messages.
 *
 * @param[in] type	of log message.
 * @param[in] file	src file the log message was generated in.
 * @param[in] line	number the log message was generated on.
 * @param[in] ci	#CONF_ITEM to print file/lineno for.
 * @param[in] fmt	of the message.
 * @param[in] ...	Message args.
 */
void _cf_log_perr(fr_log_type_t type, CONF_ITEM const *ci, char const *file, int line, char const *fmt, ...)
{
	va_list	ap;

	if ((type == L_DBG) && !DEBUG_ENABLED) return;

	if (!ci || !ci->filename) {
		va_start(ap, fmt);
		fr_vlog_perror(LOG_DST, type, file, line, fmt, ap);
		va_end(ap);
		return;
	}

	{
		char const	*e, *p;
		int		len;
		char		*msg;

		truncate_filename(&e, &p, &len, ci->filename);

		va_start(ap, fmt);
		msg = fr_vasprintf(NULL, fmt, ap);
		va_end(ap);

		fr_log_perror(LOG_DST, type, file, line, "%s%.*s[%d]: %s", e, len, p, ci->lineno, msg);
		talloc_free(msg);
	}
}

/** Log a debug message relating to a #CONF_ITEM
 *
 * Always emits a filename/lineno prefix if available
 *
 * @param[in] type	of log message.
 * @param[in] file	src file the log message was generated in.
 * @param[in] line	number the log message was generated on.
 * @param[in] ci	#CONF_ITEM to print file/lineno for.
 * @param[in] fmt	of the message.
 * @param[in] ...	Message args.
 */
void _cf_log_with_filename(fr_log_type_t type, CONF_ITEM const *ci, char const *file, int line, char const *fmt, ...)
{
	va_list	ap;

	if ((type == L_DBG) && !DEBUG_ENABLED) return;

	if (!ci || !ci->filename) {
		va_start(ap, fmt);
		fr_vlog(LOG_DST, type, file, line, fmt, ap);
		va_end(ap);
		return;
	}

	{
		char const	*e, *p;
		int		len;
		char		*msg;

		truncate_filename(&e, &p, &len, ci->filename);

		va_start(ap, fmt);
		msg = fr_vasprintf(NULL, fmt, ap);
		va_end(ap);

		fr_log(LOG_DST, type, file, line, "%s%.*s[%d]: %s", e, len, p, ci->lineno, msg);
		talloc_free(msg);
	}
}

/** Log an error message in the context of a child pair of the specified parent
 *
 * @param[in] parent	containing the pair.
 * @param[in] child	name to use as a logging context.
 * @param[in] type	of log message.
 * @param[in] file	src file the log message was generated in.
 * @param[in] line	number the log message was generated on.
 * @param[in] fmt	of the message.
 * @param[in] ...	Message args.
 */
void _cf_log_by_child(fr_log_type_t type, CONF_SECTION const *parent, char const *child,
		      char const *file, int line, char const *fmt, ...)
{
	va_list		ap;
	CONF_PAIR const	*cp;

	cp = cf_pair_find(parent, child);
	if (cp) {
		va_start(ap, fmt);
		_cf_vlog(type, CF_TO_ITEM(cp), file, line, fmt, ap);
		va_end(ap);
		return;
	}

	va_start(ap, fmt);
	_cf_vlog(type, CF_TO_ITEM(parent), file, line, fmt, ap);
	va_end(ap);
}

/** Print out debugging information about a CONFIG_ITEM
 *
 * @param[in] ci	being debugged.
 */
void _cf_debug(CONF_ITEM const *ci)
{
	fr_cursor_t	cursor;
	CONF_ITEM const	*child;

	/*
	 *	Print summary of the item
	 */
	switch (ci->type) {
	case CONF_ITEM_SECTION:
	{
		CONF_SECTION const *cs = cf_item_to_section(ci);
		int i;

		DEBUG("SECTION - %p", cs);
		DEBUG("  name1         : %s", cs->name1);
		DEBUG("  name2         : %s", cs->name2 ? cs->name2 : "<none>");
		DEBUG("  name2_quote   : %s", fr_table_str_by_value(fr_token_quotes_table, cs->name2_quote, "<INVALID>"));
		DEBUG("  argc          : %u", cs->argc);

		for (i = 0; i < cs->argc; i++) {
			char const *quote = fr_table_str_by_value(fr_token_quotes_table, cs->argv_quote[i], "<INVALID>");
			DEBUG("  argv[%i]      : %s%s%s", i, quote, cs->argv[i], quote);
		}
	}
		break;

	case CONF_ITEM_PAIR:
	{
		CONF_PAIR const	*cp = cf_item_to_pair(ci);

		DEBUG("PAIR - %p", cp);
		DEBUG("  attr          : %s", cp->attr);
		DEBUG("  value         : %s", cp->value);
		DEBUG("  operator      : %s", fr_table_str_by_value(fr_tokens_table, cp->op, "<INVALID>"));
		DEBUG("  lhs_quote     : %s", fr_table_str_by_value(fr_token_quotes_table, cp->lhs_quote, "<INVALID>"));
		DEBUG("  rhs_quote     : %s", fr_table_str_by_value(fr_token_quotes_table, cp->rhs_quote, "<INVALID>"));
		DEBUG("  pass2         : %s", cp->pass2 ? "yes" : "no");
		DEBUG("  parsed        : %s", cp->parsed ? "yes" : "no");
	}
		break;

	case CONF_ITEM_DATA:
	{
		CONF_DATA const	*cd = cf_item_to_data(ci);

		DEBUG("DATA - %p", cd);
		DEBUG("  type          : %s", cd->type);
		DEBUG("  name          : %s", cd->name);
		DEBUG("  data          : %p", cd->data);
		DEBUG("  free wth prnt : %s", cd->free ? "yes" : "no");
	}
		break;

	default:
		DEBUG("INVALID - %p", ci);
		return;
	}

	DEBUG("  filename      : %s", ci->filename);
	DEBUG("  line          : %i", ci->lineno);
	DEBUG("  next          : %p", ci->next);
	DEBUG("  parent        : %p", ci->parent);
	DEBUG("  children      : %s", ci->child ? "yes" : "no");
	DEBUG("  ident1 tree   : %p (%u entries)", ci->ident1, ci->ident1 ? rbtree_num_elements(ci->ident1) : 0);
	DEBUG("  ident2 tree   : %p (%u entries)", ci->ident2, ci->ident2 ? rbtree_num_elements(ci->ident2) : 0);

	if (!ci->child) return;

	/*
	 *	Print summary of the item's children
	 */
	DEBUG("CHILDREN");
	fr_cursor_copy(&cursor, &ci->cursor);

	for (child = fr_cursor_head(&cursor);
	     child;
	     child = fr_cursor_next(&cursor)) {
	     	char const *in_ident1, *in_ident2;

		in_ident1 = rbtree_finddata(ci->ident1, child) == child? "in ident1 " : "";
		in_ident2 = rbtree_finddata(ci->ident2, child) == child? "in ident2 " : "";

		switch (child->type) {
		case CONF_ITEM_SECTION:
		{
			CONF_SECTION const *cs = cf_item_to_section(child);

			DEBUG("  SECTION %p (%s %s) %s%s", child, cs->name1, cs->name2 ? cs->name2 : "<none>",
			      in_ident1, in_ident2);
		}
			break;

		case CONF_ITEM_PAIR:
		{
			CONF_PAIR const	*cp = cf_item_to_pair(child);
			char const	*lhs_quote = fr_table_str_by_value(fr_token_quotes_table, cp->lhs_quote, "<INVALID>");
			char const	*rhs_quote = fr_table_str_by_value(fr_token_quotes_table, cp->rhs_quote, "<INVALID>");

			DEBUG("  PAIR %p (%s%s%s %s %s%s%s) %s%s", child,
			      lhs_quote, cp->attr, lhs_quote,
			      fr_table_str_by_value(fr_tokens_table, cp->op, "<INVALID>"),
			      rhs_quote, cp->value, rhs_quote,
			      in_ident1, in_ident2);
		}
			break;

		case CONF_ITEM_DATA:
		{
			CONF_DATA const	*cd = cf_item_to_data(child);

			DEBUG("  DATA %p (%s *)%s = %p %s%s", child,
			      cd->type, cd->name ? cd->name : "", cd->data,
			      in_ident1, in_ident2);
			break;
		}

		default:
			DEBUG("  INVALID - %p", child);
			break;
		}
	}
}
