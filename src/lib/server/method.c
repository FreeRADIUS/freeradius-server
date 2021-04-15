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
 *
 * @file src/lib/server/methods.c
 * @brief Cannonical definition of abstract module methods.
 *
 * @copyright 2021 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/server/method.h>
#include <freeradius-devel/util/dict.h>

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t method_dict[];
fr_dict_autoload_t method_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_module_method;

extern fr_dict_attr_autoload_t module_method_attr[];
fr_dict_attr_autoload_t module_method_attr[] = {
	{ .out = &attr_module_method, .name = "Module-Method", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ NULL }
};

/** Add a new module method on startup
 *
 * This is useful if a module needs to define a custom method in its "load" callback.
 *
 * @param[out] id_out	New (or existing) method id.
 * @param[in] name	To add.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
module_method_id_t module_method_define(module_method_id_t *id_out, char const *name)
{
	fr_dict_enum_t	*enumv;

	fr_assert_msg(attr_module_method, "module method global init must be called first");

	enumv = fr_dict_enum_by_name(attr_module_method, name, -1);
	if (enumv) goto done;

	if (fr_dict_enum_add_name_next(fr_dict_attr_unconst(attr_module_method), name) < 0) return -1;

	enumv = fr_dict_enum_by_name(attr_module_method, name, -1);
	if (!enumv) {
		fr_strerror_printf("Failed adding method enumeration value");
		return -1;
	}

done:
	*id_out = enumv->value->vb_uint32;
	return 0;
}

/** Return the name of a module method from a given id
 *
 * @param[in] id	of module method.
 * @return
 *	- Module method name.
 *	- NULL.
 */
char const *module_method_name_by_id(module_method_id_t id)
{
	fr_dict_enum_t *enumv = fr_dict_enum_by_value(attr_module_method, fr_box_uint32(id));

	if (!enumv) return NULL;

	return enumv->name;
}

/** Return the name of a module method from a given entry
 *
 * @param[in] entry	of module method.
 * @return
 *	- Module method name.
 *	- NULL.
 */
char const *module_method_name_by_entry(module_method_entry_t const *entry)
{
	fr_dict_enum_t *enumv = fr_dict_enum_by_value(attr_module_method, fr_box_uint32(entry->id));

	if (!enumv) return NULL;

	return enumv->name;
}

/** Return the next module method in the set
 *
 * @param[in] set	to iterate over.
 * @param[in] prev	module method entry.
 * @return
 *	- NULL if no more module entries list.
 *	- Next module method entry in the set.
 */
module_method_entry_t *module_method_next(module_method_set_t *set, module_method_entry_t *prev)
{
	return fr_dlist_next(&set->list, prev);
}

/** Compare two module_method_entry_t structs by id
 *
 */
static int8_t module_method_cmp(void const *one, void const *two)
{
	module_method_entry_t const *a = one, *b = two;

	return CMP(a, b);
}

/** Allocate a new module method set
 *
 * @param[in] ctx	to allocate the module method set in.
 * @return
 *	- A new module method set.
 *	- NULL on error.
 */
module_method_set_t *module_method_alloc_set(TALLOC_CTX *ctx)
{
	module_method_set_t *set;

	MEM(set = talloc_zero(ctx, module_method_set_t));
	MEM(set->tree = fr_rb_tree_talloc_alloc(set, module_method_entry_t, node, module_method_cmp, NULL, 0));
	fr_dlist_talloc_init(&set->list, module_method_entry_t, entry);

	return set;
}

/** Add a module method into a set
 *
 * @param[in] set	to add module method to.
 * @param[in] id	of method.
 * @param[in] method	to insert.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int module_method_insert(module_method_set_t *set, module_method_id_t id, module_method_t method)
{
	module_method_entry_t	*found, find = { .id = id, .method = method };

	found = fr_rb_find(set->tree, &find);
	if (found) {
		if (unlikely(found->method != method)) {
			fr_strerror_printf("Conflict for method id %u (old %p vs new %p)",
					   id, found->method, method);
			return -1;
		}
		return 0;
	}

	MEM(found = talloc(set, module_method_entry_t));
	*found = find;

	if (!fr_rb_insert(set->tree, found)) {
		fr_strerror_printf("Failed inserting method id %u", id);
		return -1;
	}

	fr_dlist_insert_tail(&set->list, found);

	return 0;

}

/** Return a method from the specified set
 *
 * @param[in] set	to lookup method in.
 * @param[in] id	to search by.
 * @return
 *	- NULL if the id wasn't found in the method set.
 *	- Function pointer for the module method pointer.
 */
module_method_t	module_method_find(module_method_set_t *set, module_method_id_t id)
{
	module_method_entry_t	*found;

	found = fr_rb_find(set->tree, &(module_method_entry_t){ .id = id });
	if (!found) return NULL;

	return found->method;
}

/** Global initialisation for module method code
 *
 */
int module_method_global_init(void)
{
	if (fr_dict_autoload(method_dict) < 0) {
		fr_perror("module_method_global_init");
		return -1;
	}

	if (fr_dict_attr_autoload(module_method_attr) < 0) {
		fr_perror("module_method_global_init");
		return -1;
	}

	return 0;
}

/** Global de-initialisation for module method code
 *
 */
void module_method_global_free(void)
{
	fr_dict_autofree(method_dict);
}
