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

/** Resizable hash tables
 *
 * The weird "reverse" function is based on an idea from
 * "Split-Ordered Lists - Lock-free Resizable Hash Tables", with
 * modifications so that they're not lock-free. :(
 *
 * However, the split-order idea allows a fast & easy splitting of the
 * hash bucket chain when the hash table is resized.  Without it, we'd
 * have to check & update the pointers for every node in the buck chain,
 * rather than being able to move 1/2 of the entries in the chain with
 * one update.
 *
 * @file src/lib/util/hash.c
 *
 * @copyright 2005,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/hash.h>

/*
 *	A reasonable number of buckets to start off with.
 *	Should be a power of two.
 */
#define FR_HASH_NUM_BUCKETS (64)

struct fr_hash_entry_s {
	fr_hash_entry_t 	*next;
	uint32_t		reversed;
	uint32_t		key;
	void 			*data;
};

struct fr_hash_table_s {
	uint32_t		num_elements;	//!< Number of elements in the hash table.
	uint32_t		num_buckets;	//!< Number of buckets (how long the array is) - power of 2 */
	uint32_t		next_grow;
	uint32_t		mask;

	fr_free_t		free;		//!< Data free function.
	fr_hash_t		hash;		//!< Hashing function.
	fr_cmp_t		cmp;		//!< Comparison function.

	char const		*type;		//!< Talloc type to check elements against.

	fr_hash_entry_t		null;
	fr_hash_entry_t		**buckets;	//!< Array of hash buckets.
};

#ifdef TESTING
static int grow = 0;
#endif

/*
 * perl -e 'foreach $i (0..255) {$r = 0; foreach $j (0 .. 7 ) { if (($i & ( 1<< $j)) != 0) { $r |= (1 << (7 - $j));}} print $r, ", ";if (($i & 7) == 7) {print "\n";}}'
 */
static const uint8_t reversed_byte[256] = {
	0,  128, 64, 192, 32, 160, 96,  224,
	16, 144, 80, 208, 48, 176, 112, 240,
	8,  136, 72, 200, 40, 168, 104, 232,
	24, 152, 88, 216, 56, 184, 120, 248,
	4,  132, 68, 196, 36, 164, 100, 228,
	20, 148, 84, 212, 52, 180, 116, 244,
	12, 140, 76, 204, 44, 172, 108, 236,
	28, 156, 92, 220, 60, 188, 124, 252,
	2,  130, 66, 194, 34, 162, 98,  226,
	18, 146, 82, 210, 50, 178, 114, 242,
	10, 138, 74, 202, 42, 170, 106, 234,
	26, 154, 90, 218, 58, 186, 122, 250,
	6,  134, 70, 198, 38, 166, 102, 230,
	22, 150, 86, 214, 54, 182, 118, 246,
	14, 142, 78, 206, 46, 174, 110, 238,
	30, 158, 94, 222, 62, 190, 126, 254,
	1,  129, 65, 193, 33, 161, 97,  225,
	17, 145, 81, 209, 49, 177, 113, 241,
	9,  137, 73, 201, 41, 169, 105, 233,
	25, 153, 89, 217, 57, 185, 121, 249,
	5,  133, 69, 197, 37, 165, 101, 229,
	21, 149, 85, 213, 53, 181, 117, 245,
	13, 141, 77, 205, 45, 173, 109, 237,
	29, 157, 93, 221, 61, 189, 125, 253,
	3,  131, 67, 195, 35, 163, 99,  227,
	19, 147, 83, 211, 51, 179, 115, 243,
	11, 139, 75, 203, 43, 171, 107, 235,
	27, 155, 91, 219, 59, 187, 123, 251,
	7,  135, 71, 199, 39, 167, 103, 231,
	23, 151, 87, 215, 55, 183, 119, 247,
	15, 143, 79, 207, 47, 175, 111, 239,
	31, 159, 95, 223, 63, 191, 127, 255
};


/*
 * perl -e 'foreach $i (0..255) {$r = 0;foreach $j (0 .. 7) { $r = $i & (1 << (7 - $j)); last if ($r)} print $i & ~($r), ", ";if (($i & 7) == 7) {print "\n";}}'
 */
static uint8_t parent_byte[256] = {
	0, 0, 0, 1, 0, 1, 2, 3,
	0, 1, 2, 3, 4, 5, 6, 7,
	0, 1, 2, 3, 4, 5, 6, 7,
	8, 9, 10, 11, 12, 13, 14, 15,
	0, 1, 2, 3, 4, 5, 6, 7,
	8, 9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23,
	24, 25, 26, 27, 28, 29, 30, 31,
	0, 1, 2, 3, 4, 5, 6, 7,
	8, 9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23,
	24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 39,
	40, 41, 42, 43, 44, 45, 46, 47,
	48, 49, 50, 51, 52, 53, 54, 55,
	56, 57, 58, 59, 60, 61, 62, 63,
	0, 1, 2, 3, 4, 5, 6, 7,
	8, 9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23,
	24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 39,
	40, 41, 42, 43, 44, 45, 46, 47,
	48, 49, 50, 51, 52, 53, 54, 55,
	56, 57, 58, 59, 60, 61, 62, 63,
	64, 65, 66, 67, 68, 69, 70, 71,
	72, 73, 74, 75, 76, 77, 78, 79,
	80, 81, 82, 83, 84, 85, 86, 87,
	88, 89, 90, 91, 92, 93, 94, 95,
	96, 97, 98, 99, 100, 101, 102, 103,
	104, 105, 106, 107, 108, 109, 110, 111,
	112, 113, 114, 115, 116, 117, 118, 119,
	120, 121, 122, 123, 124, 125, 126, 127
};


/*
 *	Reverse a key.
 */
static uint32_t reverse(uint32_t key)
{
	/*
	 *	Cast to uint32_t is required because the
	 *	default type of of the expression is an
	 *	int and ubsan correctly complains that
	 *	the result of 0xff << 24 won't fit in a
	 *	signed 32bit integer.
	 */
	return (((uint32_t)reversed_byte[key & 0xff] << 24) |
		((uint32_t)reversed_byte[(key >> 8) & 0xff] << 16) |
		((uint32_t)reversed_byte[(key >> 16) & 0xff] << 8) |
		((uint32_t)reversed_byte[(key >> 24) & 0xff]));
}

/*
 *	Take the parent by discarding the highest bit that is set.
 */
static uint32_t parent_of(uint32_t key)
{
	if (key > 0x00ffffff)
		return (key & 0x00ffffff) | (parent_byte[key >> 24] << 24);

	if (key > 0x0000ffff)
		return (key & 0x0000ffff) | (parent_byte[key >> 16] << 16);

	if (key > 0x000000ff)
		return (key & 0x000000ff) | (parent_byte[key >> 8] << 8);

	return parent_byte[key];
}


static CC_NO_UBSAN(undefined)
int list_find(fr_hash_entry_t **found, fr_hash_table_t *ht,
	      fr_hash_entry_t *head, uint32_t reversed, void const *data)
{
	fr_hash_entry_t *cur;

	*found = NULL;

	for (cur = head; cur != &ht->null; cur = cur->next) {
		if (cur->reversed == reversed) {
			if (ht->cmp) {
				fr_cmp_ret_t cmp = ht->cmp(data, cur->data);

				if (unlikely(cmp == CMP_ERR)) return -1;
				if (cmp == CMP_GT) break;
				if (cmp == CMP_LT) continue;
			}
			*found = cur;
			return 0;
		}
		if (cur->reversed > reversed) break;
	}

	return 0;
}


/*
 *	Inserts a new entry into the list, in order.
 */
static CC_NO_UBSAN(undefined)
int list_insert(fr_hash_table_t *ht,
	        fr_hash_entry_t **head, fr_hash_entry_t *node)
{
	fr_hash_entry_t **last, *cur;

	last = head;

	for (cur = *head; cur != &ht->null; last = &(cur->next), cur = cur->next) {
		if (cur->reversed > node->reversed) break;

		if (cur->reversed == node->reversed) {
			if (ht->cmp) {
				fr_cmp_ret_t cmp = ht->cmp(node->data, cur->data);

				if (unlikely(cmp == CMP_ERR)) return -1;
				if (cmp == CMP_GT) break;
				if (cmp == CMP_LT) continue;
			}
			return 1;
		}
	}

	node->next = *last;
	*last = node;

	return 0;
}


/*
 *	Delete an entry from the list.
 */
static void list_delete(fr_hash_table_t *ht,
			fr_hash_entry_t **head, fr_hash_entry_t *node)
{
	fr_hash_entry_t **last, *cur;

	last = head;

	for (cur = *head; cur != &ht->null; cur = cur->next) {
		if (cur == node) {
			*last = node->next;
			return;
		}
		last = &(cur->next);
	}

	fr_assert(0);
}

static int _fr_hash_table_free(fr_hash_table_t *ht)
{
	uint32_t i;
	fr_hash_entry_t *node, *next;

	if (ht->free) {
		for (i = 0; i < ht->num_buckets; i++) {
			if (ht->buckets[i]) for (node = ht->buckets[i];
						 node != &ht->null;
						 node = next) {
				next = node->next;
				if (!node->data) continue; /* dummy entry */

				ht->free(node->data);
			}
		}
	}

	return 0;
}

/*
 *	Create the table.
 *
 *	Memory usage in bytes is (20/3) * number of entries.
 */
fr_hash_table_t *_fr_hash_table_alloc(TALLOC_CTX *ctx,
				      char const *type,
				      fr_hash_t hash_func,
				      fr_cmp_t cmp_func,
				      fr_free_t free_func)
{
	fr_hash_table_t *ht;

	ht = talloc(ctx, fr_hash_table_t);
	if (!ht) return NULL;
	talloc_set_destructor(ht, _fr_hash_table_free);

	*ht = (fr_hash_table_t){
		.type = type,
		.free = free_func,
		.hash = hash_func,
		.cmp = cmp_func,
		.num_buckets = FR_HASH_NUM_BUCKETS,
		.mask = FR_HASH_NUM_BUCKETS - 1,

		/*
		 *	Have a default load factor of 2.5.  In practice this
		 *	means that the average load will hit 3 before the
		 *	table grows.
		 */
		.next_grow = (FR_HASH_NUM_BUCKETS << 1) + (FR_HASH_NUM_BUCKETS >> 1),
		.buckets = talloc_zero_array(ht, fr_hash_entry_t *, FR_HASH_NUM_BUCKETS)
	};
	if (unlikely(!ht->buckets)) {
		talloc_free(ht);
		return NULL;
	}

	ht->null.reversed = ~0;
	ht->null.key = ~0;
	ht->null.next = &ht->null;
	ht->buckets[0] = &ht->null;

	return ht;
}


/*
 *	If the current bucket is uninitialized, initialize it
 *	by recursively copying information from the parent.
 *
 *	We may have a situation where entry E is a parent to 2 other
 *	entries E' and E".  If we split E into E and E', then the
 *	nodes meant for E" end up in E or E', either of which is
 *	wrong.  To solve that problem, we walk down the whole chain,
 *	inserting the elements into the correct place.
 */
static void fr_hash_table_fixup(fr_hash_table_t *ht, uint32_t entry)
{
	uint32_t parent_entry;
	fr_hash_entry_t **last, *cur;
	uint32_t this;

	parent_entry = parent_of(entry);

	/* parent_entry == entry if and only if entry == 0 */

	if (!ht->buckets[parent_entry]) {
		fr_hash_table_fixup(ht, parent_entry);
	}

	/*
	 *	Keep walking down cur, trying to find entries that
	 *	don't belong here any more.  There may be multiple
	 *	ones, so we can't have a naive algorithm...
	 */
	last = &ht->buckets[parent_entry];
	this = parent_entry;

	for (cur = *last; cur != &ht->null; cur = cur->next) {
		uint32_t real_entry;

		real_entry = cur->key & ht->mask;
		if (real_entry != this) { /* ht->buckets[real_entry] == NULL */
			*last = &ht->null;
			ht->buckets[real_entry] = cur;
			this = real_entry;
		}

		last = &(cur->next);
	}

	/*
	 *	We may NOT have initialized this bucket, so do it now.
	 */
	if (!ht->buckets[entry]) ht->buckets[entry] = &ht->null;
}

/*
 *	This should be a power of two.  Changing it to 4 doesn't seem
 *	to make any difference.
 */
#define GROW_FACTOR (2)

/*
 *	Set a maximum number of entries, which lets us avoid overflows
 *	on next_grow, GROW_FACTOR, etc.
 */
#define TABLE_MAX ((uint32_t) 0x20000000)

/*
 *	Grow the hash table.
 */
static void fr_hash_table_grow(fr_hash_table_t *ht)
{
	fr_hash_entry_t **buckets;
	size_t existing = talloc_get_size(ht->buckets);
	size_t expanded;

	/*
	 *	Cap the growth, because we need to be able to set a
	 *	mask, etc.
	 */
	if (ht->num_buckets >= TABLE_MAX) return;

	expanded = GROW_FACTOR * ht->num_buckets;
	if (expanded > TABLE_MAX) expanded = TABLE_MAX;

	buckets = talloc_realloc(ht, ht->buckets, fr_hash_entry_t *, expanded);
	if (!buckets) return;

	memset(((uint8_t *)buckets) + existing, 0, talloc_get_size(buckets) - existing);

	ht->buckets = buckets;
	ht->num_buckets = expanded;
	ht->mask = ht->num_buckets - 1;
	ht->next_grow *= GROW_FACTOR;

#ifdef TESTING
	grow = 1;
	fprintf(stderr, "GROW TO %d\n", ht->num_buckets);
#endif
}

/*
 *	Internal find a node routine.
 */
static inline CC_HINT(always_inline) int hash_table_find(fr_hash_entry_t **found, fr_hash_table_t *ht,
							  uint32_t key, void const *data)
{
	uint32_t entry;
	uint32_t reversed;

	entry = key & ht->mask;
	reversed = reverse(key);

	if (!ht->buckets[entry]) fr_hash_table_fixup(ht, entry);

	return list_find(found, ht, ht->buckets[entry], reversed, data);
}

/** Find data in a hash table
 *
 * @param[out] found	the matching element, or NULL if no element matched.
 * @param[in] ht	to find data in.
 * @param[in] data 	to find.  Will be passed to the
 *      		hashing function.
 * @return
 *      - 0 the comparison sequence succeeded, check found for the result.
 *	- -1 the comparator errored, retrieve the error with fr_strerror.
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - htrie call with first argument of void * trips --fsanitize=function */
int fr_hash_table_find(void **found, fr_hash_table_t *ht, void const *data)
{
	fr_hash_entry_t	*node;

	*found = NULL;
	if (unlikely(hash_table_find(&node, ht, ht->hash(data), data) < 0)) return -1;
	if (node) *found = UNCONST(void *, node->data);

	return 0;
}

/** Hash table lookup with pre-computed key
 *
 * @param[out] found	the matching element, or NULL if no element matched.
 * @param[in] ht	to find data in.
 * @param[in] key	the precomputed key.
 * @param[in] data	for list matching.
 * @return
 *      - 0 the comparison sequence succeeded, check found for the result.
 *	- -1 the comparator errored, retrieve the error with fr_strerror.
 */
int fr_hash_table_find_by_key(void **found, fr_hash_table_t *ht, uint32_t key, void const *data)
{
	fr_hash_entry_t	*node;

	*found = NULL;
	if (unlikely(hash_table_find(&node, ht, key, data) < 0)) return -1;
	if (node) *found = UNCONST(void *, node->data);

	return 0;
}

/** Insert data into a hash table
 *
 * @param[in] ht	to insert data into.
 * @param[in] data 	to insert.  Will be passed to the
 *      		hashing function.
 * @return
 *	- 0 if data was inserted.
 *	- 1 if data already existed and was not inserted.
 *	- -1 on comparator or allocation error, retrieve the error with fr_strerror.
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - htrie call with first argument of void * trips --fsanitize=function */
int fr_hash_table_insert(fr_hash_table_t *ht, void const *data)
{
	uint32_t		key;
	uint32_t		entry;
	uint32_t		reversed;
	fr_hash_entry_t		*node;
	int			ret;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (ht->type) (void)_talloc_get_type_abort(data, ht->type, __location__);
#endif

	if (ht->num_elements >= TABLE_MAX) return -1;

	key = ht->hash(data);
	entry = key & ht->mask;
	reversed = reverse(key);

	if (!ht->buckets[entry]) fr_hash_table_fixup(ht, entry);

	/*
	 *	If we try to do our own memory allocation here, the
	 *	speedup is only ~15% or so, which isn't worth it.
	 */
	node = talloc_zero(ht, fr_hash_entry_t);
	if (unlikely(!node)) return -1;

	node->next = &ht->null;
	node->reversed = reversed;
	node->key = key;
	node->data = UNCONST(void *, data);

	/* already in the table, can't insert it */
	ret = list_insert(ht, &ht->buckets[entry], node);
	if (ret != 0) {
		talloc_free(node);
		return ret;
	}

	/*
	 *	Check the load factor, and grow the table if
	 *	necessary.
	 */
	ht->num_elements++;
	if (ht->num_elements >= ht->next_grow) fr_hash_table_grow(ht);

	return 0;
}

/** Replace old data with new data, OR insert if there is no old
 *
 * @param[out] old	data that was replaced.  If this argument
 *			is not NULL, then the old data will not
 *			be freed, even if a free function is
 *			configured.
 * @param[in] ht	to insert data into.
 * @param[in] data 	to replace.  Will be passed to the
 *      		hashing function.
 * @return
 *      - 1 if data was replaced.
 *	- 0 if data was inserted.
 *      - -1 if we failed to replace data, retrieve the error with fr_strerror.
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - htrie call with first argument of void * trips --fsanitize=function */
int fr_hash_table_replace(void **old, fr_hash_table_t *ht, void const *data)
{
	fr_hash_entry_t	*node;

	if (unlikely(hash_table_find(&node, ht, ht->hash(data), data) < 0)) return -1;
	if (!node) {
		if (old) *old = NULL;
		return (fr_hash_table_insert(ht, data) == 0) ? 0 : -1;
	}

	if (old) {
		*old = node->data;
	} else if (ht->free) {
		ht->free(node->data);
	}

	node->data = UNCONST(void *, data);

	return 1;
}

/** Remove an entry from the hash table, without freeing the data
 *
 * @param[out] removed	the data we removed, if any.  May be NULL.
 * @param[in] ht	to remove data from.
 * @param[in] data 	to remove.  Will be passed to the
 *      		hashing function.
 * @return
 *      - 0 if we removed data, removed is populated.
 *	- 1 if we couldn't find any matching data.
 *      - -1 if the comparator errored, retrieve the error with fr_strerror.
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - htrie call with first argument of void * trips --fsanitize=function */
int fr_hash_table_remove(void **removed, fr_hash_table_t *ht, void const *data)
{
	uint32_t		key;
	uint32_t		entry;
	uint32_t		reversed;
	fr_hash_entry_t		*node;

	if (removed) *removed = NULL;

	key = ht->hash(data);
	entry = key & ht->mask;
	reversed = reverse(key);

	if (!ht->buckets[entry]) fr_hash_table_fixup(ht, entry);

	if (unlikely(list_find(&node, ht, ht->buckets[entry], reversed, data) < 0)) return -1;
	if (!node) return 1;

	list_delete(ht, &ht->buckets[entry], node);
	ht->num_elements--;

	if (removed) *removed = node->data;
	talloc_free(node);

	return 0;
}

/** Remove and free data (if a free function was specified)
 *
 * @param[in] ht	to remove data from.
 * @param[in] data 	to remove/free.
 * @return
 *	- 0 if we removed data.
 *	- 1 if we couldn't find any matching data.
 *      - -1 if the comparator errored, retrieve the error with fr_strerror.
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - htrie call with first argument of void * trips --fsanitize=function */
int fr_hash_table_delete(fr_hash_table_t *ht, void const *data)
{
	void	*old;
	int	ret;

	ret = fr_hash_table_remove(&old, ht, data);
	if (ret != 0) return ret;

	if (ht->free) ht->free(old);

	return 0;
}

/*
 *	Count number of elements
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - htrie call with first argument of void * trips --fsanitize=function */
uint32_t fr_hash_table_num_elements(fr_hash_table_t *ht)
{
	return ht->num_elements;
}

/** Iterate over entries in a hash table
 *
 * @note If the hash table is modified the iterator should be considered invalidated.
 *
 * @param[in] ht	to iterate over.
 * @param[in] iter	Pointer to an iterator struct, used to maintain
 *			state between calls.
 * @return
 *	- User data.
 *	- NULL if at the end of the list.
 */
void *fr_hash_table_iter_next(fr_hash_table_t *ht, fr_hash_iter_t *iter)
{
	fr_hash_entry_t *node;
	uint32_t	i;

	/*
	 *	Return the next element in the bucket.
	 */
	if (iter->next != &ht->null) {
		node = iter->next;
		iter->next = node->next;

		return node->data;
	}

	/*
	 *	We've wrapped around to bucket 0 again.  That means we're done.
	 */
	if (iter->bucket == 0) return NULL;

	/*
	 *	We might have to go through multiple empty
	 *	buckets to find one that contains something
	 *	we should return
	 */
	i = iter->bucket - 1;
	for (;;) {
		if (!ht->buckets[i]) fr_hash_table_fixup(ht, i);

		node = ht->buckets[i];
		if (node == &ht->null) {
			if (i == 0) break;
			i--;
			continue;	/* This bucket was empty too... */
		}

		iter->next = node->next;		/* Store the next one to examine */
		iter->bucket = i;
		return node->data;
	}
	iter->bucket = i;

	return NULL;
}

/** Initialise an iterator
 *
 * @note If the hash table is modified the iterator should be considered invalidated.
 *
 * @param[in] ht	to iterate over.
 * @param[out] iter	to initialise.
 * @return
 *	- The first entry in the hash table.
 *	- NULL if the hash table is empty.
 */
void *fr_hash_table_iter_init(fr_hash_table_t *ht, fr_hash_iter_t *iter)
{
	iter->bucket = ht->num_buckets;
	iter->next = &ht->null;

	return fr_hash_table_iter_next(ht, iter);
}

/** Copy all entries out of a hash table into an array
 *
 * @param[in] ctx	to allocate array in.
 * @param[in] out	array of hash table entries.
 * @param[in] ht	to flatter.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
int fr_hash_table_flatten(TALLOC_CTX *ctx, void **out[], fr_hash_table_t *ht)
{
	uint64_t	num = fr_hash_table_num_elements(ht), i;
	fr_hash_iter_t	iter;
	void		*item, **list;

	if (unlikely(!(list = talloc_array(ctx, void *, num)))) return -1;

	for (item = fr_hash_table_iter_init(ht, &iter), i = 0;
	     item;
	     item = fr_hash_table_iter_next(ht, &iter), i++) list[i] = item;

	*out = list;

	return 0;
}

/** Ensure all buckets are filled
 *
 * This must be called if the table will be read by multiple threads without
 * synchronisation.  Synchronisation is still required for updates.
 *
 * @param[in] ht	to fill.
 */
void fr_hash_table_fill(fr_hash_table_t *ht)
{
	uint32_t i;

	if (!ht->num_buckets) return;


	i = ht->num_buckets - 1;

	while (true) {
		if (!ht->buckets[i]) fr_hash_table_fixup(ht, i);
		if (!i) break;
		i--;
	}
}

#ifdef TESTING
/*
 *	Show what the hash table is doing.
 */
int fr_hash_table_info(fr_hash_table_t *ht)
{
	int i, a, collisions, uninitialized;
	int array[256];

	if (!ht) return 0;

	uninitialized = collisions = 0;
	memset(array, 0, sizeof(array));

	for (i = 0; i < ht->num_buckets; i++) {
		uint32_t key;
		int load;
		fr_hash_entry_t *node, *next;

		/*
		 *	If we haven't inserted or looked up an entry
		 *	in a bucket, it's uninitialized.
		 */
		if (!ht->buckets[i]) {
			uninitialized++;
			continue;
		}

		load = 0;
		key = ~0;
		for (node = ht->buckets[i]; node != &ht->null; node = next) {
			if (node->reversed == key) {
				collisions++;
			} else {
				key = node->reversed;
			}
			next = node->next;
			load++;
		}

		if (load > 255) load = 255;
		array[load]++;
	}

	printf("HASH TABLE %p\tbuckets: %d\t(%d uninitialized)\n", ht,
		ht->num_buckets, uninitialized);
	printf("\tnum entries %d\thash collisions %d\n",
		ht->num_elements, collisions);

	a = 0;
	for (i = 1; i < 256; i++) {
		if (!array[i]) continue;
		printf("%d\t%d\n", i, array[i]);

		/*
		 *	Since the entries are ordered, the lookup cost
		 *	for any one element in a chain is (on average)
		 *	the cost of walking half of the chain.
		 */
		if (i > 1) {
			a += array[i] * i;
		}
	}
	a /= 2;
	a += array[1];

	printf("\texpected lookup cost = %d/%d or %f\n\n",
	       ht->num_elements, a,
	       (float) ht->num_elements / (float) a);

	return 0;
}
#endif


#define FNV_MAGIC_INIT (0x811c9dc5)
#define FNV_MAGIC_PRIME (0x01000193)

/*
 *	A fast hash function.  For details, see:
 *
 *	http://www.isthe.com/chongo/tech/comp/fnv/
 *
 *	Which also includes public domain source.  We've re-written
 *	it here for our purposes.
 */
uint32_t fr_hash(void const *data, size_t size)
{
	uint8_t const *p = data;
	uint8_t const *q = p + size;
	uint32_t      hash = FNV_MAGIC_INIT;

	/*
	 *	FNV-1 hash each octet in the buffer
	 */
	while (p != q) {
		/*
		 *	XOR the 8-bit quantity into the bottom of
		 *	the hash.
		 */
		hash ^= (uint32_t) (*p++);

		/*
		 *	Multiply by 32-bit magic FNV prime, mod 2^32
		 */
		hash *= FNV_MAGIC_PRIME;
#if 0
		/*
		 *	Potential optimization.
		 */
		hash += (hash<<1) + (hash<<4) + (hash<<7) + (hash<<8) + (hash<<24);
#endif
	}

	return hash;
}

/*
 *	Continue hashing data.
 */
uint32_t fr_hash_update(void const *data, size_t size, uint32_t hash)
{
	uint8_t const *p = data;
	uint8_t const *q;

	if (size == 0) return hash;	/* Avoid ubsan issues with access NULL pointer */

 	q = p + size;
	while (p < q) {
		hash ^= (uint32_t) (*p++);
		hash *= FNV_MAGIC_PRIME;
	}

	return hash;
}

/*
 *	Hash a C string, so we loop over it once.
 */
uint32_t fr_hash_string(char const *p)
{
	uint32_t      hash = FNV_MAGIC_INIT;

	while (*p) {
		hash ^= (uint32_t) (*p++);
		/* coverity[overflow_const] */
		hash *= FNV_MAGIC_PRIME;
	}

	return hash;
}

/** Hash a C string, converting all chars to lowercase
 *
 */
uint32_t fr_hash_case_string(char const *p)
{
	uint32_t      hash = FNV_MAGIC_INIT;

	while (*p) {
		hash ^= (uint32_t) (tolower((uint8_t) *p++));
		/* coverity[overflow_const] */
		hash *= FNV_MAGIC_PRIME;
	}

	return hash;
}

/*
 *	64-bit variants of the above functions/
 */
#undef FNV_MAGIC_INIT
#undef FNV_MAGIC_PRIME
#define FNV_MAGIC_INIT ((uint64_t)  0xcbf29ce484222325)
#define FNV_MAGIC_PRIME ((uint64_t) 0x00000100000001B3)

/*
 *	A 64-bit version of the above hash
 */
uint64_t fr_hash64(void const *data, size_t size)
{
	uint8_t const *p = data;
	uint8_t const *q = p + size;
	uint64_t      hash = FNV_MAGIC_INIT;

	/*
	 *	FNV-1 hash each octet in the buffer
	 */
	while (p != q) {
		/*
		 *	XOR the 8-bit quantity into the bottom of
		 *	the hash.
		 */
		hash ^= (uint64_t) (*p++);

		/*
		 *	Multiply by 64-bit magic FNV prime, mod 2^64
		 */
		hash *= FNV_MAGIC_PRIME;
	}

	return hash;
}

/*
 *	Continue hashing data.
 */
uint64_t fr_hash64_update(void const *data, size_t size, uint64_t hash)
{
	uint8_t const *p = data;
	uint8_t const *q;

	if (size == 0) return hash;	/* Avoid ubsan issues with access NULL pointer */

 	q = p + size;
	while (p < q) {
		hash ^= (uint64_t) (*p++);
		hash *= FNV_MAGIC_PRIME;
	}

	return hash;
}

/** Check hash table is sane
 *
 */
void fr_hash_table_verify(fr_hash_table_t *ht)
{
	fr_hash_iter_t	iter;
	void		*ptr;

	(void)talloc_get_type_abort(ht, fr_hash_table_t);
	(void)talloc_get_type_abort(ht->buckets, fr_hash_entry_t *);

	fr_assert(talloc_array_length(ht->buckets) == ht->num_buckets);

	/*
	 *	Check talloc headers on all data
	 */
	if (ht->type) {
		for (ptr = fr_hash_table_iter_init(ht, &iter);
		     ptr;
		     ptr = fr_hash_table_iter_next(ht, &iter)) {
			(void)_talloc_get_type_abort(ptr, ht->type, __location__);
		}
	}
}

#ifdef TESTING
/*
 *  cc -g -DTESTING -I ../include hash.c -o hash
 *
 *  ./hash
 */
static uint32_t hash_int(void const *data)
{
	return fr_hash((int *) data, sizeof(int));
}

#define MAX 1024*1024
int main(int argc, char **argv)
{
	int i, *p, *q, k;
	fr_hash_table_t *ht;
	int *array;

	ht = fr_hash_table_alloc(NULL, hash_int, NULL, NULL);
	if (!ht) {
		fprintf(stderr, "Hash create failed\n");
		fr_exit(1);
	}

	array = talloc_zero_array(NULL, int, MAX);
	if (!array) fr_exit(1);

	for (i = 0; i < MAX; i++) {
		p = array + i;
		*p = i;

		if (fr_hash_table_insert(ht, p) != 0) {
			fprintf(stderr, "Failed insert %08x\n", i);
			fr_exit(1);
		}
#ifdef TEST_INSERT
		(void) fr_hash_table_find((void **)&q, ht, p);
		if (q != p) {
			fprintf(stderr, "Bad data %d\n", i);
			fr_exit(1);
		}
#endif
	}

	fr_hash_table_info(ht);

	/*
	 *	Build this to see how lookups result in shortening
	 *	of the hash chains.
	 */
	if (1) {
		for (i = 0; i < MAX ; i++) {
			(void) fr_hash_table_find((void **)&q, ht, &i);
			if (!q || *q != i) {
				fprintf(stderr, "Failed finding %d\n", i);
				fr_exit(1);
			}

#if 0
			if (fr_hash_table_delete(ht, &i) != 0) {
				fprintf(stderr, "Failed deleting %d\n", i);
				fr_exit(1);
			}
			(void) fr_hash_table_find((void **)&q, ht, &i);
			if (q) {
				fprintf(stderr, "Failed to delete %08x\n", i);
				fr_exit(1);
			}
#endif
		}

		fr_hash_table_info(ht);
	}

	fr_hash_table_free(ht);
	talloc_free(array);

	return EXIT_SUCCESS;
}
#endif
