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
#include <freeradius-devel/util/talloc.h>

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
	uint32_t		num_elements;
	uint32_t		num_buckets; /* power of 2 */
	uint32_t		next_grow;
	uint32_t		mask;

	fr_free_t		free;
	fr_hash_t		hash;
	fr_cmp_t		cmp;

	fr_hash_entry_t		null;

	fr_hash_entry_t		**buckets;
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


static fr_hash_entry_t *list_find(fr_hash_table_t *ht,
				  fr_hash_entry_t *head, uint32_t reversed, void const *data)
{
	fr_hash_entry_t *cur;

	for (cur = head; cur != &ht->null; cur = cur->next) {
		if (cur->reversed == reversed) {
			if (ht->cmp) {
				int cmp = ht->cmp(data, cur->data);
				if (cmp > 0) break;
				if (cmp < 0) continue;
			}
			return cur;
		}
		if (cur->reversed > reversed) break;
	}

	return NULL;
}


/*
 *	Inserts a new entry into the list, in order.
 */
static bool list_insert(fr_hash_table_t *ht,
		        fr_hash_entry_t **head, fr_hash_entry_t *node)
{
	fr_hash_entry_t **last, *cur;

	last = head;

	for (cur = *head; cur != &ht->null; cur = cur->next) {
		if (cur->reversed > node->reversed) break;
		last = &(cur->next);

		if (cur->reversed == node->reversed) {
			if (ht->cmp) {
				int8_t cmp = ht->cmp(node->data, cur->data);
				if (cmp > 0) break;
				if (cmp < 0) continue;
			}
			return false;
		}
	}

	node->next = *last;
	*last = node;

	return true;
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
		if (cur == node) break;
		last = &(cur->next);
	}

	*last = node->next;
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
fr_hash_table_t *fr_hash_table_alloc(TALLOC_CTX *ctx,
				     fr_hash_t hash_func,
				     fr_cmp_t cmp_func,
				     fr_free_t free_func)
{
	fr_hash_table_t *ht;

	ht = talloc_zero(ctx, fr_hash_table_t);
	if (!ht) return NULL;
	talloc_set_destructor(ht, _fr_hash_table_free);

	ht->free = free_func;
	ht->hash = hash_func;
	ht->cmp = cmp_func;
	ht->num_buckets = FR_HASH_NUM_BUCKETS;
	ht->mask = ht->num_buckets - 1;

	/*
	 *	Have a default load factor of 2.5.  In practice this
	 *	means that the average load will hit 3 before the
	 *	table grows.
	 */
	ht->next_grow = (ht->num_buckets << 1) + (ht->num_buckets >> 1);

	ht->buckets = talloc_zero_array(ht, fr_hash_entry_t *, ht->num_buckets);
	if (!ht->buckets) {
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
 *	Grow the hash table.
 */
static void fr_hash_table_grow(fr_hash_table_t *ht)
{
	fr_hash_entry_t **buckets;
	size_t existing = talloc_get_size(ht->buckets);

	buckets = talloc_realloc(ht, ht->buckets, fr_hash_entry_t *, GROW_FACTOR * ht->num_buckets);
	if (!buckets) return;

	memset(((uint8_t *)buckets) + existing, 0, talloc_get_size(buckets) - existing);

	ht->buckets = buckets;
	ht->num_buckets *= GROW_FACTOR;
	ht->next_grow *= GROW_FACTOR;
	ht->mask = ht->num_buckets - 1;
#ifdef TESTING
	grow = 1;
	fprintf(stderr, "GROW TO %d\n", ht->num_buckets);
#endif
}

/*
 *	Internal find a node routine.
 */
static inline CC_HINT(always_inline) fr_hash_entry_t *hash_table_find(fr_hash_table_t *ht,
									 uint32_t key, void const *data)
{
	uint32_t entry;
	uint32_t reversed;

	entry = key & ht->mask;
	reversed = reverse(key);

	if (!ht->buckets[entry]) fr_hash_table_fixup(ht, entry);

	return list_find(ht, ht->buckets[entry], reversed, data);
}

/** Find data in a hash table
 *
 * @param[in] ht	to find data in.
 * @param[in] data 	to find.  Will be passed to the
 *      		hashing function.
 * @return
 *      - The user data we found.
 *	- NULL if we couldn't find any matching data.
 */
void *fr_hash_table_find(fr_hash_table_t *ht, void const *data)
{
	fr_hash_entry_t *node;

	node = hash_table_find(ht, ht->hash(data), data);
	if (!node) return NULL;

	return UNCONST(void *, node->data);
}

/** Hash table lookup with pre-computed key
 *
 * @param[in] ht	to find data in.
 * @param[in] key	the precomputed key.
 * @param[in] data	for list matching.
 * @return
 *      - The user data we found.
 *	- NULL if we couldn't find any matching data.
 */
void *fr_hash_table_find_by_key(fr_hash_table_t *ht, uint32_t key, void const *data)
{
	fr_hash_entry_t *node;

	node = hash_table_find(ht, key, data);
	if (!node) return NULL;

	return UNCONST(void *, node->data);
}

/** Insert data
 *
 * @param[in] ht	to insert data into.
 * @param[in] data 	to insert.  Will be passed to the
 *      		hashing function.
 * @return
 *	- true if data was inserted.
 *	- false if data already existed and was not inserted.
 */
bool fr_hash_table_insert(fr_hash_table_t *ht, void const *data)
{
	uint32_t		key;
	uint32_t		entry;
	uint32_t		reversed;
	fr_hash_entry_t		*node;

	key = ht->hash(data);
	entry = key & ht->mask;
	reversed = reverse(key);

	if (!ht->buckets[entry]) fr_hash_table_fixup(ht, entry);

	/*
	 *	If we try to do our own memory allocation here, the
	 *	speedup is only ~15% or so, which isn't worth it.
	 */
	node = talloc_zero(ht, fr_hash_entry_t);
	if (unlikely(!node)) return false;

	node->next = &ht->null;
	node->reversed = reversed;
	node->key = key;
	node->data = UNCONST(void *, data);

	/* already in the table, can't insert it */
	if (!list_insert(ht, &ht->buckets[entry], node)) {
		talloc_free(node);
		return false;
	}

	/*
	 *	Check the load factor, and grow the table if
	 *	necessary.
	 */
	ht->num_elements++;
	if (ht->num_elements >= ht->next_grow) fr_hash_table_grow(ht);

	return true;
}

/** Replace old data with new data, OR insert if there is no old
 *
 * @param[in] ht	to insert data into.
 * @param[in] data 	to replace.  Will be passed to the
 *      		hashing function.
 * @return
 *      - 1 if data was inserted.
 *	- 0 if data was replaced.
 *      - -1 if we failed to replace data
 */
int fr_hash_table_replace(fr_hash_table_t *ht, void const *data)
{
	fr_hash_entry_t *node;

	node = hash_table_find(ht, ht->hash(data), data);
	if (!node) return fr_hash_table_insert(ht, data) ? 1 : -1;

	if (ht->free) ht->free(node->data);

	node->data = UNCONST(void *, data);

	return 0;
}

/** Remove an entry from the hash table, without freeing the data
 *
 * @param[in] ht	to remove data from.
 * @param[in] data 	to remove.  Will be passed to the
 *      		hashing function.
 * @return
 *      - The user data we removed.
 *	- NULL if we couldn't find any matching data.
 */
void *fr_hash_table_remove(fr_hash_table_t *ht, void const *data)
{
	uint32_t		key;
	uint32_t		entry;
	uint32_t		reversed;
	void			*old;
	fr_hash_entry_t		*node;

	key = ht->hash(data);
	entry = key & ht->mask;
	reversed = reverse(key);

	if (!ht->buckets[entry]) fr_hash_table_fixup(ht, entry);

	node = list_find(ht, ht->buckets[entry], reversed, data);
	if (!node) return NULL;

	list_delete(ht, &ht->buckets[entry], node);
	ht->num_elements--;

	old = node->data;
	talloc_free(node);

	return old;
}

/** Remove and free data (if a free function was specified)
 *
 * @param[in] ht	to remove data from.
 * @param[in] data 	to remove/free.
 * @return
 *	- true if we removed data.
 *      - false if we couldn't find any matching data.
 */
bool fr_hash_table_delete(fr_hash_table_t *ht, void const *data)
{
	void *old;

	old = fr_hash_table_remove(ht, data);
	if (!old) return false;

	if (ht->free) ht->free(old);

	return true;
}

/*
 *	Count number of elements
 */
uint64_t fr_hash_table_num_elements(fr_hash_table_t *ht)
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
	 *	Return the next element in the bucket
	 */
	if (iter->node != &ht->null) {
		node = iter->node;
		iter->node = node->next;

		return node->data;
	}

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

		iter->node = node->next;		/* Store the next one to examine */
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
	iter->node = &ht->null;

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
	int i;

	for (i = ht->num_buckets - 1; i >= 0; i--) if (!ht->buckets[i]) fr_hash_table_fixup(ht, i);
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
		 *	Multiple by 32-bit magic FNV prime, mod 2^32
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
		hash *= FNV_MAGIC_PRIME;
		hash ^= (uint32_t) (*p++);
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
		hash *= FNV_MAGIC_PRIME;
		hash ^= (uint32_t) (*p++);
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
		hash *= FNV_MAGIC_PRIME;
		hash ^= (uint32_t) (tolower(*p++));
	}

	return hash;
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

		if (!fr_hash_table_insert(ht, p)) {
			fprintf(stderr, "Failed insert %08x\n", i);
			fr_exit(1);
		}
#ifdef TEST_INSERT
		q = fr_hash_table_find(ht, p);
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
			q = fr_hash_table_find(ht, &i);
			if (!q || *q != i) {
				fprintf(stderr, "Failed finding %d\n", i);
				fr_exit(1);
			}

#if 0
			if (!fr_hash_table_delete(ht, &i)) {
				fprintf(stderr, "Failed deleting %d\n", i);
				fr_exit(1);
			}
			q = fr_hash_table_find(ht, &i);
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
