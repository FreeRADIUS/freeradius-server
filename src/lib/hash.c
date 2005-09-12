/*
 * hash.c	Non-thread-safe split-ordered hash table.
 *
 *  The weird "reverse" function is based on an idea from
 *  "Split-Ordered Lists - Lock-free Resizable Hash Tables", with
 *  modifications so that they're not lock-free. :(
 *
 *  However, the split-order idea allows a fast & easy splitting of the
 *  hash bucket chain when the hash table is resized.  Without it, we'd
 *  have to check & update the pointers for every node in the buck chain,
 *  rather than being able to move 1/2 of the entries in the chain with
 *  one update.
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
 *
 *  Copyright 2005  The FreeRADIUS server project
 */

static const char rcsid[] = "$Id$";

#include "autoconf.h"

#include <stdlib.h>
#include <string.h>

#include "missing.h"
#include "libradius.h"

typedef struct lrad_hash_entry_t {
	struct lrad_hash_entry_t *next;
	uint32_t	key; /* reversed image of the key */
	void		*data;
} lrad_hash_entry_t;

struct lrad_hash_table_t {
	int			num_elements;
	int			num_buckets; /* power of 2 */
	int			replace_flag;
	void			(*free)(void *);
	lrad_hash_entry_t	**buckets;
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
 *	Reverse a key.
 */
static uint32_t reverse(uint32_t key)
{
	return ((reversed_byte[key & 0xff] << 24) |
		(reversed_byte[(key >> 8) & 0xff] << 16) |
		(reversed_byte[(key >> 16) & 0xff] << 8) |
		(reversed_byte[(key >> 24) & 0xff]));
}

static lrad_hash_entry_t *list_find(lrad_hash_entry_t *head, uint32_t key)
{
	lrad_hash_entry_t *cur;

	for (cur = head; cur != NULL; cur = cur->next) {
		if (cur->key > key) return NULL;
		if (cur->key == key) return cur;
	}

	return NULL;
}

/*
 *	Inserts a new entry into the list, in order.
 */
static int list_insert(lrad_hash_entry_t **head, lrad_hash_entry_t *node)
{
	lrad_hash_entry_t **last, *cur;

	last = head;

	for (cur = *head; cur != NULL; cur = cur->next) {
		if (cur->key > node->key) break;
		last = &(cur->next);
	}

	node->next = *last;
	*last = node;

	return 1;
}


/*
 *	Delete an entry from the list.
 */
static int list_delete(lrad_hash_entry_t **head, lrad_hash_entry_t *node)
{
	lrad_hash_entry_t **last, *cur;

	last = head;
	
	for (cur = *head; cur != NULL; cur = cur->next) {
		if (cur == node) break;
		last = &(cur->next);
	}

	*last = node->next;
	return 1;
}


/*
 *	Split a list.  Everything >= key is returned, and the returned
 *	list is removed from the input list.
 */
static lrad_hash_entry_t *list_split(lrad_hash_entry_t **head, uint32_t key)
{
	lrad_hash_entry_t **last, *cur;

	last = head;
	
	for (cur = *head; cur != NULL; cur = cur->next) {
		if (cur->key >= key) break;
		last = &(cur->next);
	}

	*last = NULL;

	return cur;
}


/*
 *	Create the table.  Size is a power of two (i.e. 1..31)
 */
lrad_hash_table_t *lrad_hash_table_create(int size, void (*freeNode)(void *),
					  int replace_flag)
{
	lrad_hash_table_t *ht;

	if ((size <= 1) || (size > 31)) return NULL;

	/*
	 *	Get the nearest power of two.
	 */
	size = 1 << size;

	ht = malloc(sizeof(*ht));
	if (!ht) return NULL;

	memset(ht, 0, sizeof(*ht));
	ht->free = freeNode;
	ht->num_buckets = size;
	ht->replace_flag = replace_flag;

	ht->buckets = malloc(sizeof(*ht->buckets) * ht->num_buckets);
	if (!ht->buckets) {
		free(ht);
		return NULL;		
	}
	memset(ht->buckets, 0, sizeof(*ht->buckets) * ht->num_buckets);

	return ht;
}

/*
 *	Insert data.
 */
int lrad_hash_table_insert(lrad_hash_table_t *ht, uint32_t key, void *data)
{
	uint32_t entry;
	uint32_t reversed;
	lrad_hash_entry_t *node;

	if (!ht || !data) return 0;

	entry = key & (ht->num_buckets - 1);
	reversed = reverse(key);

	/*
	 *	Already in the table.
	 */
	node = list_find(ht->buckets[entry], reversed);
	if (node) {
		if (!ht->replace_flag) return 0;

		list_delete(&ht->buckets[entry], node);

		if (ht->free && node->data) ht->free(node->data);

		/*
		 *	Fall through to re-using the node.
		 */
	} else {
		node = malloc(sizeof(*node));
		if (!node) return 0;
	}
	memset(node, 0, sizeof(*node));
	
	node->key = reversed;
	node->data = data;
	node->next = NULL;

	list_insert(&(ht->buckets[entry]), node);
	ht->num_elements++;

	/*
	 *	Check the load factor, and grow the table if
	 *	necessary.
	 */
	if (ht->num_elements >= (3 * ht->num_buckets)) {
		int i;
		lrad_hash_entry_t **buckets;

		buckets = malloc(sizeof(*buckets) * 2 * ht->num_buckets);
		if (!buckets) return 1;

		memcpy(buckets, ht->buckets,
		       sizeof(*buckets) * ht->num_buckets);

		/*
		 *	Split the hash entries.
		 *
		 *	When we double the size of the hash array, we
		 *	do O(N/2) work.  Since this only happens after
		 *	we've inserted N elements,  we're still amortized
		 *	at O(1) inserts, deletes, and updates.
		 */
		for (i = 0; i < ht->num_buckets; i++) {
			buckets[ht->num_buckets + i] = list_split(&buckets[i],
								  reverse((uint32_t) i + ht->num_buckets));
		}
		free(ht->buckets);
		ht->buckets = buckets;
		ht->num_buckets *= 2;
#ifdef TESTING
		grow = 1;
		fprintf(stderr, "GROW TO %d\n", ht->num_buckets);
#endif
	}

	return 1;
}


/*
 *	Find data from a key.
 */
void *lrad_hash_table_finddata(lrad_hash_table_t *ht, uint32_t key)
{
	uint32_t entry;
	uint32_t reversed;
	lrad_hash_entry_t *node;

	entry = key & (ht->num_buckets - 1);
	reversed = reverse(key);

	if (!ht) return NULL;

	node = list_find(ht->buckets[entry], reversed);
	if (!node) return NULL;

	return node->data;	/* may be NULL */
}


/*
 *	Delete a piece of data from the hash table.
 */
int lrad_hash_table_delete(lrad_hash_table_t *ht, uint32_t key)
{
	uint32_t entry;
	uint32_t reversed;
	lrad_hash_entry_t *node;

	if (!ht) return 0;

	entry = key & (ht->num_buckets - 1);
	reversed = reverse(key);

	node = list_find(ht->buckets[entry], reversed);
	if (!node) return 0;
	
	if (ht->free) ht->free(node->data);
	list_delete(&ht->buckets[entry], node);
	ht->num_elements--;

	free(node);
	return 1;
}


/*
 *	Free a hash table
 */
void lrad_hash_table_free(lrad_hash_table_t *ht)
{
	lrad_hash_entry_t *node, *next;

	if (!ht) return;

	/*
	 *	The entries MUST be all in one linked list.
	 */
	for (node = ht->buckets[0]; node != NULL; node = next) {
		next = node->next;

		if (!node->data) continue; /* dummy entry */

		if (ht->free) ht->free(node->data);
		free(node);
	}

	free(ht->buckets);
	free(ht);
}


/*
 *	Count number of elements
 */
int lrad_hash_table_num_elements(lrad_hash_table_t *ht)
{
	if (!ht) return 0;

	return ht->num_elements;
}

int lrad_hash_table_walk(lrad_hash_table_t *ht,
			 int (*callback)(void * /* ctx */,
					 void * /* data */),
			 void *context)
{
	int i, rcode;;

	if (!ht || !callback) return 0;

	for (i = 0; i < ht->num_buckets; i++) {
		lrad_hash_entry_t *node;

		if (!ht->buckets[i]) continue;

		for (node = ht->buckets[i]; node != NULL; node = node->next) {
			rcode = callback(context, node->data);
			if (rcode != 0) return rcode;
		}
	}

	return 0;
}


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
uint32_t lrad_hash(const void *data, size_t size)
{
	const uint8_t *p = data;
	const uint8_t *q = p + size;
	uint32_t      hash = FNV_MAGIC_INIT;

	/*
	 *	FNV-1 hash each octet in the buffer
	 */
	while (p != q) {
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
		/*
		 *	XOR the 8-bit quantity into the bottom of
		 *	the hash.
		 */
		hash ^= (uint32_t) (*p++);
    }

    return hash;
}

/*
 *	Continue hashing data.
 */
uint32_t lrad_hash_update(const void *data, size_t size, uint32_t hash)
{
	const uint8_t *p = data;
	const uint8_t *q = p + size;

	while (p != q) {
		hash *= FNV_MAGIC_PRIME;
		hash ^= (uint32_t) (*p++);
    }

    return hash;

}

/*
 *	Return a "folded" hash, where the lower "bits" are the
 *	hash, and the upper bits are zero.
 *
 *	If you need a non-power-of-two hash, cope.
 */
uint32_t lrad_hash_fold(uint32_t hash, int bits)
{
	int count;
	uint32_t result;

	if ((bits <= 0) || (bits >= 32)) return hash;

	result = hash;

	/*
	 *	Never use the same bits twice in an xor.
	 */
	for (count = 0; count < 32; count += bits) {
		hash >>= bits;
		result ^= hash;
	}

	return result & (((uint32_t) (1 << bits)) - 1);
}


#ifdef TESTING
/*
 *  cc -DTESTING -I ../include/ hash.c -o hash
 *
 *  ./hash
 */

#include <stdio.h>
#include <stdlib.h>

#define MAX 8000
int main(int argc, char **argv)
{
	uint32_t i, *p, *q;
	lrad_hash_table_t *ht;

	ht = lrad_hash_table_create(10, free, 0);
	if (!ht) {
		fprintf(stderr, "Hash create failed\n");
		exit(1);
	}

	for (i = 0; i < MAX; i++) {
		p = malloc(sizeof(i));
		*p = i;
		if (!lrad_hash_table_insert(ht, i, p)) {
			fprintf(stderr, "Failed insert %08x\n", i);
			exit(1);
		}

		if (grow) {
			uint32_t j;

			for (j = 0; j < i; j++) {
				q = lrad_hash_table_finddata(ht, j);
				if (!q || (*q != j)) {
					fprintf(stderr, "BAD DATA %d %p\n",
						j, q);
					exit(1);
				}
			}
			grow = 0;
		}

		q = lrad_hash_table_finddata(ht, i);
		if (q != p) {
			fprintf(stderr, "Bad data %d\n", i);
			exit(1);
		}
	}

	for (i = 0; i < MAX; i++) {
		lrad_hash_table_delete(ht, i);
		q = lrad_hash_table_finddata(ht, i);
		if (q) {
			fprintf(stderr, "Failed to delete %08x\n", i);
			exit(1);
		}
	}

	lrad_hash_table_free(ht);

	exit(0);
}
#endif
