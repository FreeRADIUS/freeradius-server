/*
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
 */

/** Path-compressed prefix tries
 *
 * @file src/lib/util/trie.c
 *
 * @copyright 2017 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/trie.h>

#include <ctype.h>
#include <string.h>

/*
 *	This file implements path-compressed, level-compressed
 *	patricia tries.  The original research paper is:
 *
 *	https://www.nada.kth.se/~snilsson/publications/Dynamic-trie-compression-implementation/
 *
 *	The functionality has been extended to include intermediate
 *	nodes which consume 0 bits, but which hold user context data.
 *	These intermediate nodes allow for "longest prefix" matching.
 *	For example, in networking, you can have a routing table entry
 *	with 0/0 leading to one destination, and 10/8 leading to a
 *	different one.  Looking up an address in the 10/8 network will
 *	return the 10/8 destination.  Looking up any other address
 *	will return the default destination.
 *
 *	In addition, we desire the ability to add and delete nodes
 *	dynamically.  In the example given above, this means that
 *	after deleting 10/8, the trie should contain only the 0/0
 *	network and associated destination.
 *
 *	As of yet, it does not do level compression.  This can be
 *	added without (hopefully) too much work.  That would require
 *	an additional step to "normalize" the trie.
 *
 *	This code could be extended to do packet matching, through the
 *	inclusion of "don't care" paths.  e.g. parsing an IP header,
 *	where the src/dst IP addresses are 32-bit "don't care" fields.
 *
 *	It could also be extended via "count" paths, where the path
 *	holds a count that is used in another part of the trie.  For
 *	example, in RADIUS.  The attribute encoding is one byte
 *	attribute, one byte length, followed by "length - 2" bytes of
 *	data.  At that point though, you might as well just use Ragel.
 */

/** Enable path compression (or not)
 *
 *  With path compression, long sequences of bits are stored as a
 *  path, e.g. "abcdef".  Without path compression, we would have to
 *  create a large number of intermediate 2^N-way nodes, all of which
 *  would have only one edge.
 */
#ifndef NO_PATH_COMPRESSION
#define WITH_PATH_COMPRESSION
#endif

#define MAX_KEY_BYTES (256)
#define MAX_KEY_BITS (MAX_KEY_BYTES * 8)

#define DEFAULT_BITS (4)

/**  Internal sanity checks for debugging.
 *
 *  Tries are complex.  So we have verification routines for every
 *  type of node.  These routines are called from within the trie
 *  manipulation functions.  If the trie manipulation has a bug, the
 *  verification routines are likely to catch some of the more
 *  egregious issues.
 */
DIAG_OFF(unused-macros)
#ifdef TESTING
#  define MPRINT(...) fprintf(stderr, ## __VA_ARGS__)

   /* define this to be MPRINT for additional debugging */
#  define MPRINT2(...)
#else
#  define MPRINT(...)
#  define MPRINT2(...)
#endif

/*
 *	Macros to swap one for the other.
 */
#define	BITSOF(_x)	((_x) * 8)
#define BYTEOF(_x)	((_x) >> 3)
#define BYTES(_x)	(((_x) + 0x07) >> 3)
DIAG_ON(unused-macros)

// @todo - do level compression
// stop merging nodes if a key ends at the top of the level
// otherwise merge so we have at least 2^4 way fan-out, but no more than 2^8
// that should be a decent trade-off between memory and speed

// @todo - generalized function to normalize the trie.


/*
 *	Table of how many leading bits there are in KEY1^KEY2.
 */
static uint8_t xor2lcp[256] = {
	8, 7, 6, 6,
	5, 5, 5, 5,		/* 4x 5 */
	4, 4, 4, 4,		/* 8x 4 */
	4, 4, 4, 4,
	3, 3, 3, 3,		/* 16x 3 */
	3, 3, 3, 3,
	3, 3, 3, 3,
	3, 3, 3, 3,
	2, 2, 2, 2,		/* 32x 2 */
	2, 2, 2, 2,
	2, 2, 2, 2,
	2, 2, 2, 2,
	2, 2, 2, 2,
	2, 2, 2, 2,
	2, 2, 2, 2,
	2, 2, 2, 2,
	1, 1, 1, 1,		/* 64x 1 */
	1, 1, 1, 1,
	1, 1, 1, 1,
	1, 1, 1, 1,
	1, 1, 1, 1,
	1, 1, 1, 1,
	1, 1, 1, 1,
	1, 1, 1, 1,
	1, 1, 1, 1,
	1, 1, 1, 1,
	1, 1, 1, 1,
	1, 1, 1, 1,
	1, 1, 1, 1,
	1, 1, 1, 1,
	1, 1, 1, 1,
	1, 1, 1, 1,
	0, 0, 0, 0,		/* 128x 0 */
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
};


/*
 *  This table is used to set the "end bit" for LCP.  We OR in this
 *  value into the XOR of the two keys, and then look up the resulting
 *  value in the xor2lcp[] table above.  Setting the last bit to 1
 *  ensures that the LCP lookup is no more than (end_bit - start_bit)
 */
static uint8_t lcp_end_bit[9] = {
	0,			/* can't exist */
	0x40,
	0x20,
	0x10,
	0x08,
	0x04,
	0x02,
	0x01,
	0x00
};

#ifdef WITH_PATH_COMPRESSION
static uint8_t start_bit_mask[8] = {
	0xff, 0x7f, 0x3f, 0x1f,
	0x0f, 0x07, 0x03, 0x01
};
#endif

static uint8_t end_bit_mask[8] = {
	0x80, 0xc0, 0xe0, 0xf0,
	0xf8, 0xfc, 0xfe, 0xff,
};


/** Get the longest prefix of the two keys.
 *
 */
static int fr_trie_key_lcp(uint8_t const *key1, int keylen1, uint8_t const *key2, int keylen2, int start_bit)
{
	uint8_t xor;
	int i, bytes, lcp, end_bit, recheck;
	int s2, e2;
	int start_byte, end_byte;

	if (!keylen1 || !keylen2) return 0;
	fr_cond_assert((start_bit & 0x07) == start_bit);

	end_bit = keylen1;
	if (end_bit > keylen2) end_bit = keylen2;
	end_bit += start_bit;

	/*
	 *	Compare bits in the first byte
	 */
	lcp = 0;
	if ((start_bit != 0) || (end_bit <= 8)) {
		if (end_bit <= 8) {
			e2 = end_bit;
		} else {
			e2 = 8;
		}

		s2 = start_bit;
		fr_cond_assert(s2 <= e2);

		xor = key1[0] ^ key2[0];

		/*
		 *	Push the bits into the high bits,
		 *	and set the lowest bit which is possible
		 *	for the LCP.
		 */
		xor <<= s2;
		xor |= lcp_end_bit[e2 - s2];

		lcp = xor2lcp[xor];

		/*
		 *	We haven't found any common prefix, we're done.
		 */
		if (!lcp) return 0;

		/*
		 *	We only have one byte, and we've checked that.
		 *	Return the longest prefix.
		 */
		if (end_bit <= 8) {
			goto done;
		}

		/*
		 *	Skip the first byte, we've already checked it.
		 */
		start_byte = 1;
	} else {
		start_byte = 0;
	}

	/*
	 *	If the key ends on a byte boundary, check the last
	 *	byte.  Othewise, check all but the last byte.  We will
	 *	do a separate bit check for the last byte.
	 */
	end_byte = BYTEOF(end_bit);
	fr_cond_assert(start_byte <= end_byte);

	bytes = 0;

	/*
	 *	Compare the keys byte by byte.
	 */
	recheck = -1;
	for (i = start_byte; i < end_byte; i++) {
		if (key1[i] == key2[i]) {
			bytes++;
			continue;
		}

		recheck = i;
		break;
	}

	lcp += 8 * bytes;

	/*
	 *	Do we need to recheck the last byte?
	 */
	if (recheck < 0) {
		/*
		 *	Nope.  We're done.
		 */
		if ((end_bit & 0x07) == 0) goto done;

		recheck = BYTEOF(end_bit);
	}

	/*
	 *	We recheck starting at the recheck byte, and
	 *	continuing to the end of the keys.
	 */
	s2 = recheck * 8;
	e2 = end_bit;

	/*
	 *	If there are more than 8 bits to check, max out at the
	 *	bits in this byte (8).  Otherwise, just check the
	 *	remaining bits in this byte.
	 */
	if ((e2 - s2) > 8) {
		s2 = 0;
		e2 = 8;
	} else {
		fr_cond_assert(end_bit > s2);
		e2 = end_bit - s2;
		s2 = 0;
	}

	xor = key1[recheck] ^ key2[recheck];
	xor <<= s2;
	xor |= lcp_end_bit[e2 - s2];
	lcp += xor2lcp[xor];

done:
	fr_cond_assert(lcp <= keylen1);
	fr_cond_assert(lcp <= keylen2);
	return lcp;
}


//#define HEX_DUMP

#ifdef HEX_DUMP
static void hex_dump(FILE *fp, char const *msg, uint8_t const *key, int start_bit, int end_bit)
{
	int i;

	fprintf(fp, "%s\ts=%zd e=%zd\t\t", msg, start_bit, end_bit);

	for (i = 0; i < BYTES(end_bit); i++) {
		fprintf(fp, "%02x ", key[i]);
	}
	fprintf(fp, "\n");
}
#endif


/** Return a chunk of a key (in the low bits) for use in 2^N node de-indexing
 *
 */
static uint16_t get_chunk(uint8_t const *key, int num_bits, int start_bit, int end_bit)
{
	uint16_t chunk;

	fr_cond_assert(num_bits > 0);
	fr_cond_assert(num_bits <= 8);
	fr_cond_assert(start_bit < end_bit);

	/*
	 *	Load the byte
	 */
	chunk = key[BYTEOF(start_bit)];
	chunk <<= 8;

	if ((start_bit + 8) < end_bit) {
		chunk |= key[BYTEOF(start_bit) + 1];
	}

	/*
	 *	Shift out the bits at the start, that we don't
	 *	want.
	 */
	chunk <<= (start_bit & 0x07);

	/*
	 *	The bits we want are now all in the high bits
	 *	of "chunk".  But we only want some of them.
	 *
	 *	Shift the chunk so that the bits we want are now in
	 *	the low bits.
	 */
	chunk >>= 8 + (8 - num_bits);

	return chunk;
}

typedef enum fr_trie_type_t {
	FR_TRIE_INVALID = 0,
	FR_TRIE_USER,
	FR_TRIE_NODE,
#ifdef WITH_PATH_COMPRESSION
	FR_TRIE_PATH,
#endif
} fr_trie_type_t;

#ifdef TESTING
static int trie_number = 0;
#endif

struct fr_trie_t {
	fr_trie_type_t	type;
	fr_trie_t	*parent;
	int		bits;
#ifdef TESTING
	int		number;
#endif

	fr_trie_t	*trie;	/* only correct for USER */
};

typedef struct {
	fr_trie_type_t	type;
	fr_trie_t	*parent;
	int		bits;
#ifdef TESTING
	int		number;
#endif

	int		size;
	int		used;
	fr_trie_t	*trie[];
} fr_trie_node_t;

typedef struct {
	fr_trie_type_t	type;
	fr_trie_t	*parent;
	int		bits;
#ifdef TESTING
	int		number;
#endif

	fr_trie_t	*trie;
	void     	*data;
} fr_trie_user_t;

#ifdef WITH_PATH_COMPRESSION
typedef struct {
	fr_trie_type_t	type;
	fr_trie_t	*parent;
	int		bits;
#ifdef TESTING
	int		number;
#endif

	uint16_t	chunk;
	uint8_t		key[2];
	fr_trie_t	*trie;
} fr_trie_path_t;
#endif

/* @todo - compressed N-way nodes.  And then do linear search on the
 * indexes for matching.

4-way nodes when bits > 2 and used < 4
typedef struct {
	fr_trie_type_t	type;
	fr_trie_t	*parent;
	int		bits;
#ifdef TESTING
	int		number;
#endif


	int		used;
	uint8_t		index[4];
	fr_trie_t	*trie[4];
} fr_trie_4way_t;

4-way nodes when bits >= 4 and used < 16
typedef struct {
	fr_trie_type_t	type;
	fr_trie_t	*parent;
	int		bits;
#ifdef TESTING
	int		number;
#endif

	int		used;
	uint8_t		index[16];
	fr_trie_t	*trie[16];
} fr_trie_16way_t;
*/


static fr_trie_node_t *fr_trie_node_alloc(TALLOC_CTX *ctx, fr_trie_t *parent, int bits)
{
	fr_trie_node_t *node;
	int size;

	if (bits == 0) return NULL;
	if (bits > 8) return NULL;

	size = 1 << bits;

	node = (fr_trie_node_t *) talloc_zero_array(ctx, uint8_t, sizeof(fr_trie_node_t) + sizeof(node->trie[0]) * size);
	if (!node) return NULL;

	talloc_set_name_const(node, "fr_trie_node_t");
	node->type = FR_TRIE_NODE;
	node->parent = parent;
	node->bits = bits;
	node->size = size;

#ifdef TESTING
	node->number = trie_number++;
#endif
	return node;
}

/** Free a fr_trie_t
 *
 *  We can't use talloc_free(), because we need to reparent the nodes
 *  as we rearrange the tree.  And talloc_steal() is O(N).  So, we just recurse manually.
 */
static void fr_trie_free(fr_trie_t *trie)
{
	if (!trie) return;

	if (trie->type == FR_TRIE_USER) {
		fr_trie_user_t *user = (fr_trie_user_t *) trie;

		fr_trie_free(user->trie);
		talloc_free(user);
		return;
	}

	if (trie->type == FR_TRIE_NODE) {
		fr_trie_node_t *node = (fr_trie_node_t *) trie;
		int i;

		for (i = 0; i < node->size; i++) {
			if (!node->trie[i]) continue; /* save a function call in the common case */

			fr_trie_free(node->trie[i]);
		}

		talloc_free(node);
		return;
	}

#ifdef WITH_PATH_COMPRESSION
	if (trie->type == FR_TRIE_PATH) {
		fr_trie_path_t *path = (fr_trie_path_t *) trie;

		fr_trie_free(path->trie);
		talloc_free(path);
		return;
	}
#endif
}


static fr_trie_node_t *fr_trie_node_split(TALLOC_CTX *ctx, fr_trie_t *parent, fr_trie_node_t *node, int bits)
{
	fr_trie_node_t *split;
	int i, remaining_bits;

	if (node->type != FR_TRIE_NODE) return NULL;
	if ((bits == 0) || (bits >= node->bits)) {
		fr_strerror_printf("invalid value for split (%d / %d)", bits, node->bits);
		return NULL;
	}

	split = fr_trie_node_alloc(ctx, parent, bits);
	if (!split) return NULL;

	remaining_bits = node->bits - bits;

	/*
	 *	Allocate the children.  For now, just brute-force all
	 *	of the children.  We take a later pass at optimizing this.
	 */
	for (i = 0; i < (1 << bits); i++) {
		int j;
		fr_trie_node_t *child;

		child = fr_trie_node_alloc(ctx, parent, remaining_bits);
		if (!child) {
			fr_trie_free((fr_trie_t *) split);
			return NULL;
		}

		for (j = 0; j < (1 << remaining_bits); j++) {
			if (!node->trie[(i << remaining_bits) + j]) continue;

			child->trie[j] = node->trie[(i << remaining_bits) + j];
			child->trie[j]->parent = (fr_trie_t *) split;
			node->trie[(i << remaining_bits) + j] = NULL; /* so we don't free it when freeing 'node' */
			child->used++;
		}

		if (!child->used) {
			talloc_free(child); /* no children, so no need to recurse */
			continue;
		}

		split->trie[i] = (fr_trie_t *) child;
		split->used++;
	}

	/*
	 *	Note that we do NOT free "node".  The caller still
	 *	needs it for some activies.
	 */
	return split;
}

static fr_trie_user_t *fr_trie_user_alloc(TALLOC_CTX *ctx, fr_trie_t *parent, void *data)
{
	fr_trie_user_t *user;

	user = talloc_zero(ctx, fr_trie_user_t);
	if (!user) return NULL;

	user->type = FR_TRIE_USER;
	user->parent = parent;
	user->data = data;

#ifdef TESTING
	user->number = trie_number++;
#endif

	return user;
}

#ifdef WITH_PATH_COMPRESSION
static fr_trie_path_t *fr_trie_path_alloc(TALLOC_CTX *ctx, fr_trie_t *parent, uint8_t const *key, int start_bit, int end_bit)
{
	fr_trie_path_t *path;

	if (end_bit <= start_bit) {
		fr_strerror_printf("path asked for start >= end, %d >= %d", start_bit, end_bit);
		return NULL;
	}
	if ((end_bit - start_bit) > 8) {
		fr_strerror_printf("path asked for too many bits (%d)", end_bit - start_bit);
		return NULL;
	}

	/*
	 *	Normalize it so that the caller doesn't have to.
	 */
	if (start_bit > 7) {
		key += (start_bit >> 3);
		end_bit -= 8 * (start_bit >> 3);
		start_bit -= 8 * (start_bit >> 3);
	}

	path = talloc_zero(ctx, fr_trie_path_t);
	if (!path) return NULL;

	path->type = FR_TRIE_PATH;
	path->bits = end_bit - start_bit;
	path->parent = parent;
	path->chunk = get_chunk(key, path->bits, start_bit, end_bit);

	/*
	 *	Copy the key over, being sure to zero out unused bits
	 */
	path->key[0] = key[0] & start_bit_mask[start_bit];

	if (end_bit < 8) {
		path->key[0] &= end_bit_mask[end_bit];

	} else if ((end_bit > 8) && (end_bit < 16)) {
		path->key[1] = key[1] & end_bit_mask[end_bit & 0x03];
	}

#ifdef TESTING
	path->number = trie_number++;
#endif

	return path;
}

static fr_trie_path_t *fr_trie_path_split(TALLOC_CTX *ctx, fr_trie_t *parent, fr_trie_path_t *path, int start_bit, int lcp)
{
	fr_trie_path_t *split, *child;

	if ((lcp == 0) || (lcp > path->bits)) return NULL;

	start_bit &= 0x07;

	split = fr_trie_path_alloc(ctx, parent, &path->key[0], start_bit, start_bit + lcp);
	if (!split) {
		fr_strerror_printf("failed allocating path split at %d", __LINE__);
		return NULL;
	}

	child = fr_trie_path_alloc(ctx, (fr_trie_t *) split, &path->key[0], start_bit + lcp, start_bit + path->bits);
	if (!child) {
		fr_strerror_printf("failed allocating path child at %d", __LINE__);
		return NULL;
	}

	split->trie = (fr_trie_t *) child;
	child->trie = (fr_trie_t *) path->trie;

	talloc_free(path);
	return split;
}


static fr_trie_t *fr_trie_key_alloc(TALLOC_CTX *ctx, fr_trie_t *parent, uint8_t const *key, int start_bit, int end_bit, void *data)
{
	fr_trie_path_t *path;

	if (start_bit == end_bit) return (fr_trie_t *) fr_trie_user_alloc(ctx, parent, data);

	if (start_bit > end_bit) {
		fr_strerror_printf("key_alloc asked for start >= end, %d >= %d", start_bit, end_bit);
		return NULL;
	}

	if ((end_bit - start_bit) <= 8) {
		path = fr_trie_path_alloc(ctx, parent, key, start_bit, end_bit);
		if (!path) return NULL;

		path->trie = (fr_trie_t *) fr_trie_user_alloc(ctx, parent, data);
		return (fr_trie_t *) path;
	}

	path = fr_trie_path_alloc(ctx, parent, key, start_bit, start_bit + 8);
	if (!path) return NULL;

	path->trie = (fr_trie_t *) fr_trie_key_alloc(ctx, (fr_trie_t *) path, key, start_bit + 8, end_bit, data);
	if (!path->trie) {
		talloc_free(path); /* no children */
		return NULL;
	}

	return (fr_trie_t *) path;
}
#else  /* WITH_PATH_COMPRESSION */
static fr_trie_t *fr_trie_key_alloc(TALLOC_CTX *ctx, fr_trie_t *parent, uint8_t const *key, int start_bit, int end_bit, void *data)
{
	fr_trie_node_t *node;
	uint16_t chunk;
	int bits = DEFAULT_BITS;

	if (start_bit == end_bit) {
		return (fr_trie_t *) fr_trie_user_alloc(ctx, parent, data);
	}

	bits = end_bit - start_bit;
	if (bits > DEFAULT_BITS) bits = DEFAULT_BITS;

	node = fr_trie_node_alloc(ctx, parent, bits);
	if (!node) return NULL;

	chunk = get_chunk(key, node->bits, start_bit, end_bit);
	node->trie[chunk] = fr_trie_key_alloc(ctx, (fr_trie_t *) node, key, start_bit + node->bits, end_bit, data);
	if (!node->trie[chunk]) {
		talloc_free(node); /* no children */
		return NULL;
	}
	node->used++;

	return (fr_trie_t *) node;
}
#endif

/** Allocate a trie
 *
 * @param ctx The talloc ctx
 * @return
 *	- NULL on error
 *	- fr_trie_node_t on success
 */
fr_trie_t *fr_trie_alloc(TALLOC_CTX *ctx)
{
	/*
	 *	The trie itself is just a user node with user data that is the talloc ctx
	 */
	return (fr_trie_t *) fr_trie_user_alloc(ctx, NULL, ctx);
}

/** Match a key in a trie and return user ctx, if any
 *
 *  The key may be LONGER than entries in the trie.  In which case the
 *  closest match is returned.
 *
 * @param trie	 	the trie
 * @param key	 	the key
 * @param start_bit	the start bit
 * @param end_bit	the end bit
 * @param exact  	do we return an exact match, or the shortest one.
 * @return
 *	- NULL on not found
 *	- void* user ctx on found
 */
static void *fr_trie_key_match(fr_trie_t *trie, uint8_t const *key, int start_bit, int end_bit, bool exact)
{
	void *data = NULL;

	if (!trie) return NULL;

	/*
	 *	We've run out of trie, so it's not a match.
	 */
	if ((start_bit + trie->bits) > end_bit) {
		MPRINT2("%d + %d = %d > %d\n",
		       start_bit, trie->bits, start_bit + trie->bits, end_bit);
#ifdef TESTING
		MPRINT2("no match for key too short for trie NODE-%d at %d\n", trie->number, __LINE__);
#endif
		return NULL;
	}

	if (trie->type == FR_TRIE_USER) {
		fr_trie_user_t *user = (fr_trie_user_t *) trie;

		/*
		 *	We've matched the input exactly.  Return the
		 *	user data.
		 */
		if (start_bit == end_bit) return user->data;

		/*
		 *	We're not at the end of the input.  Go find a
		 *	deeper match.  If a match is found, return
		 *	that.
		 */
		data = fr_trie_key_match(user->trie, key, start_bit, end_bit, exact);
		if (data) return data;

		/*
		 *	We didn't find anything deeper in the trie,
		 *	AND we require an exact match.  That's a
		 *	failure.
		 */
		if (exact) {
			MPRINT2("no exact match at %d\n", __LINE__);
			return NULL;
		}

		/*
		 *	Return the closest (i.e. inexact) match.
		 */
		return user->data;
	}

	if (trie->type == FR_TRIE_NODE) {
		uint16_t chunk;
		fr_trie_node_t *node = (fr_trie_node_t *) trie;

		chunk = get_chunk(key, node->bits, start_bit, end_bit);
		if (!node->trie[chunk]) {
			MPRINT2("no match for node chunk %02x at %d\n", chunk, __LINE__);
			return NULL;
		}

		return fr_trie_key_match(node->trie[chunk], key, start_bit + node->bits, end_bit, exact);
	}

#ifdef WITH_PATH_COMPRESSION
	if (trie->type == FR_TRIE_PATH) {
		uint16_t chunk;
		fr_trie_path_t *path = (fr_trie_path_t *) trie;

		chunk = get_chunk(key, path->bits, start_bit, end_bit);
		if (chunk != path->chunk) return NULL;

		return fr_trie_key_match(path->trie, key, start_bit + path->bits, end_bit, exact);
	}
#endif

	fr_strerror_printf("unknown trie type %d in match", trie->type);
	return NULL;
}


/** Insert a binary key into the trie
 *
 *  The key must have at least ((start_bit + keylen) >> 3) bytes
 *
 * @param ctx		the talloc ctx
 * @param parent	the parent trie
 * @param[in,out] trie_p the trie where things are inserted
 * @param key		the binary key
 * @param start_bit	the start bit
 * @param end_bit	the end bit
 * @param data		user data to insert
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int fr_trie_key_insert(TALLOC_CTX *ctx, fr_trie_t *parent, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit, void *data)
{
	fr_trie_t *trie = *trie_p;

	/*
	 *	We've reached the end of the trie, but may still have
	 *	key bits to insert.
	 */
	if (!trie) {
		*trie_p = fr_trie_key_alloc(ctx, parent, key, start_bit, end_bit, data);
		if (!*trie_p) {
			MPRINT("Failed key_alloc at %d\n", __LINE__);
			return -1;
		}

		return 0;
	}

	if (trie->type == FR_TRIE_USER) {
		fr_trie_user_t *user = (fr_trie_user_t *) trie;

		/*
		 *	We're supposed to insert it here, but there's
		 *	already user data.  That's an error.
		 */
		if (start_bit == end_bit) {
			MPRINT("already has a user node at %d\n", __LINE__);
			return -1;
		}

		/*
		 *	This is in normal form already.  Don't change
		 *	it.
		 */
		if (fr_trie_key_insert(ctx, (fr_trie_t *) user, &user->trie, key, start_bit, end_bit, data) < 0) {
			MPRINT("failed key_insert at %d\n", __LINE__);
			return -1;
		}

		return 0;
	}

	/*
	 *	We've reached the end of the key.  Insert a user node
	 *	here.
	 */
	if (start_bit == end_bit) {
		fr_trie_user_t *user;

		user = fr_trie_user_alloc(ctx, parent, data);
		if (!user) return -1;

		user->trie = trie;
		trie->parent = (fr_trie_t *) user;
		*trie_p = (fr_trie_t *) user;
		return 0;
	}

	if (trie->type == FR_TRIE_NODE) {
		fr_trie_node_t *node = (fr_trie_node_t *) trie;
		fr_trie_t *trie_to_free = NULL;
		uint32_t chunk;

		/*
		 *	The current node is longer than the input bits
		 *	for the key.  Split the node into a smaller
		 *	N-way node, and insert the key into the (now
		 *	fitting) node.
		 */
		if ((start_bit + node->bits) > end_bit) {
			fr_trie_node_t *split;

			split = fr_trie_node_split(ctx, parent, node, (start_bit + node->bits) - end_bit);
			if (!split) {
				MPRINT("Failed splitting node at %d\n", __LINE__);
				return -1;
			}

			trie_to_free = (fr_trie_t *) node;
			node = split;
		}

		chunk = get_chunk(key, node->bits, start_bit, end_bit);

		/*
		 *	The current node exactly fits the key bits.
		 */
		if ((start_bit + node->bits == end_bit)) {
			fr_trie_user_t *user;

			/*
			 *	No existing trie, create a brand new
			 *	user node from the key.
			 */
			if (!node->trie[chunk]) {
				node->trie[chunk] = (fr_trie_t *) fr_trie_user_alloc(ctx, (fr_trie_t *) node, data);

			add_new:
				node->used++;
			done_set:
				if (trie_to_free) fr_trie_free(trie_to_free);
				*trie_p = (fr_trie_t *) node;
				return 0;
			}

			/*
			 *	Can't insert user data on top of user
			 *	data.
			 */
			if (node->trie[chunk]->type == FR_TRIE_USER) {
				MPRINT("already has a user node at %d\n", __LINE__);

			fail:
				if (trie_to_free) fr_trie_free(trie_to_free);
				return -1;
			}

			/*
			 *	Otherwise there is already a trie at
			 *	the end of the key, so there's another
			 *	key which is longer.  Just create a
			 *	user node and wedge it into place.
			 */
			user = fr_trie_user_alloc(ctx, (fr_trie_t *) node, data);
			if (!user) {
				MPRINT("Failed user_alloc at %d\n", __LINE__);
				goto fail;
			}

			/*
			 *	Add the existing trie *after* the new
			 *	user data.  We do this by just
			 *	rearranging the trie.
			 */
			user->trie = node->trie[chunk];
			user->trie->parent = (fr_trie_t *) user;
			node->trie[chunk] = (fr_trie_t *) user;
			goto done_set;
		}

		/*
		 *	The current node is all within the key bits.
		 */
		// assert ((start_bit + node->bits) < end_bit)

		/*
		 *	No existing trie, create a brand new trie from
		 *	the key.
		 */
		if (!node->trie[chunk]) {
			node->trie[chunk] = fr_trie_key_alloc(ctx, (fr_trie_t *) node, key, start_bit + node->bits, end_bit, data);
			if (!node->trie[chunk]) {
				MPRINT("Failed key_alloc at %d\n", __LINE__);
				goto fail;
			}
			goto add_new;
		}

		/*
		 *	Recurse in order to insert the key
		 *	into the current node.
		 */
		if (fr_trie_key_insert(ctx, (fr_trie_t *) node, &node->trie[chunk], key, start_bit + node->bits, end_bit, data) < 0) {
			MPRINT("Failed recursing at %d\n", __LINE__);
			goto fail;
		}

		goto done_set;
	}

#ifdef WITH_PATH_COMPRESSION
	if (trie->type == FR_TRIE_PATH) {
		fr_trie_path_t *path = (fr_trie_path_t *) trie;
		uint32_t chunk;
		int lcp, bits;
		uint8_t const *key2;
		int start_bit2;
		fr_trie_node_t *node;

		bits = path->bits;

		if ((start_bit + bits) > end_bit) {
			/*
			 *	Limit the number of bits we check to
			 *	the number of bits left in the key.
			 */
			bits = end_bit - start_bit;
			MPRINT2("forcing bits %d\n", bits);

		} else {	/* the key is equal in length to, or longer than the path */
			chunk = get_chunk(key, path->bits, start_bit, end_bit);

			/*
			 *	The chunk matches exactly.  Recurse to
			 *	insert the key into the child trie.
			 */
			if (chunk == path->chunk) {
				if (fr_trie_key_insert(ctx, (fr_trie_t *) path, &path->trie, key, start_bit + path->bits, end_bit, data) < 0) {
					MPRINT("failed key insert at %d\n", __LINE__);
					return -1;
				}

				return 0;
			}
		}

		/*
		 *	Figure out what part of the key we need to
		 *	look at for LCP.
		 */
		key2 = key;
		start_bit2 = start_bit;
		if (start_bit2 > 7) {
			key2 += (start_bit2 >> 3);
			start_bit2 -= 8 * (start_bit2 >> 3);
		}

		/*
		 *	Get the LCP.  If we have one, split the path
		 *	node at the LCP.  Replace the parent with the
		 *	first half of the path, and build an N-way
		 *	node for the second half.
		 */
		lcp = fr_trie_key_lcp(&path->key[0], bits, key2, bits, start_bit2);

		/*
		 *	This should have been caught above.
		 */
		if (lcp == path->bits) {
			fr_strerror_printf("found lcp which should have been previously found");
			return -1;
		}

		if (lcp > 0) {
			fr_trie_path_t *split;

			MPRINT2("splitting path length %d at lcp %d\n",
			       path->bits, lcp);

			split = fr_trie_path_split(ctx, parent, path, start_bit2, lcp);
			if (!split) {
				MPRINT("failed path split at %d\n", __LINE__);
				return -1;
			}

			/*
			 *	Swap out the original path with our
			 *	new one.  And update the various
			 *	pointers to the new locations.
			 */
			parent = (fr_trie_t *) split;
			*trie_p = parent;
			path = (fr_trie_path_t *) split->trie;
			trie_p = &split->trie;

			start_bit += lcp;
			bits -= lcp;

			/*
			 *	We've split "path" into two, and have
			 *	reached the end of the key.  Just
			 *	insert a user node.
			 */
			if (start_bit == end_bit) {
				if (fr_trie_key_insert(ctx, parent, trie_p, key, start_bit, end_bit, data) < 0) {
					MPRINT("failed key insert at %d\n", __LINE__);
					return -1;
				}

				return 0;
			}

			/* else start_bit < end_bit */
		}

		/*
		 *	Else there's no common prefix.  Just create an
		 *	N-way node.
		 */
		if (bits > DEFAULT_BITS) bits = DEFAULT_BITS;

		MPRINT2("path key alloc after split bits %d, start=%d end %d \n", bits, start_bit, end_bit);

		node = fr_trie_node_alloc(ctx, parent, bits);
		if (!node) return -1; /* @todo - don't leave "path" split in two */

		chunk = get_chunk(key, node->bits, start_bit, end_bit);
		node->trie[chunk] = fr_trie_key_alloc(ctx, (fr_trie_t *) node, key, start_bit + node->bits, end_bit, data);
		if (!node->trie[chunk]) {
			MPRINT("Failed key_alloc at %d\n", __LINE__);
			return -1;
		}
		node->used++;

		/*
		 *	We may have to split "path" *again*.
		 */
		if (node->bits == path->bits) {
			if (node->trie[path->chunk]) {
				MPRINT("False duplicate in insert at %d\n", __LINE__);
				fr_trie_free((fr_trie_t *) node);
				return -1;
			}

			node->trie[path->chunk] = path->trie;
			node->used++;

			path->trie->parent = (fr_trie_t *) node;
			talloc_free(path);
			*trie_p = (fr_trie_t *) node;
			return 0;
		}

		fr_strerror_printf("logic not implemented for path in key_insert");
		return -1;
	}
#endif

	fr_strerror_printf("unknown trie type %d in key_insert", trie->type);
	return -1;
}

/** Insert a key and user ctx into a trie
 *
 * @param ft	 the trie
 * @param key	 the key
 * @param keylen key length in bits
 * @param data	 user ctx information to associated with the key
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_trie_insert(fr_trie_t *ft, void const *key, size_t keylen, void const *data)
{
	void *my_data;
	fr_trie_user_t *user;

	if (keylen > MAX_KEY_BITS) {
		fr_strerror_printf("keylen too long (%u > %d)", (unsigned int) keylen, MAX_KEY_BITS);
		return -1;
	}

	/*
	 *	Do a lookup before insertion.  If we tried to insert
	 *	the key with new nodes and then discovered a conflict,
	 *	we would not be able to undo the process.  This check
	 *	ensures that the insertion can modify the trie in
	 *	place without worry.
	 */
	if (fr_trie_key_match(ft->trie, key, 0, keylen, true) != NULL) {
		MPRINT2("already matches at %d\n", __LINE__);
		return -1;
	}

	memcpy(&my_data, &data, sizeof(data)); /* const issues */
	MPRINT2("No match for data, inserting...\n");

	user = (fr_trie_user_t *) ft;

	if (fr_trie_key_insert(user->data, ft, &ft->trie, key, 0, keylen, my_data) < 0) {
		MPRINT("failed key_insert at %d\n", __LINE__);
		return -1;
	}

	return 0;
}

/** Remove a key from a trie, and return the user data.
 *
 */
static void *fr_trie_key_remove(TALLOC_CTX *ctx, fr_trie_t *parent, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit)
{
	fr_trie_t *trie = *trie_p;
	void *data;

	if (!trie) return NULL;

	/*
	 *	We can't remove a key which is shorter than the
	 *	current trie.
	 */
	if ((start_bit + trie->bits) > end_bit) return NULL;

	if (trie->type == FR_TRIE_USER) {
		fr_trie_user_t *user = (fr_trie_user_t *) trie;

		/*
		 *	We're at the end of the key, return the data
		 *	given here, and free the node that we're
		 *	removing.
		 */
		if (start_bit == end_bit) {
			data = user->data;

			*trie_p = user->trie;
			if (user->trie) user->trie->parent = parent;
			talloc_free(user); /* child has been reparented */

			// @todo - normalize "parent"
			return data;
		}

		return fr_trie_key_remove(ctx, (fr_trie_t *) user, &user->trie, key, start_bit, end_bit);
	}

	if (trie->type == FR_TRIE_NODE) {
		fr_trie_node_t *node = (fr_trie_node_t *) trie;
		uint32_t chunk;

		chunk = get_chunk(key, node->bits, start_bit, end_bit);
		if (!node->trie[chunk]) return NULL;

		data = fr_trie_key_remove(ctx, (fr_trie_t *) node, &node->trie[chunk], key, start_bit + node->bits, end_bit);
		if (!data) return NULL;

		/*
		 *	The trie still has a subtrie.  Just return the data.
		 */
		if (node->trie[chunk]) return data;

		/*
		 *	One less used edge.
		 */
		node->used--;
		if (node->used > 0) return data;

		/*
		 *	Our entire node is empty.  Delete it as we walk back up the trie.
		 */
		*trie_p = NULL;
		talloc_free(node); /* no children */
		return data;
	}

#ifdef WITH_PATH_COMPRESSION
	if (trie->type == FR_TRIE_PATH) {
		fr_trie_path_t *path = (fr_trie_path_t *) trie;
		uint32_t chunk;

		chunk = get_chunk(key, path->bits, start_bit, end_bit);

		/*
		 *	No match, can't remove it.
		 */
		if (path->chunk != chunk) return NULL;

		data = fr_trie_key_remove(ctx, (fr_trie_t *) path, &path->trie, key, start_bit + path->bits, end_bit);
		if (!data) return NULL;

		/*
		 *	The trie still has a subtrie.  Just return the data.
		 */
		if (path->trie) return data;

		/*
		 *	Our entire path is empty.  Delete it as we walk back up the trie.
		 */
		*trie_p = NULL;
		talloc_free(path); /* no children */
		return data;
	}
#endif

	return NULL;
}

/** Remove a key and return the associated user ctx
 *
 *  The key must match EXACTLY.  This is not a prefix match.
 *
 * @param ft	 the trie
 * @param key	 the key
 * @param keylen key length in bits
 * @return
 *	- NULL on not found
 *	- user ctx data on success
 */
void *fr_trie_remove(fr_trie_t *ft, void const *key, size_t keylen)
{
	fr_trie_user_t *user;

	if (keylen > MAX_KEY_BITS) return NULL;

	if (!ft->trie) return NULL;

	user = (fr_trie_user_t *) ft->trie;

	return fr_trie_key_remove(user->data, ft, &ft->trie, key, 0, (int) keylen);
}

/** Lookup a key in a trie and return user ctx, if any
 *
 *  The key may be LONGER than entries in the trie.  In which case the
 *  closest match is returned.
 *
 * @param ft	 the trie
 * @param key	 the key bytes
 * @param keylen length in bits of the key
 * @return
 *	- NULL on not found
 *	- void* user ctx on found
 */
void *fr_trie_lookup(fr_trie_t const *ft, void const *key, size_t keylen)
{
	if (keylen > MAX_KEY_BITS) return NULL;

	if (!ft->trie) return NULL;

	return fr_trie_key_match(ft->trie, key, 0, keylen, false);
}

/** Match a key and length in a trie and return user ctx, if any
 *
 * Only the exact match is returned.
 *
 * @param ft	 the trie
 * @param key	 the key bytes
 * @param keylen length in bits of the key
 * @return
 *	- NULL on not found
 *	- void* user ctx on found
 */
void *fr_trie_match(fr_trie_t const *ft, void const *key, size_t keylen)
{
	if (keylen > MAX_KEY_BITS) return NULL;

	if (!ft->trie) return NULL;

	return fr_trie_key_match(ft->trie, key, 0, keylen, true);
}

typedef struct fr_trie_callback_t fr_trie_callback_t;

typedef int (*fr_trie_key_walk_t)(void *trie, fr_trie_callback_t *cb, int depth, bool more);

struct fr_trie_callback_t {
	fr_trie_t	*ft;

	uint8_t		*start;
	uint8_t const	*end;

	void			*ctx;

	fr_trie_key_walk_t	callback;
	fr_trie_walk_t		user_callback;
};

static int fr_trie_key_walk(fr_trie_t *trie, fr_trie_callback_t *cb, int depth, bool more)
{
	int i, used;
	int bits_used;
	uint8_t *out, out_0;
	fr_trie_node_t *node;

	/*
	 *	Do the callback before anything else.
	 */
	if (cb->callback(trie, cb, depth, more) < 0) return -1;

	/*
	 *	Nothing more to do, return.
	 */
	if (!trie) {
		fr_cond_assert(depth == 0);
		return 0;
	}

	/*
	 *	No more buffer space, stop.
	 */
	if ((cb->start + BYTEOF(depth + trie->bits + 8)) >= cb->end) return 0;

	/*
	 *	User ctx data.  Recurse (if necessary) for any
	 *	subtrie.
	 */
	if (trie->type == FR_TRIE_USER) {
		fr_trie_user_t *user = (fr_trie_user_t *) trie;

		if (!user->trie) return 0; /* shouldn't happen */

//		MPRINT("Recursing into user at depth %d\n", depth);
		return fr_trie_key_walk(user->trie, cb, depth, more);
	}

	/*
	 *	Bits used in the last byte.
	 */
	bits_used = depth & 0x07;

	/*
	 *	Where we're writing the output string.
	 */
	out = cb->start + BYTEOF(depth);

	/*
	 *	Mask out the low bits.  They may have been written to
	 *	in a previous invocation of the function.
	 */
	if (bits_used > 0) {
		out[0] &= end_bit_mask[bits_used];
	} else {
		out[0] = 0;
	}

#ifdef WITH_PATH_COMPRESSION
	/*
	 *	Copy the path over.  By bytes if possible, otherwise
	 *	by bits.
	 */
	if (trie->type == FR_TRIE_PATH) {
		fr_trie_path_t *path = (fr_trie_path_t *) trie;

		out[0] |= path->key[0];
		if (BYTEOF(depth) != BYTEOF(depth + path->bits)) {
			out[1] = path->key[1];
		}

//		MPRINT("Recursing into path length %d at depth %d\n", path->bits, depth);
		return fr_trie_key_walk(path->trie, cb, depth + path->bits, more);
	}
#endif

	node = (fr_trie_node_t *) trie;

	/*
	 *	Track when we're done, and remember the output byte at
	 *	the start.
	 */
	used = 0;
	out_0 = out[0];

	for (i = 0; i < node->size; i++) {
		uint16_t chunk;

		/*
		 *	Nothing on this terminal node, skip it.
		 */
		if (!node->trie[i]) continue;

		/*
		 *	Get the bits we need, OR in the previous data,
		 *	and write it to the output buffer.
		 */
		chunk = i;	/* node->size bits are used here */

#if 0
		MPRINT("Recursing into node length %d chunk %04x bit_used %d out = %02x%02x at depth %d\n",
		       node->bits, chunk, bits_used, out_0, out[1], depth);
#endif

		chunk <<= (16 - node->bits - bits_used);

		out[0] = out_0 | (chunk >> 8);
		out[1] = chunk & 0xff;

		used++;

		if (fr_trie_key_walk(node->trie[i], cb, depth + node->bits,
				     more || (used < node->used)) < 0) {
			return -1;
		}
	}

	return 0;
}

#ifdef TESTING
/** Dump a trie edge in canonical form.
 *
 */
static void fr_trie_dump_edge(FILE *fp, fr_trie_t *trie)
{
	if (trie->type == FR_TRIE_USER) {
		fr_trie_user_t *user = (fr_trie_user_t *) trie;

		fprintf(fp, "NODE-%d\n", user->number);
		return;
	}

	if (trie->type == FR_TRIE_NODE) {
		fr_trie_node_t *node = (fr_trie_node_t *) trie;

		fprintf(fp, "NODE-%d\n", node->number);
		return;
	}

#ifdef WITH_PATH_COMPRESSION
	if (trie->type == FR_TRIE_PATH) {
		fr_trie_path_t *path = (fr_trie_path_t *) trie;

		fprintf(fp, "NODE-%d\n", path->number);
		return;
	}
#endif

	fprintf(fp, "NODE-???");
}


/**  Dump the trie nodes
 *
 */
static int fr_trie_dump_cb(void *ctx, fr_trie_callback_t *cb, int keylen, UNUSED bool more)
{
	int i, bytes;
	FILE *fp = cb->ctx;
	fr_trie_node_t *node;
	fr_trie_t *trie = ctx;

	if (!trie) return 0;

	bytes = BYTES(keylen);

	if (trie->type == FR_TRIE_USER) {
		fr_trie_user_t *user = (fr_trie_user_t *) trie;

		fprintf(fp, "{ NODE-%d\n", user->number);
		fprintf(fp, "\ttype\tUSER\n");
		fprintf(fp, "\tinput\t{%d}%.*s\n", keylen, bytes, cb->start);

		fprintf(fp, "\tdata\t\"%s\"\n", (char const *) user->data);
		if (!user->trie) {
			fprintf(fp, "}\n\n");
			return 0;
		}

		fprintf(fp, "\tnext\t");
		fr_trie_dump_edge(fp, user->trie);
		fprintf(fp, "}\n\n");
		return 0;
	}

#ifdef WITH_PATH_COMPRESSION
	if (trie->type == FR_TRIE_PATH) {
		fr_trie_path_t *path = (fr_trie_path_t *) trie;
		fprintf(fp, "{ NODE-%d\n", path->number);
		fprintf(fp, "\ttype\tPATH\n");
		fprintf(fp, "\tinput\t{%d}%.*s\n", keylen, bytes, cb->start);

		fprintf(fp, "\tbits\t%d\n", (int) path->bits);
		fprintf(fp, "\tpath\t");

		fprintf(fp, "%02x %02x", path->key[0], path->key[1]);

		fprintf(fp, "\n");

		fprintf(fp, "\tnext\t");
		fr_trie_dump_edge(fp, path->trie);

		fprintf(fp, "}\n\n");
		return 0;
	}
#endif


	node = (fr_trie_node_t *) trie;

	fprintf(fp, "{ NODE-%d\n", node->number);
	fprintf(fp, "\ttype\tNODE\n");
	fprintf(fp, "\tinput\t{%d}%.*s\n", keylen, bytes, cb->start);

	fprintf(fp, "\tbits\t%d\n", node->bits);
	fprintf(fp, "\tused\t%d\n", node->used);

	for (i = 0; i < (1 << node->bits); i++) {
		if (!node->trie[i]) continue;

		fprintf(fp, "\t%02x\t", (int) i);
		fr_trie_dump_edge(fp, node->trie[i]);
	}
	fprintf(fp, "}\n\n");

	return 0;
}

/**  Print the strings accepted by a trie to a file
 *
 */
static int fr_trie_print_cb(void *ctx, fr_trie_callback_t *cb, int keylen, UNUSED bool more)
{
	int bytes;
	FILE *fp = cb->ctx;
	fr_trie_user_t *user;
	fr_trie_t *trie = ctx;

	if (!trie || (trie->type != FR_TRIE_USER)) {
		return 0;
	}

	bytes = BYTES(keylen);
	user = (fr_trie_user_t *) trie;

	if ((keylen & 0x07) != 0) {
		fprintf(fp, "{%d}%.*s\t%s\n", keylen, bytes, cb->start, (char const *) user->data);
	} else {
		fprintf(fp, "%.*s\t%s\n", bytes, cb->start, (char const *) user->data);
	}

	return 0;
}
#endif	/* TESTING */


/**  Implement the user-visible side of the walk callback.
 *
 */
static int fr_trie_user_cb(void *trie, fr_trie_callback_t *cb, int keylen, UNUSED bool more)
{
	fr_trie_user_t *user;
	void *data;

	if (!trie) return 0;

	user = (fr_trie_user_t *) trie;
	if (user->type != FR_TRIE_USER) return 0;

	memcpy(&data, &user->data, sizeof(data)); /* const issues */

	if (cb->user_callback(cb->ctx, cb->start, keylen, data) < 0) {
		return -1;
	}

	return 0;
}

int fr_trie_walk(fr_trie_t *ft, void *ctx, fr_trie_walk_t callback)
{
	fr_trie_callback_t my_cb;
	uint8_t buffer[MAX_KEY_BYTES + 1];

	my_cb.ft = ft;
	my_cb.start = buffer;
	my_cb.end = buffer + sizeof(buffer);
	my_cb.callback = fr_trie_user_cb;
	my_cb.user_callback = callback;
	my_cb.ctx = ctx;

	memset(buffer, 0, sizeof(buffer));

	/*
	 *	Call the internal walk function to do the work.
	 */
	return fr_trie_key_walk(ft->trie, &my_cb, 0, false);
}

#ifdef TESTING
static bool print_lineno = false;

typedef struct {
	char	*start;
	char	*buffer;
	size_t	buflen;
} fr_trie_sprint_ctx_t;


/**  Print the strings accepted by a trie to one line
 */
static int fr_trie_sprint_cb(void *trie_ctx, fr_trie_callback_t *cb, int keylen, bool more)
{
	int bytes, len;
	fr_trie_sprint_ctx_t *ctx;
	fr_trie_user_t *user;
	fr_trie_t *trie = trie_ctx;

	ctx = cb->ctx;

	if (!trie) {
		len = snprintf(ctx->buffer, ctx->buflen, "{}");
		goto done;
	}

	if (trie->type != FR_TRIE_USER) return 0;

	bytes = BYTES(keylen);
	user = (fr_trie_user_t *) trie;

	if (!user->trie && !more) {
		len = snprintf(ctx->buffer, ctx->buflen, "%.*s=%s",
				bytes, cb->start, (char const *) user->data);
	} else {
		len = snprintf(ctx->buffer, ctx->buflen, "%.*s=%s,",
			       bytes, cb->start, (char const *) user->data);
	}

done:
	ctx->buffer += len;
	ctx->buflen -= len;

	return 0;
}


/**  Parse a string into bits + key
 *
 *  The format is one of:
 *
 *	- string such as "abcdef"
 *	- string prefixed with a bit length, {4}a
 */
static int arg2key(char *arg, char **key, int *length)
{
	char *p;
	int bits, size;

	if (*arg != '{') {
		*key = arg;
		*length = BITSOF(strlen(arg));
		return 0;
	}

	p = strchr(arg, '}');
	if (!p) {
		MPRINT("Failed to find end '}' for {bits}\n");
		return -1;
	}

	bits = BITSOF(strlen(p + 1));
	if (!bits) {
		MPRINT("No key found in in '%s'\n", arg);
		return -1;
	}

	size = atoi(arg + 1);	/* ignore end character... */
	if (size > bits) {
		MPRINT("Length '%d' is longer than bits in key %s",
			size, p + 1);
	}

	*key = p + 1;
	*length = size;

	return 0;
}

/**  Our TALLOC_CTX for the data we put into the trie.
 *
 *  Most people don't need to do this, they can just insert their own
 *  data.
 */
static void *data_ctx = NULL;

/**  Insert a key + data into a trie.
 *
 */
static int command_insert(fr_trie_t *ft, UNUSED int argc, char **argv, UNUSED char *out, UNUSED size_t outlen)
{
	int bits;
	void *answer, *data;
	char *key;

	if (arg2key(argv[0], &key, &bits) < 0) {
		return -1;
	}

	/*
	 *	This has to stick around in between command
	 *	invocations.
	 */
	data = talloc_strdup(data_ctx, argv[1]);
	if (!data) {
		MPRINT("OOM\n");
		return -1;
	}

	if (fr_trie_insert(ft, key, bits, data) < 0) {
		MPRINT("Failed inserting key %s=%s\n", key, argv[1]);
		return -1;
	}

	answer = fr_trie_key_match(ft->trie, (uint8_t *) key, 0, bits, true);
	if (!answer) {
		MPRINT("Could not match key %s bits %d\n", key, bits);
		return -1;
	}

	if (answer != data) {
		MPRINT("Inserted %s, but looked up %s\n", argv[1], (char const *) answer);
		return -1;
	}

	return 0;
}

/**  Verify a trie recursively
 *
 *  For sanity reasons, this command runs but doesn't do anything if
 *  the code is built with no trie verification.
 */
static int command_verify(fr_trie_t *ft, UNUSED int argc, UNUSED char **argv, UNUSED char *out, UNUSED size_t outlen)
{
	fr_cond_assert(ft != NULL);

	// @todo - verify the trie...

	return 0;
}

/** Print the keys accepted by a trie
 *
 *  The strings are printed to stdout.
 *
 *  @todo - allow printing to a file.
 */
static int command_keys(fr_trie_t *ft, UNUSED int argc, UNUSED char **argv, char *out, size_t outlen)
{
	fr_trie_callback_t my_cb;

	my_cb.ft = ft;
	my_cb.start = (uint8_t *) out;
	my_cb.end = (uint8_t *) (out + outlen);
	my_cb.callback = fr_trie_print_cb;
	my_cb.user_callback = NULL;
	my_cb.ctx = stdout;

	/*
	 *	Call the internal walk function to do the work.
	 */
	return fr_trie_key_walk(ft->trie, &my_cb, 0, false);
}


/** Dump the trie in internal format
 *
 *  The information is printed to stdout.
 *
 *  For sanity reasons, this command runs but doesn't do anything if
 *  the code is built with no trie dumping.
 *
 *  @todo - allow printing to a file.
 */
static int command_dump(fr_trie_t *ft, UNUSED int argc, UNUSED char **argv, char *out, size_t outlen)
{
	fr_trie_callback_t my_cb;

	my_cb.ft = ft;
	my_cb.start = (uint8_t *) out;
	my_cb.end = (uint8_t *) (out + outlen);
	my_cb.callback = fr_trie_dump_cb;
	my_cb.user_callback = NULL;
	my_cb.ctx = stdout;

	/*
	 *	Call the internal walk function to do the work.
	 */
	return fr_trie_key_walk(ft->trie, &my_cb, 0, false);
}


/**  Clear the entire trie without caring what's in it.
 *
 */
static int command_clear(fr_trie_t *ft, UNUSED int argc, UNUSED char **argv, UNUSED char *out, UNUSED size_t outlen)
{
	if (!ft->trie) return 0;

	fr_trie_free(ft->trie);
	ft->trie = NULL;

	/*
	 *	Clean up our internal data ctx, too.
	 */
	talloc_free(data_ctx);
	data_ctx = talloc_init("data_ctx");

	return 0;
}


/**  Turn on line number debugging.
 *
 *  @todo - add general "debug" functionality.
 */
static int command_lineno(UNUSED fr_trie_t *ft, UNUSED int argc, char **argv, UNUSED char *out, UNUSED size_t outlen)
{
	if (strcmp(argv[0], "true") == 0) {
		print_lineno = true;
	} else {
		print_lineno = false;
	}

	return 0;
}


/**  Match an exact key + length
 *
 *  Normally, the "lookup" returns the longest prefix match, so that
 *  *long* key lookups can return *short* matches.
 *
 *  In some cases, we want to know if an exact key is in the trie.
 *  For those cases, we use this function.
 */
static int command_match(fr_trie_t *ft, UNUSED int argc, char **argv, char *out, size_t outlen)
{
	int bits;
	void *answer;
	char *key;

	if (arg2key(argv[0], &key, &bits) < 0) {
		return -1;
	}

	answer = fr_trie_key_match(ft->trie, (uint8_t *) key, 0, bits, true);
	if (!answer) {
		strlcpy(out, "{}", outlen);
		return 0;
	}

	strlcpy(out, answer, outlen);

	return 0;
}


/**  Look up a key and return user ctx data.
 *
 *  This is done by longest prefix match, not exact match.
 */
static int command_lookup(fr_trie_t *ft, UNUSED int argc, char **argv, char *out, size_t outlen)
{
	int bits;
	void *answer;
	char *key;

	if (arg2key(argv[0], &key, &bits) < 0) {
		return -1;
	}

	answer = fr_trie_lookup(ft, key, bits);
	if (!answer) {
		strlcpy(out, "{}", outlen);
		return 0;
	}

	strlcpy(out, answer, outlen);

	return 0;
}


/**  Remove a key from the trie.
 *
 *  The key has to match exactly.
 */
static int command_remove(fr_trie_t *ft, UNUSED int argc, char **argv, char *out, size_t outlen)
{
	int bits;
	void *answer;
	char *key;

	if (arg2key(argv[0], &key, &bits) < 0) {
		return -1;
	}

	answer = fr_trie_remove(ft, key, bits);
	if (!answer) {
		MPRINT("Could not remove key %s\n", key);
		return -1;
	}

	strlcpy(out, answer, outlen);

	talloc_free(answer);

	/*
	 *	We now try to find an exact match.  i.e. we don't want
	 *	to find a shorter prefix.
	 */
	answer = fr_trie_key_match(ft->trie, (uint8_t *) key, 0, bits, true);
	if (answer) {
		MPRINT("Still in trie after 'remove' for key %s, found data %s\n", key, (char const *) answer);
		return -1;
	}

	return 0;
}


/** Print a trie to a string
 *
 *  The trie is printed one one line.  If the trie contains keys which
 *  are not on a byte boundary, well... too bad.  It gets printed
 *  terribly.
 */
static int command_print(fr_trie_t *ft, UNUSED int argc, UNUSED char **argv, char *out, size_t outlen)
{
	fr_trie_callback_t my_cb;
	fr_trie_sprint_ctx_t my_sprint;
	uint8_t buffer[MAX_KEY_BYTES + 1];

	/*
	 *	Where the output data goes.
	 */
	my_sprint.start = out;
	my_sprint.buffer = out;
	my_sprint.buflen = outlen;

	/*
	 *	Where the keys are built.
	 */
	my_cb.ft = ft;
	my_cb.start = buffer;
	my_cb.end = buffer + sizeof(buffer);
	my_cb.callback = fr_trie_sprint_cb;
	my_cb.user_callback = NULL;
	my_cb.ctx = &my_sprint;

	memset(buffer, 0, sizeof(buffer));

	/*
	 *	Call the internal walk function to do the work.
	 */
	return fr_trie_key_walk(ft->trie, &my_cb, 0, false);
}


/**  Do insert / lookup / remove all at once.
 *
 *  Sometimes it's more useful to do insert / lookup / remove for
 *  simple keys.
 */
static int command_path(fr_trie_t *ft, int argc, char **argv, char *out, size_t outlen)
{
	void *data;
	void *answer;

	data = talloc_strdup(ft, argv[1]); /* has to be malloc'd data, sorry */
	if (!data) {
		MPRINT("OOM\n");
		return -1;
	}

	if (fr_trie_insert(ft, argv[0], BITSOF(strlen(argv[0])), data) < 0) {
		MPRINT("Could not insert key %s=%s\n", argv[0], argv[1]);
		return -1;
	}

	answer = fr_trie_lookup(ft, argv[0], BITSOF(strlen(argv[0])));
	if (!answer) {
		MPRINT("Could not look up key %s\n", argv[0]);
		return -1;
	}

	if (answer != data) {
		MPRINT("Expected to find %s, got %s\n", argv[1], (char const *) answer);
		return -1;
	}

	/*
	 *	Call the command 'print' to print out the key.
	 */
	(void) command_print(ft, argc, argv, out, outlen);

	answer = fr_trie_remove(ft, (uint8_t const *) argv[0], BITSOF(strlen(argv[0])));
	if (!answer) {
		MPRINT("Could not remove key %s\n", argv[0]);
		return -1;
	}

	if (answer != data) {
		MPRINT("Expected to remove %s, got %s\n", argv[1], (char const *) answer);
		return -1;
	}

	talloc_free(answer);

	return 0;
}


/**  Return the longest common prefix of two bit strings.
 *
 *  This function doesn't use argv2key because that makes the input
 *  look confusing.  And, we want to be able to specify a common start
 *  bit.
 */
static int command_lcp(UNUSED fr_trie_t *ft, int argc, char **argv, char *out, size_t outlen)
{
	int lcp;
	int keylen1, keylen2;
	int start_bit;
	uint8_t const *key1, *key2;

	if (argc == 2) {
		key1 = (uint8_t const *) argv[0];
		keylen1 = BITSOF(strlen(argv[0]));

		key2 = (uint8_t const *) argv[1];
		keylen2 = BITSOF(strlen(argv[1]));
		start_bit = 0;

	} else if (argc == 5) {
		key1 = (uint8_t const *) argv[0];
		keylen1 = atoi(argv[1]);
		if ((keylen1 < 0) || (keylen1 > (int) BITSOF(strlen(argv[0])))) {
			MPRINT("length of key1 %s is larger than string length %ld\n",
				argv[1], BITSOF(strlen(argv[0])));
			return -1;
		}

		key2 = (uint8_t const *) argv[2];
		keylen2 = atoi(argv[3]);
		if ((keylen2 < 0) || (keylen2 > (int) BITSOF(strlen(argv[2])))) {
			MPRINT("length of key2 %s is larger than string length %ld\n",
				argv[3], BITSOF(strlen(argv[2])));
			return -1;
		}

		start_bit = atoi(argv[4]);
		if ((start_bit < 0) || (start_bit > 7)) {
			MPRINT("start_bit has invalid value %s\n", argv[4]);
			return -1;
		}

	} else {
		MPRINT("Invalid number of arguments\n");
		return -1;
	}

	lcp = fr_trie_key_lcp(key1, keylen1, key2, keylen2, start_bit);

	snprintf(out, outlen, "%d", lcp);
	return 0;
}


/**  A function to parse a trie command line.
 *
 */
typedef int (*fr_trie_function_t)(fr_trie_t *ft, int argc, char **argv, char *out, size_t outlen);

/**  Data structure which holds the trie command name, function, etc.
 *
 */
typedef struct {
	char const		*name;
	fr_trie_function_t	function;
	int			min_argc;
	int			max_argc;
	bool			output;
} fr_trie_command_t;


/**  The trie commands for debugging.
 *
 */
static fr_trie_command_t commands[] = {
	{ "lcp",	command_lcp,	2, 5, true },
	{ "path",	command_path,	2, 2, true },
	{ "insert",	command_insert,	2, 2, false },
	{ "match",	command_match,	1, 1, true },
	{ "lookup",	command_lookup,	1, 1, true },
	{ "remove",	command_remove,	1, 1, true },
	{ "print",	command_print,	0, 0, true },
	{ "dump",	command_dump,	0, 0, false },
	{ "keys",	command_keys,	0, 0, false },
	{ "verify",	command_verify,	0, 0, false },
	{ "lineno",	command_lineno, 1, 1, false },
	{ "clear",	command_clear,	0, 0, false },
	{ NULL, NULL, 0, 0}
};

#define MAX_ARGC (16)
int main(int argc, char **argv)
{
	int lineno = 0;
	int rcode = 0;
	fr_trie_t *ft;
	FILE *fp;
	int my_argc;
	char *my_argv[MAX_ARGC];
	char buffer[8192];
	char output[8192];

	if (argc < 2) {
		fprintf(stderr, "Please specify filename\n");
		exit(EXIT_SUCCESS);
	}

	fp = fopen(argv[1], "r");
	if (!fp) {
		fprintf(stderr, "Failed opening %s: %s\n", argv[1], fr_syserror(errno));
		exit(1);
	}

	/*
	 *	Tell us if we leaked memory.
	 */
	talloc_enable_null_tracking();

	data_ctx = talloc_init("data_ctx");

	ft = fr_trie_alloc(NULL);
	if (!ft) {
		fprintf(stderr, "Failed creating trie\n");
		exit(1);
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		int i, cmd;
		char *p;

		lineno++;

		/*
		 *	Remove comments.
		 */
		for (p = buffer; *p != '\0'; p++) {
			if (*p == '#') {
				*p = '\0';
				break;
			}
		}

		/*
		 *	Skip leading whitespace.
		 */
		p = buffer;
		fr_skip_spaces(p);

		/*
		 *	Skip (now) blank lines.
		 */
		if (!*p) continue;

		my_argc = fr_dict_str_to_argv(p, my_argv, MAX_ARGC);

		cmd = -1;
		for (i = 0; commands[i].name != NULL; i++) {
			if (strcmp(my_argv[0], commands[i].name) != 0) continue;

			cmd = i;
			break;
		}

		if (cmd < 0) {
			fprintf(stderr, "Unknown command '%s' at line %d\n",
				my_argv[0], lineno);
			rcode = 1;
			break;
		}

		/*
		 *	argv[0] is the command.
		 *	argv[argc-1] is the output.
		 */
		if (((commands[cmd].min_argc + 1 + commands[cmd].output) > my_argc) ||
		    ((commands[cmd].max_argc + 1 + commands[cmd].output) < my_argc)) {
			fprintf(stderr, "Invalid number of arguments to %s at line %d.  Expected %d, got %d\n",
				my_argv[0], lineno, commands[cmd].min_argc + 1, my_argc - 1);
			exit(1);
		}

		if (print_lineno) {
			printf("%d ", lineno);
			fflush(stdout);
		}

		if (commands[cmd].function(ft, my_argc - 1 - commands[cmd].output, &my_argv[1], output, sizeof(output)) < 0) {
			fprintf(stderr, "Failed running %s at line %d\n",
				my_argv[0], lineno);
			exit(1);
		}

		if (!commands[cmd].output) continue;

		if (strcmp(output, my_argv[my_argc - 1]) != 0) {
			fprintf(stderr, "Failed running %s at line %d: Expected '%s' got '%s'\n",
				my_argv[0], lineno, my_argv[my_argc - 1], output);
			exit(1);
		}
	}

	fclose(fp);

	talloc_free(ft);
	talloc_free(data_ctx);

	talloc_report_full(NULL, stdout);	/* Print details of any leaked memory */
	talloc_disable_null_tracking();		/* Cleanup talloc null tracking context */

	return rcode;
}
#endif
