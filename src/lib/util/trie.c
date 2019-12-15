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
 * @copyright 2017 Alan DeKok (aland@freeradius.org)
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
#if !defined(NO_PATH_COMPRESSION) && !defined(WITH_PATH_COMPRESSION)
#define WITH_PATH_COMPRESSION
#endif

//#define WITH_NODE_COMPRESSION

#ifdef WITH_NODE_COMPRESSION
#ifndef WITH_PATH_COMPRESSION
#define WITH_PATH_COMPRESSION
#endif

#ifndef MAX_COMP_BITS
#define MAX_COMP_BITS (8)
#endif

#ifndef MAX_COMP_EDGES
#define MAX_COMP_EDGES (4)
#endif

#endif	/* WITH_NODE_COMPRESSION */

#define MAX_KEY_BYTES (256)
#define MAX_KEY_BITS (MAX_KEY_BYTES * 8)

#ifndef MAX_NODE_BITS
#define MAX_NODE_BITS (4)
#endif

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
#define WITH_TRIE_VERIFY (1)
#  define MPRINT(...) fprintf(stderr, ## __VA_ARGS__)

   /* define this to be MPRINT for additional debugging */
#  define MPRINT2(...)
#  define MPRINT3(...)
static void fr_trie_sprint(fr_trie_t *trie, uint8_t const *key, int start_bit, int lineno);
#else
#  define MPRINT(...)
#  define MPRINT2(...)
#  define MPRINT3(...)
#define fr_trie_sprint(_trie, _key, _start_bit, _lineno)
#endif

#ifdef WITH_TRIE_VERIFY
static int fr_trie_verify(fr_trie_t *trie);
//#define VERIFY(_x) fr_cond_assert(fr_trie_verify((fr_trie_t *) _x) == 0)
#define VERIFY(_x) do { if (fr_trie_verify((fr_trie_t *) _x) < 0) { fprintf(stderr, "FAIL VERIFY at %d - %s\n", __LINE__, fr_strerror()); fr_cond_assert(0);} } while (0)
#else
#define VERIFY(_x)
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


static uint8_t start_bit_mask[8] = {
	0xff, 0x7f, 0x3f, 0x1f,
	0x0f, 0x07, 0x03, 0x01
};

static uint8_t used_bit_mask[8] = {
	0x80, 0xc0, 0xe0, 0xf0,
	0xf8, 0xfc, 0xfe, 0xff,
};

#if 0
/*
 *	For testing and debugging.
 */
static char const *spaces = "                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                ";
#endif


#if defined(WITH_PATH_COMPRESSION) || defined(TESTING)
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


/** Get the longest prefix of the two keys.
 *
 */
static int fr_trie_key_lcp(uint8_t const *key1, int keylen1, uint8_t const *key2, int keylen2, int start_bit)
{
	int lcp, end_bit;

	if (!keylen1 || !keylen2) return 0;
	fr_cond_assert((start_bit & 0x07) == start_bit);

	end_bit = keylen1;
	if (end_bit > keylen2) end_bit = keylen2;
	end_bit += start_bit;

	MPRINT2("%.*sLCP %02x%02x %02x%02x start %d length %d, %d\n",
		start_bit, spaces, key1[0], key1[1], key2[0], key2[1], start_bit, keylen1, keylen2);

	lcp = 0;

	while (end_bit > 0) {
		int num_bits;
		uint8_t cmp1, cmp2, xor;

		MPRINT2("END %d\n", end_bit);

		/*
		 *	Default to grabbing the whole byte.
		 */
		cmp1 = key1[0];
		cmp2 = key2[0];
		num_bits = 8;

		/*
		 *	The LCP ends in this byte.  Mask off the
		 *	trailing bits so that they don't affect the
		 *	result.
		 */
		if (end_bit < 8) {
			cmp1 &= used_bit_mask[end_bit - 1];
			cmp2 &= used_bit_mask[end_bit - 1];
			num_bits = end_bit;
		}

		/*
		 *	The key doesn't start on the leading bit.
		 *	Shift the data left until it does start there.
		 */
		if ((start_bit & 0x07) != 0) {
			cmp1 <<= start_bit;
			cmp2 <<= start_bit;
			num_bits -= start_bit;
			end_bit -= start_bit;

			/*
			 *	For subsequent bytes we start on a
			 *	byte boundary.
			 */
			start_bit = 0;
		}

		xor = cmp1 ^ cmp2;

		/*
		 *	A table lookup is faster than looping through
		 *	the bits.  If the LCP is smaller than the
		 *	number of bits we're looking up, we can stop.
		 *
		 *	On the other hand, if it returns the same or
		 *	too many bits, just do another round through
		 *	the loop, so that we can update the pointers
		 *	and check the exit conditions.
		 */
		if (xor2lcp[xor] < num_bits) {
			MPRINT2("RETURN %d + %d\n", lcp, xor2lcp[xor]);
			return lcp + xor2lcp[xor];
		}

		/*
		 *	The LCP may be longer than num_bits if we're
		 *	checking the first byte, which has only
		 *	"start_bit" things we care about.  Ignore that
		 *	case, and just keep going.
		 */

		lcp += num_bits;
		end_bit -= num_bits;
		key1++;
		key2++;
	}

	return lcp;
}
#endif

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

static uint16_t get_chunk(uint8_t const *key, int start_bit, int num_bits) CC_HINT(nonnull);

/** Return a chunk of a key (in the low bits) for use in 2^N node de-indexing
 *
 */
static uint16_t get_chunk(uint8_t const *key, int start_bit, int num_bits)
{
	uint16_t chunk;
	int end_bit;

	fr_cond_assert(num_bits > 0);
	fr_cond_assert(num_bits <= 16);

	/*
	 *	Normalize it so that the caller doesn't have to.
	 */
	if (start_bit > 7) {
		key += BYTEOF(start_bit);
		start_bit &= 0x07;
	}

	/*
	 *	Special-case 1-bit lookups.
	 */
	if (num_bits == 1) {
		chunk = key[0] >> (7 - start_bit);
		chunk &= 0x01;
		return chunk;
	}

	/*
	 *	Catch some simple use-cases.
	 */
	if (start_bit == 0) {
		if (num_bits < 7) return key[0] >> (8 - num_bits);
		if (num_bits == 8) return key[0];
		if (num_bits == 16) return (key[0] << 8) | key[1];
		return ((key[0] << 8) | key[1]) >> (16 - num_bits);
	}

	/*
	 *	Load the first byte and mask off the bits we don't
	 *	want.
	 */
	chunk = key[0] & start_bit_mask[start_bit & 0x07];

	fr_cond_assert(BYTEOF(start_bit + num_bits - 1) <= 1);

	if (BYTEOF(start_bit + num_bits - 1) != 0) {
		chunk <<= 8;
		chunk |= key[1];
	}

	/*
	 *	The bits we want are now all in the higher bits
	 *	of "chunk".  But we only want some of them.
	 *
	 *	Shift the chunk so that the bits we want are now in
	 *	the low bits.
	 */
	end_bit = (start_bit + num_bits) & 0x07;
	if (end_bit != 0) chunk >>= 8 - end_bit;

	fr_cond_assert(chunk < (1 << num_bits));

	return chunk;
}


static void write_chunk(uint8_t *out, int start_bit, int num_bits, uint16_t chunk) CC_HINT(nonnull);

/** Write a chunk to an output buffer
 *
 */
static void write_chunk(uint8_t *out, int start_bit, int num_bits, uint16_t chunk)
{
	fr_cond_assert(chunk < (1 << num_bits));

	/*
	 *	Normalize it so that the caller doesn't have to.
	 */
	if (start_bit > 7) {
		out += BYTEOF(start_bit);
		start_bit &= 0x07;
	}

	/*
	 *	Special-case 1-bit writes.
	 */
	if (num_bits == 1) {
		out[0] &= ~((1 << (7 - start_bit)) - 1);
		out[0] |= chunk << (7 - start_bit);
		return;
	}

	/*
	 *	Ensure that we don't write to more than 2 octets at
	 *	the same time.
	 */
	fr_cond_assert((start_bit + num_bits) <= 16);

	/*
	 *	Shift the chunk to the high bits, but leave room for
	 *	start_bit
	 */
	if ((start_bit + num_bits) < 16) chunk <<= (16 - (start_bit + num_bits));

	/*
	 *	Mask off the first bits that are already in the
	 *	output.  Then OR in the relevant bits of "chunk".
	 */
	out[0] &= (used_bit_mask[start_bit] << 1);
	out[0] |= chunk >> 8;

	if ((start_bit + num_bits) > 8) {
		out[1] = chunk & 0xff;
	}
}

typedef enum fr_trie_type_t {
	FR_TRIE_INVALID = 0,
	FR_TRIE_USER,
#ifdef WITH_PATH_COMPRESSION
	FR_TRIE_PATH,
#endif
#ifdef WITH_NODE_COMPRESSION
	FR_TRIE_COMP,		/* 4-way, N bits deep */
#endif
	FR_TRIE_NODE,
} fr_trie_type_t;

#define FR_TRIE_MAX (FR_TRIE_NODE + 1)

#ifdef TESTING
static int trie_number = 0;

#define TRIE_HEADER uint8_t type; uint8_t bits; int number
#define TRIE_TYPE_CHECK(_x, _r) do { if ((trie->type == FR_TRIE_INVALID) || \
					 (trie->type >= FR_TRIE_MAX) || \
					 !trie_ ## _x [trie->type]) { \
						fr_strerror_printf("unknown trie type %d", trie->type); \
						return _r; \
				     } } while (0)

#else
#define TRIE_HEADER uint8_t type; uint8_t bits
#define TRIE_TYPE_CHECK(_x, _r)
#endif

struct fr_trie_s {
	TRIE_HEADER;

	fr_trie_t	*trie;	/* for USER and PATH nodes*/
};

typedef struct {
	TRIE_HEADER;

	int		used;
	fr_trie_t	*trie[];
} fr_trie_node_t;

typedef struct {
	TRIE_HEADER;

	fr_trie_t	*trie;
	void     	*data;
} fr_trie_user_t;

#ifdef WITH_PATH_COMPRESSION
typedef struct {
	TRIE_HEADER;

	fr_trie_t	*trie;

	uint16_t	chunk;
	uint8_t		key[2];
} fr_trie_path_t;
#endif

#ifdef WITH_NODE_COMPRESSION
typedef struct {
	TRIE_HEADER;

	int		used;		//!< number of used entries
	uint8_t		index[MAX_COMP_EDGES];
	fr_trie_t	*trie[MAX_COMP_EDGES];
} fr_trie_comp_t;
#endif


/* ALLOC FUNCTIONS */

static fr_trie_node_t *fr_trie_node_alloc(TALLOC_CTX *ctx, int bits)
{
	fr_trie_node_t *node;
	int size;

	if ((bits <= 0) || (bits > 8)) {
		fr_strerror_printf("Invalid bit size %d passed to node alloc", bits);
		return NULL;
	}

	size = 1 << bits;

	node = (fr_trie_node_t *) talloc_zero_array(ctx, uint8_t, sizeof(fr_trie_node_t) + sizeof(node->trie[0]) * size);
	if (!node) {
		fr_strerror_printf("failed allocating node trie");
		return NULL;
	}

	talloc_set_name_const(node, "fr_trie_node_t");
	node->type = FR_TRIE_NODE;
	node->bits = bits;

#ifdef TESTING
	node->number = trie_number++;
#endif
	return node;
}

/** Free a fr_trie_t
 *
 *  We can't use talloc_free(), because we can't talloc_parent the
 *  nodes frome each other, as talloc_steal() is O(N).  So, we just
 *  recurse manually.
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

		for (i = 0; i < (1 << node->bits); i++) {
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

#ifdef WITH_NODE_COMPRESSION
	if (trie->type == FR_TRIE_COMP) {
		fr_trie_comp_t *comp = (fr_trie_comp_t *) trie;
		int i;

		for (i = 0; i < comp->used; i++) {
			fr_trie_free(comp->trie[i]);
		}

		talloc_free(comp);
		return;
	}
#endif
}

static fr_trie_user_t *fr_trie_user_alloc(TALLOC_CTX *ctx, void const *data) CC_HINT(nonnull(2));

static fr_trie_user_t *fr_trie_user_alloc(TALLOC_CTX *ctx, void const *data)
{
	fr_trie_user_t *user;

	user = talloc_zero(ctx, fr_trie_user_t);
	if (!user) {
		fr_strerror_printf("failed allocating user trie");
		return NULL;
	}

	user->type = FR_TRIE_USER;
	memcpy(&user->data, &data, sizeof(user->data));

#ifdef TESTING
	user->number = trie_number++;
#endif

	return user;
}

#ifdef WITH_PATH_COMPRESSION
static fr_trie_path_t *fr_trie_path_alloc(TALLOC_CTX *ctx, uint8_t const *key, int start_bit, int end_bit) CC_HINT(nonnull(2));

static fr_trie_path_t *fr_trie_path_alloc(TALLOC_CTX *ctx, uint8_t const *key, int start_bit, int end_bit)
{
	fr_trie_path_t *path;

	if (end_bit <= start_bit) {
		fr_strerror_printf("path asked for start >= end, %d >= %d", start_bit, end_bit);
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

	if ((end_bit - start_bit) > 16) {
		fr_strerror_printf("path asked for too many bits (%d)", end_bit - start_bit);
		return NULL;
	}

	/*
	 *	The "end_bit" is the bit we're not using, so it's
	 *	allowed to point past the end of path->key.
	 */
	if ((BYTEOF(start_bit) - BYTEOF(end_bit - 1)) > 1) {
		fr_strerror_printf("path asked for too many bits / bytes (%d)", end_bit - start_bit);
		return NULL;
	}

	path = talloc_zero(ctx, fr_trie_path_t);
	if (!path) {
		fr_strerror_printf("failed allocating path trie");
		return NULL;
	}

	path->type = FR_TRIE_PATH;
	path->bits = end_bit - start_bit;
	path->chunk = get_chunk(key, start_bit, path->bits);

	/*
	 *	Write the chunk back to the key.
	 */
	write_chunk(&path->key[0], start_bit, path->bits, path->chunk);

#if 0
	fprintf(stderr, "PATH ALLOC key %02x%02x start %d end %d bits %d == chunk %04x key %02x%02x\n",
		key[0], key[1],
		start_bit, end_bit, path->bits,
		path->chunk, path->key[0], path->key[1]);
#endif

#ifdef TESTING
	path->number = trie_number++;
#endif

	return path;
}
#endif	/* WITH_PATH_COMPRESSION */

#ifdef WITH_NODE_COMPRESSION
static fr_trie_comp_t *fr_trie_comp_alloc(TALLOC_CTX *ctx, int bits)
{
	fr_trie_comp_t *comp;

	/*
	 *	For 1 && 2 bits, just allocate fr_trie_node_t.
	 */
	if ((bits <= 2) || (bits > MAX_COMP_BITS)) {
		fr_strerror_printf("Invalid bit size %d passed to comp alloc", bits);
		return NULL;
	}

	comp = talloc_zero(ctx, fr_trie_comp_t);
	if (!comp) {
		fr_strerror_printf("failed allocating comp trie");
		return NULL;
	}

	comp->type = FR_TRIE_COMP;
	comp->bits = bits;
	comp->used = 0;

#ifdef TESTING
	comp->number = trie_number++;
#endif
	return comp;
}
#endif	/* WITH_NODE_COMPRESSION */

/** Allocate a trie
 *
 * @param ctx The talloc ctx
 * @return
 *	- NULL on error
 *	- fr_trie_node_t on success
 */
fr_trie_t *fr_trie_alloc(TALLOC_CTX *ctx)
{
	fr_trie_user_t *user;

	/*
	 *	The trie itself is just a user node with user data that is the talloc ctx
	 */
	user = (fr_trie_user_t *) fr_trie_user_alloc(ctx, "");
	if (!user) return NULL;

	/*
	 *	Only the top-level node here can have 'user->data == NULL'
	 */
	user->data = ctx;
	return (fr_trie_t *) user;
}

/* SPLIT FUNCTIONS */

/** Split a node at bits
 *
 */
static fr_trie_node_t *fr_trie_node_split(TALLOC_CTX *ctx, fr_trie_node_t *node, int bits) CC_HINT(nonnull(2));

static fr_trie_node_t *fr_trie_node_split(TALLOC_CTX *ctx, fr_trie_node_t *node, int bits)
{
	fr_trie_node_t *split;
	int i, remaining_bits;

	/*
	 *	Can't split zero bits, more bits than the node has, or
	 *	a node which has 1 bit.
	 */
	if ((bits == 0) || (bits >= node->bits) || (node->bits == 1)) {
		fr_strerror_printf("invalid value for node split (%d / %d)", bits, node->bits);
		return NULL;
	}

	split = fr_trie_node_alloc(ctx, bits);
	if (!split) return NULL;

	remaining_bits = node->bits - bits;

	/*
	 *	Allocate the children.  For now, just brute-force all
	 *	of the children.  We take a later pass at optimizing this.
	 */
	for (i = 0; i < (1 << bits); i++) {
		int j;
		fr_trie_node_t *child;

		child = fr_trie_node_alloc(ctx, remaining_bits);
		if (!child) {
			fr_trie_free((fr_trie_t *) split);
			return NULL;
		}

		for (j = 0; j < (1 << remaining_bits); j++) {
			if (!node->trie[(i << remaining_bits) + j]) continue;

			child->trie[j] = node->trie[(i << remaining_bits) + j];
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

#ifdef WITH_PATH_COMPRESSION
static fr_trie_path_t *fr_trie_path_split(TALLOC_CTX *ctx, fr_trie_path_t *path, int start_bit, int lcp) CC_HINT(nonnull(2));

static fr_trie_path_t *fr_trie_path_split(TALLOC_CTX *ctx, fr_trie_path_t *path, int start_bit, int lcp)
{
	fr_trie_path_t *split, *child;
#ifdef TESTING
	uint8_t key[2] = { 0, 0 };
#endif

	if ((lcp <= 0) || (lcp > path->bits) || (start_bit < 0)) {
		fr_strerror_printf("invalid parameter %d %d to path split", lcp, start_bit);
		return NULL;
	}

	MPRINT3("%.*sSPLIT start %d\n", start_bit, spaces, start_bit);
	start_bit &= 0x07;

	split = fr_trie_path_alloc(ctx, &path->key[0], start_bit, start_bit + lcp);
	if (!split) return NULL;

	child = fr_trie_path_alloc(ctx, &path->key[0], start_bit + lcp, start_bit + path->bits);
	if (!child) return NULL;

	split->trie = (fr_trie_t *) child;
	child->trie = (fr_trie_t *) path->trie;

	/*
	 *	Don't free "path" until we've successfully inserted
	 *	the new key.
	 */

#ifdef TESTING
	/*
	 *	Check that the two chunks add up to the parent chunk.
	 */
	fr_cond_assert(path->chunk == ((split->chunk << (path->bits - lcp)) | child->chunk));

	/*
	 *	Check that the two keys match the parent key.
	 */

	write_chunk(&key[0], start_bit, split->bits, split->chunk);
	write_chunk(&key[0], start_bit + split->bits, child->bits, child->chunk);

	fr_cond_assert(key[0] == path->key[0]);
	fr_cond_assert(key[1] == path->key[1]);

	MPRINT3("%.*ssplit %02x%02x start %d split %d -> %02x%02x %02x%02x\n",
		start_bit, spaces,
		path->key[0], path->key[1],
		start_bit, split->bits,
		split->key[0], split->key[1],
		child->key[0], child->key[1]);
#endif

	return split;
}


static fr_trie_t *fr_trie_key_alloc(TALLOC_CTX *ctx, uint8_t const *key, int start_bit, int end_bit, void *data) CC_HINT(nonnull(2));

static fr_trie_t *fr_trie_key_alloc(TALLOC_CTX *ctx, uint8_t const *key, int start_bit, int end_bit, void *data)
{
	fr_trie_path_t *path;
	int next_bit;

	if (start_bit == end_bit) return (fr_trie_t *) fr_trie_user_alloc(ctx, data);

	if (start_bit > end_bit) {
		fr_strerror_printf("key_alloc asked for start >= end, %d >= %d", start_bit, end_bit);
		return NULL;
	}

	/*
	 *	Grab some more bits.  Try to grab 16 bits at a time.
	 */
	next_bit = start_bit + 16 - (start_bit & 0x07);

	if (next_bit >= end_bit) {
		path = fr_trie_path_alloc(ctx, key, start_bit, end_bit);
		if (!path) return NULL;

		path->trie = (fr_trie_t *) fr_trie_user_alloc(ctx, data);
		return (fr_trie_t *) path;
	}


	path = fr_trie_path_alloc(ctx,  key, start_bit, next_bit);
	if (!path) return NULL;

	path->trie = (fr_trie_t *) fr_trie_key_alloc(ctx, key, next_bit, end_bit, data);
	if (!path->trie) {
		talloc_free(path); /* no children */
		return NULL;
	}

	return (fr_trie_t *) path;
}
#else  /* WITH_PATH_COMPRESSION */
static fr_trie_t *fr_trie_key_alloc(TALLOC_CTX *ctx, uint8_t const *key, int start_bit, int end_bit, void *data) CC_HINT(nonnull(2));

static fr_trie_t *fr_trie_key_alloc(TALLOC_CTX *ctx, uint8_t const *key, int start_bit, int end_bit, void *data)
{
	fr_trie_node_t *node;
	uint16_t chunk;
	int bits = MAX_NODE_BITS;

	if (start_bit == end_bit) {
		return (fr_trie_t *) fr_trie_user_alloc(ctx, data);
	}

	bits = end_bit - start_bit;
	if (bits > MAX_NODE_BITS) bits = MAX_NODE_BITS;

	/*
	 *	We only want one edge here.
	 */
	node = fr_trie_node_alloc(ctx, bits);
	if (!node) return NULL;

	chunk = get_chunk(key, start_bit, node->bits);
	node->trie[chunk] = fr_trie_key_alloc(ctx, key, start_bit + node->bits, end_bit, data);
	if (!node->trie[chunk]) {
		talloc_free(node); /* no children */
		return NULL;
	}
	node->used++;

	return (fr_trie_t *) node;
}
#endif


#if 0
/** Split a compressed at bits
 *
 */
#ifdef WITH_NODE_COMPRESSION
static fr_trie_t *fr_trie_comp_split(TALLOC_CTX *ctx, fr_trie_comp_t *comp, int start_bit, int bits)
{
	int i;
	fr_trie_comp_t *split;

	/*
	 *	Can't split zero bits, more bits than the node has, or
	 *	a node which has 1 bit.
	 */
	if ((bits == 0) || (bits >= comp->bits)) {
		fr_strerror_printf("invalid value for comp split (%d / %d)", bits, comp->bits);
		return NULL;
	}

	split = fr_trie_comp_alloc(ctx, bits);
	if (!split) return NULL;

	if (start_bit > 7) start_bit &= 0x07;

	// walk over the edges, seeing how many edges have the same before bits
	//
	// if all have the same bits, then split by creating a path
	// node, and then a child split node.

	/*
	 *	Walk over each edge, inserting the first chunk into
	 *	the new node, and the split node...
	 */
	for (i = 0; i < comp->used; i++) {
		int j, where;
		uint16_t before, after;
		uint8_t key[2];
		fr_trie_path_t *path;

		before = i >> (comp->bits - bits);
		after = i & ((1 << bits) - 1);

		write_chunk(&key[0], start_bit, comp->bits, i);

		// see if "before" was already used in the newly created node.

		where = 0;

		for (j = 0; j < split->used; j++) {
			if (before == split->index[j]) {
				where = j;
				break;
			}
		}

		if (split->index[where]) {
			// the children MUST be different
			// create another compressed node as a child, and go from there.

		} else {
			split->index[split->used] = before;
			path = fr_trie_path_alloc(ctx, &key[0], start_bit, start_bit + bits);
			if (!path) goto fail;

			split->trie[split->used++] = (fr_trie_t *) path;
			path->trie = comp->trie[i];
		}
	}

	return (fr_trie_t *) split;

fail:
	for (i = 0; i < split->used; i++) {
		talloc_free(split->trie[i]);
	}
	talloc_free(split);
	return NULL;
}
#endif	/* WITH_NODE_COMPRESSION */
#endif

/* ADD EDGES */

#ifdef WITH_PATH_COMPRESSION
/** Add an edge to a node.
 *
 *  This function is so that we can abstract 2^N-way nodes, or
 *  compressed edge nodes.
 */
static int fr_trie_add_edge(fr_trie_t *trie, uint16_t chunk, fr_trie_t *child)
{
	fr_trie_node_t *node;

#ifdef WITH_NODE_COMPRESSION
	if (trie->type == FR_TRIE_COMP) {
		fr_trie_comp_t *comp = (fr_trie_comp_t *) trie;
		int i, edge;

		if (chunk >= (1 << comp->bits)) return -1;

		if (comp->used >= MAX_COMP_EDGES) return -1;

		edge = comp->used;
		for (i = 0; i < comp->used; i++) {
			if (comp->index[i] < chunk) continue;

			if (comp->index[edge] == chunk) return -1;

			edge = i;
			break;
		}

		if (edge == MAX_COMP_EDGES) return -1;

		/*
		 *	Move the nodes up so that we have room for the
		 *	new edge.
		 */
		for (i = edge; i < comp->used; i++) {
			comp->index[i + 1] = comp->index[i];
			comp->trie[i + 1] = comp->trie[i];
		}

		comp->index[edge] = chunk;
		comp->trie[edge] = child;

		comp->used++;
		VERIFY(comp);
		return 0;
	}
#endif

	if (trie->type != FR_TRIE_NODE) return -1;

	node = (fr_trie_node_t *) trie;

	if (chunk >= (1 << node->bits)) return -1;

	if (node->trie[chunk] != NULL) return -1;

	node->used++;
	node->trie[chunk] = child;

	return 0;
}
#endif

/* MATCH FUNCTIONS */

typedef void *(*fr_trie_key_match_t)(fr_trie_t *trie, uint8_t const *key, int start_bit, int end_bit, bool exact);

static void *fr_trie_key_match(fr_trie_t *trie, uint8_t const *key, int start_bit, int end_bit, bool exact);

static void *fr_trie_user_match(fr_trie_t *trie, uint8_t const *key, int start_bit, int end_bit, bool exact)
{
	fr_trie_user_t *user = (fr_trie_user_t *) trie;
	void *data;

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

static void *fr_trie_node_match(fr_trie_t *trie, uint8_t const *key, int start_bit, int end_bit, bool exact)
{
	uint16_t chunk;
	fr_trie_node_t *node = (fr_trie_node_t *) trie;

	chunk = get_chunk(key, start_bit, node->bits);
	if (!node->trie[chunk]) {
		MPRINT2("no match for node chunk %02x at %d\n", chunk, __LINE__);
		return NULL;
	}

	return fr_trie_key_match(node->trie[chunk], key, start_bit + node->bits, end_bit, exact);
}

#ifdef WITH_PATH_COMPRESSION
static void *fr_trie_path_match(fr_trie_t *trie, uint8_t const *key, int start_bit, int end_bit, bool exact)
{
	uint16_t chunk;
	fr_trie_path_t *path = (fr_trie_path_t *) trie;

	chunk = get_chunk(key, start_bit, path->bits);
	if (chunk != path->chunk) return NULL;

	return fr_trie_key_match(path->trie, key, start_bit + path->bits, end_bit, exact);
}
#endif

#ifdef WITH_NODE_COMPRESSION
static void *fr_trie_comp_match(fr_trie_t *trie, uint8_t const *key, int start_bit, int end_bit, bool exact)
{
	int i;
	uint16_t chunk;
	fr_trie_comp_t *comp = (fr_trie_comp_t *) trie;

	chunk = get_chunk(key, start_bit, comp->bits);

	for (i = 0; i < comp->used; i++) {
		if (comp->index[i] < chunk) continue;

		if (comp->index[i] == chunk) {
			return fr_trie_key_match(comp->trie[i], key, start_bit + comp->bits, end_bit, exact);
		}

		/*
		 *	The edges are ordered smallest to largest.  So
		 *	if the edge is larger than the chunk, NO edge
		 *	will match the chunk.
		 */
		return NULL;
	}

	return NULL;
}
#endif

static fr_trie_key_match_t trie_match[FR_TRIE_MAX] = {
	[ FR_TRIE_USER ] = fr_trie_user_match,
	[ FR_TRIE_NODE ] = fr_trie_node_match,
#ifdef WITH_PATH_COMPRESSION
	[ FR_TRIE_PATH ] = fr_trie_path_match,
#endif
#ifdef WITH_NODE_COMPRESSION
	[ FR_TRIE_COMP ] = fr_trie_comp_match,
#endif
};


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

	TRIE_TYPE_CHECK(match, NULL);

	/*
	 *	Recursively match each type.
	 */
	return trie_match[trie->type](trie, key, start_bit, end_bit, exact);
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
	fr_trie_user_t *user;

	if (keylen > MAX_KEY_BITS) return NULL;

	if (!ft->trie) return NULL;

	memcpy(&user, &ft, sizeof(user)); /* const issues */

	return fr_trie_key_match(user->trie, key, 0, keylen, false);
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
	fr_trie_user_t *user;

	if (keylen > MAX_KEY_BITS) return NULL;

	if (!ft->trie) return NULL;

	memcpy(&user, &ft, sizeof(user)); /* const issues */

	return fr_trie_key_match(user->trie, key, 0, keylen, true);
}

/* INSERT FUNCTIONS */

#ifdef TESTING
static void fr_trie_check(fr_trie_t *trie, uint8_t const *key, int start_bit, int end_bit, void *data, int lineno)
{
	void *answer;

	fr_trie_sprint(trie, key, start_bit, lineno);

	answer = fr_trie_key_match(trie, key, start_bit, end_bit, true);
	if (!answer) {
		fr_strerror_printf("Failed trie check answer at %d", lineno);

		// print out the current trie!
		MPRINT3("%.*sFailed to find user data %s from start %d end %d at %d\n", start_bit, spaces, data,
			start_bit, end_bit, lineno);
		fr_cond_assert(0);
	}

	if (answer != data) {
		fr_strerror_printf("Failed trie check answer == data at %d", lineno);

		MPRINT3("%.*sFound wrong user data %s != %s, from start %d end %d at %d\n", start_bit, spaces,
			answer, data, start_bit, end_bit, lineno);
		fr_cond_assert(0);
	}
}
#else
#define fr_trie_check(_trie, _key, _start_bit, _end_bit, _data, _lineno)
#endif

static int fr_trie_key_insert(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit, void *data) CC_HINT(nonnull(2,3,6));

typedef int (*fr_trie_key_insert_t)(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit, void *data);

static int fr_trie_user_insert(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit, void *data)
{
	fr_trie_t *trie = *trie_p;
	fr_trie_user_t *user = (fr_trie_user_t *) trie;

	MPRINT3("user insert to start %d end %d with data %s\n", start_bit, end_bit, (char *) data);

	/*
	 *	Just insert the key into user->trie.
	 */
	MPRINT3("%.*srecurse at %d\n", start_bit, spaces, __LINE__);
	return fr_trie_key_insert(ctx, &user->trie, key, start_bit, end_bit, data);
}

static int fr_trie_node_insert(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit, void *data)
{
	fr_trie_t *trie = *trie_p;
	fr_trie_node_t *node = (fr_trie_node_t *) trie;
	fr_trie_t *trie_to_free = NULL;
	uint32_t chunk;

	MPRINT3("%.*snode insert end %d with data %s\n",
		start_bit, spaces, end_bit, (char *) data);

	/*
	 *	The current node is longer than the input bits
	 *	for the key.  Split the node into a smaller
	 *	N-way node, and insert the key into the (now
	 *	fitting) node.
	 */
	if ((start_bit + node->bits) > end_bit) {
		fr_trie_node_t *split;

		MPRINT3("%.*snode insert splitting %d at %d start %d end %d with data %s\n",
			start_bit, spaces,
			node->bits, start_bit - end_bit,
			start_bit, end_bit, (char *) data);

		split = fr_trie_node_split(ctx, node, end_bit - start_bit);
		if (!split) {
			fr_strerror_printf("Failed splitting node at %d\n", __LINE__);
			return -1;
		}

		trie_to_free = (fr_trie_t *) node;
		node = split;
	}

	chunk = get_chunk(key, start_bit, node->bits);

	/*
	 *	No existing trie, create a brand new trie from
	 *	the key.
	 */
	if (!node->trie[chunk]) {
		node->trie[chunk] = fr_trie_key_alloc(ctx, key, start_bit + node->bits, end_bit, data);
		if (!node->trie[chunk]) {
			fr_strerror_printf("Failed key_alloc at %d\n", __LINE__);
			if (trie_to_free) fr_trie_free(trie_to_free);
			return -1;
		}
		node->used++;

	} else {
		/*
		 *	Recurse in order to insert the key
		 *	into the current node.
		 */
		MPRINT3("%.*srecurse at %d\n", start_bit, spaces, __LINE__);
		if (fr_trie_key_insert(ctx, &node->trie[chunk], key, start_bit + node->bits, end_bit, data) < 0) {
			MPRINT("Failed recursing at %d\n", __LINE__);
			if (trie_to_free) fr_trie_free(trie_to_free);
			return -1;
		}
	}

	fr_trie_check((fr_trie_t *) node, key, start_bit, end_bit, data, __LINE__);

	MPRINT3("%.*snode insert returning at %d\n",
		start_bit, spaces, __LINE__);

	if (trie_to_free) fr_trie_free(trie_to_free);
	*trie_p = (fr_trie_t *) node;
	VERIFY(node);
	return 0;
}

#ifdef WITH_PATH_COMPRESSION
static int fr_trie_path_insert(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit, void *data) CC_HINT(nonnull(2,3,6));

static int fr_trie_path_insert(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit, void *data)
{
	fr_trie_t *trie = *trie_p;
	fr_trie_path_t *path = (fr_trie_path_t *) trie;
	uint32_t chunk;
	int lcp, bits;
	uint8_t const *key2;
	int start_bit2;
	fr_trie_t *node;
	fr_trie_t *child;

	MPRINT3("%.*spath insert start %d end %d with key %02x%02x data %s\n",
		start_bit, spaces, start_bit, end_bit, key[0], key[1], (char *) data);

	VERIFY(path);
	fr_trie_sprint((fr_trie_t *) path, key, start_bit, __LINE__);

	/*
	 *	The key exactly matches the path.  Recurse.
	 */
	if (start_bit + path->bits <= end_bit) {
		chunk = get_chunk(key, start_bit, path->bits);

		/*
		 *	The chunk matches exactly.  Recurse to
		 *	insert the key into the child trie.
		 */
		if (chunk == path->chunk) {
			MPRINT3("%.*spath chunk matches %04x bits of %d\n",
				start_bit, spaces, chunk, path->bits);
			MPRINT3("%.*srecurse at %d\n", start_bit, spaces, __LINE__);
			if (fr_trie_key_insert(ctx, &path->trie, key, start_bit + path->bits, end_bit, data) < 0) {
				return -1;
			}

			fr_trie_check((fr_trie_t *) path, key, start_bit, end_bit, data, __LINE__);

			MPRINT3("%.*spath returning at %d\n", start_bit, spaces, __LINE__);
			VERIFY(path);
			return 0;
		}

		bits = path->bits;
		MPRINT3("%.*spath using %d\n", start_bit, spaces, path->bits);

	} else {
		/*
		 *	Limit the number of bits we check to
		 *	the number of bits left in the key.
		 */
		bits = end_bit - start_bit;
		MPRINT3("%.*spath limiting %d to %d\n", start_bit, spaces, path->bits, bits);
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
	MPRINT3("%.*spath lcp %d\n", start_bit, spaces, lcp);

	/*
	 *	This should have been caught above.
	 */
	if (lcp == path->bits) {
		fr_strerror_printf("found lcp which should have been previously found");
		return -1;
	}

	if (lcp > 0) {
		fr_trie_path_t *split;

		/*
		 *	Note that "path" is still valid after this
		 *	call.  We will rewrite things on the way back
		 *	up the stack.
		 */
		MPRINT3("%.*spath split depth %d bits %d at lcp %d with data %s\n",
			start_bit, spaces, start_bit, path->bits, lcp, (char *) data);

		MPRINT3("%.*spath key %02x%02x input key %02x%02x, offset %d\n",
			start_bit, spaces,
			path->key[0],path->key[1],
			key[0], key[1],
			start_bit2);

		split = fr_trie_path_split(ctx, path, start_bit2, lcp);
		if (!split) {
			fr_strerror_printf("failed path split at %d\n", __LINE__);
			return -1;
		}

		fr_trie_sprint((fr_trie_t *) path, key, start_bit, __LINE__);
		fr_trie_sprint((fr_trie_t *) split, key, start_bit, __LINE__);
		fr_trie_sprint((fr_trie_t *) split->trie, key, start_bit + split->bits, __LINE__);

		/*
		 *	Recurse to insert the key into the child node.
		 *	Note that if "bits > MAX_NODE_BITS", we will
		 *	have to split "path" again.
		 */
		MPRINT3("%.*srecurse at %d\n", start_bit, spaces, __LINE__);
		if (fr_trie_key_insert(ctx, &split->trie, key, start_bit + split->bits, end_bit, data) < 0) {
			talloc_free(split->trie);
			talloc_free(split);
			return -1;
		}

		/*
		 *	We can't have two LCPs in a row here, as we
		 *	SHOULD have found the LCP above!
		 */
		fr_cond_assert(split->type == FR_TRIE_PATH);
		fr_cond_assert(split->trie->type != FR_TRIE_PATH);

		fr_trie_check((fr_trie_t *) split, key, start_bit, end_bit, data, __LINE__);

		MPRINT3("%.*spath returning at %d\n", start_bit, spaces, __LINE__);
		talloc_free(path);
		*trie_p = (fr_trie_t *) split;
		VERIFY(split);
		return 0;
	}

	/*
	 *	Else there's no common prefix.  Just create an
	 *	fanout node.
	 */
	/*
	 *	We only want two edges here. Try to create a
	 *	compressed N-way node if possible.
	 */
#ifdef WITH_NODE_COMPRESSION
	if (bits > 2) {
		if (bits > MAX_COMP_BITS) bits = MAX_COMP_BITS;

		MPRINT3("%.*sFanout to comp %d at depth %d data %s\n", start_bit, spaces, bits, start_bit, (char *) data);
		node = (fr_trie_t *) fr_trie_comp_alloc(ctx, bits);
	} else
#endif
	{
		/*
		 *	Without path compression create no more than a
		 *	16-way node.
		 */
		if (bits > MAX_NODE_BITS) bits = MAX_NODE_BITS;

		MPRINT3("%.*sFanout to node %d at depth %d data %s\n", start_bit, spaces, bits, start_bit, (char *) data);
		node = (fr_trie_t *) fr_trie_node_alloc(ctx, bits);
	}
	if (!node) return -1;

	/*
	 *	Get the chunk from the path, and insert the child trie
	 *	into the node at that chunk.
	 */
	chunk = get_chunk(&path->key[0], start_bit2, node->bits);

	if (node->bits == path->bits) {
		child = path->trie;

	} else {
		/*
		 *	Skip the common prefix.
		 */
		child = (fr_trie_t *) fr_trie_path_alloc(ctx, &path->key[0], start_bit2 + node->bits, start_bit2 + path->bits);
		if (!child) {
			fr_strerror_printf("failed allocating path child at %d", __LINE__);
			return -1;
		}

		/*
		 *	Patch in the child trie.
		 */
		((fr_trie_path_t *)child)->trie = path->trie;

		VERIFY(child);
	}

	trie = NULL;

	/*
	 *	Recurse to insert the key into the second edge.  If
	 *	this fails, then we haven't changed anything.  So just
	 *	free memory and return.
	 *
	 *	Note that if "bits > DEFAULT_BITS", we will have to
	 *	split "path" again.
	 */
	MPRINT3("%.*srecurse at %d\n", start_bit, spaces, __LINE__);
	if (fr_trie_key_insert(ctx, &trie, key, start_bit + node->bits, end_bit, data) < 0) {
		talloc_free(node);
		if (child != path->trie) talloc_free(child);
		return -1;
	}

	/*
	 *	Copy the first edge over to the first chunk.
	 */
	if (fr_trie_add_edge(node, chunk, child) < 0) {
		fr_strerror_printf("chunk failure in insert node %d at %d", node->bits, __LINE__);
		talloc_free(node);
		if (child != path->trie) talloc_free(child);
		return -1;
	}

	/*
	 *	Copy the second edge from the new chunk.
	 */
	chunk = get_chunk(key, start_bit, node->bits);
	if (fr_trie_add_edge(node, chunk, trie) < 0) {
		fr_strerror_printf("chunk failure in insert node %d at %d", node->bits, __LINE__);
		talloc_free(node);
		fr_trie_free(trie);
		return -1;
	}

	fr_trie_check((fr_trie_t *) node, key, start_bit, end_bit, data, __LINE__);

	MPRINT3("%.*spath returning at %d\n", start_bit, spaces, __LINE__);

	/*
	 *	Only update the answer if the insert succeeded.
	 */
	*trie_p = node;
	talloc_free(path);
	VERIFY(node);
	return 0;
}
#endif

#ifdef WITH_NODE_COMPRESSION
static int fr_trie_comp_insert(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit, void *data) CC_HINT(nonnull(2,3,6));

static int fr_trie_comp_insert(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit, void *data)
{
	int i, bits;
	fr_trie_t *trie = *trie_p;
	fr_trie_comp_t *comp = (fr_trie_comp_t *) trie;
	fr_trie_node_t *node;
	uint16_t chunk;

	MPRINT3("%.*scomp insert start %d end %d with key %02x%02x data %s\n",
		start_bit, spaces, start_bit, end_bit, key[0], key[1], (char *) data);

	if ((end_bit - start_bit) < comp->bits) {
		fr_strerror_printf("Not implemented at %d", __LINE__);
		return -1;
	}

	chunk = get_chunk(key, start_bit, comp->bits);

	/*
	 *	Search for a matching edge.  If found, recurse and
	 *	insert the key there.
	 */
	for (i = 0; i < comp->used; i++) {
		if (comp->index[i] < chunk) continue;

		/*
		 *	We've found a matching chunk, recurse.
		 */
		if (comp->index[i] == chunk) {
			MPRINT3("%.*srecurse at %d\n", start_bit, spaces, __LINE__);
			if (fr_trie_key_insert(ctx, &comp->trie[i], key, start_bit + comp->bits, end_bit, data) < 0) {
				MPRINT3("%.*scomp failed recursing at %d", start_bit, spaces, __LINE__);
				return -1;
			}

			fr_trie_check((fr_trie_t *) comp, key, start_bit, end_bit, data, __LINE__);

			MPRINT3("%.*scomp returning at %d", start_bit, spaces, __LINE__);
			VERIFY(comp);
			return 0;
		}

		/*
		 *	The chunk is larger than the current edge,
		 *	stop.
		 */
		break;
	}

	/*
	 *	No edge matches the chunk from the key.  Insert the
	 *	child trie into a place-holder entry, so that we don't
	 *	modify the current node on failure.
	 */
	if (comp->used < MAX_COMP_EDGES) {
		MPRINT3("%.*srecurse at %d\n", start_bit, spaces, __LINE__);
		trie = NULL;
		if (fr_trie_key_insert(ctx, &trie, key, start_bit + comp->bits, end_bit, data) < 0) {
			MPRINT3("%.*scomp failed recursing at %d", start_bit, spaces, __LINE__);
			return -1;
		}
		fr_cond_assert(trie != NULL);

		if (fr_trie_add_edge((fr_trie_t *) comp, chunk, trie) < 0) {
			talloc_free(trie); // @todo - there may be multiple nodes here?
			return -1;
		}

		fr_trie_check((fr_trie_t *) comp, key, start_bit, end_bit, data, __LINE__);

		VERIFY(comp);
		return 0;
	}

	/*
	 *	All edges are used.  Create an N-way node.
	 */

	/*
	 *	@todo - limit bits by calling
	 *	fr_trie_comp_split()?
	 */
	bits = comp->bits;

	MPRINT3("%.*scomp swapping to node bits %d at %d\n", start_bit, spaces, bits, __LINE__);

	node = fr_trie_node_alloc(ctx, bits);
	if (!node) return -1;

	for (i = 0; i < comp->used; i++) {
		fr_cond_assert(node->trie[comp->index[i]] == NULL);
		node->trie[comp->index[i]] = comp->trie[i];
	}
	node->used = comp->used;
	node->used += (node->trie[chunk] == NULL); /* will get set if the recursive insert succeeds */

	/*
	 *	Insert the new chunk, which may or may not overlap
	 *	with an existing one.
	 */
	MPRINT3("%.*srecurse at %d\n", start_bit, spaces, __LINE__);
	if (fr_trie_key_insert(ctx, &node->trie[chunk], key, start_bit + node->bits, end_bit, data) < 0) {
		MPRINT3("%.*scomp failed recursing at %d", start_bit, spaces, __LINE__);
		talloc_free(node);
		return -1;
	}

	fr_trie_check((fr_trie_t *) node, key, start_bit, end_bit, data, __LINE__);

	MPRINT3("%.*scomp returning at %d", start_bit, spaces, __LINE__);

	talloc_free(comp);
	*trie_p = (fr_trie_t *) node;
	VERIFY(node);
	return 0;
}
#endif

static fr_trie_key_insert_t trie_insert[FR_TRIE_MAX] = {
	[ FR_TRIE_USER ] = fr_trie_user_insert,
	[ FR_TRIE_NODE ] = fr_trie_node_insert,
#ifdef WITH_PATH_COMPRESSION
	[ FR_TRIE_PATH ] = fr_trie_path_insert,
#endif
#ifdef WITH_NODE_COMPRESSION
	[ FR_TRIE_COMP ] = fr_trie_comp_insert,
#endif
};

/** Insert a binary key into the trie
 *
 *  The key must have at least ((start_bit + keylen) >> 3) bytes
 *
 * @param ctx		the talloc ctx
 * @param[in,out] trie_p the trie where things are inserted
 * @param key		the binary key
 * @param start_bit	the start bit
 * @param end_bit	the end bit
 * @param data		user data to insert
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int fr_trie_key_insert(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit, void *data)
{
	fr_trie_t *trie = *trie_p;

	/*
	 *	We've reached the end of the trie, but may still have
	 *	key bits to insert.
	 */
	if (!trie) {
		*trie_p = fr_trie_key_alloc(ctx, key, start_bit, end_bit, data);
		if (!*trie_p) return -1;
		return 0;
	}

	MPRINT3("%.*sIN recurse at %d\n", start_bit, spaces, __LINE__);
	fr_trie_sprint(trie, key, start_bit, __LINE__);

	/*
	 *	We've reached the end of the key.  Insert a user node
	 *	here, and push the remaining bits of the trie to after
	 *	the user node.
	 */
	if (start_bit == end_bit) {
		fr_trie_user_t *user;

		if (trie->type == FR_TRIE_USER) {
			fr_strerror_printf("already has a user node at %d\n", __LINE__);
			return -1;
		}

		user = fr_trie_user_alloc(ctx, data);
		if (!user) return -1;

		user->trie = trie;
		*trie_p = (fr_trie_t *) user;
		return 0;
	}

	TRIE_TYPE_CHECK(insert, -1);

#ifndef TESTING
	return trie_insert[trie->type](ctx, trie_p, key, start_bit, end_bit, data);
#else
	MPRINT3("%.*srecurse at start %d end %d with data %s\n", start_bit, spaces, start_bit, end_bit, (char *) data);

	if (trie_insert[trie->type](ctx, trie_p, key, start_bit, end_bit, data) < 0) {
		return -1;
	}

	fr_trie_check(*trie_p, key, start_bit, end_bit, data, __LINE__);

	return 0;
#endif
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

	user = (fr_trie_user_t *) ft;

	/*
	 *	Do a lookup before insertion.  If we tried to insert
	 *	the key with new nodes and then discovered a conflict,
	 *	we would not be able to undo the process.  This check
	 *	ensures that the insertion can modify the trie in
	 *	place without worry.
	 */
	if (fr_trie_key_match(user->trie, key, 0, keylen, true) != NULL) {
		fr_strerror_printf("Cannot insert due to pre-existing key");
		return -1;
	}

	memcpy(&my_data, &data, sizeof(data)); /* const issues */
	MPRINT2("No match for data, inserting...\n");

	MPRINT3("%.*srecurse STARTS at %d with %.*s=%s\n", 0, spaces, __LINE__,
		(int) keylen, key, my_data);
	return fr_trie_key_insert(user->data, &user->trie, key, 0, keylen, my_data);
}

/* REMOVE FUNCTIONS */
static void *fr_trie_key_remove(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit);

typedef void *(*fr_trie_key_remove_t)(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit);

static void *fr_trie_user_remove(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit)
{
	fr_trie_t *trie = *trie_p;
	fr_trie_user_t *user = (fr_trie_user_t *) trie;

	/*
	 *	We're at the end of the key, return the data
	 *	given here, and free the node that we're
	 *	removing.
	 */
	if (start_bit == end_bit) {
		void *data = user->data;

		*trie_p = user->trie;
		talloc_free(user);

		return data;
	}

	return fr_trie_key_remove(ctx, &user->trie, key, start_bit, end_bit);
}

static void *fr_trie_node_remove(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit)
{
	fr_trie_t *trie = *trie_p;
	fr_trie_node_t *node = (fr_trie_node_t *) trie;
	uint32_t chunk;
	void *data;

	chunk = get_chunk(key, start_bit, node->bits);
	if (!node->trie[chunk]) return NULL;

	data = fr_trie_key_remove(ctx, &node->trie[chunk], key, start_bit + node->bits, end_bit);
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
	 *	@todo - if we have path compression, and
	 *	node->used==1, then create a fr_trie_path_t from the
	 *	chunk, and concatenate it (if necessary) to any
	 *	trailing path compression node.
	 */

	/*
	 *	Our entire node is empty.  Delete it as we walk back up the trie.
	 */
	*trie_p = NULL;
	talloc_free(node); /* no children */
	return data;
}

#ifdef WITH_PATH_COMPRESSION
static void *fr_trie_path_remove(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit)
{
	fr_trie_t *trie = *trie_p;
	fr_trie_path_t *path = (fr_trie_path_t *) trie;
	uint32_t chunk;
	void *data;

	chunk = get_chunk(key, start_bit, path->bits);

	/*
	 *	No match, can't remove it.
	 */
	if (path->chunk != chunk) return NULL;

	data = fr_trie_key_remove(ctx, &path->trie, key, start_bit + path->bits, end_bit);
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

#ifdef WITH_NODE_COMPRESSION
static void *fr_trie_comp_remove(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit)
{
	int i, j;
	uint16_t chunk;
	void *data;
	fr_trie_comp_t *comp = *(fr_trie_comp_t **) trie_p;
	fr_trie_path_t *path;

	chunk = get_chunk(key, start_bit, comp->bits);

	MPRINT3("%.*sremove at %d\n", start_bit, spaces, __LINE__);
	fr_trie_sprint(*trie_p, key, start_bit, __LINE__);

	for (i = 0; i < comp->used; i++) {
		if (comp->index[i] < chunk) continue;

		if (comp->index[i] == chunk) {
			break;
		}

		/*
		 *	The edges are ordered smallest to largest.  So
		 *	if the edge is larger than the chunk, NO edge
		 *	will match the chunk.
		 */
		if (comp->index[i] > chunk) return NULL;
	}

	/*
	 *	Didn't find it, fail.
	 */
	if (i >= comp->used) return NULL;

	fr_cond_assert(chunk == comp->index[i]);

	data = fr_trie_key_remove(ctx, &comp->trie[i], key, start_bit + comp->bits, end_bit);
	if (!data) return NULL;

	/*
	 *	The trie still has a subtrie.  Just return the data.
	 */
	if (comp->trie[i]) {
		MPRINT3("%.*sremove at %d\n", start_bit, spaces, __LINE__);
		fr_trie_sprint((fr_trie_t *) comp, key, start_bit, __LINE__);
		VERIFY(comp);
		return data;
	}

	/*
	 *	Shrinking at the end is easy, we don't need to do
	 *	anything.  For shrinking in the middle, we just copy
	 *	the entries down.
	 */
	for (j = i; j < comp->used - 1; j++) {
		comp->index[j] = comp->index[j + 1];
		comp->trie[j] = comp->trie[j + 1];
	}
	comp->used--;

	if (comp->used >= 2) {
		VERIFY(comp);
		return data;
	}

	/*
	 *	Our entire path is empty.  Delete it as we walk back
	 *	up the trie.  We hope that this doesn't happen.
	 */
	if (!comp->used) {
		*trie_p = NULL;
		talloc_free(comp); /* no children */
		MPRINT3("%.*sremove at %d\n", start_bit, spaces, __LINE__);
		return data;
	}

	/*
	 *	Only one edge.  Turn it back into a path node.  Note
	 *	that we pass "key" here, which is wrong... that's the
	 *	key we're removing, not the key left in the node.  But
	 *	we fix that later.
	 *
	 *	@todo - check the child. If it's also a path node, try
	 *	to concatenate the nodes together.
	 */
	path = fr_trie_path_alloc(ctx, key, start_bit, start_bit + comp->bits);
	if (!path) return data;

	/*
	 *	Tie the new node in.
	 */
	path->trie = comp->trie[0];

	/*
	 *	Fix up the chunk and key to be the one left in the
	 *	trie, not the one which was removed.
	 */
	path->chunk = comp->index[0];
	write_chunk(&path->key[0], start_bit & 0x07, path->bits, path->chunk);

	*trie_p = (fr_trie_t *) path;
	talloc_free(comp);
	VERIFY(path);
	return data;
}
#endif

static fr_trie_key_remove_t trie_remove[FR_TRIE_MAX] = {
	[ FR_TRIE_USER ] = fr_trie_user_remove,
	[ FR_TRIE_NODE ] = fr_trie_node_remove,
#ifdef WITH_PATH_COMPRESSION
	[ FR_TRIE_PATH ] = fr_trie_path_remove,
#endif
#ifdef WITH_NODE_COMPRESSION
	[ FR_TRIE_COMP ] = fr_trie_comp_remove,
#endif
};

/** Remove a key from a trie, and return the user data.
 *
 */
static void *fr_trie_key_remove(TALLOC_CTX *ctx, fr_trie_t **trie_p, uint8_t const *key, int start_bit, int end_bit)
{
	fr_trie_t *trie = *trie_p;

	if (!trie) return NULL;

	/*
	 *	We can't remove a key which is shorter than the
	 *	current trie.
	 */
	if ((start_bit + trie->bits) > end_bit) return NULL;

	TRIE_TYPE_CHECK(remove, NULL);

	return trie_remove[trie->type](ctx, trie_p, key, start_bit, end_bit);
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

	user = (fr_trie_user_t *) ft;

	/*
	 *	Remove the user trie, not ft->trie.
	 */
	return fr_trie_key_remove(user->data, &user->trie, key, 0, (int) keylen);
}

/* WALK FUNCTIONS */

typedef struct fr_trie_callback_s fr_trie_callback_t;

typedef int (*fr_trie_key_walk_t)(fr_trie_t *trie, fr_trie_callback_t *cb, int depth, bool more);

static int fr_trie_key_walk(fr_trie_t *trie, fr_trie_callback_t *cb, int depth, bool more);

struct fr_trie_callback_s {
	uint8_t		*start;
	uint8_t const	*end;

	void			*ctx;

	fr_trie_key_walk_t	callback;
	fr_trie_walk_t		user_callback;
};

static int fr_trie_user_walk(fr_trie_t *trie, fr_trie_callback_t *cb, int depth, bool more)
{
	fr_trie_user_t *user = (fr_trie_user_t *) trie;

	if (!user->trie) return 0;

	return fr_trie_key_walk(user->trie, cb, depth, more);
}

static int fr_trie_node_walk(fr_trie_t *trie, fr_trie_callback_t *cb, int depth, bool more)
{
	int i, used;
	fr_trie_node_t *node = (fr_trie_node_t *) trie;

	used = 0;
	for (i = 0; i < (1 << node->bits); i++) {
		if (!node->trie[i]) continue;

		write_chunk(cb->start, depth, node->bits, (uint16_t) i);
		used++;

		if (fr_trie_key_walk(node->trie[i], cb, depth + node->bits,
				     more || (used < node->used)) < 0) {
			return -1;
		}
	}

	return 0;
}

#ifdef WITH_PATH_COMPRESSION
static int fr_trie_path_walk(fr_trie_t *trie, fr_trie_callback_t *cb, int depth, bool more)
{
	fr_trie_path_t *path = (fr_trie_path_t *) trie;

	write_chunk(cb->start, depth, path->bits, path->chunk);

	fr_cond_assert(path->trie != NULL);
	return fr_trie_key_walk(path->trie, cb, depth + path->bits, more);
}
#endif

#ifdef WITH_NODE_COMPRESSION
static int fr_trie_comp_walk(fr_trie_t *trie, fr_trie_callback_t *cb, int depth, bool more)
{
	int i, used;
	fr_trie_comp_t *comp = (fr_trie_comp_t *) trie;

	used = 0;
	for (i = 0; i < comp->used; i++) {
		write_chunk(cb->start, depth, comp->bits, comp->index[i]);

		fr_cond_assert(comp->trie[i] != NULL);

		used++;
		if (fr_trie_key_walk(comp->trie[i], cb, depth + comp->bits,
				     more || (used < comp->used)) < 0) {
			return -1;
		}
	}

	return 0;
}
#endif

static fr_trie_key_walk_t trie_walk[FR_TRIE_MAX] = {
	[ FR_TRIE_USER ] = fr_trie_user_walk,
	[ FR_TRIE_NODE ] = fr_trie_node_walk,
#ifdef WITH_PATH_COMPRESSION
	[ FR_TRIE_PATH ] = fr_trie_path_walk,
#endif
#ifdef WITH_NODE_COMPRESSION
	[ FR_TRIE_COMP ] = fr_trie_comp_walk,
#endif
};

static int fr_trie_key_walk(fr_trie_t *trie, fr_trie_callback_t *cb, int depth, bool more)
{
	/*
	 *	Do the callback before anything else.
	 */
	if (cb->callback(trie, cb, depth, more) < 0) return -1;

	if (!trie) {
		fr_cond_assert(depth == 0);
		return 0;
	}

	TRIE_TYPE_CHECK(walk, -1);

	/*
	 *	No more buffer space, stop.
	 */
	if ((cb->start + BYTEOF(depth + trie->bits + 8)) >= cb->end) return 0;

	return trie_walk[trie->type](trie, cb, depth, more);
}

#ifdef WITH_TRIE_VERIFY
/* VERIFY FUNCTIONS */

typedef int (*fr_trie_verify_t)(fr_trie_t *trie);

static int fr_trie_user_verify(fr_trie_t *trie)
{
	fr_trie_user_t *user = (fr_trie_user_t *) trie;

	if (!user->data) {
		fr_strerror_printf("user node has no user data");
		return -1;
	}

	if (!user->trie) return 0;

	return fr_trie_verify(user->trie);
}

static int fr_trie_node_verify(fr_trie_t *trie)
{
	fr_trie_node_t *node = (fr_trie_node_t *) trie;
	int i, used;

	if ((node->bits == 0) || (node->bits > MAX_NODE_BITS)) {
		fr_strerror_printf("N-way node has invalid bits %d",
				   node->bits);
		return -1;
	}

	if ((node->used == 0) || (node->used > (1 << node->bits))) {
		fr_strerror_printf("N-way node has invalid used %d for bits %d",
				   node->used, node->bits);
		return -1;
	}

	used = 0;
	for (i = 0; i < (1 << node->bits); i++) {
		if (!node->trie[i]) continue;

		if (fr_trie_verify(node->trie[i]) < 0) return -1;

		used++;
	}

	if (used != node->used) {
		fr_strerror_printf("N-way node has incorrect used %d when actually used %d",
				   node->used, used);
		return -1;
	}

	return 0;
}

#ifdef WITH_PATH_COMPRESSION
static int fr_trie_path_verify(fr_trie_t *trie)
{
	fr_trie_path_t *path = (fr_trie_path_t *) trie;

	if ((path->bits == 0) || (path->bits > 16)) {
		fr_strerror_printf("path node has invalid bits %d",
				   path->bits);
		return -1;
	}

	if (!path->trie) {
		fr_strerror_printf("path node has no child trie");
		return -1;
	}

	return fr_trie_verify(path->trie);
}
#endif

#ifdef WITH_NODE_COMPRESSION
static int fr_trie_comp_verify(fr_trie_t *trie)
{
	int i, used;
	fr_trie_comp_t *comp = (fr_trie_comp_t *) trie;

	if ((comp->bits == 0) || (comp->bits > MAX_COMP_BITS)) {
		fr_strerror_printf("comp node has invalid bits %d",
				   comp->bits);
		return -1;
	}

	used = 0;
	for (i = 0; i < comp->used; i++) {
		if (!comp->trie[i]) {
			fr_strerror_printf("comp node has no child trie at %d", i);
			return -1;
		}

		if ((i + 1) < comp->used) {
			if (comp->index[i] >= comp->index[i + 1]) {
				fr_strerror_printf("comp node has inverted edges at %d (%04x >= %04x)",
						   i, comp->index[i], comp->index[i + 1]);
				return -1;
			}
		}

		if (fr_trie_verify(comp->trie[i]) < 0) return -1;
		used++;
	}

	if (used != comp->used) {
		fr_strerror_printf("Compressed node has incorrect used %d when actually used %d",
				   comp->used, used);
		return -1;
	}

	return 0;
}
#endif

static fr_trie_verify_t trie_verify[FR_TRIE_MAX] = {
	[ FR_TRIE_USER ] = fr_trie_user_verify,
	[ FR_TRIE_NODE ] = fr_trie_node_verify,
#ifdef WITH_PATH_COMPRESSION
	[ FR_TRIE_PATH ] = fr_trie_path_verify,
#endif
#ifdef WITH_NODE_COMPRESSION
	[ FR_TRIE_COMP ] = fr_trie_comp_verify,
#endif
};


/**  Verify the trie nodes
 *
 */
static int fr_trie_verify(fr_trie_t *trie)
{
	if (!trie) return 0;

	TRIE_TYPE_CHECK(verify, -1);

	return trie_verify[trie->type](trie);
}
#endif	/* WITH_TRIE_VERIFY */

/* MISCELLANEOUS FUNCTIONS */

#ifdef TESTING
/** Dump a trie edge in canonical form.
 *
 */
static void fr_trie_dump_edge(FILE *fp, fr_trie_t *trie)
{
	fr_cond_assert(trie != NULL);

	fprintf(fp, "NODE-%d\n", trie->number);
	return;
}


typedef void (*fr_trie_dump_t)(FILE *fp, fr_trie_t *trie, char const *key, int keylen);

static void fr_trie_user_dump(FILE *fp, fr_trie_t *trie, char const *key, int keylen)
{
	fr_trie_user_t *user = (fr_trie_user_t *) trie;
	int bytes = BYTES(keylen);

	fprintf(fp, "{ NODE-%d\n", user->number);
	fprintf(fp, "\ttype\tUSER\n");
	fprintf(fp, "\tinput\t{%d}%.*s\n", keylen, bytes, key);

	fprintf(fp, "\tdata\t\"%s\"\n", (char const *) user->data);
	if (!user->trie) {
		fprintf(fp, "}\n\n");
		return;
	}

	fprintf(fp, "\tnext\t");
	fr_trie_dump_edge(fp, user->trie);
	fprintf(fp, "}\n\n");
}

static void fr_trie_node_dump(FILE *fp, fr_trie_t *trie, char const *key, int keylen)
{
	fr_trie_node_t *node = (fr_trie_node_t *) trie;
	int i;
	int bytes = BYTES(keylen);

	fprintf(fp, "{ NODE-%d\n", node->number);
	fprintf(fp, "\ttype\tNODE\n");
	fprintf(fp, "\tinput\t{%d}%.*s\n", keylen, bytes, key);

	fprintf(fp, "\tbits\t%d\n", node->bits);
	fprintf(fp, "\tused\t%d\n", node->used);

	for (i = 0; i < (1 << node->bits); i++) {
		if (!node->trie[i]) continue;

		fprintf(fp, "\t%02x\t", (int) i);
		fr_trie_dump_edge(fp, node->trie[i]);
	}
	fprintf(fp, "}\n\n");
}

#ifdef WITH_PATH_COMPRESSION
static void fr_trie_path_dump(FILE *fp, fr_trie_t *trie, char const *key, int keylen)
{
	fr_trie_path_t *path = (fr_trie_path_t *) trie;
	int bytes = BYTES(keylen);

	fprintf(fp, "{ NODE-%d\n", path->number);
	fprintf(fp, "\ttype\tPATH\n");
	fprintf(fp, "\tinput\t{%d}%.*s\n", keylen, bytes, key);

	fprintf(fp, "\tbits\t%d\n", (int) path->bits);
	fprintf(fp, "\tpath\t");

	fprintf(fp, "%02x %02x", path->key[0], path->key[1]);

	fprintf(fp, "\n");

	fprintf(fp, "\tnext\t");
	fr_trie_dump_edge(fp, path->trie);

	fprintf(fp, "}\n\n");
}
#endif

#ifdef WITH_NODE_COMPRESSION
static void fr_trie_comp_dump(FILE *fp, fr_trie_t *trie, char const *key, int keylen)
{
	fr_trie_comp_t *comp = (fr_trie_comp_t *) trie;
	int i;
	int bytes = BYTES(keylen);

	fprintf(fp, "{ NODE-%d\n", comp->number);
	fprintf(fp, "\ttype\tCOMP\n");
	fprintf(fp, "\tinput\t{%d}%.*s\n", keylen, bytes, key);

	fprintf(fp, "\tbits\t%d\n", comp->bits);
	fprintf(fp, "\tused\t%d\n", comp->used);

	for (i = 0; i < comp->used; i++) {
		fprintf(fp, "\t%d = %02x\t", i, comp->index[i]);
		fr_trie_dump_edge(fp, comp->trie[i]);
	}
	fprintf(fp, "}\n\n");
}

#endif

static fr_trie_dump_t trie_dump[FR_TRIE_MAX] = {
	[ FR_TRIE_USER ] = fr_trie_user_dump,
	[ FR_TRIE_NODE ] = fr_trie_node_dump,
#ifdef WITH_PATH_COMPRESSION
	[ FR_TRIE_PATH ] = fr_trie_path_dump,
#endif
#ifdef WITH_NODE_COMPRESSION
	[ FR_TRIE_COMP ] = fr_trie_comp_dump,
#endif
};


/**  Dump the trie nodes
 *
 */
static int fr_trie_dump_cb(fr_trie_t *trie, fr_trie_callback_t *cb, int keylen, UNUSED bool more)
{
	FILE *fp = cb->ctx;

	if (!trie) return 0;

	TRIE_TYPE_CHECK(dump, -1);

	trie_dump[trie->type](fp, trie, (char const *) cb->start, keylen);
	return 0;
}

/**  Print the strings accepted by a trie to a file
 *
 */
static int fr_trie_print_cb(fr_trie_t *trie, fr_trie_callback_t *cb, int keylen, UNUSED bool more)
{
	int bytes;
	FILE *fp = cb->ctx;
	fr_trie_user_t *user;

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
static int fr_trie_user_cb(fr_trie_t *trie, fr_trie_callback_t *cb, int keylen, UNUSED bool more)
{
	fr_trie_user_t *user;
	void *data;

	if (!trie || (trie->type != FR_TRIE_USER)) return 0;

	user = (fr_trie_user_t *) trie;
	memcpy(&data, &user->data, sizeof(data)); /* const issues */

	/*
	 *	Call the user function with the key, key length, and data.
	 */
	if (cb->user_callback(cb->ctx, cb->start, keylen, data) < 0) {
		return -1;
	}

	return 0;
}

int fr_trie_walk(fr_trie_t *ft, void *ctx, fr_trie_walk_t callback)
{
	fr_trie_callback_t my_cb;
	uint8_t buffer[MAX_KEY_BYTES + 1];

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
static int fr_trie_sprint_cb(fr_trie_t *trie, fr_trie_callback_t *cb, int keylen, bool more)
{
	int bytes, len;
	fr_trie_sprint_ctx_t *ctx;
	fr_trie_user_t *user;

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


static void fr_trie_sprint(fr_trie_t *trie, uint8_t const *key, int start_bit, UNUSED int lineno)
{
	fr_trie_callback_t my_cb;
	fr_trie_sprint_ctx_t my_sprint;
	uint8_t buffer[MAX_KEY_BYTES + 1];
	char out[8192];

	/*
	 *	Initialize the buffer
	 */
	memset(buffer, 0, sizeof(buffer));
	memset(out, 0, sizeof(out));
	if (key) {
		memcpy(buffer, key, BYTES(start_bit) + 1);
	}

	/*
	 *	Where the output data goes.
	 */
	my_sprint.start = out;
	my_sprint.buffer = out;
	my_sprint.buflen = sizeof(out);

	/*
	 *	Where the keys are built.
	 */
	my_cb.start = buffer;
	my_cb.end = buffer + sizeof(buffer);
	my_cb.callback = fr_trie_sprint_cb;
	my_cb.user_callback = NULL;
	my_cb.ctx = &my_sprint;

	/*
	 *	Call the internal walk function to do the work.
	 */
	(void) fr_trie_key_walk(trie, &my_cb, start_bit, false);

	MPRINT3("%.*s%s at %d\n", start_bit, spaces, out, lineno);
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
	void *data;
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
		MPRINT("Failed inserting key %s=%s - %s\n", key, argv[1], fr_strerror());
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

	/*
	 *	The top-level node may have a NULL talloc ctx, which
	 *	is OK.  So we skip that.
	 */
	if (ft->type != FR_TRIE_USER) {
		fprintf(stderr, "Verify failed: trie is malformed\n");
		return -1;
	}

	if (fr_trie_verify(ft->trie) < 0) {
		fprintf(stderr, "Verify failed: %s\n", fr_strerror());
		return -1;
	}

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


/**  Remove a key from the trie.
 *
 *  Try to remove a key, but don't error if we can't.
 */
static int command_try_to_remove(fr_trie_t *ft, UNUSED int argc, char **argv, char *out, size_t outlen)
{
	int bits;
	void *answer;
	char *key;

	if (arg2key(argv[0], &key, &bits) < 0) {
		return -1;
	}

	answer = fr_trie_remove(ft, key, bits);
	if (!answer) {
		strlcpy(out, ".", outlen);
		return 0;
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
		MPRINT("Could not insert key %s=%s - %s\n", argv[0], argv[1], fr_strerror());
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

/** Get chunks from raw data
 *
 */
static int command_chunk(UNUSED fr_trie_t *ft, UNUSED int argc, char **argv, char *out, size_t outlen)
{
	int start_bit, num_bits;
	uint16_t chunk;

	start_bit = atoi(argv[1]);
	num_bits = atoi(argv[2]);

	chunk = get_chunk((uint8_t const *) argv[0], start_bit, num_bits);

	snprintf(out, outlen, "%04x", chunk);
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
	{ "chunk",	command_chunk,	3, 3, true },
	{ "path",	command_path,	2, 2, true },
	{ "insert",	command_insert,	2, 2, false },
	{ "match",	command_match,	1, 1, true },
	{ "lookup",	command_lookup,	1, 1, true },
	{ "remove",	command_remove,	1, 1, true },
	{ "-remove",	command_try_to_remove, 1, 1, true },
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
		fr_skip_whitespace(p);

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

		MPRINT3("[%d] %s\n", lineno, my_argv[0]);
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

	fr_trie_free(ft);
	talloc_free(data_ctx);

	talloc_report_full(NULL, stdout);	/* Print details of any leaked memory */
	talloc_disable_null_tracking();		/* Cleanup talloc null tracking context */

	return rcode;
}
#endif
