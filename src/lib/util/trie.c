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
#  define WITH_TRIE_VERIFY
#  define MPRINT(...) fprintf(stderr, ## __VA_ARGS__)
#else
#  define MPRINT(...)
#endif

#ifndef WITH_TRIE_VERIFY
#  define fr_trie_node_verify(_x)
#  define fr_trie_verify(_x)
#  ifdef WITH_PATH_COMPRESSION
#    define fr_trie_path_verify(_x)
#  endif
#endif

// @todo - do level compression
// stop merging nodes if a key ends at the top of the level
// otherwise merge so we have at least 2^4 way fan-out, but no more than 2^8
// that should be a decent trade-off between memory and speed

// @todo - generalized function to normalize the trie.

// @todo - add tests to run with / without path compression

// @todo add "depth" for test, which shows how many nodes deep the trie is

// @todo add "nodes" for test, which shows how many nodes are in the trie

// @todo - make this configurable in fr_trie_t, and pass fr_trei_t to
// all internal function.

#ifndef DEFAULT_SIZE
#define DEFAULT_SIZE	(4)
#endif

/*
 *	Macros to swap one for the other.
 */
#define	BITSOF(_x)	((_x) * 8)
#define BYTEOF(_x)	((_x) >> 3)
#define BYTES(_x)	(((_x) + 0x07) >> 3)
DIAG_ON(unused-macros)

/** A data structure which holds a path-compressed key.
 *
 */
typedef struct fr_trie_path_t {
	int			number;		//!< for debug printing
	uint8_t	const		*key;		//!< path information.
	int			length;		//!< length of the path in bits
	int			start_bit;	//!< bit where the path starts
	int			end_bit;	//!< bit where the path ends
	void			*trie;		//!< trie / user ctx associated with this entry
} fr_trie_path_t;

/** A data structure which holds a 2^N way key
 *
 */
typedef struct fr_trie_node_t {
	int			number;		//!< for debug printing
	int			size;		//!< as power of 2.  i.e. 2^1=2, 2^2=4, 2^3=8, etc.
	int			used;		//!< number of used entries
	void			*trie[];	//!< sub-trie array
} fr_trie_node_t;

/** A data structure which holds user ctx data
 *
 */
typedef struct fr_trie_user_t {
	int			number;		//!< for debug printing
	void			*data;		//!< user ctx if we have a match here
	void			*trie;		//!< subtree if the key continues past this point
} fr_trie_user_t;


/** The main trie data structure.
 *
 */
struct fr_trie_t {
	int		number;			//!< for walking back up the trie
	int		default_size;		//!< for trie nodes
	void		*trie;			//!< the first node
};


/*
 *	We pack multiple types of nodes into one pointer for
 *	simplicity.
 */
#define IS_NODE(_x)	((((uintptr_t) _x) & 0x03) == 0x00)

#define IS_USER(_x)	((((uintptr_t) _x) & 0x03) == 0x01)
#define GET_USER(_x)	((fr_trie_user_t *) (((uintptr_t) _x) & ~(uintptr_t) 0x03))
#define PUT_USER(_x)	((void *) (((uintptr_t) _x) | 0x01))

#ifdef WITH_PATH_COMPRESSION
#define IS_PATH(_x)	((((uintptr_t) _x) & 0x03) == 0x03)
#define GET_PATH(_x)	((fr_trie_path_t *) (((uintptr_t) _x) & ~(uintptr_t) 0x03))
#define PUT_PATH(_x)	((void *) (((uintptr_t) _x) | 0x03))

static void *fr_trie_path_merge_paths(fr_trie_t *ft, TALLOC_CTX *ctx, fr_trie_path_t *path1, fr_trie_path_t *path2, int depth) CC_HINT(nonnull);
#endif
static int fr_trie_merge(fr_trie_t *ft, TALLOC_CTX *ctx, void **parent_p, void *a, void *b, int depth);

static int fr_trie_key_insert(fr_trie_t *ft, TALLOC_CTX *ctx, void **parent_p, uint8_t const *key, int start_bit, int end_bit, void *trie) CC_HINT(nonnull);

static void *reparent(TALLOC_CTX *ctx, void *trie)
{
	/*
	 *	Ensure that things are parented correctly, so that
	 *	freeing nodes works.
	 */
	if (IS_USER(trie)) {
		(void) talloc_steal(ctx, GET_USER(trie));
		return trie;

	}

#ifdef WITH_PATH_COMPRESSION
	if (IS_PATH(trie)) {
		(void) talloc_steal(ctx, GET_PATH(trie));
		return trie;
	}
#endif

	fr_cond_assert(IS_NODE(trie));
	(void) talloc_steal(ctx, trie);
	return trie;
}

/** Allocate a 2^N way node
 *
 * @param ft		the root structure of the trie
 * @param ctx		the talloc context, should be the parent node that points to this one.
 * @param size		the number of bits this node will consume
 * @return
 *	- NULL on error
 *	- fr_trie_node_t* on success
 */
static fr_trie_node_t *fr_trie_node_alloc(fr_trie_t *ft, TALLOC_CTX *ctx, int size)
{
	size_t		node_size;
	fr_trie_node_t	*node;

	if (!size || (size > 8)) {
		MPRINT("FAILED %d - %d\n", __LINE__, (int) size);
		return NULL;
	}

#ifndef WITH_PATH_COMPRESSION
	if (size > DEFAULT_SIZE) size = DEFAULT_SIZE;
#endif

	node_size = sizeof(fr_trie_node_t) + (sizeof(node->trie[0]) * (1 << size));
	node = talloc_zero_size(ctx, node_size);
	if (!node) return NULL;

	(void) talloc_set_name_const(node, "fr_trie_node_t");

	node->size = size;
	node->number = ft->number++;

	return node;
}


#ifdef WITH_TRIE_VERIFY
static void *trie_parent(void *trie)
{
	/*
	 *	Ensure that things are parented correctly, so that
	 *	freeing nodes works.
	 */
	if (IS_USER(trie)) {
		return talloc_parent(GET_USER(trie));

	}
#ifdef WITH_PATH_COMPRESSION
	if (IS_PATH(trie)) {
		return talloc_parent(GET_PATH(trie));
	}
#endif

	fr_cond_assert(IS_NODE(trie));
	return talloc_parent(trie);
}

/** Verifies that a node is correct, without recursion
 *
 */
static void fr_trie_node_verify(fr_trie_node_t const *node)
{
	int i, used;

	(void) talloc_get_type_abort_const(node, fr_trie_node_t);

	fr_cond_assert(node->size > 0);
	fr_cond_assert(node->size <= 8);
	fr_cond_assert(node->used >= 0);
	fr_cond_assert(node->used <= (1 << node->size));

	used = 0;
	for (i = 0; i < (1 << node->size); i++) {
		if (!node->trie[i]) continue;

		used++;
	}

	fr_cond_assert(used == node->used);
}

#ifdef WITH_PATH_COMPRESSION
/** Verifies that a path is correct, without recursion
 *
 */
static void fr_trie_path_verify(fr_trie_path_t const *path)
{
	(void) talloc_get_type_abort_const(path, fr_trie_path_t);

	fr_cond_assert(path->start_bit >= 0);
	fr_cond_assert(path->start_bit < 8);
	fr_cond_assert(path->length > 0);
	fr_cond_assert(path->length < (1 << 20));
	fr_cond_assert(path->end_bit > 0);
	fr_cond_assert(path->length < (1 << 20));
	fr_cond_assert((path->start_bit + path->length) == path->end_bit);

	fr_cond_assert(path->key != NULL);
	fr_cond_assert(talloc_parent(path->key) == path);

	if ((path->start_bit == 0) && (path->length >= 8)) {
		fr_cond_assert(path->key[0] > ' ');
		fr_cond_assert(path->key[0] < 0x7f);
	}

	/*
	 *	This is only for testing...
	 */
	if (BYTEOF(path->end_bit) > 2) {
		int i;

		for (i = 1; i < BYTEOF(path->end_bit); i++) {
			fr_cond_assert(path->key[i] > ' ');
			fr_cond_assert(path->key[i] < 0x7f);
		}
	}

	fr_cond_assert(trie_parent(path->trie) == path);
}
#endif	/* WITH_PATH_COMPRESSION */


/** Verifies that an entrie trie is correct, with recursion
 *
 */
static void fr_trie_verify(void *trie)
{
	int i;
	fr_trie_node_t *node;

	if (IS_USER(trie)) return;

#ifdef WITH_PATH_COMPRESSION
	if (IS_PATH(trie)) {
		fr_trie_path_t *path = GET_PATH(trie);

		fr_trie_path_verify(path);

		fr_cond_assert(trie_parent(path->trie) == path);
		fr_trie_verify(path->trie);
		return;
	}
#endif

	node = trie;
	fr_trie_node_verify(node);

	for (i = 0; i < (1 << node->size); i++) {
		if (!node->trie[i]) continue;

		fr_cond_assert(trie_parent(node->trie[i]) == node);

		fr_trie_verify(node->trie[i]);
	}
}
#endif	/* WITH_TRIE_VERIFY */


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


/** Get the longest prefix of the two keys.
 *
 */
static int fr_trie_path_lcp(uint8_t const *key1, int keylen1, uint8_t const *key2, int keylen2, int start_bit)
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


#ifdef WITH_PATH_COMPRESSION
/** Allocate an fr_trie_path_t
 *
 */
static CC_HINT(nonnull) fr_trie_path_t *fr_trie_path_alloc(fr_trie_t *ft, TALLOC_CTX *ctx, uint8_t const *key, int start_bit, int end_bit, void *trie)
{
	fr_trie_path_t *path;
	uint8_t *p;

	fr_cond_assert(end_bit < MAX_KEY_BITS);
	fr_cond_assert(end_bit > 0);
	fr_cond_assert(start_bit < end_bit);
	fr_cond_assert(!IS_PATH(trie));

	path = talloc_zero(ctx, fr_trie_path_t);
	if (!path) return NULL;

	path->start_bit = start_bit & 0x07;
	path->length = end_bit - start_bit;
	path->end_bit = path->start_bit + path->length;
	fr_cond_assert(path->length > 0);
	path->number = ft->number++;

	path->key = p = talloc_memdup(path, key + BYTEOF(start_bit), BYTES(path->end_bit));
	if (!path->key) {
		talloc_free(path);
		return NULL;
	}

	/*
	 *	Mask off the lower bits in the last byte.
	 *
	 *	0 == High bit is used, so we have to mask off the lower 7 bits.
	 *	7 == low bit is used, so we don't need to mask anything off
	 */
	if ((path->end_bit & 0x07) != 0) {
		uint8_t mask;
		int bits;

		bits = path->end_bit & 0x07;		/* bits used 1..7 */
		bits = 8 - bits;			/* bits to clear 7..1 */
		mask = (1 << bits) - 1;			/* bits to clear are now all 1s */

		p[BYTEOF(path->end_bit)] &= ~mask;	/* zero out the low bits */
	}

	/*
	 *	Skip this for some cases.
	 */
	if (IS_USER(trie) && (GET_USER(trie) == NULL)) return path;

	/*
	 *	Ensure that things are parented correctly, so that
	 *	freeing nodes works.
	 */
	path->trie = reparent(path, trie);

	fr_trie_path_verify(path);

	return path;
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


/** Insert an fr_trie_path_t into an fr_trie_node_t;
 *
 *  Note that it may split the input node if the path->length is
 *  smaller than node->size
 */
static int fr_trie_path_merge(fr_trie_t *ft, TALLOC_CTX *ctx, fr_trie_node_t **node_p, fr_trie_path_t *path, int depth)
{
	fr_trie_node_t *node = *node_p;

	fr_trie_path_verify(path);

	/*
	 *	Split the node here and do all kinds of magic
	 */
	if (node->size > path->length) {
		fr_trie_node_t *small;
		void *trie;

		small = fr_trie_node_alloc(ft, ctx, path->length);
		if (!small) return -1;

		if (fr_trie_merge(ft, ctx, &trie, small, PUT_PATH(path), depth) < 0) {
			talloc_free(small);
			return -1;
		}

		fr_cond_assert(trie == small);
		fr_trie_node_verify(small);

		if (fr_trie_merge(ft, ctx, &trie, small, node, depth) < 0) {
			talloc_free(small);
			return -1;
		}

		fr_cond_assert(trie == small);
		fr_trie_node_verify(small);
		*node_p = small;

		return 0;
	}

	if (fr_trie_key_insert(ft, ctx, (void **) node_p, path->key, path->start_bit, path->end_bit, path->trie) < 0) {
		return -1;
	}

	fr_trie_node_verify(node);

	talloc_free(path);
	return 0;
}


/** Merge two keys which have no common prefix.
 *
 *  This function allocates an fr_trie_node_t which is large enough, but not too large.
 *  And then merges the two paths into it.
 */
static fr_trie_node_t *fr_trie_path_merge_disjoint(fr_trie_t *ft, TALLOC_CTX *ctx,
						   fr_trie_path_t *path1, fr_trie_path_t *path2, int depth)
{
	int size;
	fr_trie_node_t *node;
	fr_trie_path_t *td_short, *td_long;

	fr_trie_path_verify(path1);
	fr_trie_path_verify(path2);

	fr_cond_assert(path1->start_bit == path2->start_bit);

	/*
	 *	Figure out which is the shorter of the two paths.
	 */
	if (path1->length < path2->length) {
		td_short = path1;
		td_long = path2;
	} else {
		td_short = path2;
		td_long = path1;
	}

	/*
	 *	@todo - pass in ft->default_size, so we know what the
	 *	default size is.
	 */
	size = DEFAULT_SIZE;
	if (size > td_short->length) size = td_short->length;
	fr_cond_assert(size > 0);
	fr_cond_assert(size <= 8);

	node = fr_trie_node_alloc(ft, ctx, size);
	if (!node) {
		MPRINT("FAILED %d\n", __LINE__);
		return NULL;
	}

	/*
	 *	Fill the new node with the short key
	 */
	if (fr_trie_path_merge(ft, ctx, &node, td_short, depth) < 0) {
		MPRINT("FAILED %d\n", __LINE__);
		talloc_free(node);
		talloc_free(td_short);
		return NULL;
	}

	fr_trie_node_verify(node);

	/*
	 *	And then insert the longer of the two keys
	 */
	if (fr_trie_path_merge(ft, ctx, &node, td_long, depth) < 0) {
		MPRINT("FAILED %d\n", __LINE__);
		talloc_free(node);
		talloc_free(td_long);
		return NULL;
	}

	fr_trie_node_verify(node);

	return node;
}


/** Merge two paths
 *
 * @param ft		the root structure of the trie
 * @param ctx		the talloc ctx
 * @param path1		path from the existing tree.
 * @param path2		path from the insert.  MUST end in user ctx.
 * @param depth		the depth of the current node in the trie
 * @return
 *	- NULL on error.  path1 and path2 are left alone.
 *	- new trie on success.  path1 and path2 are freed
 */
static void *fr_trie_path_merge_paths(fr_trie_t *ft, TALLOC_CTX *ctx, fr_trie_path_t *path1, fr_trie_path_t *path2, int depth)
{
	int prefix_len;
	fr_trie_node_t *node;
	fr_trie_path_t *suffix1, *suffix2, *prefix;

	fr_trie_path_verify(path1);
	fr_trie_path_verify(path2);

	fr_cond_assert(path2->length > 0);
	fr_cond_assert(path1->start_bit == path2->start_bit);

	/*
	 *	path1 is from the existing trie.  path2 is the path we're trying to insert.
	 */
	fr_cond_assert(IS_USER(path2->trie));

	(void) talloc_get_type_abort(path1, fr_trie_path_t);

	prefix_len = fr_trie_path_lcp(path1->key, path1->length, path2->key, path2->length, path1->start_bit);
	if (!prefix_len) {
		return fr_trie_path_merge_disjoint(ft, ctx, path1, path2, depth);
	}

	prefix = fr_trie_path_alloc(ft, ctx, path1->key, path1->start_bit, prefix_len + path1->start_bit, PUT_USER(NULL));
	if (!prefix) {
		return NULL;
	}

	// @fixme - call key_insert instead of merge???

	/*
	 *	There is a prefix.  Pull it off and create the child
	 *	nodes.
	 */
	if (prefix_len < path1->length) {
		suffix1 = fr_trie_path_alloc(ft, ctx, path1->key, path1->start_bit + prefix_len, path1->end_bit, path1->trie);
		if (!suffix1) return NULL;
	} else {
		suffix1 = NULL;
	}

	if (prefix_len < path2->length) {
		suffix2 = fr_trie_path_alloc(ft, ctx, path2->key, path2->start_bit + prefix_len, path2->end_bit, path2->trie);
		if (!suffix2) {
			talloc_free(suffix1);
			return NULL;
		}
	} else {
		suffix2 = NULL;
	}

	/*
	 *	Both paths are the same length.  Skip over them
	 *	entirely, and merge the two subtries.
	 */
	if (!suffix1 && !suffix2) {
		/*
		 *	We can insert, but we can't over-write an entry.
		 */
		if (IS_USER(path1->trie)) {
			MPRINT("FAILED %d prefix %d\n", __LINE__, (int)prefix_len);
			return NULL;
		}

		if (fr_trie_merge(ft, prefix, &prefix->trie, path1->trie, path2->trie, depth + prefix_len) < 0) {
			return NULL;
		}

		goto done;
	}

	if (!suffix1) {
		fr_cond_assert(!IS_PATH(path1->trie));

		if (fr_trie_merge(ft, prefix, &prefix->trie, path1->trie, PUT_PATH(suffix2), depth + prefix->length) < 0) {
			talloc_free(prefix);
			talloc_free(suffix2);
			return NULL;
		}
		goto done;

	} else if (!suffix2) {
		if (fr_trie_merge(ft, prefix, &prefix->trie, PUT_PATH(suffix1), path2->trie, depth + prefix->length) < 0) {
			talloc_free(prefix);
			talloc_free(suffix1);
			return NULL;
		}
		goto done;

	} else {
		node = fr_trie_path_merge_disjoint(ft, prefix, suffix1, suffix2, depth + prefix->length);
		if (!node) {
			talloc_free(prefix);
			talloc_free(suffix1);
			talloc_free(suffix2);
			return NULL;
		}

		(void) talloc_get_type_abort(node, fr_trie_node_t);
	}

	fr_trie_node_verify(node);

	prefix->trie = reparent(prefix, node);

done:
	talloc_free(path1);
	talloc_free(path2);

	fr_trie_path_verify(prefix);

	return PUT_PATH(prefix);
}

/** Concatenate two paths together
 *
 *  This function is used to ensure normal form.  I.e. we can't have a
 *  path directly follow another path.  Instead, we just concatenate
 *  them into one longer path.
 */
static int fr_trie_path_concatenate(fr_trie_path_t *path,
				      uint8_t const *key1, int start_bit1, int keylen1,
				      uint8_t const *key2, int start_bit2, int keylen2)
{
	uint8_t *p, *q;

	fr_cond_assert(((start_bit1 + keylen1) & 0x07) == start_bit2);

	p = talloc_array(path, uint8_t, BYTES(start_bit1 + keylen1 + keylen2));
	if (!p) return -1;

	memcpy(p, key1, BYTES(start_bit1 + keylen1));

	if (start_bit2 == 0) {
		memcpy(p + BYTES(start_bit1 + keylen1), key2, BYTES(keylen2));

	} else {
		uint8_t *out;
		uint8_t mask;
		int bytes2;

		out = p + BYTEOF(start_bit1 + keylen1);

		mask = ((1 << (8 - start_bit2)) - 1);
		out[0] &= ~mask;
		out[0] |= (key2[0] & mask);

		bytes2 = BYTES(start_bit2 + keylen2);
		if (bytes2 > 1) {
			memcpy(out + 1, key2 + 1, bytes2 - 1);
		}
	}

	memcpy(&q, &path->key, sizeof(q));
	talloc_free(q);
	path->key = p;

	path->start_bit = start_bit1;
	path->length = keylen1 + keylen2;
	path->end_bit = path->start_bit + path->length;

	return 0;
}


/**  Add a prefix to a given trie
 *
 * @param ft		the root structure of the trie
 * @param ctx		the talloc ctx
 * @param trie  	the trie which is the suffix
 * @param size		the number of bits in 'input'
 * @param input		the input bits which will be turned into a path / prefix
 * @param start_bit	The start bit in 'input' where the data is located.
 */
static void *fr_trie_path_prefix_add(fr_trie_t *ft, TALLOC_CTX *ctx, void *trie, int size, uint16_t input, int start_bit)
{
	fr_trie_path_t *path;
	int bits_used;
	uint16_t chunk = input;
	uint8_t buffer[2];

	bits_used = start_bit & 0x07;

	chunk <<= (16 - size - bits_used);
	buffer[0] = chunk >> 8;
	buffer[1] = chunk & 0xff;

	if (!IS_PATH(trie)) {
		path = fr_trie_path_alloc(ft, ctx, buffer, bits_used, bits_used + size, trie);
		if (!path) return NULL;

		if (IS_NODE(trie)) (void) talloc_steal(path, trie);

		fr_trie_path_verify(path);
		return PUT_PATH(path);
	}

	fr_cond_assert(IS_PATH(trie));
	path = GET_PATH(trie);

	fr_trie_path_verify(path);

	(void) fr_trie_path_concatenate(path, buffer, bits_used, size, path->key, path->start_bit, path->length);

	return PUT_PATH(talloc_steal(ctx, path));
}
#endif	/* WITH_PATH_COMPRESSION */


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


/** A generic merge routine
 *
 * @param ft		the root structure of the trie
 * @param ctx		the talloc ctx
 * @param parent_p	where the output trie is stored
 * @param a		first mangled trie
 * @param b		second mangled trie
 * @param depth 	bit depth where the trie starts
 */
static int fr_trie_merge(fr_trie_t *ft, TALLOC_CTX *ctx, void **parent_p, void *a, void *b, int depth)
{
	if (!a && !b) {
		*parent_p = NULL;
		return 0;
	}

	if (!a) {
		*parent_p = reparent(ctx, b);
		return 0;
	}

	if (!b) {
		*parent_p = reparent(ctx, a);
		return 0;
	}

	if (IS_USER(a) && IS_USER(b)) {
		printf("FAIL %d\n", __LINE__);
		return -1;
	}

	/*
	 *	Don't matter what 'b' is.  Just recurse to merge it
	 *	in.
	 */
	if (IS_USER(a)) {
		fr_trie_user_t *user = GET_USER(a);

		if (fr_trie_merge(ft, user, &user->trie, user->trie, b, depth) < 0) {
			return -1;
		}

		*parent_p = reparent(ctx, a);
		return 0;
	}

	if (IS_USER(b)) {
		fr_trie_user_t *user = GET_USER(b);

		if (fr_trie_merge(ft, user, &user->trie, user->trie, a, depth) < 0) {
			return -1;
		}

		*parent_p = reparent(ctx, b);
		return 0;
	}

#ifdef WITH_PATH_COMPRESSION
	if (IS_PATH(a) && IS_PATH(b)) {
		/*
		 *	Do LCP and split it off.
		 */
		*parent_p = fr_trie_path_merge_paths(ft, ctx, GET_PATH(a), GET_PATH(b), depth);
		if (!*parent_p) {
			printf("FAIL %d\n", __LINE__);
			return -1;
		}
		return 0;
	}

	if (IS_PATH(a) && IS_NODE(b)) {
		fr_trie_path_t *path = GET_PATH(a);
		fr_trie_node_t *node = b;

		/*
		 *	@todo - if (path->length >= node->size)
		 *	get_chunk(path), and call ourselves
		 *	recursively.
		 */

		if (fr_trie_path_merge(ft, ctx, &node, path, depth) < 0) {
			printf("FAIL %d\n", __LINE__);
			return -1;
		}

		*parent_p = reparent(ctx, node);
		return 0;
	}

	if (IS_PATH(b) && IS_NODE(a)) {
		fr_trie_path_t *path = GET_PATH(b);
		fr_trie_node_t *node = a;

		if (fr_trie_path_merge(ft, ctx, &node, path, depth) < 0) {
			printf("FAIL %d\n", __LINE__);
			return -1;
		}

		*parent_p = reparent(ctx, node);
		return 0;
	}
#endif

	if (IS_NODE(a) && IS_NODE(b)) {
		int i, bits;
		fr_trie_node_t *node1 = a;
		fr_trie_node_t *node2 = b;

		fr_trie_node_verify(node1);
		fr_trie_node_verify(node2);

		if (node1->size == node2->size) {
			for (i = 0; i < (1 << node1->size); i++) {
				if (!node1->trie[i] && !node2->trie[i]) continue;

				if (fr_trie_merge(ft, node1, &node1->trie[i], node1->trie[i],
						  node2->trie[i], depth) < 0) {
					return -1;
				}
			}

			talloc_free(node2);
			fr_trie_node_verify(node1);

			*parent_p = reparent(ctx, node1);
			return 0;
		}

		/*
		 *	Ensure that node1 is the smaller node.
		 */
		if (node1->size > node2->size) {
			fr_trie_node_t *tmp = node1;
			node1 = node2;
			node2 = tmp;
		}

		/*
		 *	Loop over the smaller node, merging in the
		 *	results from the larger node.
		 */
		bits = node2->size - node1->size;

		for (i = 0; i < (1 << node1->size); i++) {
			uint16_t j;

			if (!fr_cond_assert(bits < 8)) return -1;

			for (j = 0; j < (1 << bits); j++) {
				void *subtrie;

				/*
				 *	If the entry in the larger
				 *	node is empty, we don't need
				 *	to do anything here.
				 */
				if (!node2->trie[(i << bits) + j]) continue;

#ifdef WITH_PATH_COMPRESSION
				/*
				 *	Convert the entry in node2
				 *	into a path + trailing
				 *	information.
				 */
				subtrie = fr_trie_path_prefix_add(ft, node1, node2->trie[(i << bits) | j],
								  bits, j, depth);
				if (!fr_cond_assert(subtrie != NULL)) return -1;

				if (fr_trie_merge(ft, node1, &node1->trie[i],
						  node1->trie[i], subtrie, depth) < 0) {
					return -1;
				}
#else
				fr_trie_node_t	*subnode;

				/*
				 *	Allocate a sub-node to fill
				 *	the gap.
				 */
				if (!node1->trie[i]) {
					subnode = node1->trie[i] = fr_trie_node_alloc(ft, node1, bits);
					if (!fr_cond_assert(subnode != NULL)) return -1;

				} else if (IS_NODE(node1->trie[i])) {
					subnode = node1->trie[i];
					if (!fr_cond_assert(IS_NODE(subnode))) return -1;

				} else {
					fr_trie_user_t *user;

					if (!fr_cond_assert(IS_USER(node1->trie[i]))) return -1;
					user = GET_USER(node1->trie[i]);

					subtrie = user->trie;
					if (!subtrie) {
						subnode = user->trie = fr_trie_node_alloc(ft, user, bits);
						if (!fr_cond_assert(subnode != NULL)) return -1;

					} else {
						/*
						 *	No path compression here.
						 */
						if (!fr_cond_assert(IS_NODE(subtrie))) return -1;
						subnode = subtrie;
						if (!fr_cond_assert(subnode->size == bits)) return -1;
					}
				}

				if (fr_trie_merge(ft, subnode, &subnode->trie[j], subnode->trie[j],
						  node2->trie[(i << bits) | j], depth) < 0) {
					return -1;
				}
#endif
			}
		}

		talloc_free(node2);

		*parent_p = reparent(ctx, node1);
		return 0;
	}

	fr_cond_assert(0);

	return -1;
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
 *
 *	@todo - change this into fr_trie_walk(), and have it return trie*
 *	the caller can then turn that into user data
 */
static void *fr_trie_key_match(void *trie, uint8_t const *key, int start_bit, int end_bit, bool exact)
{
	uint16_t chunk;
	void *data;
	fr_trie_node_t *node;
	fr_trie_user_t *user;

	/*
	 *	Nothing is "no match".
	 */
	if (!trie) return NULL;

	/*
	 *	User ctx data.
	 */
	if (IS_USER(trie)) {
		user = GET_USER(trie);

		/*
		 *	We've reached the end of the input.  Return
		 *	the user ctx data.
		 */
		if (start_bit == end_bit) {
			return user->data;
		}

		/*
		 *	Not the end of the input, keep matching.  If
		 *	we have something, return that.
		 */
		data = fr_trie_key_match(user->trie, key, start_bit, end_bit, exact);
		if (data) return data;

		/*
		 *	We didn't find anything deeper in the trie,
		 *	AND we require an exact match.  That's a
		 *	failure.
		 */
		if (exact) return NULL;

		/*
		 *	Return the inexact match.
		 */
		return user->data;
	}

	/*
	 *	No more key and it's not a user ctx node.  That's not
	 *	a match.
	 */
	if (!key || (start_bit == end_bit)) return NULL;

#ifdef WITH_PATH_COMPRESSION
	/*
	 *	Check the path, by checking the longest common prefix
	 *	of it and the input key.
	 */
	if (IS_PATH(trie)) {
		int lcp;
		fr_trie_path_t *path;

		path = GET_PATH(trie);

		/*
		 *	The key ends in the middle of this node.  That's not a
		 *	match.
		 */
		if ((end_bit - start_bit) < path->length) return NULL;

		lcp = fr_trie_path_lcp(path->key, path->length,
				       key + BYTEOF(start_bit), end_bit - start_bit, path->start_bit);

		/*
		 *	The key only matches part of the path.  That's
		 *	not a match.
		 */
		if (lcp < path->length) return NULL;

		/*
		 *	Recurse to match the child trie.
		 */
		return fr_trie_key_match(path->trie, key, start_bit + path->length, end_bit, exact);
	}
#endif

	node = trie;
	fr_trie_node_verify(node);

	/*
	 *	The key ends in the middle of this node.  That's not a
	 *	match.
	 */
	if ((end_bit - start_bit) < node->size) return NULL;

	/*
	 *	Get a chink of data from the key.
	 */
	chunk = get_chunk(key, node->size, start_bit, end_bit);

	/*
	 *	Recurse to match the child trie.
	 */
	return fr_trie_key_match(node->trie[chunk], key, start_bit + node->size, end_bit, exact);
}


/** Insert a binary key into the trie
 *
 *  The key must have at least ((start_bit + keylen) >> 3) bytes
 *
 * @param ft		the root structure of the trie
 * @param ctx		the talloc ctx
 * @param parent_p	pointer to the trie to insert into
 * @param key		the binary key
 * @param start_bit	the start bit
 * @param end_bit	the end bit
 * @param subtrie      	the subtrie to insert after the key
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int fr_trie_key_insert(fr_trie_t *ft, TALLOC_CTX *ctx, void **parent_p,
			      uint8_t const *key, int start_bit, int end_bit, void *subtrie)
{
	int incr;
	int rcode, next;
	uint16_t chunk;
	void *trie = *parent_p;
#ifdef WITH_PATH_COMPRESSION
	fr_trie_path_t *path;
#endif
	fr_trie_node_t *node;

	/*
	 *	We've reached the end of the trie, but we may still
	 *	have key bits to insert.
	 */
	if (!trie) {
		/*
		 *	Just at the end of the key, too.  Add in the
		 *	subtrie to the current location.
		 */
		if (start_bit == end_bit) {
			*parent_p = reparent(ctx, subtrie);
			return 0;
		}

#ifdef WITH_PATH_COMPRESSION
		/*
		 *	Otherise, create a path.
		 */
		path = fr_trie_path_alloc(ft, ctx, key, start_bit, end_bit, subtrie);
		if (!path) return -1;

		*parent_p = PUT_PATH(path);
		return 0;
#else
		int size;

		/*
		 *	Avoid splitting the main node immediately
		 *	after creating it.
		 */
		size = end_bit - start_bit;
		if (size > DEFAULT_SIZE) size = DEFAULT_SIZE;

		node = fr_trie_node_alloc(ft, ctx, size);
		if (!node) return -1;

		*parent_p = trie = node;
		goto insert_node;
#endif
	}

	/*
	 *	We've run out of bits.  The trie we're inserting MUST
	 *	be a user one, otherwise we don't know what to do...
	 */
	if (start_bit == end_bit) {
		fr_trie_user_t *user;

		/*
		 *	Can't insert a user ctx over top of a user
		 *	ctx.
		 */
		if (IS_USER(trie) && IS_USER(subtrie)) {
			MPRINT("FAIL %d\n", __LINE__);
			return -1;
		}

		/*
		 *	We're inserting a trie after a user ctx, that
		 *	should be fine.  It already has the correct
		 *	parent.
		 */
		if (IS_USER(trie)) {
			user = GET_USER(trie);

			return fr_trie_merge(ft, user, &user->trie, user->trie, subtrie, start_bit);
		}

		/*
		 *	Insert this key BEFORE anything else in the
		 *	trie.
		 */
		user = GET_USER(subtrie);

		/*
		 *	Nothing after this user ctx.  Just mash the
		 *	current node after it, and reparent everything
		 *	appropriately.
		 */
		if (!user->trie) {
			*parent_p = reparent(ctx, subtrie);
			user->trie = reparent(user, trie);
			return 0;
		}

		/*
		 *	Merge the two subtries.
		 */
		if (fr_trie_merge(ft, user, &user->trie, user->trie, trie, start_bit) < 0) {
			return -1;
		}

		*parent_p = reparent(ctx, subtrie);
		return 0;
	}

	/*
	 *	Asked to insert the key on top of a user ctx node.
	 *	Instead skip it and insert the key into it's child.
	 */
	if (IS_USER(trie)) {
		fr_trie_user_t *user = GET_USER(trie);

		return fr_trie_key_insert(ft, user, &user->trie, key, start_bit, end_bit, subtrie);
	}

#ifdef WITH_PATH_COMPRESSION
	/*
	 *	The current trie is a path.  Create a path from the
	 *	key, and merge it into the previous path.
	 */
	if (IS_PATH(trie)) {
		int lcp;
		fr_trie_path_t *path2;

		path = GET_PATH(trie);

		fr_cond_assert((start_bit & 0x07) == path->start_bit);

		/*
		 *	See how long the common prefix is.
		 */
		lcp = fr_trie_path_lcp(path->key, path->length,
				       key + BYTEOF(start_bit),
				       end_bit - start_bit,
				       path->start_bit);

		/*
		 *	The key matches this path exactly.  Skip the
		 *	path, and insert the key into it's child.
		 */
		if (lcp == path->length) {
			fr_cond_assert(!IS_PATH(path->trie));

			return fr_trie_key_insert(ft, path, &path->trie,
						  key, start_bit + lcp, end_bit, subtrie);
		}

		/*
		 *	Create a prefix, and merge the two paths
		 *	together.
		 */
		path2 = fr_trie_path_alloc(ft, ctx, key, start_bit, end_bit, subtrie);
		if (!path2) return -1;

		trie = fr_trie_path_merge_paths(ft, ctx, path, path2, start_bit);
		if (!trie) {
			printf("FAIL %d\n", __LINE__);
			talloc_free(path2);
			return -1;
		}

		*parent_p = trie;
		return 0;
	}
#else
insert_node:
#endif

	fr_cond_assert(IS_NODE(trie));
	node = trie;
	fr_trie_node_verify(node);

	next = start_bit + node->size;

	/*
	 *	The key stops in the middle of this node.
	 *
	 *	Create a new node of the appropriate size.
	 *	Add the subtrie to it at the appropriate
	 *	offset. Then merge the current node into the
	 *	new one.
	 */
	if (next > end_bit) {
		fr_trie_node_t *node2;
		int size = end_bit - start_bit;

		node2 = fr_trie_node_alloc(ft, node, size);
		if (!node2) {
			fr_cond_assert(0 == 1);
			MPRINT("FAILED %d\n", __LINE__);
			return -1;
		}

		chunk = get_chunk(key, size, start_bit, end_bit);
		node2->trie[chunk] = reparent(node2, subtrie);
		node2->used = 1;

		if (fr_trie_merge(ft, ctx, parent_p, node2, node, start_bit) < 0) {
			MPRINT("FAILED %d\n", __LINE__);
			return -1;
		}

		// @todo - normalize trie_p?

		return 0;
	}

	chunk = get_chunk(key, node->size, start_bit, end_bit);
	fr_cond_assert(chunk < (1 << node->size));

	incr = (node->trie[chunk] == NULL);

	rcode = fr_trie_key_insert(ft, node, &node->trie[chunk], key, next, end_bit, subtrie);
	if (rcode < 0) return rcode;

	fr_cond_assert(node->trie[chunk] != NULL);
	node->used += incr;

	return 0;
}


/** Remove a key in a trie and return the removed user ctx, if any
 *
 *  The key length MUST match the entries in the trie.
 *
 * @param ft		the root structure of the trie
 * @param ctx	 	the talloc ctx
 * @param[in,out] parent_p where the updated output is stored
 * @param key	 	the key
 * @param start_bit	the start bit
 * @param end_bit	the end bit
 * @return
 *	- NULL on no matching key
 *	- void* user ctx for the removed key
 *
 *  We delete the nodes as we going down the stack, and then collapse
 *  empty nodes going back up the stack.
 */
static void *fr_trie_key_remove(fr_trie_t *ft, TALLOC_CTX *ctx, void **parent_p, uint8_t const *key, int start_bit, int end_bit)
{
	void *data;

	if (!*parent_p) return NULL;

	/*
	 *	Removing a key from a user node.
	 */
	if (IS_USER(*parent_p)) {
		fr_trie_user_t *user;

		user = GET_USER(*parent_p);

		/*
		 *	Still have bits to match, skip this node and
		 *	remove the key from it's children.
		 */
		if (start_bit < end_bit) {
			return fr_trie_key_remove(ft, user, &user->trie, key, start_bit, end_bit);
		}

		/*
		 *	There may be a subtrie.  If so, reparent it to
		 *	this nodes parent.
		 */
		if (user->trie) {
			*parent_p = reparent(ctx, user->trie);
		} else {
			*parent_p = NULL;
		}

		data = user->data;
		talloc_free(user);
		return data;
	}

	/*
	 *	Remove a key from a 2^N way node.
	 */
	if (IS_NODE(*parent_p)) {
		uint16_t chunk;
		fr_trie_node_t *node = *parent_p;

		fr_trie_node_verify(node);

		/*
		 *	The key is too short for this trie.
		 */
		if ((start_bit + node->size) > end_bit) {
			MPRINT("FAIL %d %d + %d = %d, vs %d\n", __LINE__,
				start_bit, node->size, start_bit + node->size, end_bit);
			return NULL;
		}

		chunk = get_chunk(key, node->size, start_bit, end_bit);

		/*
		 *	This entry is empty, fail.
		 */
		if (!node->trie[chunk]) {
			MPRINT("FAIL %d\n", __LINE__);
			return NULL;
		}

		/*
		 *	Recursively remove the key.  If that fails,
		 *	return.
		 */
		data = fr_trie_key_remove(ft, node, &node->trie[chunk], key, start_bit + node->size, end_bit);
		if (!data) {
			MPRINT("FAIL %d\n", __LINE__);
			return NULL;
		}

		/*
		 *	One fewer entry is used.
		 */
		if (!node->trie[chunk]) {
			node->used--;
		}

		/*
		 *	Our node is completely empty.  Free ourselves,
		 *	and tell our parent that we're empty.
		 */
		if (!node->used) {
			talloc_free(node);
			*parent_p = NULL;
			return data;
		}

#ifdef WITH_PATH_COMPRESSION
		/*
		 *	Only one entry?  Try to convert the node into
		 *	a path.
		 */
		if (node->used == 1) {
			int i;
			void *trie;

			for (i = 0; i < (1 << node->size); i++) {
				if (node->trie[i]) {
					chunk = i;
					break;
				}
			}

			fr_cond_assert(i < (1 << node->size));

			/*
			 *	Convert the node to a PATH.
			 */
			trie = fr_trie_path_prefix_add(ft, ctx, node->trie[chunk],
						       node->size, chunk, start_bit);
			if (trie != NULL) {
				talloc_free(node);
				*parent_p = trie;
			}
			return data;
		}
#endif

		/*
		 *	Multiple entries are still used.  Leave the
		 *	node alone, and return.
		 *
		 *	@todo - normalize the trie by trying to squash
		 *	it down again.
		 */
		fr_trie_node_verify(node);
		return data;
	}

#ifdef WITH_PATH_COMPRESSION
	if (IS_PATH(*parent_p)) {
		int lcp;
		fr_trie_path_t *path = GET_PATH(*parent_p);

		fr_trie_path_verify(path);

		/*
		 *	Find out how much of the key matches this path
		 *	entry.
		 *
		 *	If it's only a partial match, we fail.
		 */
		lcp = fr_trie_path_lcp(path->key, path->length,
				       key + BYTEOF(start_bit),
				       (end_bit - start_bit),
				       path->start_bit);
		if (lcp < path->length) {
			printf("FAIL %d\n", __LINE__);
			return NULL;
		}

		fr_trie_path_verify(path);

		/*
		 *	Remove the path recursively.  If not, we fail.
		 */
		data = fr_trie_key_remove(ft, path, &path->trie, key, start_bit + path->length, end_bit);
		if (!data) {
			MPRINT("FAIL %d\n", __LINE__);
			return NULL;
		}

		/*
		 *	This path points to a path.  Concatenate the
		 *	two of them together.
		 */
		if (IS_PATH(path->trie)) {
			fr_trie_path_t *suffix = GET_PATH(path->trie);

			fr_trie_path_verify(suffix);

			if (fr_trie_path_concatenate(path, path->key, path->start_bit, path->length,
						     suffix->key, suffix->start_bit, suffix->length) == 0) {
				path->trie = reparent(path, suffix->trie);

				talloc_free(suffix);
				fr_trie_path_verify(path);
			}
		}

		/*
		 *	This path points to a non-empty trie, leave
		 *	it.
		 */
		if (path->trie) {
			fr_trie_path_verify(path);
			return data;
		}

		talloc_free(path);
		*parent_p = NULL;
		return data;
	}
#endif

	return NULL;
}



/** Allocate a trie
 *
 * @param ctx The talloc ctx
 * @return
 *	- NULL on error
 *	- fr_trie_node_t on success
 */
fr_trie_t *fr_trie_alloc(TALLOC_CTX *ctx)
{
	fr_trie_t *ft;

	ft = talloc_zero(ctx, fr_trie_t);
	if (!ft) return NULL;

#if 0
	/*
	 *	Allocate the first node with an 8-way fanout.
	 */
	ft->trie = fr_trie_node_alloc(ft, 8);
	if (!ft->trie) {
		talloc_free(ft);
		return NULL;
	}
#endif

	return ft;
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
int fr_trie_insert(fr_trie_t *ft, void const *key, size_t keylen, void *data)
{
	fr_trie_user_t *user;

	if (keylen > MAX_KEY_BITS) return -1;

	/*
	 *	Do a lookup before insertion.  If we tried to insert
	 *	the key with new nodes and then discovered a conflict,
	 *	we would not be able to undo the process.  This check
	 *	ensures that the insertion can modify the trie in
	 *	place without worry.
	 */
	if (ft->trie &&
	    (fr_trie_key_match(ft->trie, key, 0, keylen, true) != NULL)) {
		MPRINT("FAILED %d\n", __LINE__);
		return -1;
	}

	user = talloc_zero(ft, fr_trie_user_t);
	if (!user) return -1;

	user->data = data;
	user->number = ft->number++;

	if (fr_trie_key_insert(ft, ft, &ft->trie, key, 0, keylen, PUT_USER(user)) < 0) {
		talloc_free(user);
		return -1;
	}

	return 0;
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
	if (keylen > MAX_KEY_BITS) return NULL;

	if (!ft->trie) return NULL;

	return fr_trie_key_remove(ft, ft, (void **) &ft->trie, key, 0, (int) keylen);
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

static int fr_trie_key_walk(void *trie, fr_trie_callback_t *cb, int depth, bool more)
{
	int i, used;
	uint16_t base;
	int bits_used;
	uint8_t *out;
	fr_trie_node_t *node;

	/*
	 *	Do the callback before anything else.
	 */
	if (cb->callback(trie, cb, depth, more) < 0) return -1;

	/*
	 *	Nothing more to do, retun.
	 */
	if (!trie) {
		fr_cond_assert(depth == 0);
		return 0;
	}

	/*
	 *	User ctx data.  Recurse (if necessary) for any
	 *	subtrie.
	 */
	if (IS_USER(trie)) {
		fr_trie_user_t *user = GET_USER(trie);

		if (!user->trie) return 0;

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
		uint16_t mask;

		base = out[0];
		mask = ~((1 << (8 - bits_used)) - 1);
		base &= mask;
	} else {
		/*
		 *	Nothing used in this byte.  Just set it to zero.
		 */
		base = 0;
	}

	// @todo - check end against cb->end so we don't have buffer overflows...

#ifdef WITH_PATH_COMPRESSION
	/*
	 *	Copy the path over.  By bytes if possible, otherwise
	 *	by bits.
	 */
	if (IS_PATH(trie)) {
		fr_trie_path_t *path;

		path = GET_PATH(trie);

		fr_trie_path_verify(path);

		if (path->start_bit == 0) {
			fr_cond_assert((depth & 0x07) == 0);
			memcpy(out, path->key, BYTES(path->length));

		} else {
			out[0] = base | path->key[0];

			if (BYTES(path->end_bit) > 0) {
				memcpy(out + 1, path->key + 1, BYTES(path->end_bit) - 1);
			}
		}

		return fr_trie_key_walk(path->trie, cb, depth + path->length, more);
	}
#endif

	node = trie;
	fr_trie_node_verify(node);

	/*
	 *	Number of bytes we will have in the output buffer.
	 */
	base <<= 8;
	used = 0;

	for (i = 0; i < (1 << node->size); i++) {
		uint16_t chunk;

		/*
		 *	Nothing on this terminal node, skip it.
		 */
		if (!node->trie[i]) continue;

		/*
		 *	"base" has the top "bits_used" bits used, with
		 *	the bits from the output buffer.
		 *
		 *	"chunk" has the lower "node->size" bits used with
		 *	the bits for this entry.
		 *
		 *	Shift "chunk" left.  OR them together, and
		 *	store them in the output buffer.
		 */
		chunk = i;	/* node->size bits are used here */
		chunk <<= (16 - node->size - bits_used);
		chunk |= base;

		out[0] = chunk >> 8;
		out[1] = chunk & 0xff;

		used++;

		if (fr_trie_key_walk(node->trie[i], cb, depth + node->size,
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
static void fr_trie_dump_edge(FILE *fp, void *trie)
{
	if (IS_USER(trie)) {
		fr_trie_user_t *user = GET_USER(trie);

		fprintf(fp, "NODE-%d\n", user->number);
		return;
	}

	if (IS_NODE(trie)) {
		fr_trie_node_t *node = trie;

		fprintf(fp, "NODE-%d\n", node->number);
		return;
	}

#ifdef WITH_PATH_COMPRESSION
	if (IS_PATH(trie)) {
		fr_trie_path_t *path = GET_PATH(trie);

		fprintf(fp, "NODE-%d\n", path->number);
		fr_trie_path_verify(path);
		return;
	}
#endif
}


/**  Dump the trie nodes
 *
 */
static int fr_trie_dump_cb(void *trie, fr_trie_callback_t *cb, int keylen, UNUSED bool more)
{
	int i, bytes;
	FILE *fp = cb->ctx;
	fr_trie_node_t *node;

	if (!trie) return 0;

	bytes = BYTES(keylen);

	if (IS_USER(trie)) {
		fr_trie_user_t *user = GET_USER(trie);

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
	if (IS_PATH(trie)) {
		fr_trie_path_t *path = GET_PATH(trie);
		fprintf(fp, "{ NODE-%d\n", path->number);
		fprintf(fp, "\ttype\tPATH\n");
		fprintf(fp, "\tinput\t{%d}%.*s\n", keylen, bytes, cb->start);

		fprintf(fp, "\tstart\t%d\n", (int) path->start_bit);
		fprintf(fp, "\tend\t%d\n", (int) path->end_bit);
		fprintf(fp, "\tlength\t%d\n", (int) path->length);
		fprintf(fp, "\tpath\t");

		for (i = 0; i < BYTES(path->end_bit); i++) {
			fprintf(fp, "%02x", path->key[i]);
		}
		fprintf(fp, "\n");

		fr_trie_path_verify(path);

		fprintf(fp, "\tnext\t");
		fr_trie_dump_edge(fp, path->trie);

		fprintf(fp, "}\n\n");
		return 0;
	}
#endif


	node = trie;
	fr_trie_node_verify(node);

	fprintf(fp, "{ NODE-%d\n", node->number);
	fprintf(fp, "\ttype\tTRIE\n");
	fprintf(fp, "\tinput\t{%d}%.*s\n", keylen, bytes, cb->start);

	fprintf(fp, "\tbits\t%d\n", node->size);
	fprintf(fp, "\tused\t%d\n", node->used);

	for (i = 0; i < (1 << node->size); i++) {
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
static int fr_trie_print_cb(void *trie, fr_trie_callback_t *cb, int keylen, UNUSED bool more)
{
	int bytes;
	FILE *fp = cb->ctx;
	fr_trie_user_t *user;

	if (!trie || !IS_USER(trie)) {
		return 0;
	}

	bytes = BYTES(keylen);
	user = GET_USER(trie);

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

	if (!trie || !IS_USER(trie)) return 0;

	user = GET_USER(trie);

	if (cb->user_callback(cb->ctx, cb->start, keylen, user->data) < 0) {
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

typedef struct fr_trie_sprint_ctx_t {
	char	*start;
	char	*buffer;
	size_t	buflen;
} fr_trie_sprint_ctx_t;


/**  Print the strings accepted by a trie to one line
 *
 *  @todo - add a 'more' flag...
 */
static int fr_trie_sprint_cb(void *trie, fr_trie_callback_t *cb, int keylen, bool more)
{
	int bytes, len;
	fr_trie_sprint_ctx_t *ctx;
	fr_trie_user_t *user;

	ctx = cb->ctx;

	if (!trie) {
		len = snprintf(ctx->buffer, ctx->buflen, "{}");
		goto done;
	}

	if (!IS_USER(trie)) return 0;

	bytes = BYTES(keylen);
	user = GET_USER(trie);

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
		MPRINT("Could not match key %s\n", key);
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
#ifdef WITH_TRIE_VERIFY
	fr_trie_verify(ft->trie);
#else
	fr_cond_assert(ft != NULL);
#endif
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

	if (IS_USER(ft->trie)) {
		talloc_free(GET_USER(ft->trie));
	}
#ifdef WITH_PATH_COMPRESSION
	else if (IS_PATH(ft->trie)) {
		talloc_free(GET_PATH(ft->trie));
	}
#endif
	else {
		talloc_free(ft->trie);
	}

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

	lcp = fr_trie_path_lcp(key1, keylen1, key2, keylen2, start_bit);

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
typedef struct fr_trie_command_t {
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
		exit(1);
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
		while (isspace((int) *p)) p++;

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
