/*
 * tree.c	radius request tree maintenence
 *
 * Version:	$Id$
 *
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Chad Miller <cmiller@surfsouth.com>
 */

static const char rcsid[] =
"$Id$";

#include <assert.h>
#include "autoconf.h"
#include "request_storage.h"
#include "radiusd.h"

#define forestsize 256
#define NODE_MAGIC 0xfedfeeb0

typedef struct REQTREE {
	struct REQTREE *leftbranch, *rightbranch, *parent;
	REQUEST *req;
	unsigned int magic;
} REQTREE;

static REQTREE *reqtreehead[256];
static int numberrequests;

static void do_rt_add(REQTREE **, REQUEST *);
static void do_rt_delete(REQUEST *);
static REQUEST *do_rt_find(REQTREE **, REQUEST *);
static void do_rt_walk(REQTREE **, RL_WALK_FUNC, void *);
static REQUEST *do_rt_next(REQUEST *);

int rt_init(void);
REQUEST *rt_find(REQUEST *);
void rt_add(REQUEST *);
void rt_delete(REQUEST *);
void rt_walk(RL_WALK_FUNC, void *);
int rt_num_requests(void);
REQUEST *rt_next(REQUEST *);

/* put in main() */
int rt_init() {
	int i;

	for (i = 0; i < forestsize; i++) 
		reqtreehead[i] = NULL;
	numberrequests = 0;
	return(0);
}

REQUEST *rt_find(REQUEST *item) {
	return(do_rt_find(&(reqtreehead[item->packet->id%forestsize]), item));
}

REQUEST *rt_next(REQUEST *item) {
	return(do_rt_next(item));
}

void rt_add(REQUEST *item) {
	assert(item->container == NULL);
	do_rt_add(&(reqtreehead[item->packet->id%forestsize]), item);
}

void rt_delete(REQUEST *item) {
	do_rt_delete(item); /* duh.  consistency. */
}

void rt_walk(RL_WALK_FUNC func, void *data) {
	int i;
	for (i = 0; i < forestsize; i++) 
		do_rt_walk(&(reqtreehead[i]), func, data);
}

int rt_num_requests() {
	return(numberrequests);
}




/*  private functions  */

/* 
 * TODO: 
 *   - write these functions iteratively, for speed
 *   - figure out how the compiler will order the REQUEST struct (in a 64-bit-word-safe way), so a memcmp() is possible
 *   - remove or #ifdef assert()ions
 */


#define self (*tree)

#define REQCOMPARE(LEFT, RIGHT, HIT) \
	if (reqobject->packet->code < self->req->packet->code) { \
		LEFT; \
	} else if (reqobject->packet->code > self->req->packet->code) { \
		RIGHT; \
	} else { \
		if (reqobject->packet->src_port < self->req->packet->src_port) { \
			LEFT; \
		} else if (reqobject->packet->src_port > self->req->packet->src_port) { \
			RIGHT; \
		} else { \
			if (reqobject->packet->src_ipaddr < self->req->packet->src_ipaddr) { \
				LEFT; \
			} else if (reqobject->packet->src_ipaddr > self->req->packet->src_ipaddr) { \
				RIGHT; \
			} else { \
				HIT; \
			} \
		} \
	}
 
static void do_rt_walk(REQTREE **tree, RL_WALK_FUNC fun, void *data) {
	if (self == NULL)
		return;

	assert(self->magic == NODE_MAGIC);

	if (self->leftbranch != NULL) {
		assert(self->leftbranch->parent == self);
		do_rt_walk(&(self->leftbranch), fun, data);
	}

	if (self->rightbranch != NULL) {
		assert(self->rightbranch->parent == self);
		do_rt_walk(&(self->rightbranch), fun, data);
	}

	fun(self->req, data);  /* last, since after this, all bets are off WRT status of self */
}


static void do_rt_add(REQTREE **tree, REQUEST *reqobject) {
	int cmp;

	if (self == NULL) { /* first node */
		(self = rad_malloc(sizeof(REQTREE)));
		self->req = reqobject;
		self->magic = NODE_MAGIC;
		self->leftbranch = NULL;
		self->rightbranch = NULL;
		self->parent = NULL;
		(REQTREE *)reqobject->container = self;
		numberrequests += 1;
		return;
	}

	assert(self->magic == NODE_MAGIC);
	assert((self->parent == NULL) || (self->parent->magic == NODE_MAGIC));
	assert((self->parent == NULL) || (self->parent->leftbranch == self) || (self->parent->rightbranch == self));
	assert((self->leftbranch == NULL) || (self->leftbranch->parent == self));
	assert((self->rightbranch == NULL) || (self->rightbranch->parent == self));

	REQCOMPARE( cmp = -1, cmp = 1, cmp = 0 );

	if (self->req == reqobject) {
		printf("ERROR: attempted insert of same request\n");
		return;
	}

	if (cmp == 0) {
		printf("ERROR: attempted insert of request with same values -- %d, %d, %d\n", reqobject->packet->code, reqobject->packet->src_port, reqobject->packet->src_ipaddr);
		return;
	}  /* or */   /* FIXME -- decide which to do */
	assert(cmp != 0);  /* these aren't allowed */

	if (cmp < 0) {
		if (self->leftbranch == NULL) {
			self->leftbranch = rad_malloc(sizeof(REQTREE));
			self->leftbranch->req = reqobject;
			self->leftbranch->parent = self;
			self->leftbranch->leftbranch = NULL;
			self->leftbranch->rightbranch = NULL;
			self->leftbranch->magic = NODE_MAGIC;
			(REQTREE *)reqobject->container = self->leftbranch;
			numberrequests += 1;
		} else {
			assert(self->leftbranch->magic == NODE_MAGIC);
			assert((self->rightbranch == NULL) || (self->rightbranch->parent == self));
			assert((self->leftbranch == NULL) || (self->leftbranch->parent == self));
			do_rt_add(&(self->leftbranch), reqobject);
		}
	} else {
		if (self->rightbranch == NULL) {
			self->rightbranch = rad_malloc(sizeof(REQTREE));
			self->rightbranch->req = reqobject;
			self->rightbranch->parent = self;
			self->rightbranch->leftbranch = NULL;
			self->rightbranch->rightbranch = NULL;
			self->rightbranch->magic = NODE_MAGIC;
			(REQTREE *)reqobject->container = self->rightbranch;
			numberrequests += 1;
		} else {
			assert(self->rightbranch->magic == NODE_MAGIC);
			assert((self->rightbranch == NULL) || (self->rightbranch->parent == self));
			assert((self->leftbranch == NULL) || (self->leftbranch->parent == self));
			do_rt_add(&(self->rightbranch), reqobject);
		}
	}
}


static void do_rt_delete(REQUEST *reqobject) {
	REQTREE *doppelganger;
	REQTREE **tree; /* we find this in a moment */

	if (reqobject == NULL) {
		return;
	}

	self = (REQTREE *)reqobject->container;

	assert(self != NULL);
	assert(self->magic == NODE_MAGIC);
	assert((self->parent == NULL) || (self->parent->magic == NODE_MAGIC));
	assert((self->parent == NULL) || ((self->parent->rightbranch == self) || (self->parent->leftbranch == self)));
	assert((self->rightbranch == NULL) || (self->rightbranch->parent == self));
	assert((self->leftbranch == NULL) || (self->leftbranch->parent == self));
	assert((self->leftbranch == NULL) || (self->leftbranch->req->packet->code <= self->req->packet->code));
	assert((self->rightbranch == NULL) || (self->req->packet->code <= self->rightbranch->req->packet->code));
	assert((self->rightbranch == NULL) || (self->leftbranch == NULL) || (self->leftbranch->req->packet->code <= self->rightbranch->req->packet->code));

	assert(reqobject != NULL);  

	doppelganger = self;

	assert(self != NULL);  
	if ((self->rightbranch == NULL) || (self->leftbranch == NULL)) { /* easy -- link-up only child */
		REQTREE *onlychild;
		onlychild = (self->rightbranch == NULL) ? self->leftbranch : self->rightbranch;

		if (onlychild != NULL) {  /* perhaps BOTH are NULL */
			onlychild->parent = self->parent;
		}

		if (self->parent != NULL) {  
			assert(self->parent != self);
			if (self->parent->rightbranch == self) {
				self->parent->rightbranch = onlychild;
			} else {
				self->parent->leftbranch = onlychild;
			}
		} else {  /* funny case of being the root */
			reqtreehead[self->req->packet->id] = onlychild;
		}

	} else { /* we have to do this the ugly way */
		REQTREE *graftpoint;

		graftpoint = self->rightbranch;
		while (graftpoint->leftbranch != NULL) {
			graftpoint = graftpoint->leftbranch;
		}

		assert(graftpoint != NULL);
		assert(graftpoint->leftbranch == NULL);

		/* reattach left side to right's leftmost free spot */
		self->leftbranch->parent = graftpoint;
		graftpoint->leftbranch = self->leftbranch;

		/* link up right side */
		self->rightbranch->parent = self->parent;
		if (self->parent != NULL) {  
			assert(self->parent != self);
			if (self->parent->rightbranch == self) {
				self->parent->rightbranch = self->rightbranch;
			} else {
				self->parent->leftbranch = self->rightbranch;
			}
		} else {  /* funny case of being the root */
			reqtreehead[self->req->packet->id] = self->rightbranch;
		}
	}

	assert((self == NULL) || (self->parent == NULL) || (self->parent->magic == NODE_MAGIC));
	assert((self == NULL) || (self->rightbranch == NULL) || (self->rightbranch->magic == NODE_MAGIC));
	assert((self == NULL) || (self->leftbranch == NULL) || (self->leftbranch->magic == NODE_MAGIC));

	assert(doppelganger->magic == NODE_MAGIC);

	numberrequests -= 1;

	/* free structure */
	doppelganger->magic -= 1; 
	free(doppelganger);

	/* free request?  Alan's request_list does. */
}


static REQUEST *do_rt_find(REQTREE **tree, REQUEST *reqobject) {

	if (self == NULL) {
		return(NULL);
	}

	assert(self->magic == NODE_MAGIC);
	assert((self->parent == NULL) || (self->parent->magic == NODE_MAGIC));

	REQCOMPARE( do_rt_find(&(self->leftbranch), reqobject), do_rt_find(&(self->rightbranch), reqobject), return(self->req) );

	return(NULL); /* avoid compiler warnings */
}


static REQUEST *do_rt_next(REQUEST *reqobject) {
	REQTREE *ptr, *next;
	int i;
	/* this should/must walk in the same order as walk() */

	if (reqobject != NULL) {
		ptr = ((REQTREE *)reqobject->container);
		assert(ptr != NULL);

		if (ptr->parent != NULL) {
			if ((ptr->parent->leftbranch == ptr) && 
					(ptr->parent->rightbranch != NULL)) {
				next = ptr->parent->rightbranch;
				while (next->leftbranch != NULL) {
					next = next->leftbranch;
				}
				return(next->req);
			} else {
				return(ptr->parent->req);
			}
		} else {
			i = (ptr->req->packet->id + 1) % 256;
			while (reqtreehead[i] == NULL) {
				i = (i + 1) % 256;
			}
			assert(reqtreehead[i] != NULL);

			next = reqtreehead[i];
			while (next->leftbranch) {
				next = next->leftbranch;
			}

			if (ptr == next) { /* we looped */
				return(NULL);
			} else {
				return(next->req);
			}
		}
	} else {  /* we were passed a NULL, so we give back the first request we have. */
		i = 0;
		while ((reqtreehead[i] == NULL) && (i < 256)) {
			i = i + 1;
		}

		if (reqtreehead[i] == NULL) 
			return(NULL);

		next = reqtreehead[i];
		while (next->leftbranch) {
			next = next->leftbranch;
		}
		return(next->req);
	}

	return(NULL); /* kill warnings */
}
