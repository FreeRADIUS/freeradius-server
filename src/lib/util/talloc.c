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

/** Functions which we wish were included in the standard talloc distribution
 *
 * @file src/lib/util/talloc.c
 *
 * @copyright 2017 The FreeRADIUS server project
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/talloc.h>

#include <string.h>
#include <unistd.h>

/** Retrieve the current talloc NULL ctx
 *
 * Talloc doesn't provide a function to retrieve the top level memory tracking context.
 * This function does that...
 *
 * @return the current talloc NULL context or NULL if memory tracking is not enabled.
 */
void *talloc_null_ctx(void)
{
	TALLOC_CTX *null_ctx;
	bool *tmp;

	tmp = talloc(NULL, bool);
	null_ctx = talloc_parent(tmp);
	talloc_free(tmp);

	return null_ctx;
}

/** Called with the fire_ctx is freed
 *
 */
static int _talloc_destructor_fire(fr_talloc_destructor_t *d)
{
	if (d->ds) {
		talloc_set_destructor(d->ds, NULL);	/* Disarm the disarmer */
		TALLOC_FREE(d->ds);			/* Free the disarm trigger ctx */
	}

	return d->func(d->fire, d->uctx);
}

/** Called when the disarm_ctx ctx is freed
 *
 */
static int _talloc_destructor_disarm(fr_talloc_destructor_disarm_t *ds)
{
	talloc_set_destructor(ds->d, NULL);		/* Disarm the destructor */
	return talloc_free(ds->d);			/* Free memory allocated to the destructor */
}

/** Add an additional destructor to a talloc chunk
 *
 * @param[in] fire_ctx		When this ctx is freed the destructor function
 *				will be called.
 * @param[in] disarm_ctx	When this ctx is freed the destructor will be
 *				disarmed. May be NULL.  #talloc_destructor_disarm
 *				may be used to disarm the destructor too.
 * @param[in] func		to call when the fire_ctx is freed.
 * @param[in] uctx		data to pass to the above function.
 * @return
 *	- A handle to access the destructor on success.
 *	- NULL on failure.
 */
fr_talloc_destructor_t *talloc_destructor_add(TALLOC_CTX *fire_ctx, TALLOC_CTX *disarm_ctx,
					      fr_talloc_free_func_t func, void const *uctx)
{
	fr_talloc_destructor_t *d;

	if (!fire_ctx) return NULL;

	d = talloc(fire_ctx, fr_talloc_destructor_t);
	if (!d) return NULL;

	d->fire = fire_ctx;
	d->func = func;
	memcpy(&d->uctx, &uctx, sizeof(d->uctx));

	if (disarm_ctx) {
		fr_talloc_destructor_disarm_t *ds;

		ds = talloc(disarm_ctx, fr_talloc_destructor_disarm_t);
		if (!ds) {
			talloc_free(d);
			return NULL;
		}
		ds->d = d;
		d->ds = ds;
		talloc_set_destructor(ds, _talloc_destructor_disarm);
	}

	talloc_set_destructor(d, _talloc_destructor_fire);

	return d;
}

/** Disarm a destructor and free all memory allocated in the trigger ctxs
 *
 */
void talloc_destructor_disarm(fr_talloc_destructor_t *d)
{
	if (d->ds) {
		talloc_set_destructor(d->ds, NULL);	/* Disarm the disarmer */
		TALLOC_FREE(d->ds);			/* Free the disarmer ctx */
	}

	talloc_set_destructor(d, NULL);			/* Disarm the destructor */
	talloc_free(d);					/* Free the destructor ctx */
}

static int _talloc_link_ctx_free(UNUSED void *parent, void *child)
{
	talloc_free(child);

	return 0;
}

/** Link two different parent and child contexts, so the child is freed before the parent
 *
 * @note This is not thread safe. Do not free parent before threads are joined, do not call from a
 *	child thread.
 *
 * @param parent who's fate the child should share.
 * @param child bound to parent's lifecycle.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int talloc_link_ctx(TALLOC_CTX *parent, TALLOC_CTX *child)
{
	if (!talloc_destructor_add(parent, child, _talloc_link_ctx_free, child)) return -1;

	return 0;
}

/** Return a page aligned talloc memory array
 *
 * Because we can't intercept talloc's malloc() calls, we need to do some tricks
 * in order to get the first allocation in the array page aligned, and to limit
 * the size of the array to a multiple of the page size.
 *
 * The reason for wanting a page aligned talloc array, is it allows us to
 * mprotect() the pages that belong to the array.
 *
 * Talloc chunks appear to be allocated within the protected region, so this should
 * catch frees too.
 *
 * @param[in] ctx	to allocate array memory in.
 * @param[out] start	The first aligned address in the array.
 * @param[in] alignment	What alignment the memory chunk should have.
 * @param[in] size	How big to make the array.  Will be corrected to a multiple
 *			of the page size.  The actual array size will be size
 *			rounded to a multiple of the (page_size), + page_size
 * @return
 *	- A talloc chunk on success.
 *	- NULL on failure.
 */
TALLOC_CTX *talloc_aligned_array(TALLOC_CTX *ctx, void **start, size_t alignment, size_t size)
{
	size_t		rounded;
	size_t		array_size;
	void		*next;
	TALLOC_CTX	*array;

	rounded = ROUND_UP(size, alignment);		/* Round up to a multiple of the page size */
	if (rounded == 0) rounded = alignment;

	array_size = rounded + alignment;
	array = talloc_array(ctx, uint8_t, array_size);		/* Over allocate */
	if (!array) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}

	next = (void *)ROUND_UP((uintptr_t)array, alignment);		/* Round up address to the next multiple */
	*start = next;

	return array;
}

/** Return a page aligned talloc memory pool
 *
 * Because we can't intercept talloc's malloc() calls, we need to do some tricks
 * in order to get the first allocation in the pool page aligned, and to limit
 * the size of the pool to a multiple of the page size.
 *
 * The reason for wanting a page aligned talloc pool, is it allows us to
 * mprotect() the pages that belong to the pool.
 *
 * Talloc chunks appear to be allocated within the protected region, so this should
 * catch frees too.
 *
 * @param[in] ctx	to allocate pool memory in.
 * @param[out] start	A page aligned address within the pool.  This can be passed
 *			to mprotect().
 * @param[out] end	of the pages that should be protected.
 * @param[in] size	How big to make the pool.  Will be corrected to a multiple
 *			of the page size.  The actual pool size will be size
 *			rounded to a multiple of the (page_size), + page_size
 */
TALLOC_CTX *talloc_page_aligned_pool(TALLOC_CTX *ctx, void **start, void **end, size_t size)
{
	size_t		rounded, page_size = (size_t)getpagesize();
	size_t		hdr_size, pool_size;
	void		*next, *chunk;
	TALLOC_CTX	*pool;

	rounded = ROUND_UP(size, page_size);			/* Round up to a multiple of the page size */
	if (rounded == 0) rounded = page_size;

	pool_size = rounded + page_size;
	pool = talloc_pool(ctx, pool_size);			/* Over allocate */
	if (!pool) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}

	chunk = talloc_size(pool, 1);				/* Get the starting address */
	if (!fr_cond_assert((chunk > pool) && ((uintptr_t)chunk < ((uintptr_t)pool + rounded)))) {
		fr_strerror_printf("Initial allocation outside of pool memory");
	error:
		talloc_free(pool);
		return NULL;
	}
	hdr_size = (uintptr_t)chunk - (uintptr_t)pool;

	next = (void *)ROUND_UP((uintptr_t)chunk, page_size);	/* Round up address to the next page */

	/*
	 *	Depending on how talloc allocates the chunk headers,
	 *	the memory allocated here might not align to a page
	 *	boundary, but that's ok, we just need future allocations
	 *	to occur on or after 'next'.
	 */
	if (((uintptr_t)next - (uintptr_t)chunk) > 0) {
		size_t	pad_size;
		void	*padding;

		pad_size = ((uintptr_t)next - (uintptr_t)chunk);
		if (pad_size > hdr_size) {
			pad_size -= hdr_size;			/* Save ~111 bytes by not over-padding */
		} else {
			pad_size = 1;
		}

		padding = talloc_size(pool, pad_size);
		if (!fr_cond_assert(((uintptr_t)padding + (uintptr_t)pad_size) >= (uintptr_t)next)) {
			fr_strerror_printf("Failed padding pool memory");
			goto error;
		}
	}

	*start = next;						/* This is the address we feed into mprotect */
	*end = (void *)((uintptr_t)next + (uintptr_t)rounded);

	if (talloc_set_memlimit(pool, pool_size) < 0) goto error; /* Don't allow allocations outside of the pool */

	return pool;
}

/** Call talloc_strdup, setting the type on the new chunk correctly
 *
 * For some bizarre reason the talloc string functions don't set the
 * memory chunk type to char, which causes all kinds of issues with
 * verifying VALUE_PAIRs.
 *
 * @param[in] ctx	The talloc context to hang the result off.
 * @param[in] p		The string you want to duplicate.
 * @return
 *	- Duplicated string.
 *	- NULL on error.
 */
char *talloc_typed_strdup(TALLOC_CTX *ctx, char const *p)
{
	char *n;

	n = talloc_strdup(ctx, p);
	if (!n) return NULL;
	talloc_set_type(n, char);

	return n;
}

/** Call talloc vasprintf, setting the type on the new chunk correctly
 *
 * For some bizarre reason the talloc string functions don't set the
 * memory chunk type to char, which causes all kinds of issues with
 * verifying VALUE_PAIRs.
 *
 * @param[in] ctx	The talloc context to hang the result off.
 * @param[in] fmt	The format string.
 * @return
 *	- Formatted string.
 *	- NULL on error.
 */
char *talloc_typed_asprintf(TALLOC_CTX *ctx, char const *fmt, ...)
{
	char *n;
	va_list ap;

	va_start(ap, fmt);
	n = talloc_vasprintf(ctx, fmt, ap);
	va_end(ap);
	if (!n) return NULL;
	talloc_set_type(n, char);

	return n;
}

/** Call talloc vasprintf, setting the type on the new chunk correctly
 *
 * For some bizarre reason the talloc string functions don't set the
 * memory chunk type to char, which causes all kinds of issues with
 * verifying VALUE_PAIRs.
 *
 * @param[in] ctx	The talloc context to hang the result off.
 * @param[in] fmt	The format string.
 * @param[in] ap	varadic arguments.
 * @return
 *	- Formatted string.
 *	- NULL on error.
 */
char *talloc_typed_vasprintf(TALLOC_CTX *ctx, char const *fmt, va_list ap)
{
	char *n;

	n = talloc_vasprintf(ctx, fmt, ap);
	if (!n) return NULL;
	talloc_set_type(n, char);

	return n;
}

/** Binary safe strdup function
 *
 * @param[in] ctx 	he talloc context to allocate new buffer in.
 * @param[in] in	String to dup, may contain embedded '\0'.
 * @return duped string.
 */
char *talloc_bstrdup(TALLOC_CTX *ctx, char const *in)
{
	char	*p;
	size_t	len = talloc_array_length(in);

	if (len == 0) len = 1;

	p = talloc_array(ctx, char, len);
	if (!p) return NULL;

	/*
	 * C99 (7.21.1/2) - Length zero results in noop
	 *
	 * But ubsan still flags this, grrr.
	 */
	if (inlen > 0) memcpy(p, in, len - 1);
	p[len] = '\0';

	return p;
}

/** Binary safe strndup function
 *
 * @param[in] ctx 	he talloc context to allocate new buffer in.
 * @param[in] in	String to dup, may contain embedded '\0'.
 * @param[in] inlen	Number of bytes to dup.
 * @return duped string.
 */
char *talloc_bstrndup(TALLOC_CTX *ctx, char const *in, size_t inlen)
{
	char *p;

	p = talloc_array(ctx, char, inlen + 1);
	if (!p) return NULL;

	/*
	 * C99 (7.21.1/2) - Length zero results in noop
	 *
	 * But ubsan still flags this, grrr.
	 */
	if (inlen > 0) memcpy(p, in, inlen);
	p[inlen] = '\0';

	return p;
}

/** Append a bstr to a bstr
 *
 * @param[in] ctx	to allocated.
 * @param[in] to	string to append to.
 * @param[in] from	string to append from.
 * @param[in] from_len	Length of from.
 * @return
 *	- Realloced buffer containing both to and from.
 *	- NULL on failure. To will still be valid.
 */
char *talloc_bstr_append(TALLOC_CTX *ctx, char *to, char const *from, size_t from_len)
{
	char	*n;
	size_t	to_len;

	to_len = talloc_array_length(to);
	if (to[to_len - 1] == '\0') to_len--;	/* Inlen should be length of input string */

	n = talloc_realloc_size(ctx, to, to_len + from_len + 1);
	if (!n) return NULL;

	memcpy(n + to_len, from, from_len);
	n[to_len + from_len] = '\0';
	talloc_set_type(n, char);

	return n;
}

/** Trim a bstr (char) buffer
 *
 * Reallocs to inlen + 1 and '\0' terminates the string buffer.
 *
 * @param[in] ctx	to realloc buffer into.
 * @param[in] in	string to trim.  Will be invalid after
 *			this function returns. If NULL a new zero terminated
 *			buffer of inlen bytes will be allocated.
 * @param[in] inlen	Length to trim string to.
 * @return
 *	- The realloced string on success.  in then points to invalid memory.
 *	- NULL on failure. In will still be valid.
 */
char *talloc_bstr_realloc(TALLOC_CTX *ctx, char *in, size_t inlen)
{
	char *n;

	if (!in) {
		n = talloc_array(ctx, char, inlen);
		n[0] = '\0';
		return n;
	}

	n = talloc_realloc_size(ctx, in, inlen + 1);
	if (!n) return NULL;

	n[inlen] = '\0';
	talloc_set_type(n, char);

	return n;
}

/** Concatenate to + from
 *
 * @param[in] ctx	to allocate realloced buffer in.
 * @param[in] to	talloc string buffer to append to.
 * @param[in] from	talloc string buffer to append.
 * @return
 *	- NULL if to or from are NULL or if the realloc fails.
 *	  Note: You'll still need to free to if this function
 *	  returns NULL.
 *	- The concatenation of to + from.  After this function
 *	  returns to may point to invalid memory and should
 *	  not be used.
 */
char *talloc_buffer_append_buffer(TALLOC_CTX *ctx, char *to, char const *from)
{
	size_t to_len, from_len, total_len;
	char *out;

	if (!to || !from) return NULL;

	to_len = talloc_array_length(to);
	from_len = talloc_array_length(from);
	total_len = to_len + (from_len - 1);

	out = talloc_realloc(ctx, to, char, total_len);
	if (!out) return NULL;

	memcpy(out + (to_len - 1), from, from_len);
	out[total_len - 1] = '\0';

	return out;
}

/** Concatenate to + ...
 *
 * @param[in] ctx	to allocate realloced buffer in.
 * @param[in] to	talloc string buffer to append to.
 * @param[in] argc	how many variadic arguments were passed.
 * @param[in] ...	talloc string buffer(s) to append.
 *			Arguments can be NULL to simplify
 *			calling logic.
 * @return
 *	- NULL if to or from are NULL or if the realloc fails.
 *	  Note: You'll still need to free to if this function
 *	  returns NULL.
 *	- The concatenation of to + from.  After this function
 *	  returns to may point to invalid memory and should
 *	  not be used.
 */
char *talloc_buffer_append_variadic_buffer(TALLOC_CTX *ctx, char *to, int argc, ...)
{
	va_list		ap_val, ap_len;
	int		i;

	size_t		to_len, total_len = 0;
	char		*out, *p;

	if (!to) return NULL;

	va_start(ap_val, argc);
	va_copy(ap_len, ap_val);

	total_len += to_len = talloc_array_length(to) - 1;

	/*
	 *	Figure out how much we need to realloc
	 */
	for (i = 0; i < argc; i++) {
		char *arg;

		arg = va_arg(ap_len, char *);
		if (!arg) continue;

		total_len += (talloc_array_length(arg) - 1);
	}

	/*
	 *	It's a noop...
	 */
	if (total_len == to_len) {
		va_end(ap_val);
		va_end(ap_len);
		return to;
	}

	out = talloc_realloc(ctx, to, char, total_len + 1);
	if (!out) goto finish;

	p = out + to_len;

	/*
	 *	Copy the args in
	 */
	for (i = 0; i < argc; i++) {
		char	*arg;
		size_t	len;

		arg = va_arg(ap_val, char *);
		if (!arg) continue;

		len = talloc_array_length(arg) - 1;

		memcpy(p, arg, len);
		p += len;
	}
	*p = '\0';

finish:
	va_end(ap_val);
	va_end(ap_len);

	return out;
}

/** Compares two talloced uint8_t arrays with memcmp
 *
 * Talloc arrays carry their length as part of the structure, so can be passed to a generic
 * comparison function.
 *
 * @param a	Pointer to first array.
 * @param b	Pointer to second array.
 * @return
 *	- 0 if the arrays match.
 *	- a positive or negative integer otherwise.
 */
int talloc_memcmp_array(uint8_t const *a, uint8_t const *b)
{
	size_t a_len, b_len;

	a_len = talloc_array_length(a);
	b_len = talloc_array_length(b);

	if (a_len > b_len) return +1;
	if (a_len < b_len) return -1;

	return memcmp(a, b, a_len);
}

/** Compares two talloced char arrays with memcmp
 *
 * Talloc arrays carry their length as part of the structure, so can be passed to a generic
 * comparison function.
 *
 * @param a	Pointer to first array.
 * @param b	Pointer to second array.
 * @return
 *	- 0 if the arrays match.
 *	- a positive or negative integer otherwise.
 */
int talloc_memcmp_bstr(char const *a, char const *b)
{
	size_t a_len, b_len;

	a_len = talloc_array_length(a);
	b_len = talloc_array_length(b);

	if (a_len > b_len) return +1;
	if (a_len < b_len) return -1;

	return memcmp(a, b, a_len);
}

/** Decrease the reference count on a ptr
 *
 * Ptr will be freed if count reaches zero.
 *
 * This is equivalent to talloc 1.0 behaviour of talloc_free.
 *
 * @param ptr to decrement ref count for.
 * @return
 *	- 0	The memory was freed.
 *	- >0	How many references remain.
 */
int talloc_decrease_ref_count(void const *ptr)
{
	size_t ref_count;
	void *to_free;

	if (!ptr) return 0;

	memcpy(&to_free, &ptr, sizeof(to_free));

	ref_count = talloc_reference_count(to_free);
	if (ref_count == 0) {
		talloc_free(to_free);
	} else {
		talloc_unlink(talloc_parent(ptr), to_free);
	}

	return ref_count;
}

/** Add a NULL pointer to an array of pointers
 *
 * This is needed by some 3rd party libraries which take NULL terminated
 * arrays for arguments.
 *
 * If allocation fails, NULL will be returned and the original array
 * will not be touched.
 *
 * @param[in] array to null terminate.  Will be invalidated (realloced).
 * @return
 *	- NULL if array is NULL, or if reallocation fails.
 *	- A realloced version of array with an additional NULL element.
 */
void **talloc_array_null_terminate(void **array)
{
	size_t		len;
	TALLOC_CTX	*ctx;
	void		**new;

	if (!array) return NULL;

	len = talloc_array_length(array);
	ctx = talloc_parent(array);

	new = talloc_realloc_fn(ctx, array, len + 1);
	if (!new) return NULL;

	new[len] = NULL;

	return new;
}

/** Remove a NULL termination pointer from an array of pointers
 *
 * If the end of the array is not NULL, NULL will be returned (error).
 *
 * @param[in] array to null strip.  Will be invalidated (realloced).
 * @return
 *	- NULL if array is NULL, if terminating element is not NULL, or reallocation fails.
 *	- A realloced version of array without the terminating NULL element.
 */
void **talloc_array_null_strip(void **array)
{
	size_t		len;
	TALLOC_CTX	*ctx;
	void		**new;

	if (!array) return NULL;

	len = talloc_array_length(array);
	ctx = talloc_parent(array);

	if ((len - 1) == 0) return NULL;

	if (array[len - 1] != NULL) return NULL;

	new = talloc_realloc_fn(ctx, array, len - 1);
	if (!new) return NULL;

	return new;
}

/** Free const'd memory
 *
 * @param[in] ptr	to free.
 */
int talloc_const_free(void const *ptr)
{
	void *tmp;

	if (!ptr) return 0;

	memcpy(&tmp, &ptr, sizeof(tmp));
	return talloc_free(tmp);
}

struct talloc_child_ctx_s {
	struct talloc_child_ctx_s *next;
};

static int _child_ctx_free(TALLOC_CHILD_CTX *list)
{
	while (list->next != NULL) {
		TALLOC_CHILD_CTX *entry = list->next;
		TALLOC_CHILD_CTX *next = entry->next;

		if (talloc_free(entry) < 0) return -1;

		list->next = next;
	}

	return 0;
}

/** Allocate and initialize a TALLOC_CHILD_CTX
 *
 *  The TALLOC_CHILD_CTX ensures ordering for allocators and
 *  destructors.  When a TALLOC_CHILD_CTX is created, it is added to
 *  parent, in FILO order.  In contrast, the basic talloc operations
 *  do not guarantee any kind of order.
 *
 *  When the TALLOC_CHILD_CTX is freed, the children are freed in FILO
 *  order.  That process ensures that the children are freed before
 *  the parent, and that the younger siblings are freed before the
 *  older siblings.
 *
 *  The idea is that if we have an initializer for A, which in turn
 *  initializes B and C.  When the memory is freed, we should do the
 *  operations in the reverse order.
 */
TALLOC_CHILD_CTX *talloc_child_ctx_init(TALLOC_CTX *ctx)
{
	TALLOC_CHILD_CTX *child;

	child = talloc_zero(ctx, TALLOC_CHILD_CTX);
	if (!child) return NULL;

	talloc_set_destructor(child, _child_ctx_free);
	return child;
}

/** Allocate a TALLOC_CHILD_CTX from a parent.
 *
 */
TALLOC_CHILD_CTX *talloc_child_ctx_alloc(TALLOC_CHILD_CTX *parent)
{
	TALLOC_CHILD_CTX *child;

	child = talloc(parent, TALLOC_CHILD_CTX);
	if (!child) return NULL;

	child->next = parent->next;
	parent->next = child;
	return child;
}
