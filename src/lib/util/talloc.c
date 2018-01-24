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

/**
 * @file lib/util/talloc.c
 * @brief Functions which we wish were included in the standard talloc distribution.
 *
 * @copyright 2017 The FreeRADIUS server project
 * @copyright 2017 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/talloc.h>
#include <string.h>

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

/** Call talloc_strdup, setting the type on the new chunk correctly
 *
 * For some bizarre reason the talloc string functions don't set the
 * memory chunk type to char, which causes all kinds of issues with
 * verifying VALUE_PAIRs.
 *
 * @param[in] t The talloc context to hang the result off.
 * @param[in] p The string you want to duplicate.
 * @return
 *	- Duplicated string.
 *	- NULL on error.
 */
char *talloc_typed_strdup(void const *t, char const *p)
{
	char *n;

	n = talloc_strdup(t, p);
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
 * @param[in] t The talloc context to hang the result off.
 * @param[in] fmt The format string.
 * @return
 *	- Formatted string.
 *	- NULL on error.
 */
char *talloc_typed_asprintf(void const *t, char const *fmt, ...)
{
	char *n;
	va_list ap;

	va_start(ap, fmt);
	n = talloc_vasprintf(t, fmt, ap);
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
 * @param[in] t The talloc context to hang the result off.
 * @param[in] fmt The format string.
 * @param[in] ap varadic arguments.
 * @return
 *	- Formatted string.
 *	- NULL on error.
 */
char *talloc_typed_vasprintf(void const *t, char const *fmt, va_list ap)
{
	char *n;

	n = talloc_vasprintf(t, fmt, ap);
	if (!n) return NULL;
	talloc_set_type(n, char);

	return n;
}


/** Binary safe strndup function
 *
 * @param[in] t 	he talloc context to allocate new buffer in.
 * @param[in] in	String to dup, may contain embedded '\0'.
 * @param[in] inlen	Number of bytes to dup.
 * @return duped string.
 */
char *talloc_bstrndup(void const *t, char const *in, size_t inlen)
{
	char *p;

	p = talloc_array(t, char, inlen + 1);
	if (!p) return NULL;
	memcpy(p, in, inlen);
	p[inlen] = '\0';

	return p;
}

/** Trim a bstr (char) buffer
 *
 * Reallocs to inlen + 1 and '\0' terminates the string buffer.
 *
 * @param[in] in	string to trim.  Will be invalid after
 *			this function returns.
 * @param[in] inlen	Length to trim string to.
 * @return
 *	- The realloced string on success.  in then points to invalid memory.
 *	- NULL on failure. In will still be valid.
 */
char *talloc_realloc_bstr(char *in, size_t inlen)
{
	char *n;

	n = talloc_realloc_size(talloc_parent(in), in, inlen + 1);
	if (!n) return NULL;

	n[inlen] = '\0';
	talloc_set_type(n, char);

	return n;
}

/** Concatenate to + from
 *
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
char *talloc_buffer_append_buffer(char *to, char const *from)
{
	size_t to_len, from_len, total_len;
	char *out;

	if (!to || !from) return NULL;

	to_len = talloc_array_length(to);
	from_len = talloc_array_length(from);
	total_len = to_len + (from_len - 1);

	out = talloc_realloc(talloc_parent(to), to, char, total_len);
	if (!out) return NULL;

	memcpy(out + (to_len - 1), from, from_len);
	out[total_len - 1] = '\0';

	return out;
}

/** Concatenate to + ...
 *
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
char *talloc_buffer_append_variadic_buffer(char *to, int argc, ...)
{
	va_list		ap_val, ap_len;
	int		i;

	size_t		to_len, from_len = 0, total_len;
	char		*out, *p;

	if (!to) return NULL;

	va_start(ap_val, argc);
	va_copy(ap_len, ap_val);

	to_len = talloc_array_length(to);

	/*
	 *	Figure out how much we need to realloc
	 */
	for (i = 0; i < argc; i++) {
		char *arg;

		arg = va_arg(ap_len, char *);
		if (!arg) continue;

		from_len += (talloc_array_length(arg) - 1);
	}
	total_len = to_len + from_len;
	if (total_len == to_len) {
		va_end(ap_val);
		va_end(ap_len);
		return to;
	}

	out = talloc_realloc(talloc_parent(to), to, char, total_len);
	if (!out) goto finish;

	p = out + (to_len - 1);

	/*
	 *	Copy the args in
	 */
	for (i = 0; i < argc; i++) {
		char	*arg;
		size_t	len;

		arg = va_arg(ap_val, char *);
		if (!arg) continue;

		len = talloc_array_length(arg);

		memcpy(p, arg, len - 1);
		p += (len - 1);
	}

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
	if (b_len < a_len) return -1;

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
	if (b_len < a_len) return -1;

	return memcmp(a, b, a_len);
}

/** Decrease the reference count on a ptr
 *
 * Ptr will be freed if count reaches zero.
 *
 * This is equivalent to talloc 1.0 behaviour of talloc_free.
 *
 * @param ptr to decrement ref count for.
 */
void talloc_decrease_ref_count(void const *ptr)
{
	void *to_free;

	if (!ptr) return;

	memcpy(&to_free, &ptr, sizeof(to_free));

	talloc_unlink(talloc_parent(ptr), to_free);
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
void talloc_const_free(void const *ptr)
{
	void *tmp;
	if (!ptr) return;

	memcpy(&tmp, &ptr, sizeof(tmp));
	talloc_free(tmp);
}
