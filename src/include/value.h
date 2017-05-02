/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifndef _FR_VALUE_H
#define _FR_VALUE_H
extern size_t const value_box_field_sizes[];
extern size_t const value_box_offsets[];

#define value_box_foreach(_v, _iv) for (value_box_t *_iv = v; _iv; _iv = _iv->next)

/*
 *	Allocation
 */
value_box_t	*value_box_alloc(TALLOC_CTX *ctx, PW_TYPE type);

void		value_box_clear(value_box_t *data);

/*
 *	Comparison
 */
int		value_box_cmp(value_box_t const *a, value_box_t const *b);

int		value_box_cmp_op(FR_TOKEN op, value_box_t const *a, value_box_t const *b);

/*
 *	Conversion
 */
size_t		value_str_unescape(uint8_t *out, char const *in, size_t inlen, char quote);

int		value_box_hton(value_box_t *dst, value_box_t const *src);

int		value_box_cast(TALLOC_CTX *ctx, value_box_t *dst,
			       PW_TYPE dst_type, fr_dict_attr_t const *dst_enumv,
			       value_box_t const *src);

/*
 *	Assignment
 */
int		value_box_copy(TALLOC_CTX *ctx, value_box_t *dst,  const value_box_t *src);
void		value_box_copy_shallow(TALLOC_CTX *ctx, value_box_t *dst, const value_box_t *src);
int		value_box_steal(TALLOC_CTX *ctx, value_box_t *dst, value_box_t const *src);

int		value_box_strdup(TALLOC_CTX *ctx, value_box_t *dst, char const *src, bool tainted);
int		value_box_strdup_buffer(TALLOC_CTX *ctx, value_box_t *dst, char const *src, bool tainted);
int		value_box_strsteal(TALLOC_CTX *ctx, value_box_t *dst, char *src, bool tainted);
int		value_box_strdup_shallow(value_box_t *dst, char const *src, bool tainted);
int		value_box_strdup_buffer_shallow(TALLOC_CTX *ctx, value_box_t *dst, char const *src, bool tainted);

int		value_box_memdup(TALLOC_CTX *ctx, value_box_t *dst, uint8_t const *src, size_t len, bool tainted);
int		value_box_memdup_buffer(TALLOC_CTX *ctx, value_box_t *dst, uint8_t *src, bool tainted);
int		value_box_memsteal(TALLOC_CTX *ctx, value_box_t *dst, uint8_t const *src, bool tainted);
int		value_box_memdup_shallow(value_box_t *dst, uint8_t *src, size_t len, bool tainted);
int		value_box_memdup_buffer_shallow(TALLOC_CTX *ctx, value_box_t *dst, uint8_t *src, bool tainted);

/*
 *	Parsing
 */
int		value_box_from_str(TALLOC_CTX *ctx, value_box_t *dst,
				    PW_TYPE *src_type, fr_dict_attr_t const *src_enumv,
				    char const *src, ssize_t src_len, char quote);

/*
 *	Printing
 */
char		*value_box_asprint(TALLOC_CTX *ctx, value_box_t const *data, char quote);

size_t		value_box_snprint(char *out, size_t outlen, value_box_t const *data, char quote);
#endif /* _FR_VALUE_H */
