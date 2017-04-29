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

value_box_t	*value_box_alloc(TALLOC_CTX *ctx, PW_TYPE type);

void		value_box_list_free(value_box_t **head);

int		value_box_cmp(value_box_t const *a, value_box_t const *b);

int		value_box_cmp_op(FR_TOKEN op, value_box_t const *a, value_box_t const *b);

size_t		value_str_unescape(uint8_t *out, char const *in, size_t inlen, char quote);

void		value_box_clear(value_box_t *data);

int		value_box_from_str(TALLOC_CTX *ctx, value_box_t *dst,
				    PW_TYPE *src_type, fr_dict_attr_t const *src_enumv,
				    char const *src, ssize_t src_len, char quote);

int		value_box_hton(value_box_t *dst, value_box_t const *src);

int		value_box_cast(TALLOC_CTX *ctx, value_box_t *dst,
			       PW_TYPE dst_type, fr_dict_attr_t const *dst_enumv,
			       value_box_t const *src);

value_box_t	value_box_dup(TALLOC_CTX *ctx, const value_box_t *src);

void		value_box_copy_shallow(value_box_t *dst, const value_box_t *src);

int		value_box_copy(TALLOC_CTX *ctx, value_box_t *dst,  const value_box_t *src);

int		value_box_talloc_strcpy(VALUE_PAIR *vp, void const *src);

size_t		value_box_snprint(char *out, size_t outlen, value_box_t const *data, char quote);

int		value_box_steal(TALLOC_CTX *ctx, value_box_t *dst, value_box_t const *src);

char		*value_box_asprint(TALLOC_CTX *ctx, value_box_t const *data, char quote);

#endif /* _FR_VALUE_H */
