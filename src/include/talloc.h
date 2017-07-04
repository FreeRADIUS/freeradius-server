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
#ifndef _FR_TALLOC_H
#define _FR_TALLOC_H

#include <talloc.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>

void		*talloc_null_ctx(void);

char		*talloc_typed_strdup(void const *t, char const *p);

char		*talloc_typed_asprintf(void const *t, char const *fmt, ...) CC_HINT(format (printf, 2, 3));

char		*talloc_typed_vasprintf(void const *t, char const *fmt, va_list ap) CC_HINT(format (printf, 2, 0)) CC_HINT(nonnull (2));

char		*talloc_bstrndup(void const *t, char const *in, size_t inlen);

int		talloc_memcmp_array(uint8_t const *a, uint8_t const *b);

int		talloc_memcmp_bstr(char const *a, char const *b);

void		talloc_decrease_ref_count(void const *ptr);

void		**talloc_array_null_terminate(void **array);

void		**talloc_array_null_strip(void **array);

#endif
