#ifndef FR_PARSER_H
#define FR_PARSER_H

/*
 * parser.h	Structures and prototypes for parsing
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2013 Alan DeKok <aland@freeradius.org>
 */

RCSIDH(parser_h, "$Id$");

#ifdef __cplusplus
extern "C" {
#endif

ssize_t fr_condition_tokenize(const char *start, const char **error);

#ifdef __cplusplus
}
#endif

#endif /* FR_PARSER_H */
