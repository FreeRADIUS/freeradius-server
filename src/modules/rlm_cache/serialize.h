/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/*
 * $Id$
 * @file serialize.h
 * @brief Serialize and deserialise cache entries.
 *
 * @author Arran Cudbard-Bell
 * @copyright 2014  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2014  The FreeRADIUS server project
 */
RCSIDH(serialize_h, "$Id$")

int cache_serialize(TALLOC_CTX *ctx, char **out, rlm_cache_entry_t *c);
int cache_deserialize(rlm_cache_entry_t *c, char *in, ssize_t inlen);
