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
#ifndef EXFILE_H
#define EXFILE_H
/*
 * $Id$
 *
 * @file exfile.h
 * @brief Functions for managing concurrent file access.
 *
 * @copyright 2014 The FreeRADIUS server project
 */
RCSIDH(exfile_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif


/*
 *	Multiple threads logging to one or more files.
 */
typedef struct exfile_t exfile_t;

exfile_t *exfile_init(TALLOC_CTX *ctx, uint32_t entries, uint32_t idle, bool locking);
int exfile_open(exfile_t *lf, char const *filename, mode_t permissions);
int exfile_close(exfile_t *lf, int fd);

#ifdef __cplusplus
}
#endif
#endif
