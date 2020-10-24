#pragma once
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

/**
 * $Id$
 *
 * @file src/lib/soh/base.h
 * @brief Common libraries for parsing Microsoft SOH data
 *
 * @copyright 2010 Phil Mayers (p.mayers@imperial.ac.uk)
 */
RCSIDH(soh_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

int		soh_verify(request_t *request, uint8_t const *data, unsigned int data_len) CC_HINT(nonnull);
uint16_t	soh_pull_be_16(uint8_t const *p);
uint32_t	soh_pull_be_24(uint8_t const *p);
uint32_t	soh_pull_be_32(uint8_t const *p);

int		fr_soh_init(void);
void		fr_soh_free(void);
#ifdef __cplusplus
}
#endif
