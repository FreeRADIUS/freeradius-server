#ifndef FR_SOH_H
#define FR_SOH_H

/*
 * @file soh.h
 * @brief Microsoft SoH support
 *
 * Version:     $Id$
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
 * Copyright 2010 Phil Mayers <p.mayers@imperial.ac.uk>
 */

#include <freeradius-devel/ident.h>
RCSIDH(soh_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

  int soh_verify(REQUEST *request, VALUE_PAIR *sohvp, const uint8_t *data, unsigned int data_len);
uint16_t soh_pull_be_16(const uint8_t *p);
uint32_t soh_pull_be_24(const uint8_t *p);
uint32_t soh_pull_be_32(const uint8_t *p);

#ifdef __cplusplus
}
#endif

#endif
