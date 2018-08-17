#pragma once
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

/**
 * $Id$
 * @file comp128.h
 * @brief Implementations of comp128v1, comp128v2, comp128v3 algorithms
 *
 * @note The above GPL license only applies to comp128v1, the license for comp128v2 and comp128v3 is unknown.
 *
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 Hacking projects [http://www.hackingprojects.net/]
 * @copyright 2009 Sylvain Munaut <tnt@246tNt.com>
 */
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

void comp128v1(uint8_t sres[4], uint8_t kc[8], uint8_t const ki[16], uint8_t const rand[16]);
void comp128v23(uint8_t sres[4], uint8_t kc[8], uint8_t const ki[16], uint8_t const rand[16], bool v2);
