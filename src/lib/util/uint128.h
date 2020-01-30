#pragma once
/*
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The original 128bit maths functions were mostly taken from:
 *
 *   http://www.codeproject.com/Tips/617214/UInt-Addition-Subtraction
 *
 * As indicated by the original author, this code is redistributed here
 * under the 2-Clause BSD license.
 *
 * This code is copyright 2014 Jacob F. W.
 *
 * Other code in this file is distributed under the GPLv2 license.
 */

/*
 *   This program is free software; you can redistribute it and/or modify
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
 * @file uint128.h
 * @brief Common functions for manipulating unsigned 128bit integers on
 * platforms without compiler support.
 *
 * @author Jacob F. W
 * @author Arran Cudbard-Bell
 *
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2019 The FreeRADIUS server project
 */

/*
 *	128bit integers are not standard on many compilers
 *	despite SSE2 instructions for dealing with them
 *	specifically.
 */
#ifndef HAVE_128BIT_INTEGERS
/** Create a 128 bit integer value with n bits high
 *
 */
static uint128_t uint128_gen_mask(uint8_t bits)
{
	uint128_t ret;

	rad_assert(bits < 128);

	if (bits > 64) {
		ret.l = 0xffffffffffffffff;
		ret.h = (uint64_t)1 << (bits - 64);
		ret.h ^= (ret.h - 1);
		return ret;
	}
	ret.h = 0;
	ret.l = (uint64_t)1 << bits;
	ret.l ^= (ret.l - 1);

	return ret;
}

/** Increment a 128bit unsigned integer
 *
 * @author Jacob F. W
 */
static uint128_t uint128_increment(uint128_t *n)
{
	uint64 t = (n.l + 1);

	n.h += ((n.l ^ t) & n.l) >> 63;
	n.l = t;

	return n;
}

/** Decrement a 128bit unsigned integer
 *
 * @author Jacob F. W
 */
static uint128_t uint128_decrement(uint128_t *n)
{
	uint64 t = (n.l - 1);
	n.h -= ((t ^ n.l) & t) >> 63;
	n.l = t;

	return n;
}

/** Add two 128bit unsigned integers
 *
 * @author Jacob F. W
 */
static uint128_t uint128_add(uint128_t a, uint128_t b)
{
	uint128_t ret;
	uint64_t tmp = (((a.l & b.l) & 1) + (a.l >> 1) + (b.l >> 1)) >> 63;
	ret.l = a.l + b.l;
	ret.h = a.h + b.h + tmp;
	return ret;
}

/** Subtract one 128bit integer from another
 *
 * @author Jacob F. W
 */
static uint128_t uint128_sub(uint128_t a, uint128_t b)
{
	uint128_t ret;
	uint64_t c;

	ret.l = a.l - b.l;
	c = (((ret.l & b.l) & 1) + (b.l >> 1) + (ret.l >> 1)) >> 63;
	ret.h = a.h - (b.h + c);

	return ret;
}

/** Multiply two unsigned 64bit integers to get an unsigned 128bit integer
 *
 * @author Jacob F. W
 */
static uint128_t uint128_mul64(uint64 u, uint64 v)
{
	uint128_t ret;
	uint64_t u1 = (u & 0xffffffff);
	uint64_t v1 = (v & 0xffffffff);

	uint64_t t = (u1 * v1);

	uint64_t w3 = (t & 0xffffffff);

	uint64_t k = (t >> 32);

	uint64_t w1;

	u >>= 32;
	t = (u * v1) + k;
	k = (t & 0xffffffff);
	w1 = (t >> 32);

	v >>= 32;
	t = (u1 * v) + k;
	k = (t >> 32);

	ret.h = (u * v) + w1 + k;
	ret.l = (t << 32) + w3;
}

/** Multiply two unsigned 128bit integers
 *
 * @author Jacob F. W
 */
static uint128_t uint128_mul(uint128_t n, uint128_t m)
{
	uint128_t ret;

	ret = uint128_mul64(n.l, m.l);
	ret.h += (n.h * m.l) + (n.l * m.h);

	return ret;
}

/** Left shift 128 bit integer
 *
 * @note shift must be 127 bits or less.
 */
static uint128_t uint128_lshift(uint128_t num, uint8_t bits)
{
	rad_assert(bits < 128);

	if (bits >= 64) {
		num.l = 0;
		num.h = num.l << (bits - 64);
		return num;
	}
	num.h = (num.h << bits) | (num.l >> (64 - bits));
	num.l <<= bits;

	return num;
}

/** Right shift 128 bit integer
 *
 * @note shift must be 127 bits or less.
 */
static uint128_t uint128_rshift(uint128_t num, uint8_t bits)
{
	rad_assert(bits < 128);

	if (bits >= 64) {
		num.h = 0;
		num.l = num.h >> (bits - 64);
		return num;
	}
	num.l = (num.l >> bits) | (num.h << (64 - bits));
	num.h >>= bits;

	return num;
}

/** Perform bitwise & of two 128bit unsigned integers
 *
 */
static uint128_t uint128_band(uint128_t a, uint128_t b)
{
	uint128_t ret;
	ret.l = a.l & b.l;
	ret.h = a.h & b.h;
	return ret;
}

/** Perform bitwise | of two 128bit unsigned integers
 *
 */
static uint128_t uint128_bor(uint128_t a, uint128_t b)
{
	uint128_t ret;
	ret.l = a.l | b.l;
	ret.h = a.h | b.h;
	return ret;
}

/** Return whether the integers are equal
 *
 */
static bool uint128_eq(uint128_t a, uint128_t b)
{
	return (a.h == b.h) && (a.l == b.l);
}

/** Return whether one integer is greater than the other
 *
 */
static bool uint128_gt(uint128_t a, uint128_t b)
{
	if (a.h < b.h) return false;
	if (a.h > b.h) return true;
	return (a.l > b.l);
}

/** Creates a new uint128_t from a uint64_t
 *
 */
static uint128_t uint128_new(uint64_t h, uint64_t l) {
	uint128_t ret;
	ret.l = l;
	ret.h = h;
	return ret;
}
#else
#define uint128_gen_mask(_bits) (((_bits) >= 128) ? ~(uint128_t)0x00 : (((uint128_t)1) << (_bits)) - 1)

#define uint128_increment(_a) (*_a++)
#define uint128_decrement(_a) (*_a--)
#define uint128_add(_a, _b) (_a + _b)
#define uint128_sub(_a, _b) (_a - _b)
#define uint128_mul64(_a, _b) (((uint128_t)_a) * ((uint128_t)(_b)))
#define uint128_mul(_a, _b) ((_a) * (_b))

#define uint128_lshift(_num, _bits) (_num << _bits)
#define uint128_rshift(_num, _bits) (_num >> _bits)
#define uint128_band(_a, _b) (_a & _b)
#define uint128_bor(_a, _b) (_a | _b)

#define uint128_eq(_a, _b) (_a == _b)
#define uint128_gt(_a, _b) (_a > _b)

#define uint128_new(_a, _b) ((uint128_t)_b | ((uint128_t)_a << 64))
#endif
