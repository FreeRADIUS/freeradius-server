/*
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
 */

/**
 * $Id$
 * @file ts_34_108.h
 * @brief Implementation of the TS.34.108 dummy USMI algorithm
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Arran Cudbard-Bell \<a.cudbardb@freeradius.org\>
 */

#include <stddef.h>
#include <string.h>

#include <freeradius-devel/util/proto.h>
#include "common.h"
#include "ts_34_108.h"

static_assert(TS_34_108_KI_SIZE == TS_34_108_RAND_SIZE,
	      "TS.34.108 Ki and RAND sizes must be identical");

#define TS_34_108_XDOUT_SIZE	TS_34_108_RAND_SIZE
#define TS_34_108_CDOUT_SIZE	8
#define TS_34_108_XMAC_SIZE	8

int ts_34_108_umts_generate(uint8_t autn[TS_34_108_AUTN_SIZE],
			    uint8_t ik[TS_34_108_IK_SIZE],
			    uint8_t ck[TS_34_108_CK_SIZE],
			    uint8_t ak[TS_34_108_AK_SIZE],
			    uint8_t res[TS_34_108_RES_SIZE],
			    uint8_t const amf[TS_34_108_AMF_SIZE],
			    uint8_t const ki[TS_34_108_KI_SIZE],
			    uint64_t sqn,
			    uint8_t const rand[TS_34_108_RAND_SIZE])
{
	size_t		i;
	uint8_t		xdout[TS_34_108_XDOUT_SIZE];
	uint8_t		cdout[TS_34_108_CDOUT_SIZE];
	uint8_t		xmac[TS_34_108_XMAC_SIZE];
	uint8_t		sqn_buff[TS_34_108_SQN_SIZE];
	uint8_t		*p;

	/*
	 *  Step 1:
	 *	XOR to the challenge RAND, a predefined number K (in which at least
	 *	one bit is not zero, see clause 8.2), having the same bit length
	 *	(128 * bits) as RAND.
	 */
	for (i = 0; i < sizeof(xdout); i++) xdout[i] = ki[i] ^ rand[i];

	/*
	 *  Step 2:
	 *	RES (test USIM), XRES (SS), CK, IK and AK are extracted from
	 *	XDOUT.
	 */

	/*
	 *	RES[bits 0,1, ...n-1,n] = f2(XDOUT,n) = XDOUT[bits 0,1, . . .n-1,n]
	 */
	memcpy(res, xdout, TS_34_108_RES_SIZE);

	/*
	 *	CK[bits 0,1, ...126,127] = f3(XDOUT) = XDOUT[bits 8,9, ...126,127,0,1, ...6,7]
	 */
	memcpy(ck, xdout + 1, TS_34_108_CK_SIZE - 1);
	ck[TS_34_108_CK_SIZE - 1] = xdout[0];

	/*
	 *	IK[bits0,1, ...126,127] = f4(XDOUT) = XDOUT[bits16,17, ...126,127,0,1, ...14,15]
	 */
	p = ik;
	memcpy(ik, xdout + 2, TS_34_108_CK_SIZE - 2);
	ik[TS_34_108_CK_SIZE - 2] = xdout[0];
	ik[TS_34_108_CK_SIZE - 1] = xdout[1];

	/*
	 *	AK[bits0,1, ...46,47] = f5(XDOUT) = XDOUT[bits24,25, ...70,71]
	 */
	memcpy(ak, xdout + 3, TS_34_108_AK_SIZE);

	/*
	 *  Step 3:
	 *	Concatenate SQN with AMF to obtain CDOUT
	 */
	uint48_to_buff(sqn_buff, sqn);
	p = cdout;
	memcpy(p, sqn_buff, TS_34_108_SQN_SIZE);
	p += TS_34_108_SQN_SIZE;
	memcpy(p, amf, TS_34_108_AMF_SIZE);

	/*
	 *  Step 4:
	 *	XMAC (test USIM) and MAC (SS) are calculated from XDOUT and CDOUT.
	 */
	for (i = 0; i < sizeof(xmac); i++) xmac[i] = xdout[i] ^ cdout[i];

	/*
	 *  Step 5:
	 *	The SS calculates the authentication token AUTN.
	 */
	p = autn;
	for (i = 0; i < sizeof(sqn_buff); i++) p[i] = sqn_buff[i] ^ ak[i];
	p += sizeof(sqn_buff);
	memcpy(p, amf, TS_34_108_AMF_SIZE);
	p += TS_34_108_AMF_SIZE;
	memcpy(p, xmac, TS_34_108_XMAC_SIZE);

	return 0;
}
