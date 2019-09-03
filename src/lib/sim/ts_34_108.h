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
 * @file ts_34_108.h
 * @brief Implementation of the TS.34.108 dummy USMI algorithm
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Arran Cudbard-Bell \<a.cudbardb@freeradius.org\>
 */

/*
 *	Inputs
 */
#define TS_34_108_KI_SIZE	16		//!< Subscriber key.
#define TS_34_108_OP_SIZE	16		//!< Operator code (unique to the operator)
#define TS_34_108_AMF_SIZE	2		//!< Authentication management field.
#define TS_34_108_SQN_SIZE	6		//!< Sequence number.
#define TS_34_108_RAND_SIZE	16		//!< Random challenge.

/*
 *	UMTS Outputs
 */
#define TS_34_108_AK_SIZE	6		//!< Anonymisation key.
#define TS_34_108_AUTN_SIZE	16		//!< Network authentication key.
#define TS_34_108_IK_SIZE	16		//!< Integrity key.
#define	TS_34_108_CK_SIZE	16		//!< Ciphering key.
#define TS_34_108_RES_SIZE	16
#define TS_34_108_AUTS_SIZE	14

int	ts_34_108_umts_generate(uint8_t autn[TS_34_108_AUTN_SIZE],
				uint8_t ik[TS_34_108_IK_SIZE],
				uint8_t ck[TS_34_108_CK_SIZE],
				uint8_t ak[TS_34_108_AK_SIZE],
				uint8_t res[TS_34_108_RES_SIZE],
				uint8_t const amf[TS_34_108_AMF_SIZE],
				uint8_t const ki[TS_34_108_KI_SIZE],
				uint64_t sqn,
				uint8_t const rand[TS_34_108_RAND_SIZE]);
