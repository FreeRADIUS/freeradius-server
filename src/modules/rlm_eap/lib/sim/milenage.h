/**
 * @file rlm_eap/lib/sim/milenage.h
 * @brief 3GPP AKA - Milenage algorithm (3GPP TS 35.205, .206, .207, .208)
 *
 * This file implements an example authentication algorithm defined for 3GPP
 * AKA. This can be used to implement a simple HLR/AuC into hlr_auc_gw to allow
 * EAP-AKA to be tested properly with real USIM cards.
 *
 * This implementations assumes that the r1..r5 and c1..c5 constants defined in
 * TS 35.206 are used, i.e., r1=64, r2=0, r3=32, r4=64, r5=96, c1=00..00,
 * c2=00..01, c3=00..02, c4=00..04, c5=00..08. The block cipher is assumed to
 * be AES (Rijndael).
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * @copyright 2017 The FreeRADIUS server project
 * @copyright 2006-2007 <j@w1.fi>
 */
#include <stddef.h>

int	milenage_umts_generate(uint8_t autn[16], uint8_t ik[16], uint8_t ck[16], uint8_t *res, size_t *res_len,
			       uint8_t const opc[16], uint8_t const amf[2], uint8_t const k[16],
			       uint8_t const sqn[6], uint8_t const rand[16]);

int	milenage_auts(uint8_t sqn[6],
		      uint8_t const opc[16], uint8_t const k[16], uint8_t const rand[16], uint8_t const auts[14]);

int	milenage_gsm_generate(uint8_t sres[4], uint8_t kc[8],
			      uint8_t const opc[16], uint8_t const k[16], uint8_t const rand[16]);

int	milenage_check(uint8_t ik[16], uint8_t ck[16], uint8_t *res, size_t *res_len, uint8_t *auts,
		       uint8_t const opc[16], uint8_t const k[16], uint8_t const sqn[6],
		       uint8_t const rand[16], uint8_t const autn[16]);
