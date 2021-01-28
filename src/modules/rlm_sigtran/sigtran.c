/*
 * @copyright (c) 2016, Network RADIUS SARL (license@networkradius.com)
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Network RADIUS SARL nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * $Id$
 * @file rlm_sigtran/sigtran.c
 * @brief Miscellaneous functions.
 */
#define LOG_PREFIX "rlm_sigtran - "

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/sccp/sccp.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include "sigtran.h"

/** Conversion table to transform ASCII to Telephony Binary Coded Decimal
 *
 * Should be safe to use without validation, invalid digits will be replaced
 * with zeroes.
 */
uint8_t const ascii_to_tbcd[] = {
	[0] = 0,
	['0'] = 0x00,
	['1'] = 0x01,
	['2'] = 0x02,
	['3'] = 0x03,
	['4'] = 0x04,
	['5'] = 0x05,
	['6'] = 0x06,
	['7'] = 0x07,
	['8'] = 0x08,
	['9'] = 0x09,
	['*'] = 0x0a,
	['#'] = 0x0b,
	['a'] = 0x0c,
	['b'] = 0x0d,
	['c'] = 0x0e,
	[255] = 0
};

/** Check is a char is valid Telephony Binary Coded Decimal
 *
 */
uint8_t const is_char_tbcd[] = {
	[0] = 0,
	['0'] = 1,
	['1'] = 1,
	['2'] = 1,
	['3'] = 1,
	['4'] = 1,
	['5'] = 1,
	['6'] = 1,
	['7'] = 1,
	['8'] = 1,
	['9'] = 1,
	['*'] = 1,
	['#'] = 1,
	['a'] = 1,
	['b'] = 1,
	['c'] = 1,
	[255] = 0
};

int sigtran_ascii_to_tbcd(TALLOC_CTX *ctx, uint8_t **out, char const *digits)
{
	size_t	len = talloc_array_length(digits) - 1;
	size_t 	outlen = (len / 2) + (len & 0x01);
	uint8_t	*p;
	size_t	i;

	if (len == 0) return -1;

	*out = p = talloc_array(ctx, uint8_t, outlen);

	/*
	 *	Encode each digit as BCD
	 *	Digit 0 goes in low nibble.
	 *	Digit 1 goes in high nibble.
	 *	Digit 3 goes in low nibble.
	 *	Digit 4 goes in high nibble and so on...
	 */
	for (i = 0; i < (len - 1); i += 2) {
		(*p++) = ascii_to_tbcd[(uint8_t) digits[i]] | (ascii_to_tbcd[(uint8_t) digits[i + 1]] << 4);
	}

	/*
	 *	If the number of digits is odd, then the last nibble
	 *	(which will be high) is set to 0xf0.
	 */
	if (len & 0x01) {
		*p = ascii_to_tbcd[(uint8_t) digits[i]];
		*p |= 0xf0;
	}

	return 0;
}

/** Convert a global title to wire format for SCCP
 *
 * @param[in] ctx	To allocate the buffer in.
 * @param[out] out	Where to write the SCCP global title value.
 * @param[in] gt_ind	One of the SCCP_TITLE_IND_* macros.
 *			- SCCP_TITLE_IND_NONE			- Don't call this function...
 *			- SCCP_TITLE_IND_NATURE_ONLY		- Nature of address indicator only.
 *			- SCCP_TITLE_IND_TRANSLATION_ONLY	- Translation type indicator only.
 *			- SCCP_TITLE_IND_TRANS_NUM_ENC		- Translation type, numbering plan, encoding scheme.
 *			- SCCP_TITLE_IND_TRANS_NUM_ENC_NATURE	- Translation type, numbering plan, encoding scheme,
 *								  nature of address indicator.
 * @param[in] digits	To convert to BCD (with nibbles reversed).
 * @param[in] tt	Title translation.
 * @param[in] es	Encoding scheme (specify in lower nibble).
 *			- 0x00 - Unknown
 *			- 0x01 - BCD odd number of digits.
 *			- 0x02 - BCD even number of digits.
 *			- 0x04 - National specific.
 *			- 0x05 to 0x0e - Spare.
 *			- 0x0f - Reserved.
 * @param[in] np	Numbering plan (specify in lower nibble, will shift).
 *			- 0x00 - Unknown.
 *			- 0x01 - ISDN.
 *			- 0x02 - Generic numbering plan.
 *			- 0x03 - Data number plan.
 *			- 0x04 - Telex number plan.
 *			- 0x05 - Maritime mobile number plan.
 *			- 0x06 - Land mobile numbering plan.
 *			- 0x07 - ISDN/mobile numbering plan.
 *			- 0x08 to 0x0d - spare.
 *			- 0x0e - Private or network specific numbering plan.
 *			- 0x0f - Reserved.
 * @param[in] nai	Nature of address indicator.
 *			- 0x00 - Unknown
 *			- 0x01 - Subscriber number.
 *			- 0x02 - Reserved for national use.
 *			- 0x03 - National significant number.
 *			- 0x04 - International number.
 *			- Bit 8 (0xf0) 0 - even number of address signals, 1 - odd number of address signals.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int sigtran_sccp_global_title(TALLOC_CTX *ctx, uint8_t **out, int gt_ind, char const *digits,
			      uint8_t tt, uint8_t np, uint8_t es, uint8_t nai)
{
	size_t	len = talloc_array_length(digits) - 1;
	size_t 	outlen = (len / 2) + (len & 0x01);
	uint8_t	*p;
	size_t	i;

	if (len == 0) return -1;

	/*
	 *	Nature of address indicator bit 8
	 *	gets set high on odd number of digits.
	 */
	if (len & 0x01) nai |= 0xf0;

	switch (gt_ind) {
	default:
	case SCCP_TITLE_IND_NONE:
		*out = p = talloc_array(ctx, uint8_t, outlen);
		break;

	case SCCP_TITLE_IND_NATURE_ONLY:
		*out = p = talloc_array(ctx, uint8_t, (outlen + 1));
		(*p++) = nai;
		break;

	case SCCP_TITLE_IND_TRANSLATION_ONLY:
		*out = p = talloc_array(ctx, uint8_t, (outlen + 1));
		(*p++) = tt;
		break;

	case SCCP_TITLE_IND_TRANS_NUM_ENC:
		*out = p = talloc_array(ctx, uint8_t, (outlen + 3));
		(*p++) = tt;
		(*p++) = ((np & 0x0f) << 4) | (es & 0x0f);
		break;

	case SCCP_TITLE_IND_TRANS_NUM_ENC_NATURE:
		*out = p = talloc_array(ctx, uint8_t, (outlen + 4));
		(*p++) = tt;
		(*p++) = ((np & 0x0f) << 4) | (es & 0x0f);
		(*p++) = nai;
		break;
	}

	/*
	 *	Encode each digit as BCD
	 *	Digit 0 goes in low nibble.
	 *	Digit 1 goes in high nibble.
	 *	Digit 3 goes in low nibble.
	 *	Digit 4 goes in high nibble and so on...
	 */
	for (i = 0; i < (len - 1); i += 2) {
		(*p++) = ascii_to_tbcd[(uint8_t) digits[i]] | (ascii_to_tbcd[(uint8_t) digits[i + 1]] << 4);
	}

	/*
	 *	If the number of digits is odd, then the last nibble
	 *	(which will be high) is set to 0x00.
	 */
	if (len & 0x01) *p = ascii_to_tbcd[(uint8_t) digits[i]];

	return 0;
}

