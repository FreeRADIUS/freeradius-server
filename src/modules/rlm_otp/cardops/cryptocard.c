/*
 * cryptocard.c
 * $Id$
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
 * Copyright 2005,2006 TRI-D Systems, Inc.
 */

#include <inttypes.h>
#include <string.h>
#include <time.h>

#include "../otp.h"
#include "../otp_cardops.h"
#include "cryptocard.h"

/* Card name to feature mask mappings */
static struct {
  const char *name;
  uint32_t fm;
} card[] = {
  { "cryptocard-h8-rc", CRYPTOCARD_H8_RC },
  { "cryptocard-d8-rc", CRYPTOCARD_D8_RC },
  { "cryptocard-h7-rc", CRYPTOCARD_H7_RC },
  { "cryptocard-d7-rc", CRYPTOCARD_D7_RC },
  { "cryptocard-hp-rc", CRYPTOCARD_HP_RC },
  { "cryptocard-dp-rc", CRYPTOCARD_DP_RC },
  { "cryptocard-h8-es", CRYPTOCARD_H8_ES },
  { "cryptocard-d8-es", CRYPTOCARD_D8_ES },
  { "cryptocard-h7-es", CRYPTOCARD_H7_ES },
  { "cryptocard-d7-es", CRYPTOCARD_D7_ES },
  { "cryptocard-hp-es", CRYPTOCARD_HP_ES },
  { "cryptocard-dp-es", CRYPTOCARD_DP_ES },
  { "cryptocard-h8-rs", CRYPTOCARD_H8_RS },
  { "cryptocard-d8-rs", CRYPTOCARD_D8_RS },
  { "cryptocard-h7-rs", CRYPTOCARD_H7_RS },
  { "cryptocard-d7-rs", CRYPTOCARD_D7_RS },
  { "cryptocard-hp-rs", CRYPTOCARD_HP_RS },
  { "cryptocard-dp-rs", CRYPTOCARD_DP_RS },

  { NULL, 0 }					/* end of list */
};


/*
 * Convert card name to feature mask.
 * Returns 0 on success, non-zero otherwise.
 */
static int
cryptocard_name2fm(const char *name, uint32_t *featuremask)
{
  int i;

  for (i = 0; card[i].name; ++i) {
    if (!strcasecmp(name, card[i].name)) {
      *featuremask = card[i].fm;
      return 0;
    }
  }
  return 1;
}


/*
 * Convert an ASCII keystring to a keyblock.
 * Returns keylen on success, -1 otherwise.
 */
static int
cryptocard_keystring2keyblock(otp_card_info_t *card_info)
{
  /* 64-bit DES key with optional line ending */
  if ((strlen(card_info->keystring) & ~1) != 16)
    return 1;

  return otp_keystring2keyblock(card_info->keystring, card_info->keyblock);
}


/*
 * Set nullstate.
 * We don't currently support nullstate for CRYPTOCard, so return -1.
 */
static int
cryptocard_nullstate(
#ifdef __GNUC__
__attribute__ ((unused))
#endif
                      const otp_option_t *opt,
#ifdef __GNUC__
__attribute__ ((unused))
#endif
                      const otp_card_info_t *card_info,
#ifdef __GNUC__
__attribute__ ((unused))
#endif
                      otp_user_state_t *user_state, 
#ifdef __GNUC__
__attribute__ ((unused))
#endif
                      time_t when,
                      const char *log_prefix)
{
  otp_log(OTP_LOG_ERR, "%s: %s: null state not supported for CRYPTOCard",
          log_prefix, __func__);
  return -1;
}


/*
 * Return a synchronous challenge.
 * Returns 0 on success, -1 otherwise.
 * (-2 rc is for early challenge, N/A for cryptocard.)
 */
static int
cryptocard_challenge(const otp_card_info_t *card_info,
                     otp_user_state_t *user_state,
                     unsigned char challenge[OTP_MAX_CHALLENGE_LEN],
#ifdef __GNUC__
__attribute__ ((unused))
#endif
                     time_t when,
#ifdef __GNUC__
__attribute__ ((unused))
#endif
                     int twin,
#ifdef __GNUC__
__attribute__ ((unused))
#endif
                     int ewin,
                     const char *log_prefix)
{
  unsigned char output[8];
  int i;

  /* run x99 once on the previous challenge */
  if (otp_x99_mac(challenge, user_state->clen, output, card_info->keyblock,
                  log_prefix))
    return -1;

  /* convert the mac into the next challenge */
  for (i = 0; i < 8; ++i) {
    output[i] &= 0x0f;
    if (output[i] > 9)
      output[i] -= 10;
    output[i] |= 0x30;
  }
  (void) memcpy(challenge, output, 8);
  user_state->clen = 8;

  return 0;
}


/*
 * Return the expected card response for a given challenge.
 * Returns 0 on success, non-zero otherwise.
 *
 * The X9.9 MAC is used by CRYPTOcard in the following manner:
 *
 * 1. Convert the challenge to ASCII (eg "12345" -> 0x3132333435).
 *    We don't actually do a conversion, the challenge is already ASCII.
 *    Note that Secure Computing SafeWord Gold/Platinum tokens can use
 *    "raw" challenge bytes.
 * 2. Use the challenge as the plaintext input to the X9.9 MAC algorithm.
 *
 * 3. Convert the 32 bit MAC to ASCII (eg 0x1234567f -> "1234567f").
 *    Note that SafeWord Gold/Platinum tokens can display a 64 bit MAC.
 * 4. Possibly apply transformations on chars "a" thru "f".
 * 5. Truncate the response for 7 digit display modes.
 */
static int
cryptocard_response(otp_card_info_t *card_info,
                    const unsigned char challenge[OTP_MAX_CHALLENGE_LEN],
                    size_t len, char response[OTP_MAX_RESPONSE_LEN + 1],
                    const char *log_prefix)
{
  unsigned char output[8];
  const char *conversion;

  /* Step 1, 2. */
  if (otp_x99_mac(challenge, len, output,
                  card_info->keyblock, log_prefix) !=0)
    return 1;

  /* Setup for step 4. */
  if (card_info->featuremask & OTP_CF_DD)
    conversion = otp_cc_dec_conversion;
  else
    conversion = otp_hex_conversion;

  /* Step 3, 4. */
  (void) otp_keyblock2keystring(response, output, 4, conversion);

  /* Step 5. */
  if (card_info->featuremask & OTP_CF_R7)
    (void) memmove(&response[3], &response[4], 5);
  else if (card_info->featuremask & OTP_CF_RP)
    response[3] = '-';

  return 0;
}


/*
 * Update rd (there is no csd for cryptocard).
 * Returns 0 if succesful, -1 otherwise.
 */
static int
cryptocard_updatecsd(otp_user_state_t *user_state,
#ifdef __GNUC__
__attribute__ ((unused))
#endif
                     time_t when,
#ifdef __GNUC__
__attribute__ ((unused))
#endif
                     int twin,
                     int ewin,
                     int auth_rc)
{
  if (auth_rc == OTP_RC_OK)
    user_state->rd[0] = '\0';				/* reset */
  else
    (void) sprintf(user_state->rd, "%" PRIx32,
                   (int32_t) ewin);			/* rwindow candidate */

  return 0;
}


/*
 * Determine if a window position if consecutive relative to a saved
 * (rwindow candidate) window position, for rwindow override.
 * user_state contains the previous auth position, twin and ewin the current.
 * Returns 1 on success (consecutive), 0 otherwise.
 */
static int
cryptocard_isconsecutive(
#ifdef __GNUC__
__attribute__ ((unused))
#endif
                         const otp_card_info_t *card_info,
                         const otp_user_state_t *user_state,
                         int thisewin, const char *log_prefix)
{
  int nextewin;

  /* extract the saved rwindow candidate position */
  if (sscanf(user_state->rd, "%" SCNx32, &nextewin) != 1) {
    otp_log(OTP_LOG_ERR, "%s: %s: invalid rwindow data for [%s]",
            log_prefix, __func__, card_info->username);
    return 0;
  }
  nextewin++;

  /* Is this the next passcode? */
  if (thisewin == nextewin)
    return 1;	/* yes */
  else
    return 0;	/* no */
}


/* no twin so just return 0 */
static int
cryptocard_maxtwin(
#ifdef __GNUC__
__attribute__ ((unused))
#endif
                    const otp_card_info_t *card_info,
#ifdef __GNUC__
__attribute__ ((unused))
#endif
                    const char csd[OTP_MAX_CSD_LEN + 1])
{
  return 0;
}


/* return human-readable challenge */
static char *
cryptocard_printchallenge(char s[OTP_MAX_CHALLENGE_LEN * 2 + 1],
                          const unsigned char challenge[OTP_MAX_CHALLENGE_LEN],
                          size_t len)
{
  /* cryptocard challenge is implicitly ASCII */
  (void) memcpy(s, challenge, len);
  s[len] = '\0';
  return s;
}


/* cardops instance */
static cardops_t cryptocard_cardops = {
  .prefix		= "cryptocard",
  .prefix_len		= 10, /* strlen("cryptocard") */

  .name2fm		= cryptocard_name2fm,
  .keystring2keyblock	= cryptocard_keystring2keyblock,
  .nullstate		= cryptocard_nullstate,
  .challenge		= cryptocard_challenge,
  .response		= cryptocard_response,
  .updatecsd		= cryptocard_updatecsd,
  .isconsecutive	= cryptocard_isconsecutive,
  .maxtwin		= cryptocard_maxtwin,
  .printchallenge	= cryptocard_printchallenge,
};


/* constructor */
void
cryptocard_init(void)
{
  if (otp_num_cardops == OTP_MAX_VENDORS) {
    otp_log(OTP_LOG_ERR, "cryptocard_init: module limit exceeded");
    return;
  }

  otp_cardops[otp_num_cardops++] = cryptocard_cardops;
  otp_log(OTP_LOG_DEBUG, "cryptocard_init: loaded");
}
