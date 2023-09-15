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
 * @file totp.c
 * @brief Sample test for libfreeradius-totp interface.
 *
 * @copyright 2023  Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/totp/base.h>
#include <freeradius-devel/util/base32.h>
#include <freeradius-devel/util/sbuff.h>

#define TIME_STEP	(30)
#define OTP_LEN		(8)
#define BACK_STEPS	(1)
#define BACK_STEP_SECS	(30)

typedef struct fr_test_cmd_s {
	char const *cmd;
	int (*func)(int argc, char *argv[]);
} fr_test_cmd_t;

/*
 *  decode <base32>
 */
static int fr_test_cmd_decode(int argc, char *argv[]) {
	size_t len;
	uint8_t *key;
	uint8_t	buffer[80];	/* multiple of 5*8 characters */
	fr_dbuff_t out;

	if (argc < 3) {
		printf("Usage: %s decode <base32>", argv[0]);
		return 0;
	}

	fr_dbuff_init(&out, (uint8_t *)buffer, sizeof(buffer));

	len = fr_base32_decode(&out, &FR_SBUFF_IN(argv[2], strlen(argv[2])), true, true);
	key = fr_dbuff_start(&out);

	DEBUG("Decoded len=%ld out=\"%s\"", len, key);

	return 0;
}

/*
 *	TOTP <time> <key> <8-character-expected-token>
 */
static int fr_test_cmd_totp(int argc, char *argv[]) {
	uint64_t now;
	fr_totp_t cfg = {
		.time_step         = TIME_STEP,		//!< seconds
		.otp_length        = OTP_LEN,		//!< forced to 6 or 8
		.lookback_steps    = BACK_STEPS,	//!< number of steps to look back
		.lookback_interval = BACK_STEP_SECS	//!< interval in seconds between steps
	};

	if (argc < 5) {
		printf("Usage: %s totp <time> <sha1key> <8-character-challenge>\n", argv[0]);
		return 0;
	}

	DEBUG("TOTP INPUT now=%s secret-sha1key=%s character-challenge=%s\n", argv[2], argv[3], argv[4]);

	sscanf(argv[2], "%llu", &now);

	if (fr_totp_cmp(&cfg, (time_t) now, (uint8_t const *) argv[3], strlen(argv[3]), argv[4]) == 0) {
		DEBUG("OK");
		return 0;
	}

	DEBUG("FAIL");

	return 1;
}

static fr_test_cmd_t test_cmds[] = {
	{ "decode", fr_test_cmd_decode },
	{ "totp", fr_test_cmd_totp },
	{ NULL, NULL }
};

int main(int argc, char **argv)
{
	fr_test_cmd_t *p;
	fr_debug_lvl = 5;

	if (argc < 2) {
		printf("Usage: %s <command> <args> <args...>\n", argv[0]);
		printf("\n");
		printf("  %s decode <base32>\n", argv[0]);
		printf("  %s totp <time> <secret-sha1key> <8-character-challenge>\n", argv[0]);
		printf("\n");
		return 0;
	}

	for (p = test_cmds; p->func; p++) {
		if (!strcmp(argv[1], p->cmd)) {
			return p->func(argc, argv);
		}
	}

	ERROR("Unknown command %s", argv[1]);

	return 1;
}
