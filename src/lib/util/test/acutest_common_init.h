#pragma once
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

/** Common initialisation for acutest binaries
 *
 * @file src/lib/util/test/acutest_common_init.h
 *
 * The test wrapper's timeout arrives as SIGALRM, and stdout is block
 * buffered when redirected to a log file, so a test binary without signal
 * handlers dies with no backtrace and loses every progress line since the
 * last buffer flush.  The TEST_INIT hook below installs the fatal signal
 * handlers and switches stdout to line buffering before each test runs.
 *
 * To use: include this header first, in place of acutest.h.
 *
 * TEST_INIT must be defined before acutest.h is included, but the function
 * body reads acutest_argv0_, which acutest.h defines, so the declaration
 * sits above the include and the definition below.
 *
 * @copyright 2026 Arran Cudbard-Bell
 */
static void acutest_common_init(void);

#define TEST_INIT acutest_common_init()

#include "acutest.h"

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/strerror.h>

#include <stdio.h>
#include <stdlib.h>

static void acutest_common_init(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);

	if (fr_fault_setup(NULL, getenv("PANIC_ACTION"), acutest_argv0_, PANIC_ACTION_SIGNALS) < 0) {
		fprintf(stderr, "Running without fatal signal handlers, because fr_fault_setup failed: %s\n",
			fr_strerror());
	}
}
