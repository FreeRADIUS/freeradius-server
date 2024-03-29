/*
 * @copyright (c) 2016, Network RADIUS SAS (license@networkradius.com)
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Network RADIUS SAS nor the
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
 * @file rlm_sigtran/log.c
 * @brief Interface libosmo with FreeRADIUS logging
 */
#define LOG_PREFIX "sigtran"

#include <freeradius-devel/server/base.h>
#include <osmocom/core/logging.h>
#include "sigtran.h"

static void do_log(UNUSED struct log_target *target, unsigned int level, const char *log)
{
	switch (level) {
	case LOGL_DEBUG:
		DEBUG2("%s", log);
		break;

	case LOGL_INFO:
	case LOGL_NOTICE:
		INFO("%s", log);
		break;

	case LOGL_ERROR:
	case LOGL_FATAL:
	default:
		ERROR("%s", log);
		break;
	}
}

/** Patch our logging system into libosmo's
 *
 */
void sigtran_log_init(TALLOC_CTX *ctx)
{
	struct log_target	*log;
	static struct log_info	info;

	log_init(&info, ctx);

	/*
	 *	Setup logging
	 */
	log = log_target_create();
	log_set_use_color(log, 0);
	log_set_print_extended_timestamp(log, 0);
	log_set_print_timestamp(log, 0);
	if (DEBUG_ENABLED3) {
		log_set_print_category(log, 1);
		log_set_print_filename(log, 1);
	} else {
		log_set_print_category(log, 0);
		log_set_print_filename(log, 0);
	}
	log->output = do_log;	/* Use our proxy logging function */
	log_add_target(log);
	log_set_all_filter(log, 1);
}

