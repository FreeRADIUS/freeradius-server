#pragma once
/*
 *   This program is free software; you can kafkatribute it and/or modify
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
 * @file lib/kafka/base.h
 * @brief Common functions for interacting with kafk
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2022 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(kafka_base_h, "$Id$")

#ifdef HAVE_WDOCUMENTATION
DIAG_OFF(documentation-deprecated-sync)
DIAG_OFF(documentation)
#endif
#include <librdkafka/rdkafka.h>
#ifdef HAVE_WDOCUMENTATION
DIAG_ON(documentation)
DIAG_ON(documentation-deprecated-sync)
#endif

#include <freeradius-devel/server/cf_parse.h>

#ifdef __cplusplus
extern "C" {
#endif

extern CONF_PARSER const kafka_base_consumer_config[];
extern CONF_PARSER const kafka_base_producer_config[];

#ifdef __cplusplus
}
#endif
