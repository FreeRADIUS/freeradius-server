#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/server/signal.h
 * @brief Signals that can be sent to a request.
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(signal_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

/** Signals that can be generated/processed by request signal handlers
 *
 * This is a bitfield so that it can be used to specify signal masks.
 */
DIAG_OFF(attributes) /* Stupid GCC */
typedef enum CC_HINT(flag_enum) {	/* server action */
	FR_SIGNAL_INVALID	= 0x00,
	FR_SIGNAL_CANCEL	= 0x01,	//!< Request has been cancelled.
					///< If a module is signalled with this, the module
					///< should stop processing the request and cleanup
					///< anything it's done.
	FR_SIGNAL_DUP		= 0x02,	//!< A duplicate request was received.
	FR_SIGNAL_DETACH	= 0x04,	//!< Request is being detached from its parent.
	FR_SIGNAL_RETRY		= 0x08,	//!< a retry timer has hit
	FR_SIGNAL_TIMEOUT	= 0x10	//!< a retry timeout or max count has hit
} fr_signal_t;
DIAG_ON(attributes)

#define fr_signal_is_cancel(_signal)	(_signal & FR_SIGNAL_CANCEL)
#define fr_signal_is_dup(_signal)	(_signal & FR_SIGNAL_DUP)
#define fr_signal_is_detach(_signal)	(_signal & FR_SIGNAL_DETACH)
#define fr_signal_is_retry(_signal)	(_signal & FR_SIGNAL_RETRY)
#define fr_signal_is_timeout(_signal)	(_signal & FR_SIGNAL_TIMEOUT)

#ifdef __cplusplus
}
#endif
