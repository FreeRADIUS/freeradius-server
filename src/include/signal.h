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
#ifndef _FR_SIGNAL_H
#define _FR_SIGNAL_H
/**
 * $Id$
 *
 * @file include/signal.h
 * @brief Signals that can be sent to a request.
 *
 * @copyright  2018 The FreeRADIUS server project
 * @copyright  2018 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(signal_h, "$Id$")


#ifdef __cplusplus
extern "C" {
#endif

/** Signals that can be generated/processed by request signal handlers
 *
 */
typedef enum fr_state_signal_t {	/* server action */
	FR_SIGNAL_INVALID = 0,
	FR_SIGNAL_RUN,
	FR_SIGNAL_DONE,			//!< Request is completed.  If a module is signalled
					///< with this, the module should stop processing
					///< the request and cleanup.
	FR_SIGNAL_DUP,			//!< A duplicate request was received.
} fr_state_signal_t;

#ifdef __cplusplus
}
#endif
#endif /* _FR_SIGNAL_H */
