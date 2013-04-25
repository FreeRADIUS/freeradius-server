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
#ifndef FR_LOG_H
#define FR_LOG_H
/*
 * $Id$
 *
 * @file log.h
 * @brief Structures and prototypes for logging.
 *
 * @copyright 2013 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(log_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef enum radlog_dest_t {
  RADLOG_STDOUT = 0,
  RADLOG_FILES,
  RADLOG_SYSLOG,
  RADLOG_STDERR,
  RADLOG_NULL,
  RADLOG_NUM_DEST
} radlog_dest_t;

typedef struct fr_log_t {
	int		colourise;
	int		fd;
	radlog_dest_t	dest;
	char		*file;
	char		*debug_file;
} fr_log_t;

extern fr_log_t default_log;

#ifdef __cplusplus
}
#endif

#endif /* FR_LOG_H */
