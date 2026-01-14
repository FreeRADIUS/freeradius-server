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
 * @file lib/server/radmin.h
 * @brief Administration tools
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(radmin_h, "$Id$")

#include <freeradius-devel/server/command.h>
#include <freeradius-devel/server/main_config.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	For radmin over TCP.
 */
#define FR_RADMIN_PORT 18120

int fr_radmin_start(main_config_t *config, bool cli, int std_fd[static 3]);
void fr_radmin_stop(void);

int fr_radmin_register(TALLOC_CTX *talloc_ctx, char const *name, void *ctx, fr_cmd_table_t *table);
int fr_radmin_run(fr_cmd_info_t *info, FILE *fp, FILE *fp_err, char *command, bool read_only);
void fr_radmin_help(FILE *fp, char const *text);
void fr_radmin_complete(FILE *fp, const char *text, int start);

#ifdef __cplusplus
}
#endif
