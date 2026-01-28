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
 * @file lib/server/cf_file.h
 * @brief Parse on-disk text based config files into the FreeRADIUS internal format.
 *
 * @copyright 2017 The FreeRADIUS server project
 */
RCSIDH(cf_file_h, "$Id$")

#include <stddef.h>
#include <stdint.h>

#include <freeradius-devel/server/cf_util.h>

#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/print.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Results of file checks
 *
 */
typedef enum {
	CF_FILE_OK = 0,		//!< File checks passed.
	CF_FILE_NO_PERMISSION = -1,	//!< Requested permissions not set
	CF_FILE_NO_EXIST = -2,		//!< File does not exist
	CF_FILE_NO_UNIX_SOCKET = -3,	//!< File is not a unix socket
	CF_FILE_OTHER_ERROR = -4	//!< Other error occurred checking permissions
} cf_file_check_err_t;

/*
 *	Config file parsing
 */
int			cf_file_read(CONF_SECTION *cs, char const *file, bool root);
int			cf_section_pass2(CONF_SECTION *cs);
void			cf_file_free(CONF_SECTION *cs);

void			cf_file_check_set_uid_gid(uid_t uid, gid_t gid);
cf_file_check_err_t	cf_file_check_effective(char const *filename,
						cf_file_check_err_t (*cb)(char const *filename, void *uctx), void *uctx);

cf_file_check_err_t	cf_file_check_unix_connect(char const *filename, UNUSED void *uctx);
cf_file_check_err_t	cf_file_check_unix_perm(char const *filename, UNUSED void *uctx);
cf_file_check_err_t	cf_file_check_open_read(char const *filename, void *uctx);

cf_file_check_err_t	cf_file_check(CONF_PAIR *cp, bool check_perms);


void			cf_md5_init(void);
void			cf_md5_final(uint8_t *digest);

/*
 *	Config file writing
 */
int			cf_section_write(FILE *fp, CONF_SECTION *cs, int depth);

/*
 *	Misc
 */
CONF_ITEM		*cf_reference_item(CONF_SECTION const *parentcs, CONF_SECTION const *outercs, char const *ptr);
char const		*cf_expand_variables(char const *filename, int lineno,
				     	     CONF_SECTION *outer_cs,
					     char *output, size_t outsize,
					     char const *input, ssize_t inlen, bool *soft_fail);
void			cf_section_set_unlang(CONF_SECTION *cs);

#ifdef __cplusplus
}
#endif
