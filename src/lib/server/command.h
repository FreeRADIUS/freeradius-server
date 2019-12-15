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
 * @file lib/server/command.h
 * @brief Structures and prototypes command functions
 *
 * @copyright 2007 Alan DeKok
 */
RCSIDH(command_h, "$Id$")

#include <freeradius-devel/util/value.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CMD_MAX_ARGV (32)

typedef struct fr_cmd_s fr_cmd_t;

typedef struct {
	int		argc;				//!< current argument count
	int		max_argc;			//!< maximum number of arguments
	bool		runnable;			//!< is the command runnable?
	char const     	**argv;				//!< text version of commands
	fr_value_box_t	**box;				//!< value_box version of commands.
	fr_cmd_t	**cmd;				//!< cached commands at each offset
} fr_cmd_info_t;

typedef int (*fr_cmd_func_t)(FILE *fp, FILE *fp_err, void *ctx, fr_cmd_info_t const *info);

typedef int (*fr_cmd_tab_t)(TALLOC_CTX *talloc_ctx, void *ctx, fr_cmd_info_t *info, int max_expansions, char const **expansions);

typedef struct {
	char const		*parent;		//!< e.g. "show module"
	char const		*name;			//!< e.g. "stats"
	char const		*syntax;		//!< e.g. "STRING"
	char const		*help;			//!< help text
	fr_cmd_func_t		func;			//!< function to process this command
	fr_cmd_tab_t		tab_expand;		//!< tab expand things in the syntax string
	bool			read_only;
	bool			add_name;		//!< do we add a name here?
} fr_cmd_table_t;

#define CMD_TABLE_END { .help = NULL }

typedef struct {
	int		num_parents;
	char const	**parents;
	char const	*name;
	char const	*syntax;
	char const	*help;
} fr_cmd_walk_info_t;

typedef int (*fr_cmd_walk_t)(void *ctx, fr_cmd_walk_info_t *);
typedef int (*fr_command_register_hook_t)(TALLOC_CTX *talloc_ctx, char const *name, void *ctx, fr_cmd_table_t *table);
extern fr_command_register_hook_t fr_command_register_hook;

int fr_command_add(TALLOC_CTX *talloc_ctx, fr_cmd_t **head_p, char const *name, void *ctx, fr_cmd_table_t const *table);
int fr_command_add_multi(TALLOC_CTX *talloc_ctx, fr_cmd_t **heap_p, char const *name, void *ctx, fr_cmd_table_t const *table);
int fr_command_walk(fr_cmd_t *head, void **walk_ctx, void *ctx, fr_cmd_walk_t callback);
int fr_command_tab_expand(TALLOC_CTX *ctx, fr_cmd_t *head, fr_cmd_info_t *info, int max_expansions, char const **expansions);
char const *fr_command_help(fr_cmd_t *head, int argc, char *argv[]);
int fr_command_run(FILE *fp, FILE *fp_err, fr_cmd_info_t *info, bool read_only);
void fr_command_debug(FILE *fp, fr_cmd_t *head);
int fr_command_str_to_argv(fr_cmd_t *head, fr_cmd_info_t *info, char const *str);
int fr_command_clear(int new_argc, fr_cmd_info_t *info) CC_HINT(nonnull);


#define FR_COMMAND_OPTION_NONE		(0)
#define FR_COMMAND_OPTION_LIST_CHILD	(1 << 0)
#define FR_COMMAND_OPTION_NAME		(1 << 1)
#define FR_COMMAND_OPTION_HELP		(1 << 2)

void fr_command_list(FILE *fp, int max_depth, fr_cmd_t *head, int options);
void fr_command_info_init(TALLOC_CTX *ctx, fr_cmd_info_t *info);

int fr_command_complete(fr_cmd_t *head, char const *text, int start,
			int max_expansions, char const **expansions);
int fr_command_print_help(FILE *fp, fr_cmd_t *head, char const *text);
bool fr_command_strncmp(const char *text, const char *name) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
