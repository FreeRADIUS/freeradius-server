/*
 * conffile.h	Defines for the conffile parsing routines.
 *
 * Version:	@(#)conffile.h  1.00  02-Nov-1998  miquels@cistron.nl
 *
 */

#include "token.h"

typedef struct conf_pair {
	char				*attr;
	char				*value;
	int					operator;
	struct conf_pair	*next;
} CONF_PAIR;

typedef struct conf_part {
	char				*name1;
	char				*name2;
	CONF_PAIR			*cps;
	struct conf_part	*sub;
	struct conf_part	*next;
} CONF_SECTION;

CONF_SECTION	*conf_read(char *conffile);
CONF_PAIR		*cp_alloc(char *attr, char *value, int operator);
void			cp_free(CONF_PAIR *cp);
CONF_SECTION	*cs_alloc(char *name1, char *name2);
CONF_SECTION	*cs_find(char *name1, char *name2);
void			cs_free(CONF_SECTION *cp);
void			cs_free_all(CONF_SECTION *cp);

/* JLN -- Newly added */

CLIENT			*client_find(UINT4 ipno);
REALM			*realm_find(char *realm);
char			*client_name(UINT4 ipaddr);
int				generate_clients();
int				generate_realms();

CONF_PAIR		*pair_find(char *name, CONF_SECTION *section);
CONF_PAIR		*pair_find_next(char *name, CONF_PAIR *pair, CONF_SECTION *section);
CONF_SECTION	*section_find(char *name);
CONF_SECTION	*section_sub_find(CONF_SECTION *section, char *name);
CONF_SECTION	*module_config_find(char *modulename);
char 			*value_find(char *attr, CONF_SECTION *section);
