#ifndef _CONFFILE_H
#define _CONFFILE_H

/*
 * conffile.h	Defines for the conffile parsing routines.
 *
 * Version:	$Id$
 *
 */

#include "token.h"

typedef struct conf_pair {
	char			*attr;
	char			*value;
	int			operator;
	int			lineno;
	struct conf_pair	*next;
} CONF_PAIR;

typedef struct conf_part {
	char			*name1;
	char			*name2;
	int			lineno;
	CONF_PAIR		*cps;
	struct conf_part	*sub;
	struct conf_part	*next;
	struct conf_part	*parent;
} CONF_SECTION;

/*
 *  Instead of putting the information into a configuration structure,
 *  the configuration file routines MAY just parse it directly into
 *  user-supplied variables.
 */
#define PW_TYPE_STRING_PTR	100
#define PW_TYPE_BOOLEAN		101

typedef struct CONF_PARSER {
  const char *name;
  int type;			/* PW_TYPE_STRING, etc. */
  void *data;			/* pointer to where to put it */
  const char *dflt;		/* default as it would appear in radiusd.conf */
} CONF_PARSER;

/* This preprocessor trick will be useful in initializing CONF_PARSER struct */
#define XStringify(x) #x
#define Stringify(x) XStringify(x)

CONF_SECTION	*conf_read(const char *conffile);
CONF_PAIR	*cf_pair_alloc(const char *attr, const char *value, int operator);
void		cf_pair_add(CONF_SECTION *cs, CONF_PAIR *cp_new);
void		cf_pair_free(CONF_PAIR *cp);
void		cf_section_free(CONF_SECTION *cp);
void		cf_section_free_all(CONF_SECTION *cp);
int		cf_section_parse(CONF_SECTION *cs, const CONF_PARSER *variables);

/* JLN -- Newly added */
		
CONF_PAIR	*cf_pair_find(CONF_SECTION *section, const char *name);
CONF_PAIR	*cf_pair_find_next(CONF_SECTION *section, CONF_PAIR *pair, const char *name);
CONF_SECTION	*cf_section_find(const char *name);
CONF_SECTION	*cf_section_sub_find(CONF_SECTION *section, const char *name);
char 		*cf_section_value_find(CONF_SECTION *section, const char *attr);

int		read_radius_conf_file(void);

char *cf_pair_attr(CONF_PAIR *pair);
char *cf_pair_value(CONF_PAIR *pair);
int dump_config(void);
CONF_SECTION *cf_subsection_find_next(CONF_SECTION *section,
				      CONF_SECTION *subsection,
				      const char *name1);
#endif /* _CONFFILE_H */
