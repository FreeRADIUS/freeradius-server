#ifndef _CONFFILE_H
#define _CONFFILE_H

/*
 * conffile.h	Defines for the conffile parsing routines.
 *
 * Version:	$Id$
 *
 */

#include <stddef.h>
#include "token.h"

/*
 * Export the minimum amount of information about these structs
 */
typedef struct conf_item CONF_ITEM;
typedef struct conf_pair CONF_PAIR;
typedef struct conf_part CONF_SECTION;

/*
 *  Instead of putting the information into a configuration structure,
 *  the configuration file routines MAY just parse it directly into
 *  user-supplied variables.
 */
#define PW_TYPE_STRING_PTR	100
#define PW_TYPE_BOOLEAN		101
#define PW_TYPE_SUBSECTION	102

typedef struct CONF_PARSER {
  const char *name;
  int type;			/* PW_TYPE_STRING, etc. */
  size_t offset;		/* relative pointer within "base" */
  void *data;			/* absolute pointer if base is NULL */
  const char *dflt;		/* default as it would appear in radiusd.conf */
} CONF_PARSER;

/* This preprocessor trick will be useful in initializing CONF_PARSER struct */
#define XStringify(x) #x
#define Stringify(x) XStringify(x)
/* And this pointer trick too */
#ifndef offsetof
# define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

void		cf_pair_free(CONF_PAIR **cp);
void		cf_section_free(CONF_SECTION **cp);
int		cf_section_parse(CONF_SECTION *cs, void *base, const CONF_PARSER *variables);

/* JLN -- Newly added */
		
CONF_PAIR	*cf_pair_find(CONF_SECTION *section, const char *name);
CONF_PAIR	*cf_pair_find_next(CONF_SECTION *section, CONF_PAIR *pair, const char *name);
CONF_SECTION	*cf_section_find(const char *name);
CONF_SECTION	*cf_section_sub_find(CONF_SECTION *section, const char *name);
char 		*cf_section_value_find(CONF_SECTION *section, const char *attr);

int		read_radius_conf_file(void);

char *cf_pair_attr(CONF_PAIR *pair);
char *cf_pair_value(CONF_PAIR *pair);
char *cf_section_name1(CONF_SECTION *section);
char *cf_section_name2(CONF_SECTION *section);
int dump_config(void);
CONF_SECTION *cf_subsection_find_next(CONF_SECTION *section,
				      CONF_SECTION *subsection,
				      const char *name1);
int cf_section_lineno(CONF_SECTION *section);
int cf_pair_lineno(CONF_PAIR *pair);
CONF_ITEM *cf_item_find_next(CONF_SECTION *section, CONF_ITEM *item);
int cf_item_is_section(CONF_ITEM *item);
CONF_PAIR *cf_itemtopair(CONF_ITEM *item);
CONF_SECTION *cf_itemtosection(CONF_ITEM *item);
CONF_ITEM *cf_pairtoitem(CONF_PAIR *cp);
CONF_ITEM *cf_sectiontoitem(CONF_SECTION *cs);
#endif /* _CONFFILE_H */
