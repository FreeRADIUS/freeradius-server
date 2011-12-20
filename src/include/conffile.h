#ifndef _CONFFILE_H
#define _CONFFILE_H

/*
 * conffile.h	Defines for the conffile parsing routines.
 *
 * Version:	$Id$
 *
 */

#include <freeradius-devel/ident.h>
RCSIDH(conffile_h, "$Id$")

#include <stddef.h>
#include <freeradius-devel/token.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Export the minimum amount of information about these structs
 */
typedef struct conf_item CONF_ITEM;
typedef struct conf_pair CONF_PAIR;
typedef struct conf_part CONF_SECTION;
typedef struct conf_data CONF_DATA;

/*
 *  Instead of putting the information into a configuration structure,
 *  the configuration file routines MAY just parse it directly into
 *  user-supplied variables.
 */
#define PW_TYPE_STRING_PTR	100
#define PW_TYPE_BOOLEAN		101
#define PW_TYPE_SUBSECTION	102
#define PW_TYPE_FILENAME	103

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

void		cf_pair_free(CONF_PAIR **cp);
int		cf_pair_replace(CONF_SECTION *cs, CONF_PAIR *cp,
				const char *value);
void		cf_section_free(CONF_SECTION **cp);
int		cf_item_parse(CONF_SECTION *cs, const char *name,
			      int type, void *data, const char *dflt);
int		cf_section_parse(CONF_SECTION *, void *base,
				 const CONF_PARSER *variables);
void		cf_section_parse_free(CONF_SECTION *cs, void *base);
const CONF_PARSER *cf_section_parse_table(CONF_SECTION *cs);
CONF_SECTION	*cf_file_read(const char *file);
int		cf_file_include(const char *file, CONF_SECTION *cs);

CONF_PAIR	*cf_pair_find(const CONF_SECTION *, const char *name);
CONF_PAIR	*cf_pair_find_next(const CONF_SECTION *, CONF_PAIR *, const char *name);
CONF_SECTION	*cf_section_find(const char *name);
CONF_SECTION	*cf_section_find_name2(const CONF_SECTION *section,
				       const char *name1, const char *name2);
CONF_SECTION	*cf_section_sub_find(const CONF_SECTION *, const char *name);
CONF_SECTION	*cf_section_sub_find_name2(const CONF_SECTION *, const char *name1, const char *name2);
const char 	*cf_section_value_find(const CONF_SECTION *, const char *attr);
CONF_SECTION	*cf_top_section(CONF_SECTION *cs);

void *cf_data_find(CONF_SECTION *, const char *);
int cf_data_add(CONF_SECTION *, const char *, void *, void (*)(void *));

const char *cf_pair_attr(CONF_PAIR *pair);
const char *cf_pair_value(CONF_PAIR *pair);
VALUE_PAIR *cf_pairtovp(CONF_PAIR *pair);
const char *cf_section_name1(const CONF_SECTION *);
const char *cf_section_name2(const CONF_SECTION *);
int dump_config(CONF_SECTION *cs);
CONF_SECTION *cf_subsection_find_next(CONF_SECTION *section,
				      CONF_SECTION *subsection,
				      const char *name1);
CONF_SECTION *cf_section_find_next(CONF_SECTION *section,
				   CONF_SECTION *subsection,
				   const char *name1);
int cf_section_lineno(CONF_SECTION *section);
int cf_pair_lineno(CONF_PAIR *pair);
const char *cf_pair_filename(CONF_PAIR *pair);
const char *cf_section_filename(CONF_SECTION *section);
CONF_ITEM *cf_item_find_next(CONF_SECTION *section, CONF_ITEM *item);
CONF_SECTION *cf_item_parent(CONF_ITEM *ci);
int cf_item_is_section(CONF_ITEM *item);
int cf_item_is_pair(CONF_ITEM *item);
CONF_PAIR *cf_itemtopair(CONF_ITEM *item);
CONF_SECTION *cf_itemtosection(CONF_ITEM *item);
CONF_ITEM *cf_pairtoitem(CONF_PAIR *cp);
CONF_ITEM *cf_sectiontoitem(CONF_SECTION *cs);
int cf_section_template(CONF_SECTION *cs, CONF_SECTION *template);
void cf_log_err(CONF_ITEM *ci, const char *fmt, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 2, 3)))
#endif
;
void cf_log_info(CONF_SECTION *cs, const char *fmt, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 2, 3)))
#endif
;
void cf_log_module(CONF_SECTION *cs, const char *fmt, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 2, 3)))
#endif
;
CONF_ITEM *cf_reference_item(const CONF_SECTION *parentcs,
			     CONF_SECTION *outercs,
			     const char *ptr);
extern int cf_log_config;
extern int cf_log_modules;

extern int cf_pair2xml(FILE *fp, const CONF_PAIR *cp);
extern int cf_section2xml(FILE *fp, const CONF_SECTION *cs);
extern int cf_pair2file(FILE *fp, const CONF_PAIR *cp);
extern int cf_section2file(FILE *fp, const CONF_SECTION *cs);

/*
 *	Big magic.
 */
int cf_section_migrate(CONF_SECTION *dst, CONF_SECTION *src);

#ifdef __cplusplus
}
#endif

#endif /* _CONFFILE_H */
