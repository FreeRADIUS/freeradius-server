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
#define PW_TYPE_DEPRECATED	(1 << 10)

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

CONF_SECTION	*cf_section_alloc(CONF_SECTION *parent, const char *name1,
			          const char *name2);
int		cf_pair_replace(CONF_SECTION *cs, CONF_PAIR *cp,
				const char *value);
int		cf_item_parse(CONF_SECTION *cs, const char *name,
			      int type, void *data, const char *dflt);
int		cf_section_parse(CONF_SECTION *, void *base,
				 const CONF_PARSER *variables);
const CONF_PARSER *cf_section_parse_table(CONF_SECTION *cs);
CONF_SECTION	*cf_file_read(const char *file);
void		cf_file_free(CONF_SECTION *cs);
int		cf_file_include(CONF_SECTION *cs, const char *file);

CONF_PAIR	*cf_pair_find(const CONF_SECTION *, const char *name);
CONF_PAIR	*cf_pair_find_next(const CONF_SECTION *, const CONF_PAIR *, const char *name);
CONF_SECTION	*cf_section_find(const char *name);
CONF_SECTION	*cf_section_find_name2(const CONF_SECTION *section,
				       const char *name1, const char *name2);
CONF_SECTION	*cf_section_sub_find(const CONF_SECTION *, const char *name);
CONF_SECTION	*cf_section_sub_find_name2(const CONF_SECTION *, const char *name1, const char *name2);
const char 	*cf_section_value_find(const CONF_SECTION *, const char *attr);
CONF_SECTION	*cf_top_section(CONF_SECTION *cs);

void *cf_data_find(const CONF_SECTION *, const char *);
int cf_data_add(CONF_SECTION *, const char *, void *, void (*)(void *));

const char *cf_pair_attr(const CONF_PAIR *pair);
const char *cf_pair_value(const CONF_PAIR *pair);
FR_TOKEN cf_pair_operator(const CONF_PAIR *pair);
FR_TOKEN cf_pair_value_type(const CONF_PAIR *pair);
VALUE_PAIR *cf_pairtovp(CONF_PAIR *pair);
const char *cf_section_name1(const CONF_SECTION *);
const char *cf_section_name2(const CONF_SECTION *);
int dump_config(const CONF_SECTION *cs);
CONF_SECTION *cf_subsection_find_next(const CONF_SECTION *section,
				      const CONF_SECTION *subsection,
				      const char *name1);
CONF_SECTION *cf_section_find_next(const CONF_SECTION *section,
				   const CONF_SECTION *subsection,
				   const char *name1);
int cf_section_lineno(const CONF_SECTION *section);
int cf_pair_lineno(const CONF_PAIR *pair);
const char *cf_pair_filename(const CONF_PAIR *pair);
const char *cf_section_filename(const CONF_SECTION *section);
CONF_ITEM *cf_item_find_next(const CONF_SECTION *section, const CONF_ITEM *item);
CONF_SECTION *cf_item_parent(const CONF_ITEM *ci);
int cf_item_is_section(const CONF_ITEM *item);
int cf_item_is_pair(const CONF_ITEM *item);
CONF_PAIR *cf_itemtopair(const CONF_ITEM *item);
CONF_SECTION *cf_itemtosection(const CONF_ITEM *item);
CONF_ITEM *cf_pairtoitem(const CONF_PAIR *cp);
CONF_ITEM *cf_sectiontoitem(const CONF_SECTION *cs);
int cf_section_template(CONF_SECTION *cs, CONF_SECTION *template);
void cf_log_err(const CONF_ITEM *ci, const char *fmt, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 2, 3)))
#endif
;
void cf_log_info(const CONF_SECTION *cs, const char *fmt, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 2, 3)))
#endif
;
void cf_log_module(const CONF_SECTION *cs, const char *fmt, ...)
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
