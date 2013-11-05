/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
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

/**
 * @file rlm_date.c
 * @brief Translates timestrings between formats.
 *
 * @author Artur Malinowski <artur@wow.com>
 *
 * @copyright 2013 Artur Malinowski <artur@wow.com>
 * @copyright 1999-2013 The FreeRADIUS Server Project.
 */

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <time.h>

typedef struct rlm_date_t {
	char const *xlat_name;
	char const *fmt;
} rlm_date_t;

static const CONF_PARSER module_config[] = {
	{"format", PW_TYPE_STRING_PTR, offsetof(rlm_date_t, fmt), NULL,
	 "%b %e %Y %H:%M:%S %Z"},
	{NULL, -1, 0, NULL, NULL}
};

DIAG_OFF(format-nonliteral)
static ssize_t from_str(void *instance, UNUSED REQUEST *request,
			 char const *fmt, char *out, size_t outlen)
{
	rlm_date_t *inst = instance;
	time_t date;
	struct tm tminfo;

	if (strptime(fmt, inst->fmt, &tminfo) == NULL) {
		REDEBUG("Failed to parse time string \"%s\"", fmt);
		*out = '\0';
		return -1;
	}

	date = mktime(&tminfo);
	if (date < 0) {
		REDEBUG("Failed converting parsed time into unix time");
		*out = '\0';
		return -1;
	}
	
	return snprintf(out, outlen, "%" PRIu64, (uint64_t) date);
}
DIAG_ON(format-nonliteral)

DIAG_OFF(format-nonliteral)
static ssize_t to_str(void *instance, UNUSED REQUEST *request,
		      char const *fmt, char *out, size_t outlen)
{
	rlm_date_t *inst = instance;
	time_t date;
	struct tm tminfo;
	
	if (fr_get_time(fmt, &date) < 0) {
		REDEBUG("Failed to parse time string \"%s\"", fmt);
		*out = '\0';
		return -1;
	}

	if (localtime_r(&date, &tminfo) == NULL) {
		REDEBUG("Failed converting time string to localtime");
		*out = '\0';
		return -1;
	}
	
	return strftime(out, outlen, inst->fmt, &tminfo);
}
DIAG_ON(format-nonliteral)

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_date_t *inst = instance;
	char *p;
	
	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
	}

	p = talloc_asprintf(inst, "from%s", inst->xlat_name);
	DEBUG("Registering xlat %s", p);
	xlat_register(p, from_str, NULL, inst);
	talloc_free(p);

	p = talloc_asprintf(inst, "to%s", inst->xlat_name);
	DEBUG("Registering xlat %s", p);
	xlat_register(p, to_str, NULL, inst);
	talloc_free(p);
	
	return 0;
}

module_t rlm_date = {
	RLM_MODULE_INIT,
	"date",				/* Name */
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	sizeof(rlm_date_t),
	module_config,
	mod_instantiate,		/* instantiation */
	NULL,				/* detach */
	{
		NULL,			/* authentication */
		NULL,			/* authorization */
		NULL,			/* pre-accounting */
		NULL			/* accounting */
	},
};

