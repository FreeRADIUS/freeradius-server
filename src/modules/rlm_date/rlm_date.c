/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @author Artur Malinowski (artur@wow.com)
 *
 * @copyright 2013 Artur Malinowski (artur@wow.com)
 * @copyright 1999-2018 The FreeRADIUS Server Project.
 */

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <ctype.h>
#include <time.h>

typedef struct {
	char const *xlat_name;
	char const *fmt;
	bool utc;
} rlm_date_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("format", FR_TYPE_STRING, rlm_date_t, fmt), .dflt = "%b %e %Y %H:%M:%S %Z" },
	{ FR_CONF_OFFSET("utc", FR_TYPE_BOOL, rlm_date_t, utc), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

DIAG_OFF(format-nonliteral)
static ssize_t date_convert_string(REQUEST *request, char **out, size_t outlen,
				   const char *str, const char *fmt)
{
	struct tm tminfo;
	time_t date = 0;

	if (strptime(str, fmt, &tminfo) == NULL) {
		REDEBUG("Failed to parse time string \"%s\" as format '%s'", str, fmt);
		return -1;
	}

	date = mktime(&tminfo);
	if (date < 0) {
		REDEBUG("Failed converting parsed time into unix time");
		return -1;
	}

	return snprintf(*out, outlen, "%" PRIu64, (uint64_t) date);
}

static ssize_t date_encode_strftime(char **out, size_t outlen, rlm_date_t const *inst,
				    REQUEST *request, time_t date)
{
	struct tm tminfo;

	if (inst->utc) {
		if (gmtime_r(&date, &tminfo) == NULL) {
			REDEBUG("Failed converting time string to gmtime: %s", fr_syserror(errno));
			return -1;
		}
	} else {
		if (localtime_r(&date, &tminfo) == NULL) {
			REDEBUG("Failed converting time string to localtime: %s", fr_syserror(errno));
			return -1;
		}
	}

	return strftime(*out, outlen, inst->fmt, &tminfo);
}
DIAG_ON(format-nonliteral)

static ssize_t xlat_date_convert(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				 void const *mod_inst, UNUSED void const *xlat_inst,
				 REQUEST *request, char const *fmt)
{
	rlm_date_t const *inst = mod_inst;
	struct tm tminfo;
	VALUE_PAIR *vp;

	memset(&tminfo, 0, sizeof(tminfo));

	if (strcmp(fmt, "request") == 0) {
		return date_encode_strftime(out, outlen, inst, request,
					    fr_time_to_sec(request->packet->timestamp));
	}

	if (strcmp(fmt, "now") == 0) {
		return date_encode_strftime(out, outlen, inst, request, fr_time_to_sec(fr_time()));
	}

	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) return 0;

	switch (vp->vp_type) {
	/*
	 *	These are 'to' types, i.e. we'll convert the integers
	 *	to a time structure, and then output it in the specified
	 *	format as a string.
	 */
	case FR_TYPE_DATE:
		return date_encode_strftime(out, outlen, inst, request, vp->vp_date);

	case FR_TYPE_UINT32:
		return date_encode_strftime(out, outlen, inst, request, (time_t) vp->vp_uint32);


	case FR_TYPE_UINT64:
		return date_encode_strftime(out, outlen, inst, request, (time_t) vp->vp_uint64);

	/*
	 *	These are 'from' types, i.e. we'll convert the input string
	 *	into a time structure, and then output it as an integer
	 *	unix timestamp.
	 */
	case FR_TYPE_STRING:
		return date_convert_string(request, out, outlen, vp->vp_strvalue, inst->fmt);

	default:
		REDEBUG("Can't convert type %s into date", fr_table_str_by_num(fr_value_box_type_table, vp->da->type, "<INVALID>"));
	}

	return -1;
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_date_t *inst = instance;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
	}

	xlat_register(inst, inst->xlat_name, xlat_date_convert, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);

	return 0;
}

extern module_t rlm_date;
module_t rlm_date = {
	.magic		= RLM_MODULE_INIT,
	.name		= "date",
	.inst_size	= sizeof(rlm_date_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap
};

