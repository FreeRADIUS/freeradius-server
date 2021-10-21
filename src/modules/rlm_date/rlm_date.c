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
static xlat_action_t date_convert_string(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
				   const char *str, rlm_date_t const *inst)
{
	struct tm	tminfo;
	time_t		date = 0;
	fr_value_box_t	*vb;
	bool		utc = inst->utc;

#ifdef __APPLE__
	/*
	 *	OSX "man strptime" says it only accepts the local time zone, and GMT.
	 *
	 *	However, when printing dates via strftime(), it prints
	 *	"UTC" instead of "GMT".  So... we have to fix it up
	 *	for stupid nonsense.
	 */
	char const *tz = strstr(str, "UTC");
	if (tz) {
		char *my_str;
		char *p;

		/*
		 *	
		 */
		MEM(my_str = talloc_strdup(ctx, str));
		p = my_str + (tz - str);
		memcpy(p, "GMT", 3);

		p = strptime(my_str, inst->fmt, &tminfo);
		if (!p) {
			REDEBUG("Failed to parse time string \"%s\" as format '%s'", my_str, inst->fmt);
			talloc_free(my_str);
			return XLAT_ACTION_FAIL;
		}
		talloc_free(my_str);		

		/*
		 *	The output is converted to the local time zone, so
		 *	we can't use UTC.
		 */
		utc = false;
	} else
#endif

	if (strptime(str, inst->fmt, &tminfo) == NULL) {
		REDEBUG("Failed to parse time string \"%s\" as format '%s'", str, inst->fmt);
		return XLAT_ACTION_FAIL;
	}

	if (utc) {
		date = timegm(&tminfo);
	} else {
		date = mktime(&tminfo);
	}
	if (date < 0) {
		REDEBUG("Failed converting parsed time into unix time");
		return XLAT_ACTION_FAIL;
	}

	vb = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL, false);
	vb->vb_uint64 = (uint64_t) date;
	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

static xlat_action_t date_encode_strftime(TALLOC_CTX *ctx, fr_dcursor_t *out, rlm_date_t const *inst,
				    request_t *request, time_t date)
{
	struct tm	tminfo;
	char		buff[64];
	fr_value_box_t	*vb;

	if (inst->utc) {
		if (gmtime_r(&date, &tminfo) == NULL) {
			REDEBUG("Failed converting time string to gmtime: %s", fr_syserror(errno));
			return XLAT_ACTION_FAIL;
		}
	} else {
		if (localtime_r(&date, &tminfo) == NULL) {
			REDEBUG("Failed converting time string to localtime: %s", fr_syserror(errno));
			return XLAT_ACTION_FAIL;
		}
	}

	if (strftime(buff, sizeof(buff), inst->fmt, &tminfo) == 0) return XLAT_ACTION_FAIL;

	vb = fr_value_box_alloc_null(ctx);
	fr_value_box_strdup(ctx, vb, NULL, buff, false);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}
DIAG_ON(format-nonliteral)

static int mod_xlat_instantiate(void *xlat_inst, UNUSED xlat_exp_t const *exp, void *uctx)
{
	*((void **)xlat_inst) = talloc_get_type_abort(uctx, rlm_date_t);
	return 0;
}

static xlat_arg_parser_t const xlat_date_convert_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Get or convert time and date
 *
 * Using the format in the module instance configuration, get
 * various timestamps, or convert strings to date format.
 *
 * When the request arrived:
@verbatim
%(date:request)
@endverbatim
 *
 * Now:
@verbatim
%(date:now}
@endverbatim
 *
 * Examples (Tmp-Integer-0 = 1506101100):
@verbatim
update request {
  &Tmp-String-0 := "%(date:%{Tmp-Integer-0})" ("Fri 22 Sep 18:25:00 BST 2017")
  &Tmp-Integer-1 := "%(date:%{Tmp-String-0})" (1506101100)
}
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_date_convert(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
				       void const *xlat_inst, UNUSED void *xlat_thread_inst,
				       fr_value_box_list_t *in)
{
	rlm_date_t const	*inst;
	void			*instance;
	struct tm 		tminfo;
	fr_value_box_t		*arg = fr_dlist_head(in);

	memcpy(&instance, xlat_inst, sizeof(instance));

	inst = talloc_get_type_abort(instance, rlm_date_t);

	memset(&tminfo, 0, sizeof(tminfo));

	/*
	 *	Certain strings have magical meanings.
	 */
	if (arg->type == FR_TYPE_STRING) {
		if (strcmp(arg->vb_strvalue, "request") == 0) {
			return date_encode_strftime(ctx, out, inst, request,
						    fr_time_to_sec(request->packet->timestamp));
		}

		if (strcmp(arg->vb_strvalue, "now") == 0) {
			return date_encode_strftime(ctx, out, inst, request, fr_time_to_sec(fr_time()));
		}
	}

	switch (arg->type) {
	/*
	 *	These are 'to' types, i.e. we'll convert the integers
	 *	to a time structure, and then output it in the specified
	 *	format as a string.
	 */
	case FR_TYPE_DATE:
		return date_encode_strftime(ctx, out, inst, request, fr_unix_time_to_sec(arg->vb_date));

	case FR_TYPE_UINT32:
		return date_encode_strftime(ctx, out, inst, request, (time_t) arg->vb_uint32);

	case FR_TYPE_UINT64:
		return date_encode_strftime(ctx, out, inst, request, (time_t) arg->vb_uint64);

	/*
	 *	These are 'from' types, i.e. we'll convert the input string
	 *	into a time structure, and then output it as an integer
	 *	unix timestamp.
	 */
	case FR_TYPE_STRING:
		return date_convert_string(ctx, out, request, arg->vb_strvalue, inst);

	default:
		REDEBUG("Can't convert type %s into date", fr_table_str_by_value(fr_value_box_type_table, arg->type, "<INVALID>"));
	}

	return XLAT_ACTION_FAIL;
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_date_t 	*inst = instance;
	xlat_t 		*xlat;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
	}

	xlat = xlat_register(inst, inst->xlat_name, xlat_date_convert, false);
	xlat_func_args(xlat,xlat_date_convert_args);
	xlat_async_instantiate_set(xlat, mod_xlat_instantiate, rlm_date_t *, NULL, inst);

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

