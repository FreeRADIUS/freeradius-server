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
 * @author Artur Malinowski <artur@wow.com>
 * @author Matthew Newton
 *
 * @copyright 2013 Artur Malinowski <artur@wow.com>
 * @copyright 1999-2023 The FreeRADIUS Server Project.
 */

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <ctype.h>
#include <time.h>

typedef struct rlm_date_t {
	char const *xlat_name;
	char const *fmt;
	bool utc;
} rlm_date_t;

static const CONF_PARSER module_config[] = {
	{ "format", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_date_t, fmt), "%b %e %Y %H:%M:%S %Z" },
	{ "utc", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_date_t, utc), "no" },
	CONF_PARSER_TERMINATOR
};

DIAG_OFF(format-nonliteral)
static ssize_t xlat_date_convert(void *instance, REQUEST *request, char const *fmt, char *out, size_t outlen)
{
	rlm_date_t *inst = instance;
	time_t date = 0;
	struct tm tminfo;
	VALUE_PAIR *vp;

	memset(&tminfo, 0, sizeof(tminfo));

	if ((radius_get_vp(&vp, request, fmt) < 0) || !vp) {
		*out = '\0';
		return 0;
	}

	switch (vp->da->type) {
	/*
	 *	These are 'to' types, i.e. we'll convert the integers
	 *	to a time structure, and then output it in the specified
	 *	format as a string.
	 */
	case PW_TYPE_DATE:
		date = vp->vp_date;
		goto encode;

	case PW_TYPE_INTEGER:
	case PW_TYPE_INTEGER64:
		date = (time_t) vp->vp_integer;

	encode:
		if (!inst->utc) {
			if (localtime_r(&date, &tminfo) == NULL) {
				REDEBUG("Failed converting time string to localtime");
				goto error;
			}
		} else {
			if (gmtime_r(&date, &tminfo) == NULL) {
				REDEBUG("Failed converting time string to gmtime");
				goto error;
			}
		}
		return strftime(out, outlen, inst->fmt, &tminfo);

	/*
	 *	These are 'from' types, i.e. we'll convert the input string
	 *	into a time structure, and then output it as an integer
	 *	unix timestamp.
	 */
	case PW_TYPE_STRING:
		if (strptime(vp->vp_strvalue, inst->fmt, &tminfo) == NULL) {
			REDEBUG("Failed to parse time string \"%s\" as format '%s'", vp->vp_strvalue, inst->fmt);
			goto error;
		}

		if (!inst->utc) {
			date = mktime(&tminfo);
		} else {
			date = timegm(&tminfo);
		}
		if (date < 0) {
			REDEBUG("Failed converting parsed time into unix time");

		}
		return snprintf(out, outlen, "%" PRIu64, (uint64_t) date);

	default:
		REDEBUG("Can't convert type %s into date", fr_int2str(dict_attr_types, vp->da->type, "<INVALID>"));
	}

	error:
	*out = '\0';
	return -1;
}
DIAG_ON(format-nonliteral)


/** Get time in ms since either epoch or another value
 *
 *  %{time_since:s} - return seconds since epoch
 *  %{time_since:ms 0} - return milliseconds since epoch
 *  %{time_since:us 1695745763034443} - return microseconds since Tue 26 Sep 17:29:23.034443 BST 2023
 *  %{time_since:us &Tmp-Integer64-1} - return microseconds since value in &Tmp-Integer64-1
 */

static ssize_t xlat_time_since(UNUSED void *instance, REQUEST *request, char const *fmt, char *out, size_t outlen)
{
	uint64_t time_now = 0;
	uint64_t time_delta = 0;
	uint64_t time_since = 0;
	struct timeval tv;

	enum timebase {
		S = 1,
		MS = 1000,
		US = 1000000,
	};
	enum timebase time_base;

	while (isspace((uint8_t) *fmt)) fmt++;

	/*
	 *  Work out what time base we are using, s, ms or us.
	 */
	if (fmt[0] == 'm' && fmt[1] == 's') {
		time_base = MS;
		fmt += 2;
	} else if (fmt[0] == 'u' && fmt[1] == 's') {
		time_base = US;
		fmt += 2;
	} else if (fmt[0] == 's') {
		time_base = S;
		fmt++;
	} else {
		REDEBUG("Time base (ms, us, s) missing in time_since xlat");
	error:
		*out = '\0';
		return -1;
	}

	if (fmt[0] != '\0' && fmt[0] != ' ') {
		REDEBUG("Invalid arguments passed to time_since xlat");
		goto error;
	}

	while (isspace((uint8_t) *fmt)) fmt++;

	/*
	 *  Handle the different formats that we can be passed
	 */
	if (fmt[0] == '\0') {
		/*
		 *  %{time_since:[mu]?s} - epoch
		 */
		time_since = 0;

	} else if (fmt[0] == '&') {
		/*
		 *  We were provided with an attribute
		 *
		 *  %{time_since:[mu]?s &list:Attr-Name}
		 */
		value_data_t	outnum;
		VALUE_PAIR	*vp;
		vp_tmpl_t	vpt;
		ssize_t         slen;

		fmt++;
		slen = tmpl_from_attr_substr(&vpt, fmt, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false);
		if (slen <= 0) {
			/* Attribute name doesn't exist */
			REDEBUG("Unable to parse attribute in time_since xlat");
			goto error;
		}
		fmt += slen;

		if (tmpl_find_vp(&vp, request, &vpt) < 0) {
			/* Attribute exists but is not in the list */
			RWDEBUG("Can't find &%.*s", (int)vpt.len, vpt.name);
			goto error;
		}

		if (vp->da->type == PW_TYPE_INTEGER64) {
			/*
			 *  Int64 is easy
			 */
			time_since = vp->vp_integer64;
		} else {
			/*
			 *  ...but not others - try and convert, but warn it's likely nonsensical.
			 */
			if (value_data_cast(request, &outnum,
					PW_TYPE_INTEGER64, NULL, vp->da->type, NULL,
					&vp->data, vp->vp_length) < 0) {
				REDEBUG("Unable to convert %s to integer", fmt);
				goto error;
			}
			if (vp->da->type == PW_TYPE_DATE) {
				/*
				 *  Special case a Date - we know it's seconds
				 */
				RDEBUG3("Attribute \"%s\" is a date; multiplying seconds by %d", fmt, time_base);
				time_since = outnum.integer64 * time_base;
			} else {
				RWDEBUG("Attribute \"%s\" is not integer, conversion may not make sense", fmt);
				time_since = outnum.integer64;
			}
		}

	} else if (fmt[0] == '-') {
		REDEBUG("time_since xlat only accepts positive integers");
		goto error;

	} else {
		/*
		 *  Otherwise we hope we were provided with an integer value
		 *
		 *  %{time_since:[mu]?s 12345}
		 */
		if (sscanf(fmt, "%" PRIu64, &time_since) != 1) {
			REDEBUG("Failed parsing \"%s\" as integer", fmt);
			goto error;
		}
	}

	/*
	 *  Get current time and add milli/micro component if needed
	 */
	gettimeofday(&tv, NULL);

	time_now = (uint64_t)tv.tv_sec * time_base;

	if (time_base == MS) {
		time_now += (uint64_t)tv.tv_usec / 1000;
	} else if (time_base == US) {
		time_now += (uint64_t)tv.tv_usec;
	}

	/*
	 *  time_since needs to be in the past
	 */
	if (time_since > time_now) {
		REDEBUG("time provided to time_since needs to be in the past");
		goto error;
	}

	/*
	 *  Calculate time since provided value
	 */
	time_delta = time_now - time_since;

	/*
	 *  Write out and return
	 */
	if ((size_t)snprintf(out, outlen, "%" PRIu64, time_delta) >= outlen) {
		REDEBUG("Insufficient space to write 64-bit time value");
		goto error;
	}

	return 0;
}


static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_date_t *inst = instance;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
	}

	xlat_register(inst->xlat_name, xlat_date_convert, NULL, inst);
	xlat_register("time_since", xlat_time_since, NULL, inst);

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

