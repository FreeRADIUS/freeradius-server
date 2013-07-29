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
 * $Id$
 * @file collectd.c
 * @brief Helper functions to enabled radsniff to talk to collectd
 *
 * @copyright 2013 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#ifdef HAVE_COLLECTDC_H
#include <assert.h>
#include <ctype.h>

#include <collectd/client.h>
#include <freeradius-devel/radsniff.h>

/** Copy a 64bit unsigned integer into a double
 *
 */
static void _copy_uint64_to_double(UNUSED rs_t *conf, rs_stats_tmpl_t *tmpl)
{
	assert(tmpl->src);
	assert(tmpl->dst);

	*((double *) tmpl->dst) = *((uint64_t *) tmpl->src);
}

static void _copy_uint64_to_uint64(UNUSED rs_t *conf, rs_stats_tmpl_t *tmpl)
{
	assert(tmpl->src);
	assert(tmpl->dst);

	*((uint64_t *) tmpl->dst) = *((uint64_t *) tmpl->src);
}

static void _copy_double_to_double(UNUSED rs_t *conf, rs_stats_tmpl_t *tmpl)
{
	assert(tmpl->src);
	assert(tmpl->dst);

	*((uint64_t *) tmpl->dst) = *((uint64_t *) tmpl->src);
}

/** Allocates a stats template which describes a single guage/counter
 *
 * This is just intended to simplify allocating a fairly complex memory structure
 * src and dst pointers must be set
 *
 * @param ctx Context to allocate collectd struct in.
 * @param conf Radsniff configuration.
 * @param value_type one of the LCC_TYPE_* macros.
 * @param type string, the name of a collection of stats e.g. linked_request_response.
 * @param type_instance the name of the counter/guage within the collection e.g. latency.
 * @param stats structure to derive statistics from.
 * @param src pointer into stats (where to retrieve the value from).
 * @param cb to process the latest statistics from the stats structure.
 * @return a new rs_stats_tmpl_t on success or NULL on failure.
 */
static rs_stats_tmpl_t *rs_stats_collectd_init(TALLOC_CTX *ctx, rs_t *conf, int value_type,
					       char const *type, char const *type_instance,
					       void *stats, void *src, rs_stats_cb_t cb)
{
	static char hostname[LCC_NAME_LEN];
	rs_stats_tmpl_t *tmpl;
	lcc_value_list_t *value;

	assert(conf);
	assert(type);
	assert(type_instance);
	assert(cb);

	/*
	 *	Initialise hostname once so we don't call gethostname every time
	 */
	if (*hostname == '\0') {
		if (gethostname(hostname, sizeof(hostname)) < 0) {
			ERROR("Error getting hostname: %s", fr_syserror(errno));

			return NULL;
		}
	}

	tmpl = talloc_zero(ctx, rs_stats_tmpl_t);
	if (!tmpl) return NULL;

	tmpl->cb = cb;
	tmpl->src = src;
	tmpl->stats = stats;

	value = talloc_zero(tmpl, lcc_value_list_t);
	if (!value) goto error;
	value->interval = conf->stats.interval;
	value->values_len = 1;

	value->values_types = talloc_array(value, int, 1);
	if (!value->values_types) goto error;
	*(value->values_types) = value_type;

	value->values = talloc_zero_array(value, value_t, 1);
	if (!value->values) goto error;

	switch (value_type) {
		case LCC_TYPE_COUNTER:
			tmpl->dst = &value->values->counter;
			break;

		case LCC_TYPE_GAUGE:
			tmpl->dst = &value->values->gauge;
			break;

		case LCC_TYPE_DERIVE:
			tmpl->dst = &value->values->derive;
			break;

		case LCC_TYPE_ABSOLUTE:
			tmpl->dst = &value->values->absolute;
			break;
	}

	strlcpy(value->identifier.host, hostname, sizeof(value->identifier.host));
	strlcpy(value->identifier.plugin, "radsniff", sizeof(value->identifier.plugin));
	strlcpy(value->identifier.plugin_instance, conf->stats.prefix, sizeof(value->identifier.plugin_instance));
	strlcpy(value->identifier.type, type, sizeof(value->identifier.type));
	strlcpy(value->identifier.type_instance, type_instance, sizeof(value->identifier.type_instance));
	tmpl->value = value;

	return tmpl;

	error:
	talloc_free(tmpl);
	return NULL;
}

/** Setup stats templates for latency
 *
 */
rs_stats_tmpl_t *rs_stats_collectd_init_latency(TALLOC_CTX *ctx, rs_stats_tmpl_t **out, rs_t *conf,
						char const *type, rs_latency_t *stats, PW_CODE code)
{
	rs_stats_tmpl_t **tmpl, *last;
	char *p;
	char extended_instance[512];
	tmpl = out;

#define INIT_LATENCY(_vt, _ti, _src, _cb) do {\
		snprintf(extended_instance, sizeof(extended_instance), "%s_%s", fr_packet_codes[code], _ti);\
		for (p = extended_instance; *p; ++p) *p = tolower(*p);\
		last = *tmpl = rs_stats_collectd_init(ctx, conf, _vt, type, extended_instance, stats, _src, _cb);\
		if (!*tmpl) {\
			TALLOC_FREE(*out);\
			return NULL;\
		}\
		tmpl = &(*tmpl)->next;\
		ctx = *tmpl;\
		} while (0)

	INIT_LATENCY(LCC_TYPE_GAUGE, "linked", &stats->interval.linked, _copy_uint64_to_double);
	INIT_LATENCY(LCC_TYPE_GAUGE, "latency_cma", &stats->latency_cma, _copy_double_to_double);
	INIT_LATENCY(LCC_TYPE_GAUGE, "latency_avg", &stats->interval.latency_average, _copy_double_to_double);
	INIT_LATENCY(LCC_TYPE_GAUGE, "latency_high", &stats->interval.latency_high, _copy_double_to_double);
	INIT_LATENCY(LCC_TYPE_GAUGE, "latency_low", &stats->interval.latency_low, _copy_double_to_double);
	INIT_LATENCY(LCC_TYPE_COUNTER, "cma_datapoints", &stats->latency_cma_count, _copy_double_to_double);

	return last;
}

rs_stats_tmpl_t *rs_stats_collectd_init_counter(TALLOC_CTX *ctx, rs_stats_tmpl_t **out, rs_t *conf,
						char const *type, uint64_t *counter, PW_CODE code)
{
	char *p;
	char extended_instance[512];

	strlcpy(extended_instance, fr_packet_codes[code], sizeof(extended_instance));
	for (p = extended_instance; *p; ++p) *p = tolower(*p);

	*out = rs_stats_collectd_init(ctx, conf, LCC_TYPE_COUNTER, type, extended_instance,
				      NULL, counter, _copy_uint64_to_uint64);
	if (!*out) {
		return NULL;
	}

	return *out;
}

/** Refresh and send the stats to the collectd server
 *
 */
void rs_stats_collectd_do_stats(rs_t *conf, rs_stats_tmpl_t *tmpls, struct timeval *now)
{
	rs_stats_tmpl_t *tmpl = tmpls;

	while (tmpl) {
		/*
		 *	Refresh the value of whatever were sending
		 */
		tmpl->cb(conf, tmpl);

		if (lcc_putval(conf->stats.handle, tmpl->value) < 0) {
			ERROR("Failed PUTVAL for '%s/%s/%s/%s': %s",
			      tmpl->value->identifier.plugin,
			      tmpl->value->identifier.plugin_instance,
			      tmpl->value->identifier.type,
			      tmpl->value->identifier.type_instance,
			      lcc_strerror(conf->stats.handle));
		} else switch (tmpl->value->values_types[0]) {
		case LCC_TYPE_COUNTER:
		case LCC_TYPE_DERIVE:
		case LCC_TYPE_ABSOLUTE:
			DEBUG1("Successful PUTVAL for '%s/%s/%s/%s' -> %" PRIu64,
			       tmpl->value->identifier.plugin,
			       tmpl->value->identifier.plugin_instance,
			       tmpl->value->identifier.type,
			       tmpl->value->identifier.type_instance,
			       tmpl->value->values[0].counter);
			break;
		case LCC_TYPE_GAUGE:
			DEBUG1("Successful PUTVAL for '%s/%s/%s/%s' -> %lf",
			       tmpl->value->identifier.plugin,
			       tmpl->value->identifier.plugin_instance,
			       tmpl->value->identifier.type,
			       tmpl->value->identifier.type_instance,
			       tmpl->value->values[0].gauge);
			break;
		}

		tmpl->value->time = now->tv_sec + (now->tv_usec / 1000000.0);
		tmpl = tmpl->next;
	}
}

/** Connect to a collectd server for stats output
 *
 * @param[in,out] conf radsniff configuration, we write the generate handle here.
 * @return 0 on success -1 on failure.
 */
int rs_stats_collectd_open(rs_t *conf)
{
	assert(conf->stats.collectd);

	/*
	 *	There's no way to get the error from the connection handle
	 *	because it's freed on failure, before lcc returns.
	 */
	if (lcc_connect(conf->stats.collectd, &(conf->stats.handle)) < 0) {
		ERROR("Failed opening collectd socket: %s", fr_syserror(errno));
		return -1;
	}
	DEBUG1("Connected to \"%s\"", conf->stats.collectd);

	assert(conf->stats.handle);
	return 0;
}
#endif
