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
 * @param plugin_instance usually the type of packet (in our case).
 * @param type string, the name of a collection of stats e.g. exchange
 * @param type_instance the name of the counter/guage within the collection e.g. latency.
 * @param stats structure to derive statistics from.
 * @param src pointer into stats (where to retrieve the value from).
 * @param cb to process the latest statistics from the stats structure.
 * @return a new rs_stats_tmpl_t on success or NULL on failure.
 */
static rs_stats_tmpl_t *rs_stats_collectd_init(TALLOC_CTX *ctx, rs_t *conf, int value_type,
					       char const *plugin_instance,
					       char const *type, char const *type_instance,
					       void *stats, void *src, rs_stats_cb_t cb)
{
	static char hostname[255];
	static char fqdn[LCC_NAME_LEN];

	size_t len;
	int i;
	char *p;
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
	if (*fqdn == '\0') {
		int ret;
		struct addrinfo hints, *info = NULL;

		if (gethostname(hostname, sizeof(hostname)) < 0) {
			ERROR("Error getting hostname: %s", fr_syserror(errno));

			return NULL;
		}

		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_UNSPEC; /*either IPV4 or IPV6*/
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_CANONNAME;

		if ((ret = getaddrinfo(hostname, "radius", &hints, &info)) != 0) {
			ERROR("Error getting hostname: %s", gai_strerror(ret));
		    	return NULL;
		}

		strlcpy(fqdn, info->ai_canonname, sizeof(fqdn));

		freeaddrinfo(info);
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

	/*
	 *	These should be OK as is
	 */
	strlcpy(value->identifier.host, fqdn, sizeof(value->identifier.host));

	/*
	 *	Plugin is ASCII only and no '/'
	 */
	fr_print_string(conf->stats.prefix, strlen(conf->stats.prefix),
			value->identifier.plugin, sizeof(value->identifier.plugin));
	for (p = value->identifier.plugin; *p; ++p) {
		if ((*p == '-') || (*p == '/'))*p = '_';
	}

	/*
	 *	Plugin instance is ASCII only (assuming printable only) and no '/'
	 */
	fr_print_string(plugin_instance, strlen(plugin_instance),
			value->identifier.plugin_instance, sizeof(value->identifier.plugin_instance));
	for (p = value->identifier.plugin_instance; *p; ++p) {
		if ((*p == '-') || (*p == '/')) *p = '_';
	}

	/*
	 *	Type is ASCII only (assuming printable only) and no '/' or '-'
	 */
	fr_print_string(type, strlen(type),
			value->identifier.type, sizeof(value->identifier.type));
	for (p = value->identifier.type; *p; ++p) {
		if ((*p == '-') || (*p == '/')) *p = '_';
	}

	fr_print_string(type_instance, strlen(type_instance),
			value->identifier.type_instance, sizeof(value->identifier.type_instance));
	for (p = value->identifier.type_instance; *p; ++p) {
		if ((*p == '-') || (*p == '/')) *p = '_';
	}

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
	char buffer[LCC_NAME_LEN];
	tmpl = out;
	int i;

#define INIT_LATENCY(_vt, _ti, _src, _cb) do {\
		strlcpy(buffer, fr_packet_codes[code], sizeof(buffer)); \
		for (p = buffer; *p; ++p) *p = tolower(*p);\
		last = *tmpl = rs_stats_collectd_init(ctx, conf, _vt, buffer, type, _ti, stats, _src, _cb);\
		if (!*tmpl) {\
			TALLOC_FREE(*out);\
			return NULL;\
		}\
		tmpl = &(*tmpl)->next;\
		ctx = *tmpl;\
		} while (0)

	INIT_LATENCY(LCC_TYPE_GAUGE, "linked", &stats->interval.linked, _copy_uint64_to_double);
	INIT_LATENCY(LCC_TYPE_GAUGE, "unlinked", &stats->interval.unlinked, _copy_uint64_to_double);
	INIT_LATENCY(LCC_TYPE_GAUGE, "reused", &stats->interval.reused, _copy_uint64_to_double);

	for (i = 0; i <= RS_RETRANSMIT_MAX; i++) {
		char type_instance[LCC_NAME_LEN];
		if (i != RS_RETRANSMIT_MAX) {
			snprintf(type_instance, sizeof(type_instance), "retry_%i", i);
		} else {
			snprintf(type_instance, sizeof(type_instance), "retry_%i+", i);
		}

		INIT_LATENCY(LCC_TYPE_GAUGE, type_instance, &stats->interval.rt[i], _copy_uint64_to_double);
	}

	INIT_LATENCY(LCC_TYPE_GAUGE, "lost", &stats->interval.lost, _copy_uint64_to_double);

	INIT_LATENCY(LCC_TYPE_GAUGE, "latency_avg", &stats->interval.latency_average, _copy_double_to_double);
	INIT_LATENCY(LCC_TYPE_GAUGE, "latency_high", &stats->interval.latency_high, _copy_double_to_double);
	INIT_LATENCY(LCC_TYPE_GAUGE, "latency_low", &stats->interval.latency_low, _copy_double_to_double);
	INIT_LATENCY(LCC_TYPE_GAUGE, "latency_cma", &stats->latency_cma, _copy_double_to_double);
	INIT_LATENCY(LCC_TYPE_COUNTER, "cma_datapoints", &stats->latency_cma_count, _copy_double_to_double);

	return last;
}

rs_stats_tmpl_t *rs_stats_collectd_init_counter(TALLOC_CTX *ctx, rs_stats_tmpl_t **out, rs_t *conf,
						char const *type, uint64_t *counter, PW_CODE code)
{
	char *p;
	char buffer[LCC_NAME_LEN];

	strlcpy(buffer, fr_packet_codes[code], sizeof(buffer));
	for (p = buffer; *p; ++p) {
		*p = tolower(*p);
	}

	*out = rs_stats_collectd_init(ctx, conf, LCC_TYPE_COUNTER, buffer, type, "received", counter,
				      counter, _copy_uint64_to_uint64);
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
		tmpl->value->time = now->tv_sec + (now->tv_usec / 1000000.0);

		if (lcc_putval(conf->stats.handle, tmpl->value) < 0) switch (tmpl->value->values_types[0]) {
		case LCC_TYPE_COUNTER:
		case LCC_TYPE_DERIVE:
		case LCC_TYPE_ABSOLUTE:
			ERROR("Failed PUTVAL %s/%s/%s-%s interval=%i %i:%" PRIu64 ": %s",
			       tmpl->value->identifier.plugin,
			       tmpl->value->identifier.plugin_instance,
			       tmpl->value->identifier.type,
			       tmpl->value->identifier.type_instance,
			       tmpl->value->interval,
			       tmpl->value->time,
			       tmpl->value->values[0].counter,
			       lcc_strerror(conf->stats.handle));
			break;
		case LCC_TYPE_GAUGE:
			ERROR("Failed PUTVAL %s/%s/%s-%s interval=%i %i:%lf: %s",
			       tmpl->value->identifier.plugin,
			       tmpl->value->identifier.plugin_instance,
			       tmpl->value->identifier.type,
			       tmpl->value->identifier.type_instance,
			       tmpl->value->interval,
			       tmpl->value->time,
			       tmpl->value->values[0].gauge,
			       lcc_strerror(conf->stats.handle));
		} else switch (tmpl->value->values_types[0]) {
		case LCC_TYPE_COUNTER:
		case LCC_TYPE_DERIVE:
		case LCC_TYPE_ABSOLUTE:
			DEBUG1("Successful PUTVAL %s/%s/%s-%s interval=%i %i:%" PRIu64,
			       tmpl->value->identifier.plugin,
			       tmpl->value->identifier.plugin_instance,
			       tmpl->value->identifier.type,
			       tmpl->value->identifier.type_instance,
			       tmpl->value->interval,
			       tmpl->value->time,
			       tmpl->value->values[0].counter);
			break;
		case LCC_TYPE_GAUGE:
			DEBUG1("Successful PUTVAL %s/%s/%s-%s interval=%i %i:%lf",
			       tmpl->value->identifier.plugin,
			       tmpl->value->identifier.plugin_instance,
			       tmpl->value->identifier.type,
			       tmpl->value->identifier.type_instance,
			       tmpl->value->interval,
			       tmpl->value->time,
			       tmpl->value->values[0].gauge);
			break;
		}

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
