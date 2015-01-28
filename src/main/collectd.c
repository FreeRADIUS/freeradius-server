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
 * $Id$
 * @file collectd.c
 * @brief Helper functions to enabled radsniff to talk to collectd
 *
 * @copyright 2013 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <assert.h>
#include <ctype.h>

#ifdef HAVE_COLLECTDC_H
#include <collectd/client.h>
#include <freeradius-devel/radsniff.h>

/** Copy a 64bit unsigned integer into a double
 *
 */
/*
static void _copy_uint64_to_double(UNUSED rs_t *conf, rs_stats_value_tmpl_t *tmpl)
{
	assert(tmpl->src);
	assert(tmpl->dst);

	*((double *) tmpl->dst) = *((uint64_t *) tmpl->src);
}
*/

/*
static void _copy_uint64_to_uint64(UNUSED rs_t *conf, rs_stats_value_tmpl_t *tmpl)
{
	assert(tmpl->src);
	assert(tmpl->dst);

	*((uint64_t *) tmpl->dst) = *((uint64_t *) tmpl->src);
}
*/

static void _copy_double_to_double(UNUSED rs_t *conf, rs_stats_value_tmpl_t *tmpl)
{
	assert(tmpl->src);
	assert(tmpl->dst);

	*((double *) tmpl->dst) = *((double*) tmpl->src);
}


/** Allocates a stats template which describes a single guage/counter
 *
 * This is just intended to simplify allocating a fairly complex memory structure
 * src and dst pointers must be set
 *
 * @param ctx Context to allocate collectd struct in.
 * @param conf Radsniff configuration.
 * @param plugin_instance usually the type of packet (in our case).
 * @param type string, the name of a collection of stats e.g. exchange
 * @param type_instance the name of the counter/guage within the collection e.g. latency.
 * @param stats structure to derive statistics from.
 * @param values Value templates used to populate lcc_value_list.
 * @return a new rs_stats_tmpl_t on success or NULL on failure.
 */
static rs_stats_tmpl_t *rs_stats_collectd_init(TALLOC_CTX *ctx, rs_t *conf,
					       char const *plugin_instance,
					       char const *type, char const *type_instance,
					       void *stats,
					       rs_stats_value_tmpl_t const *values)
{
	static char hostname[255];
	static char fqdn[LCC_NAME_LEN];

	size_t len;
	int i;
	char *p;

	rs_stats_tmpl_t *tmpl;
	lcc_value_list_t *value;

	assert(conf);
	assert(type);
	assert(type_instance);

	for (len = 0; values[len].src; len++) {} ;
	assert(len > 0);

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
	if (!tmpl) {
		return NULL;
	}

	tmpl->value_tmpl = talloc_zero_array(tmpl, rs_stats_value_tmpl_t, len);
	if (!tmpl->value_tmpl) {
		goto error;
	}

	tmpl->stats = stats;

	value = talloc_zero(tmpl, lcc_value_list_t);
	if (!value) {
		goto error;
	}
	tmpl->value = value;

	value->interval = conf->stats.interval;
	value->values_len = len;

	value->values_types = talloc_zero_array(value, int, len);
	if (!value->values_types) {
		goto error;
	}

	value->values = talloc_zero_array(value, value_t, len);
	if (!value->values) {
		goto error;
	}

	for (i = 0; i < (int) len; i++) {
		assert(values[i].src);
		assert(values[i].cb);

		tmpl->value_tmpl[i] = values[i];
		switch (tmpl->value_tmpl[i].type) {
		case LCC_TYPE_COUNTER:
			tmpl->value_tmpl[i].dst = &value->values[i].counter;
			break;

		case LCC_TYPE_GAUGE:
			tmpl->value_tmpl[i].dst = &value->values[i].gauge;
			break;

		case LCC_TYPE_DERIVE:
			tmpl->value_tmpl[i].dst = &value->values[i].derive;
			break;

		case LCC_TYPE_ABSOLUTE:
			tmpl->value_tmpl[i].dst = &value->values[i].absolute;
			break;

		default:
			assert(0);
		}
		value->values_types[i] = tmpl->value_tmpl[i].type;
	}

	/*
	 *	These should be OK as is
	 */
	strlcpy(value->identifier.host, fqdn, sizeof(value->identifier.host));

	/*
	 *	Plugin is ASCII only and no '/'
	 */
	fr_prints(value->identifier.plugin, sizeof(value->identifier.plugin),
		  conf->stats.prefix, strlen(conf->stats.prefix), '\0');
	for (p = value->identifier.plugin; *p; ++p) {
		if ((*p == '-') || (*p == '/'))*p = '_';
	}

	/*
	 *	Plugin instance is ASCII only (assuming printable only) and no '/'
	 */
	fr_prints(value->identifier.plugin_instance, sizeof(value->identifier.plugin_instance),
		  plugin_instance, strlen(plugin_instance), '\0');
	for (p = value->identifier.plugin_instance; *p; ++p) {
		if ((*p == '-') || (*p == '/')) *p = '_';
	}

	/*
	 *	Type is ASCII only (assuming printable only) and no '/' or '-'
	 */
	fr_prints(value->identifier.type, sizeof(value->identifier.type),
		  type, strlen(type), '\0');
	for (p = value->identifier.type; *p; ++p) {
		if ((*p == '-') || (*p == '/')) *p = '_';
	}

	fr_prints(value->identifier.type_instance, sizeof(value->identifier.type_instance),
		  type_instance, strlen(type_instance), '\0');
	for (p = value->identifier.type_instance; *p; ++p) {
		if ((*p == '-') || (*p == '/')) *p = '_';
	}


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

	rs_stats_value_tmpl_t rtx[(RS_RETRANSMIT_MAX + 1) + 1 + 1];	// RTX bins + 0 bin + lost + NULL
	int i;

	/* not static so were thread safe */
	rs_stats_value_tmpl_t const _packet_count[] = {
		{ &stats->interval.received, LCC_TYPE_GAUGE,  _copy_double_to_double, NULL },
		{ &stats->interval.linked, LCC_TYPE_GAUGE,  _copy_double_to_double, NULL },
		{ &stats->interval.unlinked, LCC_TYPE_GAUGE,  _copy_double_to_double, NULL },
		{ &stats->interval.reused, LCC_TYPE_GAUGE,  _copy_double_to_double, NULL },
		{ NULL, 0, NULL, NULL }
	};

	rs_stats_value_tmpl_t const _latency[] = {
		{ &stats->latency_smoothed, LCC_TYPE_GAUGE, _copy_double_to_double, NULL },
		{ &stats->interval.latency_average, LCC_TYPE_GAUGE, _copy_double_to_double, NULL },
		{ &stats->interval.latency_high, LCC_TYPE_GAUGE, _copy_double_to_double, NULL },
		{ &stats->interval.latency_low, LCC_TYPE_GAUGE, _copy_double_to_double, NULL },
		{ NULL, 0, NULL, NULL }
	};

#define INIT_STATS(_ti, _v) do {\
		strlcpy(buffer, fr_packet_codes[code], sizeof(buffer)); \
		for (p = buffer; *p; ++p) *p = tolower(*p);\
		last = *tmpl = rs_stats_collectd_init(ctx, conf, type, _ti, buffer, stats, _v);\
		if (!*tmpl) {\
			TALLOC_FREE(*out);\
			return NULL;\
		}\
		tmpl = &(*tmpl)->next;\
		ctx = *tmpl;\
		} while (0)


	INIT_STATS("radius_count", _packet_count);
	INIT_STATS("radius_latency", _latency);

	for (i = 0; i < (RS_RETRANSMIT_MAX + 1); i++) {
		rtx[i].src = &stats->interval.rt[i];
		rtx[i].type = LCC_TYPE_GAUGE;
		rtx[i].cb = _copy_double_to_double;
		rtx[i].dst = NULL;
	}

	rtx[i].src = &stats->interval.lost;
	rtx[i].type = LCC_TYPE_GAUGE;
	rtx[i].cb = _copy_double_to_double;
	rtx[i].dst = NULL;

	memset(&rtx[++i], 0, sizeof(rs_stats_value_tmpl_t));

	INIT_STATS("radius_rtx", rtx);

	return last;
}

/** Refresh and send the stats to the collectd server
 *
 */
void rs_stats_collectd_do_stats(rs_t *conf, rs_stats_tmpl_t *tmpls, struct timeval *now)
{
	rs_stats_tmpl_t *tmpl = tmpls;
	char identifier[6 * LCC_NAME_LEN];
	int i;

	while (tmpl) {
		/*
		 *	Refresh the value of whatever were sending
		 */
		for (i = 0; i < (int) tmpl->value->values_len; i++) {
			tmpl->value_tmpl[i].cb(conf, &tmpl->value_tmpl[i]);
		}

		tmpl->value->time = now->tv_sec;

		lcc_identifier_to_string(conf->stats.handle, identifier, sizeof(identifier), &tmpl->value->identifier);

		if (lcc_putval(conf->stats.handle, tmpl->value) < 0) {
			char const *error;

			error = lcc_strerror(conf->stats.handle);
			ERROR("Failed PUTVAL \"%s\" interval=%i %" PRIu64 " : %s",
			      identifier,
			      (int) tmpl->value->interval,
			      (uint64_t) tmpl->value->time,
			      error ? error : "unknown error");
		}

		tmpl = tmpl->next;
	}
}

/** Connect to a collectd server for stats output
 *
 * @param[in,out] conf radsniff configuration, we write the generated handle here.
 * @return 0 on success -1 on failure.
 */
int rs_stats_collectd_open(rs_t *conf)
{
	assert(conf->stats.collectd);

	/*
	 *	Tear down stale connections gracefully.
	 */
	rs_stats_collectd_close(conf);

	/*
	 *	There's no way to get the error from the connection handle
	 *	because it's freed on failure, before lcc returns.
	 */
	if (lcc_connect(conf->stats.collectd, &conf->stats.handle) < 0) {
		ERROR("Failed opening connection to collectd: %s", fr_syserror(errno));
		return -1;
	}
	DEBUG2("Connected to \"%s\"", conf->stats.collectd);

	assert(conf->stats.handle);
	return 0;
}

/** Close connection
 *
 * @param[in,out] conf radsniff configuration.
 * @return 0 on success -1 on failure.
 */
int rs_stats_collectd_close(rs_t *conf)
{
	assert(conf->stats.collectd);

	int ret = 0;

	if (conf->stats.handle) {
		ret = lcc_disconnect(conf->stats.handle);
		conf->stats.handle = NULL;
	}

	return ret;
}
#endif
