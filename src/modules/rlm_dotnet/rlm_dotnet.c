/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

/**
 * $Id$
 * @file rlm_dotnet.c
 * @brief Host .NET assemblies via hostfxr / nethost (see README.md).
 *
 * @copyright 2026 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/rad_assert.h>

#include <pthread.h>
#include <dlfcn.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <nethost.h>

#include <freeradius-devel/log.h>

#include "rlm_dotnet_hostfxr.h"

/*
 *	Export for managed code: maps to radlog(3) so ExamplePolicy can mirror
 *	rlm_python / rlm_perl example debug output.
 */
void dotnet_fr_radlog(int lvl, char const *msg)
{
	if (!msg) return;
	radlog((log_type_t)lvl, "%s", msg);
}

/** Trim trailing '/' or '\\' in place. */
static void dotnet_path_trim_slashes(char *s)
{
	size_t n;

	if (!s) return;
	n = strlen(s);
	while (n > 0 && (s[n - 1] == '/' || s[n - 1] == '\\')) s[--n] = '\0';
}

/** Collapse duplicate '/' inside a path (in place). */
static void dotnet_path_collapse_slashes(char *s)
{
	char *w, *r;

	if (!s || !*s) return;
	w = s;
	r = s;
	if (*r == '/') *w++ = *r++;
	while (*r) {
		if (*r == '/' && w > s && w[-1] == '/') {
			r++;
			continue;
		}
		*w++ = *r++;
	}
	*w = '\0';
}

static char const *dotnet_path_basename(char const *path)
{
	char const *slash = strrchr(path, '/');
#ifdef WIN32
	char const *bs = strrchr(path, '\\');

	if (!slash || (bs && bs > slash)) slash = bs;
#endif
	return slash ? (slash + 1) : path;
}

/*
 *	hostfxr requires a path to a .runtimeconfig.json file. If the operator
 *	passes a directory (common mistake: trailing '/'), build
 *	<dir>/<assembly_stem>.runtimeconfig.json from assembly_path.
 */
static char *dotnet_normalize_runtime_config(TALLOC_CTX *ctx, char const *assembly_path,
					   char const *runtime_path_in)
{
	struct stat	st;
	char		*work;
	char const	*base;
	size_t		blen;

	work = talloc_strdup(ctx, runtime_path_in);
	if (!work) return NULL;

	dotnet_path_trim_slashes(work);

	if (stat(work, &st) == 0 && S_ISDIR(st.st_mode)) {
		base = dotnet_path_basename(assembly_path);
		blen = strlen(base);
		if (blen < 4 || strcmp(base + blen - 4, ".dll") != 0) {
			ERROR("rlm_dotnet: assembly_path must end with .dll when runtime_config_path is a directory");
			talloc_free(work);
			return NULL;
		}
		{
			char *resolved = talloc_asprintf(ctx, "%s/%.*s.runtimeconfig.json",
							 work, (int)(blen - 4), base);
			talloc_free(work);
			work = resolved;
		}
		if (!work) return NULL;
	}
	dotnet_path_collapse_slashes(work);
	return work;
}

#ifndef HOSTFXR_DL_NAME
#define HOSTFXR_DL_NAME "libhostfxr.so"
#endif

typedef hostfxr_handle dotnet_hostfxr_cxt_t;

typedef int (HOSTFXR_CALLTYPE *hostfxr_initialize_for_runtime_config_fn)(
	char const *runtime_config_path, void const *parameters, dotnet_hostfxr_cxt_t *host_context);
typedef int (HOSTFXR_CALLTYPE *hostfxr_get_runtime_delegate_fn)(
	dotnet_hostfxr_cxt_t host_context, int32_t type, void **delegate);
typedef int (HOSTFXR_CALLTYPE *hostfxr_close_fn)(dotnet_hostfxr_cxt_t host_context);

typedef int (HOSTFXR_CALLTYPE *load_assembly_and_get_function_pointer_fn)(
	char const *assembly_path, char const *type_name, char const *method_name,
	char const *delegate_type_name, void *reserved, void **delegate);

typedef int (*dotnet_fr_instantiate_fn)(char const *config_json, void **out_handle);
typedef void (*dotnet_fr_detach_fn)(void *handle);
typedef int (*dotnet_fr_authorize_fn)(void *handle, uint8_t const *request_blob,
				      int32_t request_len, uint8_t *reply_buf, int32_t reply_buf_len,
				      int32_t *out_written, int32_t *out_reply_format,
				      uint8_t *error_buf, int32_t error_buf_len,
				      int32_t *out_error_written);
typedef int (*dotnet_fr_ensure_thread_policy_fn)(void *factory_handle, void **out_policy_handle);

typedef struct {
	uint64_t	calls;
	uint64_t	failures;
	uint64_t	total_usec;
	uint64_t	last_usec;
} dotnet_stats_t;

typedef struct {
	char const			*name;
	char const			*assembly_path;
	char const			*runtime_config_path;
	char const			*native_exports_type;	//!< "Namespace.Type, Assembly" (hostfxr exports)
	char const			*policy_type;		//!< "Namespace.Class, Assembly" (user module)
	char const			*extra_config;		//!< optional JSON object merged into boot "extra"
	char const			*policy_instance_mode;	//!< "shared" or "per_thread"
	uint32_t			reply_buffer_size;
	uint32_t			error_buffer_size;
	bool				stats;
	uint32_t			stats_log_interval;
	uint32_t			async_timeout_ms;

	dotnet_stats_t			stats_accum;
	uint64_t			stats_last_log_usec;	/* monotonic; interval stats */
	uint64_t			stats_interval_base_calls;
	uint64_t			stats_interval_base_usec;

	void				*hostfxr_dl;
	hostfxr_initialize_for_runtime_config_fn init_for_config;
	hostfxr_get_runtime_delegate_fn	get_runtime_delegate;
	hostfxr_close_fn			close_fn;
	load_assembly_and_get_function_pointer_fn load_asm;

	dotnet_hostfxr_cxt_t			host_context;
	dotnet_fr_instantiate_fn		fn_instantiate;
	dotnet_fr_detach_fn			fn_detach;
	dotnet_fr_ensure_thread_policy_fn	fn_ensure_thread_policy;
	dotnet_fr_authorize_fn			fn_authorize;

	/*
	 *	shared: one policy GCHandle for all workers.
	 *	per_thread: factory GCHandle; per-worker policy via fr_thread_local + EnsureThreadPolicy.
	 */
	void					*managed_handle;
	bool					per_thread_policy;
} rlm_dotnet_t;

#define DOTNET_REPLY_BUF_DEFAULT	65536
#define DOTNET_REPLY_BUF_MIN		4096
#define DOTNET_REPLY_BUF_MAX		(16 * 1024 * 1024)
#define DOTNET_ERROR_BUF_DEFAULT	8192
#define DOTNET_ERROR_BUF_MIN		256
#define DOTNET_ERROR_BUF_MAX		(1024 * 1024)

#define DOTNET_REPLY_FORMAT_PAIRLIST	0
#define DOTNET_REPLY_FORMAT_BLOB_V1	1

#define DOTNET_REPLY_BLOB_VERSION	1
#define DOTNET_REPLY_FLAG_MERGE		0x02

#define DOTNET_REQ_VFLAG_XLAT		0x01

static void dotnet_publish_authorize_fn(dotnet_fr_authorize_fn *slot, void *fn);

typedef struct {
	void				*policy_handle;
	dotnet_fr_detach_fn		detach_fn;
} dotnet_thread_policy_t;

fr_thread_local_setup(dotnet_thread_policy_t *, dotnet_thread_policy)

static void dotnet_thread_policy_free(void *arg)
{
	dotnet_thread_policy_t	*ctx = arg;

	if (!ctx) return;
	if (ctx->policy_handle && ctx->detach_fn) ctx->detach_fn(ctx->policy_handle);
	talloc_free(ctx);
}

/** Append one JSON-escaped UTF-8 byte sequence to a talloc buffer. Returns -1 on OOM. */
static int dotnet_json_append_escaped(TALLOC_CTX *ctx, char **out, char const *s)
{
	char const	*p;
	char		*buf;
	size_t		alloc, len;

	if (!s) s = "";
	if (!*out) {
		alloc = 256;
		buf = talloc_array(ctx, char, alloc);
		if (!buf) return -1;
		buf[0] = '\0';
		*out = buf;
		len = 0;
	} else {
		buf = *out;
		len = strlen(buf);
		alloc = len + 1;
	}

	for (p = s; *p; p++) {
		unsigned char	c = (unsigned char)*p;
		char		esc[7];
		char const	*insert = NULL;
		size_t		ins_len = 0;

		switch (c) {
		case '"':
		case '\\':
			esc[0] = '\\';
			esc[1] = (char)c;
			esc[2] = '\0';
			insert = esc;
			ins_len = 2;
			break;

		case '\b':
			insert = "\\b";
			ins_len = 2;
			break;
		case '\f':
			insert = "\\f";
			ins_len = 2;
			break;
		case '\n':
			insert = "\\n";
			ins_len = 2;
			break;
		case '\r':
			insert = "\\r";
			ins_len = 2;
			break;
		case '\t':
			insert = "\\t";
			ins_len = 2;
			break;

		default:
			if (c < 0x20) {
				snprintf(esc, sizeof(esc), "\\u%04x", c);
				insert = esc;
				ins_len = 6;
			} else {
				esc[0] = (char)c;
				esc[1] = '\0';
				insert = esc;
				ins_len = 1;
			}
			break;
		}

		while (len + ins_len + 1 > alloc) {
			size_t	n = alloc * 2;
			char	*nbuf = talloc_realloc(ctx, buf, char, n);

			if (!nbuf) return -1;
			buf = nbuf;
			alloc = n;
			*out = buf;
		}
		memcpy(buf + len, insert, ins_len);
		len += ins_len;
		buf[len] = '\0';
	}
	return 0;
}

/** Build boot JSON with proper string escaping. `extra_config` must be a JSON object (or null). */
static char *dotnet_build_boot_json(TALLOC_CTX *ctx, rlm_dotnet_t const *inst)
{
	char	*escaped = NULL;
	char	*json;
	char const *extra;

	if (dotnet_json_append_escaped(ctx, &escaped, inst->name) < 0) return NULL;
	json = talloc_asprintf(ctx, "{\"instance_name\":\"%s\"", escaped);
	talloc_free(escaped);
	if (!json) return NULL;

	escaped = NULL;
	if (dotnet_json_append_escaped(ctx, &escaped, inst->assembly_path) < 0) return NULL;
	json = talloc_asprintf_append_buffer(json, ",\"assembly_path\":\"%s\"", escaped);
	talloc_free(escaped);
	if (!json) return NULL;

	escaped = NULL;
	if (dotnet_json_append_escaped(ctx, &escaped, inst->runtime_config_path) < 0) return NULL;
	json = talloc_asprintf_append_buffer(json, ",\"runtime_config_path\":\"%s\"", escaped);
	talloc_free(escaped);
	if (!json) return NULL;

	escaped = NULL;
	if (dotnet_json_append_escaped(ctx, &escaped, inst->native_exports_type) < 0) return NULL;
	json = talloc_asprintf_append_buffer(json, ",\"native_exports_type\":\"%s\"", escaped);
	talloc_free(escaped);
	if (!json) return NULL;

	escaped = NULL;
	if (dotnet_json_append_escaped(ctx, &escaped, inst->policy_type) < 0) return NULL;
	json = talloc_asprintf_append_buffer(json, ",\"policy_type\":\"%s\"", escaped);
	talloc_free(escaped);
	if (!json) return NULL;

	json = talloc_asprintf_append_buffer(json,
					     ",\"radlog_fn\":\"0x%" PRIxPTR "\""
					     ",\"publish_authorize_fn\":\"0x%" PRIxPTR "\""
					     ",\"authorize_fn_out\":\"0x%" PRIxPTR "\""
					     ",\"policy_instance_mode\":\"%s\""
					     ",\"async_timeout_ms\":%u",
					     (uintptr_t)dotnet_fr_radlog,
					     (uintptr_t)dotnet_publish_authorize_fn,
					     (uintptr_t)&inst->fn_authorize,
					     inst->per_thread_policy ? "per_thread" : "shared",
					     inst->async_timeout_ms);
	if (!json) return NULL;

	extra = inst->extra_config;
	if (!extra || !*extra) extra = "{}";
	else {
		while (*extra == ' ' || *extra == '\t') extra++;
		if (*extra != '{') {
			ERROR("rlm_dotnet: extra_config must be a JSON object (starts with '{')");
			return NULL;
		}
	}
	return talloc_asprintf_append_buffer(json, ",\"extra\":%s}", extra);
}

/** Log managed error JSON from AuthorizeBlob (UTF-8, may be truncated). */
static void dotnet_log_managed_error(REQUEST *request, char const *error_json)
{
	if (!error_json || !*error_json) return;
	RERROR("rlm_dotnet: managed policy error: %s", error_json);
}

/** Monotonic microseconds (not subject to wall-clock adjustment). */
static uint64_t dotnet_time_usec(void)
{
#if defined(HAVE_CLOCK_GETTIME)
	{
		struct timespec ts;

		if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
			return ((uint64_t)ts.tv_sec * 1000000) + ((uint64_t)ts.tv_nsec / 1000);
		}
	}
#endif
	{
		struct timeval tv;

		gettimeofday(&tv, NULL);
		return ((uint64_t)tv.tv_sec * 1000000) + (uint64_t)tv.tv_usec;
	}
}

static void dotnet_stats_log(rlm_dotnet_t *inst, char const *when, bool interval)
{
	uint64_t	calls, failures, total_usec, last_usec;
	double		avg_ms, calls_per_sec = 0.0;

	if (!inst->stats) return;

	calls = __atomic_load_n(&inst->stats_accum.calls, __ATOMIC_RELAXED);
	failures = __atomic_load_n(&inst->stats_accum.failures, __ATOMIC_RELAXED);
	total_usec = __atomic_load_n(&inst->stats_accum.total_usec, __ATOMIC_RELAXED);
	last_usec = __atomic_load_n(&inst->stats_accum.last_usec, __ATOMIC_RELAXED);
	avg_ms = (calls > 0) ? ((double)total_usec / (double)calls) / 1000.0 : 0.0;

	if (interval) {
		uint64_t	now = dotnet_time_usec();
		uint64_t	delta_calls = calls - inst->stats_interval_base_calls;
		uint64_t	delta_usec = now - inst->stats_interval_base_usec;

		if (delta_usec > 0) {
			calls_per_sec = ((double)delta_calls * 1000000.0) / (double)delta_usec;
		}
		inst->stats_interval_base_calls = calls;
		inst->stats_interval_base_usec = now;
		INFO("rlm_dotnet (%s) stats [%s]: calls=%" PRIu64 " failures=%" PRIu64
		     " avg_ms=%.3f last_ms=%.3f calls_per_sec=%.2f",
		     inst->name, when, calls, failures, avg_ms, (double)last_usec / 1000.0, calls_per_sec);
		return;
	}

	INFO("rlm_dotnet (%s) stats [%s]: calls=%" PRIu64 " failures=%" PRIu64
	     " avg_ms=%.3f last_ms=%.3f",
	     inst->name, when, calls, failures, avg_ms, (double)last_usec / 1000.0);
}

/** Log stats every stats_log_interval seconds (0 = disabled). */
static void dotnet_stats_maybe_log_interval(rlm_dotnet_t *inst)
{
	uint64_t	now, last, interval_usec;

	if (!inst->stats || inst->stats_log_interval == 0) return;

	interval_usec = (uint64_t)inst->stats_log_interval * 1000000ULL;
	now = dotnet_time_usec();
	last = __atomic_load_n(&inst->stats_last_log_usec, __ATOMIC_RELAXED);
	if ((now - last) < interval_usec) return;

	if (!__atomic_compare_exchange_n(&inst->stats_last_log_usec, &last, now,
				       false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		return;
	}

	dotnet_stats_log(inst, "interval", true);
}

static void dotnet_stats_record(rlm_dotnet_t *inst, uint64_t elapsed_usec, bool failed)
{
	if (!inst->stats) return;

	__atomic_fetch_add(&inst->stats_accum.calls, 1, __ATOMIC_RELAXED);
	__atomic_fetch_add(&inst->stats_accum.total_usec, elapsed_usec, __ATOMIC_RELAXED);
	__atomic_store_n(&inst->stats_accum.last_usec, elapsed_usec, __ATOMIC_RELAXED);
	if (failed) __atomic_fetch_add(&inst->stats_accum.failures, 1, __ATOMIC_RELAXED);

	dotnet_stats_maybe_log_interval(inst);
}

static uint16_t dotnet_blob_read_u16_be(uint8_t const *p)
{
	return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t dotnet_blob_read_u32_be(uint8_t const *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/** Decode one wire VP into request->reply (merge). */
static int dotnet_reply_blob_read_vp(TALLOC_CTX *ctx, REQUEST *request, uint8_t const **pos, uint8_t const *end)
{
	uint16_t	name_len;
	uint8_t		tag, op, value_flags, reserved;
	uint16_t	pw_type;
	uint32_t	value_len;
	char		*name;
	DICT_ATTR const	*da;
	VALUE_PAIR	*vp;
	uint8_t const	*value;

	if ((size_t)(end - *pos) < 2) return -1;
	name_len = dotnet_blob_read_u16_be(*pos);
	*pos += 2;
	if ((size_t)(end - *pos) < (size_t)name_len + 6 + 4) return -1;

	name = talloc_strndup(ctx, (char const *)*pos, name_len);
	if (!name) return -1;
	*pos += name_len;

	tag = (int8_t)(*pos)[0];
	op = (*pos)[1];
	value_flags = (*pos)[2];
	reserved = (*pos)[3];
	(void)reserved;
	pw_type = dotnet_blob_read_u16_be(*pos + 4);
	*pos += 6;
	/*
	 *	Wire pw_type is informational; dict_attrbyname() selects the
	 *	canonical type used by fr_pair_value_memcpy().
	 */
	(void)pw_type;

	value_len = dotnet_blob_read_u32_be(*pos);
	*pos += 4;
	if ((size_t)(end - *pos) < value_len) {
		talloc_free(name);
		return -1;
	}
	value = *pos;
	*pos += value_len;

	da = dict_attrbyname(name);
	if (!da) {
		RERROR("rlm_dotnet: unknown attribute in reply blob \"%s\"", name);
		talloc_free(name);
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) {
		talloc_free(name);
		return -1;
	}
	vp->op = (FR_TOKEN)op;
	vp->tag = tag;

	if (value_flags & DOTNET_REQ_VFLAG_XLAT) {
		vp->type = VT_XLAT;
		vp->value.xlat = talloc_strndup(vp, (char const *)value, value_len);
		if (!vp->value.xlat) {
			talloc_free(vp);
			talloc_free(name);
			return -1;
		}
	} else {
		fr_pair_value_memcpy(vp, value, value_len);
	}

	fr_pair_add(&request->reply->vps, vp);
	talloc_free(name);
	return 0;
}

/** Apply RDr1 v1 reply blob to request->reply (merge by default). */
static int dotnet_apply_reply_blob(REQUEST *request, uint8_t const *blob, size_t len)
{
	uint32_t	payload_len, vp_count, i;
	uint16_t	version, flags;
	uint8_t const	*pos, *end, *payload;

	if (!request->reply) {
		RERROR("rlm_dotnet: cannot apply reply blob (reply is NULL)");
		return -1;
	}
	if (len < 12) {
		RERROR("rlm_dotnet: reply blob shorter than header");
		return -1;
	}
	if (blob[0] != 'R' || blob[1] != 'D' || blob[2] != 'r' || blob[3] != '1') {
		RERROR("rlm_dotnet: reply blob bad magic (expected RDr1)");
		return -1;
	}

	version = dotnet_blob_read_u16_be(blob + 4);
	flags = dotnet_blob_read_u16_be(blob + 6);
	payload_len = dotnet_blob_read_u32_be(blob + 8);
	if (version != DOTNET_REPLY_BLOB_VERSION) {
		RERROR("rlm_dotnet: unsupported reply blob version %u", version);
		return -1;
	}
	if (12 + payload_len != len) {
		RERROR("rlm_dotnet: reply blob length mismatch");
		return -1;
	}
	(void)flags;

	payload = blob + 12;
	end = payload + payload_len;
	pos = payload;
	if ((size_t)(end - pos) < 4) {
		RERROR("rlm_dotnet: reply blob truncated at vp_count");
		return -1;
	}

	if (!(flags & DOTNET_REPLY_FLAG_MERGE)) {
		fr_pair_list_free(&request->reply->vps);
	}

	vp_count = dotnet_blob_read_u32_be(pos);
	pos += 4;
	for (i = 0; i < vp_count; i++) {
		if (dotnet_reply_blob_read_vp(request, request, &pos, end) < 0) return -1;
	}
	if (pos != end) {
		RERROR("rlm_dotnet: reply blob trailing garbage");
		return -1;
	}
	return 0;
}

static void *dotnet_policy_handle_get(rlm_dotnet_t *inst)
{
	dotnet_thread_policy_t	*ctx;
	void			*policy = NULL;
	int			rc;

	if (!inst->per_thread_policy) return inst->managed_handle;

	ctx = fr_thread_local_init(dotnet_thread_policy, dotnet_thread_policy_free);
	if (!ctx) {
		ctx = talloc_zero(NULL, dotnet_thread_policy_t);
		if (!ctx) return NULL;
		ctx->detach_fn = inst->fn_detach;
		if (fr_thread_local_set(dotnet_thread_policy, ctx) != 0) {
			talloc_free(ctx);
			return NULL;
		}
	} else if (!ctx->detach_fn) {
		ctx->detach_fn = inst->fn_detach;
	}

	if (ctx->policy_handle) return ctx->policy_handle;

	if (!inst->fn_ensure_thread_policy) return NULL;
	rc = inst->fn_ensure_thread_policy(inst->managed_handle, &policy);
	if (rc != 0 || !policy) return NULL;
	ctx->policy_handle = policy;
	return ctx->policy_handle;
}

/**
 *	Called from managed during Instantiate to store the AuthorizeBlob thunk in native memory.
 *	Managed-side <c>Marshal.WriteIntPtr</c> into <c>rlm_dotnet_t</c> from the hosted CLR has been
 *	observed to silently no-op; performing the store from native C avoids that.
 */
static void dotnet_publish_authorize_fn(dotnet_fr_authorize_fn *slot, void *fn)
{
	if (slot) *slot = (dotnet_fr_authorize_fn)(uintptr_t)fn;
}

static pthread_once_t		dotnet_host_once = PTHREAD_ONCE_INIT;
static void			*g_hostfxr_dl;
static hostfxr_initialize_for_runtime_config_fn g_init_for_config;
static hostfxr_get_runtime_delegate_fn	g_get_runtime_delegate;
static hostfxr_close_fn			g_close_fn;

static void dotnet_host_load_once(void)
{
	char		hostfxr_path[PATH_MAX];
	size_t		buf_size = sizeof(hostfxr_path);
	int		rc;
	void		*dl;

	rc = get_hostfxr_path(hostfxr_path, &buf_size, NULL);
	if (rc != 0) {
		ERROR("rlm_dotnet: get_hostfxr_path failed (%d) — is .NET installed?", rc);
		return;
	}

	dl = dlopen(hostfxr_path, RTLD_NOW | RTLD_LOCAL);
	if (!dl) {
		ERROR("rlm_dotnet: dlopen(%s) failed: %s", hostfxr_path, dlerror());
		return;
	}

	g_init_for_config = (hostfxr_initialize_for_runtime_config_fn)dlsym(dl, "hostfxr_initialize_for_runtime_config");
	g_get_runtime_delegate = (hostfxr_get_runtime_delegate_fn)dlsym(dl, "hostfxr_get_runtime_delegate");
	g_close_fn = (hostfxr_close_fn)dlsym(dl, "hostfxr_close");

	if (!g_init_for_config || !g_get_runtime_delegate || !g_close_fn) {
		ERROR("rlm_dotnet: missing symbols in hostfxr: %s", dlerror());
		dlclose(dl);
		return;
	}
	g_hostfxr_dl = dl;
}

static int dotnet_resolve_runtime(rlm_dotnet_t *inst)
{
	int		rc;
	void		*delegate = NULL;

	pthread_once(&dotnet_host_once, dotnet_host_load_once);
	if (!g_hostfxr_dl) return -1;

	inst->hostfxr_dl = g_hostfxr_dl;
	inst->init_for_config = g_init_for_config;
	inst->get_runtime_delegate = g_get_runtime_delegate;
	inst->close_fn = g_close_fn;

	rc = inst->init_for_config(inst->runtime_config_path, NULL, &inst->host_context);
	if (rc != 0 || !inst->host_context) {
		ERROR("rlm_dotnet: hostfxr_initialize_for_runtime_config failed (%d) for \"%s\"",
		      rc, inst->runtime_config_path);
		return -1;
	}

	rc = inst->get_runtime_delegate(inst->host_context, (int32_t)hdt_load_assembly_and_get_function_pointer, &delegate);
	if (rc != 0 || !delegate) {
		ERROR("rlm_dotnet: hostfxr_get_runtime_delegate failed (%d)", rc);
		inst->close_fn(inst->host_context);
		inst->host_context = NULL;
		return -1;
	}
	inst->load_asm = (load_assembly_and_get_function_pointer_fn)delegate;
	return 0;
}

/**
 *	Split "Namespace.Type, Assembly" from native_exports_type (first comma only).
 */
static int dotnet_split_native_exports_type(TALLOC_CTX *ctx, char const *native_exports_type,
					    char **out_type, char **out_asm)
{
	char const	*comma;
	char		*type, *asmq;
	size_t		len;

	comma = strchr(native_exports_type, ',');
	if (!comma || !comma[1]) {
		ERROR("rlm_dotnet: native_exports_type must be \"TypeName, Assembly\"");
		return -1;
	}

	type = talloc_strndup(ctx, native_exports_type, (size_t)(comma - native_exports_type));
	if (!type) return -1;
	len = strlen(type);
	while (len > 0 && (type[len - 1] == ' ' || type[len - 1] == '\t')) type[--len] = '\0';

	comma++;
	while (*comma == ' ' || *comma == '\t') comma++;
	asmq = talloc_strdup(ctx, comma);
	if (!asmq) {
		talloc_free(type);
		return -1;
	}
	len = strlen(asmq);
	while (len > 0 && (asmq[len - 1] == ' ' || asmq[len - 1] == '\t')) asmq[--len] = '\0';

	*out_type = type;
	*out_asm = asmq;
	return 0;
}

/**
 *	Bind a hostfxr export. `method` is the managed name (`Instantiate`, `Detach`, …).
 *	`delegate_type_name` must match DNNE: "EnclosingType+MethodDelegate, Assembly" (see interop DLL).
 */
static int dotnet_bind_export(rlm_dotnet_t *inst, char const *method, char const *delegate_type_name, void **out)
{
	int rc;

	rc = inst->load_asm(inst->assembly_path, inst->native_exports_type, method,
			   delegate_type_name, NULL, out);
	if (rc != 0 || !*out) {
		ERROR("rlm_dotnet: load_assembly_and_get_function_pointer(%s) failed (%d) (0x%x)",
		      method, rc, (unsigned int)(uint32_t)rc);
		return -1;
	}
	return 0;
}

/*
 *	Binary request snapshot v1 (managed decoder: RadiusRequestBlob.Parse).
 *	Big-endian where noted. Max size DOTNET_REQUEST_BLOB_MAX.
 *
 *	Header (12 bytes): magic "RDb1", version u16 BE, flags u16 BE, payload_len u32 BE
 *	Payload: section_len u16 BE + UTF-8 section, num_lists u16 BE,
 *		then for each list: vp_count u32 BE + vp_count * VpRecord
 *	VpRecord: name_len u16 BE + name UTF-8, tag int8, op uint8, value_flags uint8,
 *		reserved uint8, pw_type u16 BE (PW_TYPE), value_len u32 BE, value bytes
 *	value_flags: bit0 = VT_XLAT template (value is UTF-8 of expansion source; pw_type is still dict type)
 *	List order: packet, reply, config, session_state [, proxy_request, proxy_reply if WITH_PROXY]
 */
#define DOTNET_REQ_BLOB_VERSION		1
#define DOTNET_REQUEST_BLOB_MAX		(1024 * 1024)

typedef struct {
	TALLOC_CTX	*ctx;
	uint8_t		*buf;
	size_t		len, alloc;
} dotnet_blob_t;

static int dotnet_blob_grow(dotnet_blob_t *b, size_t need)
{
	if (b->len + need > DOTNET_REQUEST_BLOB_MAX) return -1;
	while (b->len + need > b->alloc) {
		size_t	n = b->alloc ? b->alloc * 2 : 4096;
		uint8_t	*nbuf = talloc_realloc(b->ctx, b->buf, uint8_t, n);

		if (!nbuf) return -1;
		b->buf = nbuf;
		b->alloc = n;
	}
	return 0;
}

static int dotnet_blob_append_raw(dotnet_blob_t *b, void const *data, size_t datalen)
{
	if (datalen == 0) return 0;
	if (dotnet_blob_grow(b, datalen) < 0) return -1;
	memcpy(b->buf + b->len, data, datalen);
	b->len += datalen;
	return 0;
}

static void dotnet_blob_put_u16_be(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static int dotnet_blob_append_u16_be(dotnet_blob_t *b, uint16_t v)
{
	uint8_t tmp[2];

	dotnet_blob_put_u16_be(tmp, v);
	return dotnet_blob_append_raw(b, tmp, sizeof(tmp));
}

static int dotnet_blob_append_u32_be(dotnet_blob_t *b, uint32_t v)
{
	uint8_t tmp[4];

	tmp[0] = (uint8_t)(v >> 24);
	tmp[1] = (uint8_t)(v >> 16);
	tmp[2] = (uint8_t)(v >> 8);
	tmp[3] = (uint8_t)v;
	return dotnet_blob_append_raw(b, tmp, sizeof(tmp));
}

static int dotnet_blob_append_i8(dotnet_blob_t *b, int8_t v)
{
	uint8_t u = (uint8_t)v;

	return dotnet_blob_append_raw(b, &u, 1);
}

static int dotnet_blob_append_u8(dotnet_blob_t *b, uint8_t v)
{
	return dotnet_blob_append_raw(b, &v, 1);
}

/** Append one VALUE_PAIR in v1 wire form. */
static int dotnet_blob_append_vp(dotnet_blob_t *b, VALUE_PAIR const *vp)
{
	size_t			name_len;
	uint8_t const		*vdata = NULL;
	ssize_t			vlen = 0;
	uint8_t			value_flags = 0;
	char const		*xlat;
	PW_TYPE			pw_type = vp->da->type;

	name_len = strlen(vp->da->name);
	if (name_len > 65535) return -1;

	if (vp->type == VT_XLAT) {
		value_flags |= DOTNET_REQ_VFLAG_XLAT;
		xlat = vp->value.xlat;
		if (!xlat) {
			vdata = (uint8_t const *)"";
			vlen = 0;
		} else {
			vdata = (uint8_t const *)xlat;
			vlen = (ssize_t)strlen(xlat);
		}
	} else {
		vlen = rad_vp2data(&vdata, vp);
		if (vlen < 0) {
			if (vp->vp_length > 0 && vp->vp_octets) {
				vdata = vp->vp_octets;
				vlen = (ssize_t)vp->vp_length;
			} else {
				vdata = NULL;
				vlen = 0;
			}
		}
	}

	if (dotnet_blob_append_u16_be(b, (uint16_t)name_len) < 0) return -1;
	if (name_len > 0 && dotnet_blob_append_raw(b, vp->da->name, name_len) < 0) return -1;
	if (dotnet_blob_append_i8(b, vp->tag) < 0) return -1;
	if (dotnet_blob_append_u8(b, (uint8_t)vp->op) < 0) return -1;
	if (dotnet_blob_append_u8(b, value_flags) < 0) return -1;
	if (dotnet_blob_append_u8(b, 0) < 0) return -1; /* reserved */
	if (dotnet_blob_append_u16_be(b, (uint16_t)pw_type) < 0) return -1;
	if ((size_t)vlen > (size_t)UINT32_MAX) return -1;
	if (dotnet_blob_append_u32_be(b, (uint32_t)vlen) < 0) return -1;
	if (vlen > 0 && vdata && dotnet_blob_append_raw(b, vdata, (size_t)vlen) < 0) return -1;
	return 0;
}

static int dotnet_blob_append_vplist(dotnet_blob_t *b, VALUE_PAIR *vps)
{
	VALUE_PAIR	*vp;
	uint32_t	n = 0;

	for (vp = vps; vp != NULL; vp = vp->next) n++;
	if (dotnet_blob_append_u32_be(b, n) < 0) return -1;
	for (vp = vps; vp != NULL; vp = vp->next) {
		if (dotnet_blob_append_vp(b, vp) < 0) return -1;
	}
	return 0;
}

static uint8_t *dotnet_request_to_blob(TALLOC_CTX *ctx, REQUEST *request, char const *section, size_t *out_len)
{
	dotnet_blob_t	b;
	uint32_t	payload_len;
	uint8_t		hdr[12];
	char const	*sec = section ? section : "";
	size_t		slen = strlen(sec);

	*out_len = 0;
	memset(&b, 0, sizeof(b));
	b.ctx = ctx;

	if (!request->packet || !request->reply) {
		RERROR("rlm_dotnet: cannot build request blob (packet or reply is NULL)");
		return NULL;
	}
	if (slen > 65535) {
		RERROR("rlm_dotnet: section name too long for request blob");
		return NULL;
	}

	if (dotnet_blob_grow(&b, 12) < 0) return NULL;
	b.len = 12;

	if (dotnet_blob_append_u16_be(&b, (uint16_t)slen) < 0) goto fail;
	if (slen > 0 && dotnet_blob_append_raw(&b, sec, slen) < 0) goto fail;
#ifdef WITH_PROXY
	if (dotnet_blob_append_u16_be(&b, 6) < 0) goto fail;
#else
	if (dotnet_blob_append_u16_be(&b, 4) < 0) goto fail;
#endif
	if (dotnet_blob_append_vplist(&b, request->packet->vps) < 0) goto fail;
	if (dotnet_blob_append_vplist(&b, request->reply->vps) < 0) goto fail;
	if (dotnet_blob_append_vplist(&b, request->config) < 0) goto fail;
	if (dotnet_blob_append_vplist(&b, request->state) < 0) goto fail;
#ifdef WITH_PROXY
	if (dotnet_blob_append_vplist(&b, (request->proxy && request->proxy->vps) ? request->proxy->vps : NULL) < 0) goto fail;
	if (dotnet_blob_append_vplist(&b, (request->proxy_reply && request->proxy_reply->vps) ? request->proxy_reply->vps : NULL) < 0) goto fail;
#endif
	if (b.len > DOTNET_REQUEST_BLOB_MAX) {
		RERROR("rlm_dotnet: request blob exceeds max (%u bytes)", DOTNET_REQUEST_BLOB_MAX);
		goto fail;
	}

	payload_len = (uint32_t)(b.len - 12);
	hdr[0] = 'R';
	hdr[1] = 'D';
	hdr[2] = 'b';
	hdr[3] = '1';
	dotnet_blob_put_u16_be(hdr + 4, DOTNET_REQ_BLOB_VERSION);
	dotnet_blob_put_u16_be(hdr + 6, 0);
	hdr[8] = (uint8_t)(payload_len >> 24);
	hdr[9] = (uint8_t)(payload_len >> 16);
	hdr[10] = (uint8_t)(payload_len >> 8);
	hdr[11] = (uint8_t)payload_len;
	memcpy(b.buf, hdr, sizeof(hdr));

	*out_len = b.len;
	return b.buf;

fail:
	talloc_free(b.buf);
	return NULL;
}

static int dotnet_apply_reply_pairs(REQUEST *request, char const *reply_spec)
{
	FR_TOKEN tok;

	if (!reply_spec || !*reply_spec) return 0;

	tok = fr_pair_list_afrom_str(request->reply, reply_spec, &request->reply->vps);
	if (tok == T_INVALID) {
		RERROR("Failed parsing reply attribute list from .NET module");
		return -1;
	}
	return 0;
}

static const CONF_PARSER module_config[] = {
	{ "assembly_path", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_dotnet_t, assembly_path), NULL },
	{ "runtime_config_path", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dotnet_t, runtime_config_path), NULL },
	{ "native_exports_type", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_dotnet_t, native_exports_type), NULL },
	{ "policy_type", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_dotnet_t, policy_type), NULL },
	{ "extra_config", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dotnet_t, extra_config), NULL },
	{ "policy_instance_mode", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dotnet_t, policy_instance_mode), "shared" },
	{ "reply_buffer_size", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_dotnet_t, reply_buffer_size), "65536" },
	{ "error_buffer_size", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_dotnet_t, error_buffer_size), "8192" },
	{ "async_timeout_ms", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_dotnet_t, async_timeout_ms), "0" },
	{ "stats", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_dotnet_t, stats), "yes" },
	{ "stats_log_interval", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_dotnet_t, stats_log_interval), "0" },
	CONF_PARSER_TERMINATOR
};

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_dotnet_t	*inst = instance;
	char		*boot_json = NULL;
	int		rc;

	inst->name = cf_section_name1(conf);

	{
		char const *rtc_src;
		char		*rtc_auto = NULL;
		char		*rtc_final;

		if (!inst->runtime_config_path) {
			char const *p = strrchr(inst->assembly_path, '.');
			size_t		dir_len;
			char const	*slash = strrchr(inst->assembly_path, '/');
#ifdef WIN32
			char const	*bs = strrchr(inst->assembly_path, '\\');
			if (!slash || (bs && bs > slash)) slash = bs;
#endif
			if (!slash) {
				cf_log_err_cs(conf, "assembly_path must contain a directory component");
				return -1;
			}
			dir_len = (size_t)(slash - inst->assembly_path) + 1;
			if (!p || strcmp(p, ".dll") != 0) {
				cf_log_err_cs(conf, "assembly_path must end with .dll when runtime_config_path is not set");
				return -1;
			}
			rtc_auto = talloc_asprintf(inst, "%.*s%.*s.runtimeconfig.json",
						   (int)dir_len, inst->assembly_path,
						   (int)(p - inst->assembly_path), inst->assembly_path);
			if (!rtc_auto) return -1;
			rtc_src = rtc_auto;
		} else {
			rtc_src = inst->runtime_config_path;
		}

		rtc_final = dotnet_normalize_runtime_config(inst, inst->assembly_path, rtc_src);
		if (!rtc_final) {
			talloc_free(rtc_auto);
			return -1;
		}
		talloc_free(rtc_auto);
		inst->runtime_config_path = rtc_final;
	}

	if (!inst->policy_instance_mode) inst->policy_instance_mode = "shared";
	if (strcmp(inst->policy_instance_mode, "shared") == 0) {
		inst->per_thread_policy = false;
	} else if (strcmp(inst->policy_instance_mode, "per_thread") == 0) {
		inst->per_thread_policy = true;
	} else {
		cf_log_err_cs(conf, "policy_instance_mode must be \"shared\" or \"per_thread\"");
		return -1;
	}

	if (!inst->reply_buffer_size) {
		inst->reply_buffer_size = DOTNET_REPLY_BUF_DEFAULT;
	} else if (inst->reply_buffer_size < DOTNET_REPLY_BUF_MIN ||
		   inst->reply_buffer_size > DOTNET_REPLY_BUF_MAX) {
		cf_log_err_cs(conf, "reply_buffer_size must be between %u and %u",
			      DOTNET_REPLY_BUF_MIN, DOTNET_REPLY_BUF_MAX);
		return -1;
	}

	if (!inst->error_buffer_size) {
		inst->error_buffer_size = DOTNET_ERROR_BUF_DEFAULT;
	} else if (inst->error_buffer_size < DOTNET_ERROR_BUF_MIN ||
		   inst->error_buffer_size > DOTNET_ERROR_BUF_MAX) {
		cf_log_err_cs(conf, "error_buffer_size must be between %u and %u",
			      DOTNET_ERROR_BUF_MIN, DOTNET_ERROR_BUF_MAX);
		return -1;
	}

	memset(&inst->stats_accum, 0, sizeof(inst->stats_accum));
	inst->stats_last_log_usec = dotnet_time_usec();
	inst->stats_interval_base_usec = inst->stats_last_log_usec;

	if (dotnet_resolve_runtime(inst) < 0) return -1;

	{
		char *export_type = NULL, *export_asm = NULL;
		char *d_inst, *d_detach, *d_ensure = NULL;

		if (dotnet_split_native_exports_type(inst, inst->native_exports_type, &export_type, &export_asm) < 0) goto fail;

		d_inst = talloc_asprintf(inst, "%s+InstantiateDelegate, %s", export_type, export_asm);
		d_detach = talloc_asprintf(inst, "%s+DetachDelegate, %s", export_type, export_asm);
		if (inst->per_thread_policy) {
			d_ensure = talloc_asprintf(inst, "%s+EnsureThreadPolicyDelegate, %s", export_type, export_asm);
		}
		if (!d_inst || !d_detach || (inst->per_thread_policy && !d_ensure)) goto fail;

		if (dotnet_bind_export(inst, "Instantiate", d_inst, (void **)&inst->fn_instantiate) < 0) goto fail;
		if (dotnet_bind_export(inst, "Detach", d_detach, (void **)&inst->fn_detach) < 0) goto fail;
		if (inst->per_thread_policy &&
		    dotnet_bind_export(inst, "EnsureThreadPolicy", d_ensure,
				       (void **)&inst->fn_ensure_thread_policy) < 0) goto fail;
	}

	boot_json = dotnet_build_boot_json(inst, inst);
	if (!boot_json) goto fail;

	rc = inst->fn_instantiate(boot_json, &inst->managed_handle);
	if (rc != 0 || !inst->managed_handle) {
		cf_log_err_cs(conf, ".NET instantiate failed (%d)", rc);
		goto fail;
	}
	if (!inst->fn_authorize) {
		cf_log_err_cs(conf, ".NET instantiate did not publish AuthorizeBlob pointer (authorize_fn_out); "
				    "rebuild and `dotnet publish -c Release -o dotnet/publish/Release` the interop assembly");
		goto fail;
	}

	talloc_free(boot_json);
	return 0;

fail:
	if (inst->host_context && inst->close_fn) {
		inst->close_fn(inst->host_context);
		inst->host_context = NULL;
	}
	talloc_free(boot_json);
	return -1;
}

static int mod_detach(void *instance)
{
	rlm_dotnet_t *inst = instance;

	dotnet_stats_log(inst, "detach", false);

	if (inst->managed_handle && inst->fn_detach) {
		inst->fn_detach(inst->managed_handle);
		inst->managed_handle = NULL;
	}
	if (inst->host_context && inst->close_fn) {
		inst->close_fn(inst->host_context);
		inst->host_context = NULL;
	}
	return 0;
}

static rlm_rcode_t CC_HINT(nonnull) dotnet_dispatch(void *instance, REQUEST *request, char const *section)
{
	rlm_dotnet_t	*inst = instance;
	void		*policy_handle;
	uint8_t		*req_blob = NULL;
	size_t		blob_len = 0;
	uint8_t		*reply_buf = NULL;
	uint8_t		*error_buf = NULL;
	size_t		reply_sz, err_sz;
	int32_t		written = 0;
	int32_t		reply_format = 0;
	int32_t		error_written = 0;
	uint64_t	t_start, t_elapsed;
	int		rc;
	rlm_rcode_t	ret;
	bool		failed = false;

	if (!inst->managed_handle || !inst->fn_authorize) {
		RERROR("rlm_dotnet: no managed policy handle (section %s) — module instantiate failed or detached",
		       section);
		return RLM_MODULE_FAIL;
	}

	policy_handle = dotnet_policy_handle_get(inst);
	if (!policy_handle) {
		RERROR("rlm_dotnet: no per-thread policy handle (section %s)", section);
		return RLM_MODULE_FAIL;
	}

	req_blob = dotnet_request_to_blob(request, request, section, &blob_len);
	if (!req_blob) {
		RERROR("rlm_dotnet: failed to build request blob for section %s", section);
		return RLM_MODULE_FAIL;
	}

	RDEBUG2("rlm_dotnet: section=%s request blob (%zu bytes)", section, blob_len);

	reply_sz = inst->reply_buffer_size;
	reply_buf = talloc_array(request, uint8_t, reply_sz);
	if (!reply_buf) {
		RERROR("rlm_dotnet: out of memory allocating reply buffer (section %s)", section);
		talloc_free(req_blob);
		return RLM_MODULE_FAIL;
	}
	memset(reply_buf, 0, reply_sz);

	err_sz = inst->error_buffer_size;
	error_buf = talloc_array(request, uint8_t, err_sz);
	if (!error_buf) {
		RERROR("rlm_dotnet: out of memory allocating error buffer (section %s)", section);
		talloc_free(req_blob);
		talloc_free(reply_buf);
		return RLM_MODULE_FAIL;
	}
	memset(error_buf, 0, err_sz);

	t_start = dotnet_time_usec();
	rc = inst->fn_authorize(policy_handle, req_blob, (int32_t)blob_len, reply_buf,
				(int32_t)reply_sz, &written, &reply_format,
				error_buf, (int32_t)err_sz, &error_written);
	t_elapsed = dotnet_time_usec() - t_start;
	talloc_free(req_blob);

	if (written < 0 || (reply_format == DOTNET_REPLY_FORMAT_PAIRLIST && (size_t)written >= reply_sz) ||
	    (reply_format == DOTNET_REPLY_FORMAT_BLOB_V1 && (size_t)written > reply_sz)) {
		RERROR("rlm_dotnet: invalid reply length from .NET policy (%d) format %d (section %s)",
		       written, reply_format, section);
		talloc_free(reply_buf);
		talloc_free(error_buf);
		dotnet_stats_record(inst, t_elapsed, true);
		return RLM_MODULE_FAIL;
	}

	if (error_written < 0 || (size_t)error_written >= err_sz) {
		RERROR("rlm_dotnet: invalid error metadata length from .NET policy (%d) (section %s)",
		       error_written, section);
		talloc_free(reply_buf);
		talloc_free(error_buf);
		dotnet_stats_record(inst, t_elapsed, true);
		return RLM_MODULE_FAIL;
	}
	if (error_written > 0) error_buf[error_written] = '\0';

	if (written > 0) {
		if (reply_format == DOTNET_REPLY_FORMAT_BLOB_V1) {
			if (dotnet_apply_reply_blob(request, reply_buf, (size_t)written) < 0) {
				RERROR("rlm_dotnet: invalid reply blob from .NET policy (section %s)", section);
				talloc_free(reply_buf);
				talloc_free(error_buf);
				dotnet_stats_record(inst, t_elapsed, true);
				return RLM_MODULE_FAIL;
			}
		} else {
			reply_buf[written] = '\0';
			if (dotnet_apply_reply_pairs(request, (char const *)reply_buf) < 0) {
				RERROR("rlm_dotnet: invalid reply pair-list from .NET policy (section %s)", section);
				talloc_free(reply_buf);
				talloc_free(error_buf);
				dotnet_stats_record(inst, t_elapsed, true);
				return RLM_MODULE_FAIL;
			}
		}
	}
	talloc_free(reply_buf);

	if (rc < RLM_MODULE_REJECT || rc >= RLM_MODULE_NUMCODES) {
		RERROR("rlm_dotnet: invalid rlm_rcode (%d) from .NET policy (section %s)", rc, section);
		talloc_free(error_buf);
		dotnet_stats_record(inst, t_elapsed, true);
		return RLM_MODULE_FAIL;
	}
	if (rc == RLM_MODULE_FAIL) {
		failed = true;
		if (error_written > 0) {
			dotnet_log_managed_error(request, (char const *)error_buf);
		} else {
			RWARN("rlm_dotnet: policy returned fail (section %s) with no error metadata — "
			      "check policy radlog output or enable exceptions in the interop assembly",
			      section);
		}
	}
	talloc_free(error_buf);
	dotnet_stats_record(inst, t_elapsed, failed);
	ret = (rlm_rcode_t)rc;
	return ret;
}

static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
{
	return dotnet_dispatch(instance, request, "authorize");
}

static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
	return dotnet_dispatch(instance, request, "authenticate");
}

static rlm_rcode_t CC_HINT(nonnull) mod_preacct(void *instance, REQUEST *request)
{
	return dotnet_dispatch(instance, request, "preacct");
}

static rlm_rcode_t CC_HINT(nonnull) mod_accounting(void *instance, REQUEST *request)
{
	return dotnet_dispatch(instance, request, "accounting");
}

static rlm_rcode_t CC_HINT(nonnull) mod_session(void *instance, REQUEST *request)
{
	return dotnet_dispatch(instance, request, "session");
}

static rlm_rcode_t CC_HINT(nonnull) mod_pre_proxy(void *instance, REQUEST *request)
{
	return dotnet_dispatch(instance, request, "pre_proxy");
}

static rlm_rcode_t CC_HINT(nonnull) mod_post_proxy(void *instance, REQUEST *request)
{
	return dotnet_dispatch(instance, request, "post_proxy");
}

static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST *request)
{
	return dotnet_dispatch(instance, request, "post_auth");
}

static rlm_rcode_t CC_HINT(nonnull) mod_recv_coa(void *instance, REQUEST *request)
{
	return dotnet_dispatch(instance, request, "recv_coa");
}

static rlm_rcode_t CC_HINT(nonnull) mod_send_coa(void *instance, REQUEST *request)
{
	return dotnet_dispatch(instance, request, "send_coa");
}

extern module_t rlm_dotnet;
module_t rlm_dotnet = {
	.magic			= RLM_MODULE_INIT,
	.name			= "dotnet",
	.type			= RLM_TYPE_THREAD_SAFE | RLM_TYPE_HUP_SAFE,
	.inst_size		= sizeof(rlm_dotnet_t),
	.config			= module_config,
	.instantiate		= mod_instantiate,
	.detach			= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_SESSION]		= mod_session,
		[MOD_PRE_PROXY]		= mod_pre_proxy,
		[MOD_POST_PROXY]	= mod_post_proxy,
		[MOD_POST_AUTH]		= mod_post_auth,
		[MOD_RECV_COA]		= mod_recv_coa,
		[MOD_SEND_COA]		= mod_send_coa,
	},
};
