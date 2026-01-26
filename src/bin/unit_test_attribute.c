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
 */

/**
 * $Id$
 *
 * @file unit_test_attribute.c
 * @brief Provides a test harness for various internal libraries and functions.
 *
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2010 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

typedef struct request_s request_t;

#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/command.h>
#include <freeradius-devel/server/dependency.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/server/tmpl.h>
#ifdef WITH_TLS
#  include <freeradius-devel/tls/base.h>
#endif
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/unlang/xlat.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/base64.h>
#include <freeradius-devel/util/calc.h>
#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/dns.h>
#include <freeradius-devel/util/file.h>
#include <freeradius-devel/util/log.h>
#include <freeradius-devel/util/skip.h>
#include <freeradius-devel/util/pair_legacy.h>
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/util/syserror.h>

#include <freeradius-devel/util/dict_priv.h>

#include <ctype.h>

#ifdef __clangd__
#  undef HAVE_SANITIZER_LSAN_INTERFACE_H
#endif
#ifdef HAVE_SANITIZER_LSAN_INTERFACE_H
#  include <sanitizer/asan_interface.h>
#endif

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <assert.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifndef HAVE_SANITIZER_LSAN_INTERFACE_H
#  define ASAN_POISON_MEMORY_REGION(_start, _end)
#  define ASAN_UNPOISON_MEMORY_REGION(_start, _end)
#endif

#define EXIT_WITH_FAILURE \
do { \
	ret = EXIT_FAILURE; \
	goto cleanup; \
} while (0)

#define COMMAND_OUTPUT_MAX	8192

#define RETURN_OK(_len) \
	do { \
		result->rcode = RESULT_OK; \
		result->file = __FILE__; \
		result->line = __LINE__; \
		return (_len); \
	} while (0)

#define RETURN_OK_WITH_ERROR() \
	do { \
		result->rcode = RESULT_OK; \
		result->file = __FILE__; \
		result->line = __LINE__; \
		result->error_to_data = true; \
		return 0; \
	} while (0)

#define RETURN_NOOP(_len) \
	do { \
		result->rcode = RESULT_NOOP; \
		result->file = __FILE__; \
		result->line = __LINE__; \
		return (_len); \
	} while (0)

#define RETURN_SKIP_FILE() \
	do { \
		result->rcode = RESULT_SKIP_FILE; \
		result->file = __FILE__; \
		result->line = __LINE__; \
		return 0; \
	} while (0)

#define RETURN_PARSE_ERROR(_offset) \
	do { \
		result->rcode = RESULT_PARSE_ERROR; \
		result->offset = _offset; \
		result->file = __FILE__; \
		result->line = __LINE__; \
		return 0; \
	} while (0)

#define RETURN_COMMAND_ERROR() \
	do { \
		result->rcode = RESULT_COMMAND_ERROR; \
		result->file = __FILE__; \
		result->line = __LINE__; \
		return 0; \
	} while (0)

#define RETURN_MISMATCH(_len) \
	do { \
		result->rcode = RESULT_MISMATCH; \
		result->file = __FILE__; \
		result->line = __LINE__; \
		return (_len); \
	} while (0)

#define RETURN_EXIT(_ret) \
	do { \
		result->rcode = RESULT_EXIT; \
		result->ret = _ret; \
		result->file = __FILE__; \
		result->line = __LINE__; \
		return 0; \
	} while (0)

/** Default buffer size for a command_file_ctx_t
 *
 */
#define DEFAULT_BUFFER_SIZE	1024

typedef enum {
	RESULT_OK = 0,				//!< Not an error - Result as expected.
	RESULT_NOOP,				//!< Not an error - Did nothing...
	RESULT_SKIP_FILE,			//!< Not an error - Skip the rest of this file, or until we
						///< reach an "eof" command.
	RESULT_PARSE_ERROR,			//!< Fatal error - Command syntax error.
	RESULT_COMMAND_ERROR,			//!< Fatal error - Command operation error.
	RESULT_MISMATCH,			//!< Fatal error - Result didn't match what we expected.
	RESULT_EXIT,				//!< Stop processing files and exit.
} command_rcode_t;

static fr_table_num_sorted_t command_rcode_table[] = {
	{ L("command-error"),		RESULT_COMMAND_ERROR			},
	{ L("exit"),			RESULT_EXIT				},
	{ L("ok"),			RESULT_OK				},
	{ L("parse-error"),		RESULT_PARSE_ERROR			},
	{ L("result-mismatch"),		RESULT_MISMATCH				},
	{ L("skip-file"),		RESULT_SKIP_FILE			},
};
static size_t command_rcode_table_len = NUM_ELEMENTS(command_rcode_table);

typedef struct {
	TALLOC_CTX	*tmp_ctx;		//!< Temporary context to hold buffers
						///< in this
	union {
		size_t	offset;			//!< Where we failed parsing the command.
		int	ret;			//!< What code we should exit with.
	};
	char const	*file;
	int		line;
	command_rcode_t	rcode;
	bool		error_to_data;
} command_result_t;

/** Configuration parameters passed to command functions
 *
 */
typedef struct {
	fr_dict_t 		*dict;			//!< Dictionary to "reset" to.
	fr_dict_gctx_t const	*dict_gctx;		//!< Dictionary gctx to "reset" to.
	char const		*confdir;
	char const		*dict_dir;
	char const		*fuzzer_dir;		//!< Where to write fuzzer files.
	CONF_SECTION		*features;		//!< Enabled features.
} command_config_t;

typedef struct {
	TALLOC_CTX		*tmp_ctx;		//!< Talloc context for test points.

	char			*path;			//!< Current path we're operating in.
	char const		*filename;		//!< Current file we're operating on.
	uint32_t		lineno;			//!< Current line number.

	uint32_t		test_count;		//!< How many tests we've executed in this file.
	ssize_t			last_ret;		//!< Last return value.

	uint8_t			*buffer;		//!< Temporary resizable buffer we use for
							///< holding non-string data.
	uint8_t			*buffer_start;		//!< Where the non-poisoned region of the buffer starts.
	uint8_t			*buffer_end;		//!< Where the non-poisoned region of the buffer ends.

	tmpl_rules_t		tmpl_rules;		//!< To pass to parsing functions.
	fr_dict_t		*test_internal_dict;	//!< Internal dictionary of test_gctx.
	fr_dict_gctx_t const	*test_gctx;		//!< Dictionary context for test dictionaries.

	int			fuzzer_dir;		//!< File descriptor pointing to a a directory to
							///< write fuzzer output.
	command_config_t const	*config;
} command_file_ctx_t;


typedef struct {
	fr_dlist_t	entry;	//!< Entry in the dlist.
	uint32_t	start;	//!< Start of line range.
	uint32_t	end;	//!< End of line range.
} command_line_range_t;

/** Command to execute
 *
 * @param[out] result	Of executing the command.
 * @param[in] cc	Information about the file being processed.
 * @param[in,out] data	Output of this command, or the previous command.
 * @param[in] data_used	Length of data in the data buffer.
 * @param[in] in	Command text to process.
 * @param[in] inlen	Length of the remainder of the command to process.
 */
typedef size_t (*command_func_t)(command_result_t *result, command_file_ctx_t *cc, char *data,
				 size_t data_used, char *in, size_t inlen);

typedef struct {
	command_func_t	func;
	char const	*usage;
	char const	*description;
} command_entry_t;

static xlat_arg_parser_t const xlat_test_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_arg_parser_t const xlat_test_no_args[] = {
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t xlat_test(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
			       UNUSED xlat_ctx_t const *xctx, UNUSED request_t *request,
			       UNUSED fr_value_box_list_t *in)
{
	return XLAT_ACTION_DONE;
}

static char		proto_name_prev[128] = {};
static dl_t		*dl = NULL;
static dl_loader_t	*dl_loader = NULL;

static fr_event_list_t	*el = NULL;

static bool		allow_purify = false;

static char const	*write_filename = NULL;
static FILE		*write_fp = NULL;

static char const		*receipt_file = NULL;
static char const		*receipt_dir = NULL;
static char const      		*fail_file = "";

size_t process_line(command_result_t *result, command_file_ctx_t *cc, char *data, size_t data_used, char *in, size_t inlen);
static int process_file(bool *exit_now, TALLOC_CTX *ctx,
			command_config_t const *config, const char *root_dir, char const *filename, fr_dlist_head_t *lines);

#ifdef HAVE_SANITIZER_LSAN_INTERFACE_H
#  define BUFF_POISON_START	1024
#  define BUFF_POISON_END	1024

/** Unpoison the start and end regions of the buffer
 *
 */
static int _free_buffer(uint8_t *buff)
{
	size_t size = talloc_array_length(buff) - (BUFF_POISON_START + BUFF_POISON_END);

	ASAN_UNPOISON_MEMORY_REGION(buff, BUFF_POISON_START);
	ASAN_UNPOISON_MEMORY_REGION(buff + BUFF_POISON_START + size, BUFF_POISON_END);

	return 0;
}
#else
#  define BUFF_POISON_START     0
#  define BUFF_POISON_END	0
#endif

/** Allocate a special buffer with poisoned memory regions at the start and end
 *
 */
static int poisoned_buffer_allocate(TALLOC_CTX *ctx, uint8_t **buff, size_t size)
{
	uint8_t *our_buff = *buff;

	if (our_buff) {
		/*
		 *	If it's already the correct length
		 *	don't bother re-allocing the buffer,
		 *	just memset it to zero.
		 */
		if ((size + BUFF_POISON_START + BUFF_POISON_END) == talloc_array_length(our_buff)) {
			memset(our_buff + BUFF_POISON_START, 0, size);
			return 0;
		}

		talloc_free(our_buff);	/* Destructor de-poisons */
		*buff = NULL;
	}

	our_buff = talloc_array(ctx, uint8_t, size + BUFF_POISON_START + BUFF_POISON_END);
	if (!our_buff) return -1;

#ifdef HAVE_SANITIZER_LSAN_INTERFACE_H
	talloc_set_destructor(our_buff, _free_buffer);

	/*
	 *	Poison regions before and after the buffer
	 */
	ASAN_POISON_MEMORY_REGION(our_buff, BUFF_POISON_START);
	ASAN_POISON_MEMORY_REGION(our_buff + BUFF_POISON_START + size, BUFF_POISON_END);
#endif

	*buff = our_buff;

	return 0;
}
#define POISONED_BUFFER_START(_p) ((_p) + BUFF_POISON_START)
#define POISONED_BUFFER_END(_p) ((_p) + BUFF_POISON_START + (talloc_array_length(_p) - (BUFF_POISON_START + BUFF_POISON_END)))

static void mismatch_print(command_file_ctx_t *cc, char const *command,
			   char *expected, size_t expected_len, char *got, size_t got_len,
			   bool print_diff)
{
	char *g, *e;

	ERROR("%s failed %s/%s:%d", command, cc->path, cc->filename, cc->lineno);

	if (!print_diff) {
		ERROR("  got      : %.*s", (int) got_len, got);
		ERROR("  expected : %.*s", (int) expected_len, expected);
	} else {
		g = got;
		e = expected;

		while (*g && *e && (*g == *e)) {
			g++;
			e++;
		}

		if (expected_len < 100) {
			char const *spaces = "                                                                                ";

			ERROR("  EXPECTED : %.*s", (int) expected_len, expected);
			ERROR("  GOT      : %.*s", (int) got_len, got);
			ERROR("             %.*s^ differs here (%zu)", (int) (e - expected), spaces, e - expected);
		} else if (fr_debug_lvl > 1) {
			ERROR("  EXPECTED : %.*s", (int) expected_len, expected);
			ERROR("  GOT      : %.*s", (int) got_len, got);
			ERROR("Differs at : %zu", e - expected);

		} else {
			size_t glen, elen;

			elen = strlen(e);
			if (elen > 70) elen = 70;
			glen = strlen(g);
			if (glen > 70) glen = 70;

			ERROR("(%zu) ... %.*s ... ", e - expected, (int) elen, e);
			ERROR("(%zu) ... %.*s ... ", e - expected, (int) glen, g);
		}
	}
}

/** Print hex string to buffer
 *
 */
static inline CC_HINT(nonnull) size_t hex_print(char *out, size_t outlen, uint8_t const *in, size_t inlen)
{
	char	*p = out;
	char	*end = p + outlen;
	size_t	i;

	if (inlen == 0) {
		*p = '\0';
		return 0;
	}

	for (i = 0; i < inlen; i++) {
		size_t len;

		len = snprintf(p, end - p, "%02x ", in[i]);
		if (is_truncated(len, end - p)) return 0;

		p += len;
	}

	*(--p) = '\0';

	return p - out;
}

/** Concatenate error stack
 */
static inline size_t strerror_concat(char *out, size_t outlen)
{
	char *end = out + outlen;
	char *p = out;
	char const *err;

	while ((p < end) && (err = fr_strerror_pop())) {
		if (*fr_strerror_peek()) {
			p += snprintf(p, end - p, "%s: ", err);
		} else {
			p += strlcpy(p, err, end - p);
		}
	}

	return p - out;
}

static inline CC_HINT(nonnull) int dump_fuzzer_data(int fd_dir, char const *text, uint8_t const *data, size_t data_len)
{
	fr_sha1_ctx	ctx;
	uint8_t		digest[SHA1_DIGEST_LENGTH];
	char		digest_str[(SHA1_DIGEST_LENGTH * 2) + 1];
	int		file_fd;

	fr_assert(data_len <= COMMAND_OUTPUT_MAX);

	fr_sha1_init(&ctx);
	fr_sha1_update(&ctx, (uint8_t const *)text, strlen(text));
	fr_sha1_final(digest, &ctx);

	/*
	 *	We need to use the url alphabet as the standard
	 *	one contains forwarded slashes which openat
	 *      doesn't like.
	 */
	fr_base64_encode_nstd(&FR_SBUFF_OUT(digest_str, sizeof(digest_str)), &FR_DBUFF_TMP(digest, sizeof(digest)),
			      false, fr_base64_url_alphabet_encode);

	file_fd = openat(fd_dir, digest_str, O_RDWR | O_CREAT | O_TRUNC,
			 S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (file_fd < 0) {
		fr_strerror_printf("Failed opening or creating corpus seed file \"%s\": %s",
				   digest_str, fr_syserror(errno));
		return -1;
	}

	if (flock(file_fd, LOCK_EX) < 0) {
		close(file_fd);
		fr_strerror_printf("Failed locking corpus seed file \"%s\": %s",
				   digest_str, fr_syserror(errno));
		return -1;
	}

	while (data_len) {
		ssize_t ret;

		ret = write(file_fd, data, data_len);
		if (ret < 0) {
			fr_strerror_printf("Failed writing to corpus seed file \"%s\": %s",
					   digest_str, fr_syserror(errno));
			(void)flock(file_fd, LOCK_UN);
			unlinkat(fd_dir, digest_str, 0);
			close(file_fd);
			return -1;
		}
		data_len -= ret;
		data += ret;
	}
	(void)flock(file_fd, LOCK_UN);
	close(file_fd);

	return 0;
}

/*
 *	End of hacks for xlat
 *
 **********************************************************************/

static ssize_t encode_tlv(char *buffer, uint8_t *output, size_t outlen);

static char const hextab[] = "0123456789abcdef";

static ssize_t encode_data_string(char *buffer, uint8_t *output, size_t outlen)
{
	ssize_t slen = 0;
	char *p;

	p = buffer + 1;

	while (*p && (outlen > 0)) {
		if (*p == '"') {
			return slen;
		}

		if (*p != '\\') {
			*(output++) = *(p++);
			outlen--;
			slen++;
			continue;
		}

		switch (p[1]) {
		default:
			*(output++) = p[1];
			break;

		case 'n':
			*(output++) = '\n';
			break;

		case 'r':
			*(output++) = '\r';
			break;

		case 't':
			*(output++) = '\t';
			break;
		}

		outlen--;
		slen++;
	}

	ERROR("String is not terminated");
	return 0;
}

static ssize_t encode_data_tlv(char *buffer, char **endptr, uint8_t *output, size_t outlen)
{
	int		depth = 0;
	ssize_t		slen;
	char		*p;

	for (p = buffer; *p != '\0'; p++) {
		if (*p == '{') depth++;
		if (*p == '}') {
			depth--;
			if (depth == 0) break;
		}
	}

	if (*p != '}') {
		ERROR("No trailing '}' in string starting with \"%s\"", buffer);
		return 0;
	}

	*endptr = p + 1;
	*p = '\0';

	p = buffer + 1;
	fr_skip_whitespace(p);

	slen = encode_tlv(p, output, outlen);
	if (slen <= 0) return 0;

	return slen;
}

static ssize_t hex_to_bin(uint8_t *out, size_t outlen, char *in, size_t inlen)
{
	char		*p = in;
	char		*end = in + inlen;
	uint8_t		*out_p = out, *out_end = out_p + outlen;

	while (p < end) {
		char *c1, *c2;

		if (out_p >= out_end) {
			fr_strerror_const("Would overflow output buffer");
			return -(p - in);
		}

		fr_skip_whitespace(p);

		if (!*p) break;

		c1 = memchr(hextab, tolower((uint8_t) *p++), sizeof(hextab));
		if (!c1) {
		bad_input:
			fr_strerror_printf("Invalid hex data starting at \"%s\"", p);
			return -(p - in);
		}

		c2 = memchr(hextab, tolower((uint8_t)*p++), sizeof(hextab));
		if (!c2) goto bad_input;

		*out_p++ = ((c1 - hextab) << 4) + (c2 - hextab);
	}

	return out_p - out;
}


static ssize_t encode_data(char *p, uint8_t *output, size_t outlen)
{
	ssize_t slen;

	if (!isspace((uint8_t) *p)) {
		ERROR("Invalid character following attribute definition");
		return 0;
	}

	fr_skip_whitespace(p);

	if (*p == '{') {
		size_t	sublen;
		char	*q;

		slen = 0;

		do {
			fr_skip_whitespace(p);
			if (!*p) {
				if (slen == 0) {
					ERROR("No data");
					return 0;
				}

				break;
			}

			sublen = encode_data_tlv(p, &q, output, outlen);
			if (sublen <= 0) return 0;

			slen += sublen;
			output += sublen;
			outlen -= sublen;
			p = q;
		} while (*q);

		return slen;
	}

	if (*p == '"') {
		slen = encode_data_string(p, output, outlen);
		return slen;
	}

	slen = hex_to_bin(output, outlen, p, strlen(p));
	if (slen <= 0) {
		fr_strerror_const_push("Empty hex string");
		return slen;
	}

	return slen;
}

static int decode_attr(char *buffer, char **endptr)
{
	long attr;

	attr = strtol(buffer, endptr, 10);
	if (*endptr == buffer) {
		ERROR("No valid number found in string starting with \"%s\"", buffer);
		return 0;
	}

	if (!**endptr) {
		ERROR("Nothing follows attribute number");
		return 0;
	}

	if ((attr <= 0) || (attr > 256)) {
		ERROR("Attribute number is out of valid range");
		return 0;
	}

	return (int) attr;
}

static int decode_vendor(char *buffer, char **endptr)
{
	long vendor;

	if (*buffer != '.') {
		ERROR("Invalid separator before vendor id");
		return 0;
	}

	vendor = strtol(buffer + 1, endptr, 10);
	if (*endptr == (buffer + 1)) {
		ERROR("No valid vendor number found");
		return 0;
	}

	if (!**endptr) {
		ERROR("Nothing follows vendor number");
		return 0;
	}

	if ((vendor <= 0) || (vendor > (1 << 24))) {
		ERROR("Vendor number is out of valid range");
		return 0;
	}

	if (**endptr != '.') {
		ERROR("Invalid data following vendor number");
		return 0;
	}
	(*endptr)++;

	return (int) vendor;
}

static ssize_t encode_tlv(char *buffer, uint8_t *output, size_t outlen)
{
	int	attr;
	ssize_t slen;
	char	*p;

	attr = decode_attr(buffer, &p);
	if (attr == 0) return 0;

	output[0] = attr;
	output[1] = 2;

	if (*p == '.') {
		p++;
		slen = encode_tlv(p, output + 2, outlen - 2);

	} else {
		slen = encode_data(p, output + 2, outlen - 2);
	}

	if (slen <= 0) return slen;
	if (slen > (255 - 2)) {
		ERROR("TLV data is too long");
		return 0;
	}

	output[1] += slen;

	return slen + 2;
}

static ssize_t encode_vsa(char *buffer, uint8_t *output, size_t outlen)
{
	int	vendor;
	ssize_t	slen;
	char	*p;

	vendor = decode_vendor(buffer, &p);
	if (vendor == 0) return 0;

	output[0] = 0;
	output[1] = (vendor >> 16) & 0xff;
	output[2] = (vendor >> 8) & 0xff;
	output[3] = vendor & 0xff;

	slen = encode_tlv(p, output + 4, outlen - 4);
	if (slen <= 0) return slen;
	if (slen > (255 - 6)) {
		ERROR("VSA data is too long");
		return 0;
	}

	return slen + 4;
}

static ssize_t encode_evs(char *buffer, uint8_t *output, size_t outlen)
{
	int	vendor;
	int	attr;
	ssize_t	slen;
	char	*p;

	vendor = decode_vendor(buffer, &p);
	if (vendor == 0) return 0;

	attr = decode_attr(p, &p);
	if (attr == 0) return 0;

	output[0] = 0;
	output[1] = (vendor >> 16) & 0xff;
	output[2] = (vendor >> 8) & 0xff;
	output[3] = vendor & 0xff;
	output[4] = attr;

	slen = encode_data(p, output + 5, outlen - 5);
	if (slen <= 0) return slen;

	return slen + 5;
}

static ssize_t encode_extended(char *buffer, uint8_t *output, size_t outlen)
{
	int	attr;
	ssize_t	slen;
	char	*p;

	attr = decode_attr(buffer, &p);
	if (attr == 0) return 0;

	output[0] = attr;

	if (attr == 26) {
		slen = encode_evs(p, output + 1, outlen - 1);
	} else {
		slen = encode_data(p, output + 1, outlen - 1);
	}
	if (slen <= 0) return slen;
	if (slen > (255 - 3)) {
		ERROR("Extended Attr data is too long");
		return 0;
	}

	return slen + 1;
}

static ssize_t encode_long_extended(char *buffer, uint8_t *output, size_t outlen)
{
	int	attr;
	ssize_t slen, total;
	char	*p;

	attr = decode_attr(buffer, &p);
	if (attr == 0) return 0;

	/* output[0] is the extended attribute */
	output[1] = 4;
	output[2] = attr;
	output[3] = 0;

	if (attr == 26) {
		slen = encode_evs(p, output + 4, outlen - 4);
		if (slen <= 0) return slen;

		output[1] += 5;
		slen -= 5;
	} else {
		slen = encode_data(p, output + 4, outlen - 4);
	}
	if (slen <= 0) return slen;

	total = 0;
	while (1) {
		int sublen = 255 - output[1];

		if (slen <= sublen) {
			output[1] += slen;
			total += output[1];
			break;
		}

		slen -= sublen;

		memmove(output + 255 + 4, output + 255, slen);
		memcpy(output + 255, output, 4);

		output[1] = 255;
		output[3] |= 0x80;

		output += 255;
		output[1] = 4;
		total += 255;
	}

	return total;
}

static ssize_t encode_rfc(char *buffer, uint8_t *output, size_t outlen)
{
	int	attr;
	ssize_t slen, sublen;
	char	*p;

	attr = decode_attr(buffer, &p);
	if (attr == 0) return 0;

	slen = 2;
	output[0] = attr;
	output[1] = 2;

	if (attr == 26) {
		sublen = encode_vsa(p, output + 2, outlen - 2);

	} else if ((attr < 241) || (attr > 246)) {
		sublen = encode_data(p, output + 2, outlen - 2);

	} else {
		if (*p != '.') {
			ERROR("Invalid data following attribute number");
			return 0;
		}

		if (attr < 245) {
			sublen = encode_extended(p + 1, output + 2, outlen - 2);
		} else {
			/*
			 *	Not like the others!
			 */
			return encode_long_extended(p + 1, output, outlen);
		}
	}
	if (sublen <= 0) return sublen;
	if (sublen > (255 -2)) {
		ERROR("RFC Data is too long");
		return 0;
	}

	output[1] += sublen;
	return slen + sublen;
}


static void unload_proto_library(void)
{
	proto_name_prev[0] = '\0';
	TALLOC_FREE(dl);
}

static ssize_t load_proto_library(char const *proto_name)
{
	char	dl_name[128];

	if (strcmp(proto_name_prev, proto_name) != 0) {
		/*
		 *	Ensure the old proto library is unloaded
		 */
		unload_proto_library();

		snprintf(dl_name, sizeof(dl_name), "libfreeradius-%s", proto_name);
		if (dl) TALLOC_FREE(dl);

		dl = dl_by_name(dl_loader, dl_name, NULL, false);
		if (!dl) {
			fr_perror("Failed to link to library \"%s\"", dl_name);
			unload_proto_library();
			return 0;
		}

		strlcpy(proto_name_prev, proto_name, sizeof(proto_name_prev));
	}

	fr_assert(dl != NULL);
	return strlen(proto_name);
}

static ssize_t load_test_point_by_command(void **symbol, char *command, char const *dflt_symbol)
{
	char		buffer[256];
	char const	*p, *q;
	void		*dl_symbol;

	if (!dl) {
		fr_strerror_printf("No protocol library loaded. Specify library with \"load <proto name>\"");
		return 0;
	}

	p = command;

	/*
	 *	Use the dflt_symbol name as the test point
	 */
	if ((*p == '.') && (q = strchr(p, ' ')) && (q != (p + 1)) && ((size_t)(q - p) < sizeof(buffer))) {
		p++;
		strlcpy(buffer, p, (q - p) + 1);
		p = q + 1;
	} else {
		snprintf(buffer, sizeof(buffer), "%s_%s", proto_name_prev, dflt_symbol);
	}

	dl_symbol = dlsym(dl->handle, buffer);
	if (!dl_symbol) {
		fr_strerror_printf("Test point (symbol \"%s\") not exported by library", buffer);
		unload_proto_library();
		return 0;
	}
	*symbol = dl_symbol;

	return p - command;
}

static fr_dict_t *dictionary_current(command_file_ctx_t *cc)
{
	if (cc->tmpl_rules.attr.dict_def) {
		return UNCONST(fr_dict_t *, cc->tmpl_rules.attr.dict_def);
	}

	return cc->config->dict;
}

/** Common dictionary load function
 *
 * Callers call fr_dict_global_ctx_set to set the context
 * the dictionaries will be loaded into.
 */
static int dictionary_load_common(command_result_t *result, command_file_ctx_t *cc, char const *in, char const *default_subdir)
{
	char const	*dir;
	char		*q;
	char const	*name;
	char		*tmp = NULL;
	int		ret;
	fr_dict_t	*dict;

	if (in[0] == '\0') {
		fr_strerror_const("Missing dictionary name");
		RETURN_PARSE_ERROR(0);
	}

	/*
	 *	Decrease ref count if we're loading in a new dictionary
	 */
	if (cc->tmpl_rules.attr.dict_def) {
		if (fr_dict_const_free(&cc->tmpl_rules.attr.dict_def, __FILE__) < 0) RETURN_COMMAND_ERROR();
	}

	q = strchr(in, ' ');
	if (q) {
		name = tmp = talloc_bstrndup(NULL, in, q - in);
		q++;
		dir = q;
	} else {
		name = in;
		dir = default_subdir;
	}

	ret = fr_dict_protocol_afrom_file(&dict, name, dir, __FILE__);
	talloc_free(tmp);
	if (ret < 0) RETURN_COMMAND_ERROR();

	cc->tmpl_rules.attr.dict_def = dict;
	cc->tmpl_rules.attr.namespace = fr_dict_root(dict);

	/*
	 *	Dump the dictionary if we're in super debug mode
	 */
	if (fr_debug_lvl > 5) fr_dict_debug(fr_log_fp, cc->tmpl_rules.attr.dict_def);


	RETURN_OK(0);
}

static size_t parse_typed_value(command_result_t *result, command_file_ctx_t *cc, fr_value_box_t *box, char const **out, char const *in, size_t inlen)
{
	fr_type_t	type;
	size_t		match_len;
	ssize_t		slen;
	char const     	*p;
	fr_sbuff_t	sbuff;
	fr_dict_attr_t const *enumv = NULL;

	/*
	 *	Parse data types
	 */
	type = fr_table_value_by_longest_prefix(&match_len, fr_type_table, in, inlen, FR_TYPE_NULL);
	if (fr_type_is_null(type)) {
		RETURN_PARSE_ERROR(0);
	}
	fr_assert(match_len < inlen);

	p = in + match_len;
	fr_skip_whitespace(p);
	*out = p;

	if (type == FR_TYPE_ATTR) {
		enumv = cc->tmpl_rules.attr.dict_def ?
			fr_dict_root(cc->tmpl_rules.attr.dict_def) :
			fr_dict_root(fr_dict_internal());
	}

	/*
	 *	As a hack, allow most things to be inside
	 *	double-quoted strings.  This is really only for dates,
	 *	which are space-delimited.
	 */
	if (*p == '"'){
		p++;
		sbuff = FR_SBUFF_IN(p, strlen(p));
		slen = fr_value_box_from_substr(box, box, FR_TYPE_STRING, enumv,
						&sbuff,
						&value_parse_rules_double_quoted);
		if (slen < 0) {
			RETURN_OK_WITH_ERROR();
		}

		p += fr_sbuff_used(&sbuff);
		if (*p != '"') {
			RETURN_PARSE_ERROR(0);
		}
		p++;

		if (type != FR_TYPE_STRING) {
			if (fr_value_box_cast_in_place(box, box, type, NULL) < 0) {
				RETURN_PARSE_ERROR(0);
			}
		}

	} else {
		sbuff = FR_SBUFF_IN(p, strlen(p));

		/*
		 *	We have no other way to pass the dict to the value-box parse function.
		 */
		if (type == FR_TYPE_ATTR) {
			fr_dict_t const *dict = dictionary_current(cc);

			if (!dict) {
				fr_strerror_const("proto-dictionary must be defined");
				RETURN_PARSE_ERROR(0);
			}

			enumv = fr_dict_root(dict);
		}

		slen = fr_value_box_from_substr(box, box, type, enumv,
						&sbuff,
						&value_parse_rules_bareword_unquoted);
		if (slen < 0) {
			RETURN_OK_WITH_ERROR();
		}
		p += fr_sbuff_used(&sbuff);
	}
	fr_skip_whitespace(p);

	RETURN_OK(p - in);
}

static fr_cmd_t *command_head = NULL;

static int command_func(UNUSED FILE *fp, UNUSED FILE *fp_err, UNUSED void *ctx, UNUSED fr_cmd_info_t const *info)
{
	return 0;
}

static int command_walk(UNUSED void *ctx, fr_cmd_walk_info_t *info)
{
	int i;

	for (i = 0; i < info->num_parents; i++) {
		printf("%s ", info->parents[i]);
	}

	printf(":%s ", info->name);
	if (info->syntax) printf("%s", info->syntax);
	printf("%s", "");

	return 1;
}

static void command_print(void)
{
	void *walk_ctx = NULL;

	printf("Command hierarchy --------");
	fr_cmd_debug(stdout, command_head);

	printf("Command list --------");
	while (fr_command_walk(command_head, &walk_ctx, NULL, command_walk) == 1) {
		// do nothing
	}
}

#define CLEAR_TEST_POINT(_cc) \
do { \
	talloc_free_children((_cc)->tmp_ctx); \
	tp = NULL; \
} while (0)

/** Placeholder function for comments
 *
 */
static size_t command_comment(UNUSED command_result_t *result, UNUSED command_file_ctx_t *cc,
			      UNUSED char *data, UNUSED size_t data_used, UNUSED char *in, UNUSED size_t inlen)
{
	return 0;
}

/** Execute another test file
 *
 */
static size_t command_include(command_result_t *result, command_file_ctx_t *cc,
			      UNUSED char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	char	*q;
	bool	exit_now = false;
	int	ret;

	if (write_fp) {
		fprintf(stderr, "Can't do $INCLUDE with -w %s\n", write_filename);
		RETURN_EXIT(1);
	}

	q = strrchr(cc->path, '/');
	if (q) {
		*q = '\0';
		ret = process_file(&exit_now, cc->tmp_ctx, cc->config, cc->path, in, NULL);
		if (exit_now || (ret != 0)) RETURN_EXIT(ret);
		*q = '/';
		RETURN_OK(0);
	}

	ret = process_file(&exit_now, cc->tmp_ctx, cc->config, NULL, in, NULL);
	if (exit_now || (ret != 0)) RETURN_EXIT(ret);

	RETURN_OK(0);
}

/** Determine if unresolved attributes are allowed
 *
 */
static size_t command_allow_unresolved(command_result_t *result, command_file_ctx_t *cc,
				       UNUSED char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	fr_sbuff_t	our_in = FR_SBUFF_IN(in, inlen);
	bool		res;

	if (fr_sbuff_out_bool(&res, &our_in) == 0) {
		fr_strerror_printf("Invalid boolean value, must be \"yes\" or \"no\"");
		RETURN_COMMAND_ERROR();
	}
	cc->tmpl_rules.attr.allow_unresolved = res;

	RETURN_OK(0);
}

#define ATTR_COMMON \
	fr_sbuff_t		our_in = FR_SBUFF_IN(in, inlen); \
	fr_dict_attr_err_t	err; \
	fr_slen_t		slen; \
	fr_dict_attr_t const	*root; \
	fr_dict_attr_t const	*da; \
	root = cc->tmpl_rules.attr.dict_def ? \
		fr_dict_root(cc->tmpl_rules.attr.dict_def) : \
		fr_dict_root(fr_dict_internal()); \
	slen = fr_dict_attr_by_oid_substr(&err, \
					  &da, \
					  root, \
					  &our_in, NULL); \
	if (err != FR_DICT_ATTR_OK) FR_SBUFF_ERROR_RETURN(&our_in)


/** Print attribute information
 *
 */
static size_t command_attr_children(command_result_t *result, command_file_ctx_t *cc,
				    UNUSED char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	fr_hash_table_t *namespace;
	fr_hash_iter_t	iter;
	fr_dict_attr_t const *ref;
	fr_sbuff_t out = FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX);
	ATTR_COMMON;

	namespace = dict_attr_namespace(da);
	fr_assert(namespace != NULL);

	for (da = fr_hash_table_iter_init(namespace, &iter);
	     da != NULL;
	     da = fr_hash_table_iter_next(namespace, &iter)) {
		if (da->flags.is_alias) {
			ref = fr_dict_attr_ref(da);
			fr_assert(ref != NULL);

			slen = fr_sbuff_in_sprintf(&out, "%s (ALIAS ref=", da->name);
			if (slen <= 0) RETURN_OK_WITH_ERROR();

			slen = fr_dict_attr_oid_print(&out, fr_dict_root(da->dict), ref, false);
			if (slen <= 0) RETURN_OK_WITH_ERROR();

			slen = fr_sbuff_in_strcpy(&out, "), ");
			if (slen <= 0) RETURN_OK_WITH_ERROR();
			continue;
		}

		slen = fr_sbuff_in_sprintf(&out, "%s (%s), ", da->name, fr_type_to_str(da->type));
		if (slen <= 0) RETURN_OK_WITH_ERROR();
	}

	fr_sbuff_trim(&out, (bool[UINT8_MAX + 1]){ [' '] = true, [','] = true });

	RETURN_OK(fr_sbuff_used(&out));
}


/** Print attribute information
 *
 */
static size_t command_attr_flags(command_result_t *result, command_file_ctx_t *cc,
				 UNUSED char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	ATTR_COMMON;

	slen = fr_dict_attr_flags_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), da->dict, da->type, &da->flags);
	if (slen <= 0) RETURN_OK_WITH_ERROR();

	RETURN_OK(slen);
}

/** Print attribute information
 *
 */
static size_t command_attr_name(command_result_t *result, command_file_ctx_t *cc,
				 UNUSED char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	ATTR_COMMON;

	slen = fr_dict_attr_oid_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), root, da, false);
	if (slen <= 0) RETURN_OK_WITH_ERROR();

	RETURN_OK(slen);
}

/** Print attribute information
 *
 */
static size_t command_attr_oid(command_result_t *result, command_file_ctx_t *cc,
			       UNUSED char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	ATTR_COMMON;

	slen = fr_dict_attr_oid_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), root, da, true);
	if (slen <= 0) RETURN_OK_WITH_ERROR();

	RETURN_OK(slen);
}

/** Print attribute information
 *
 */
static size_t command_attr_type(command_result_t *result, command_file_ctx_t *cc,
			       UNUSED char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	ATTR_COMMON;

	slen = fr_sbuff_in_strcpy(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), fr_type_to_str(da->type));
	if (slen <= 0) RETURN_OK_WITH_ERROR();

	RETURN_OK(slen);
}

static const fr_token_t token2op[UINT8_MAX + 1] = {
	[ '+' ] = T_ADD,
	[ '-' ] = T_SUB,
	[ '*' ] = T_MUL,
	[ '/' ] = T_DIV,
	[ '^' ] = T_XOR,
	[ '.' ] = T_ADD,
	[ '&' ] = T_AND,
	[ '|' ] = T_OR,
	[ '%' ] = T_MOD,
};

/** Perform calculations
 *
 */
static size_t command_calc(command_result_t *result, command_file_ctx_t *cc,
			   char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	fr_value_box_t *a, *b, *out;
	size_t match_len;
	fr_type_t type;
	fr_token_t op;
	char const *p, *value, *end;
	size_t slen;
	bool assignment;

	a = talloc_zero(cc->tmp_ctx, fr_value_box_t);
	b = talloc_zero(cc->tmp_ctx, fr_value_box_t);

	p = in;
	end = in + inlen;

	match_len = parse_typed_value(result, cc, a, &value, p, end - p);
	if (match_len == 0) return 0; /* errors have already been updated */

	p += match_len;
	fr_skip_whitespace(p);

	op = fr_table_value_by_longest_prefix(&match_len, fr_tokens_table, p, end - p, T_INVALID);
	if (op != T_INVALID) {
		p += match_len;
		assignment = fr_assignment_op[op];

	} else {
		op = token2op[(uint8_t) p[0]];
		if (op == T_INVALID) {
			fr_strerror_printf("Unknown operator '%c'", p[0]);
			RETURN_PARSE_ERROR(0);
		}
		p++;

		assignment = false;
	}
	fr_skip_whitespace(p);

	match_len = parse_typed_value(result, cc, b, &value, p, end - p);
	if (match_len == 0) return 0;

	p += match_len;
	fr_skip_whitespace(p);

	if (assignment) {
		if (fr_value_calc_assignment_op(cc->tmp_ctx, a, op, b) < 0) {
			RETURN_OK_WITH_ERROR();
		}
		out = a;

	} else {
		out = talloc_zero(cc->tmp_ctx, fr_value_box_t);

		/*
		 *	If there's no output data type, then the code tries to
		 *	figure one out automatically.
		 */
		if (!*p) {
			type = FR_TYPE_NULL;
		} else {
			if (strncmp(p, "->", 2) != 0) RETURN_PARSE_ERROR(0);
			p += 2;
			fr_skip_whitespace(p);

			type = fr_table_value_by_longest_prefix(&match_len, fr_type_table, p, end - p, FR_TYPE_MAX);
			if (type == FR_TYPE_MAX) RETURN_PARSE_ERROR(0);
			fr_value_box_init(out, type, NULL, false);
		}

		if (fr_value_calc_binary_op(cc->tmp_ctx, out, type, a, op, b) < 0) {
			RETURN_OK_WITH_ERROR();
		}
	}

	slen = fr_value_box_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), out, NULL);
	if (slen <= 0) RETURN_OK_WITH_ERROR();

	RETURN_OK(slen);
}

/** Perform calculations on multi-valued ops
 *
 */
static size_t command_calc_nary(command_result_t *result, command_file_ctx_t *cc,
				char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	fr_value_box_t *group, *a, *out;
	size_t match_len;
	fr_type_t type;
	fr_token_t op;
	char const *p, *value, *end;
	size_t slen;

	group = talloc_zero(cc->tmp_ctx, fr_value_box_t);
	fr_value_box_init(group, FR_TYPE_GROUP, NULL, false);

	p = in;
	end = in + inlen;

	/*
	 *	Multi-valued operations
	 */
	op = token2op[(uint8_t) p[0]];
	if (op == T_INVALID) {
		fr_strerror_printf("Unknown operator '%c'", p[0]);
		RETURN_PARSE_ERROR(0);
	}
	p++;

	while (p < end) {
		fr_skip_whitespace(p);

		a = talloc_zero(group, fr_value_box_t);

		match_len = parse_typed_value(result, cc, a, &value, p, end - p);
		if (match_len == 0) return 0; /* errors have already been updated */

		fr_value_box_list_insert_tail(&group->vb_group, a);

		p += match_len;

		if (strncmp(p, "->", 2) == 0) break;
	}

	out = talloc_zero(cc->tmp_ctx, fr_value_box_t);
	fr_value_box_mark_safe_for(out, FR_VALUE_BOX_SAFE_FOR_ANY);

	if (strncmp(p, "->", 2) != 0) RETURN_PARSE_ERROR(0);
	p += 2;
	fr_skip_whitespace(p);

	type = fr_table_value_by_longest_prefix(&match_len, fr_type_table, p, end - p, FR_TYPE_MAX);
	if (type == FR_TYPE_MAX) RETURN_PARSE_ERROR(0);


	if (fr_value_calc_nary_op(cc->tmp_ctx, out, type, op, group) < 0) {
		RETURN_OK_WITH_ERROR();
	}

	slen = fr_value_box_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), out, NULL);
	if (slen <= 0) RETURN_OK_WITH_ERROR();

	RETURN_OK(slen);
}

/** Perform casting
 *
 */
static size_t command_cast(command_result_t *result, command_file_ctx_t *cc,
			   char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	fr_value_box_t *a, *out;
	size_t match_len;
	fr_type_t type;
	char const *p, *value, *end;
	size_t slen;
	fr_dict_attr_t const *enumv = NULL;

	a = talloc_zero(cc->tmp_ctx, fr_value_box_t);

	p = in;
	end = in + inlen;

	match_len = parse_typed_value(result, cc, a, &value, p, end - p);
	if (match_len == 0) return 0; /* errors have already been updated */

	p += match_len;
	fr_skip_whitespace(p);

	out = talloc_zero(cc->tmp_ctx, fr_value_box_t);

	if (strncmp(p, "->", 2) != 0) RETURN_PARSE_ERROR(0);
	p += 2;
	fr_skip_whitespace(p);

	type = fr_table_value_by_longest_prefix(&match_len, fr_type_table, p, end - p, FR_TYPE_MAX);
	if (type == FR_TYPE_MAX) RETURN_PARSE_ERROR(0);
	fr_value_box_init(out, type, NULL, false);

	if (type == FR_TYPE_ATTR) {
		enumv = cc->tmpl_rules.attr.dict_def ?
			fr_dict_root(cc->tmpl_rules.attr.dict_def) :
			fr_dict_root(fr_dict_internal());
	}

	if (fr_value_box_cast(out, out, type, enumv, a) < 0) {
		RETURN_OK_WITH_ERROR();
	}

	slen = fr_value_box_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), out, NULL);
	if (slen <= 0) RETURN_OK_WITH_ERROR();

	RETURN_OK(slen);
}

/** Change the working directory
 *
 */
static size_t command_cd(command_result_t *result, command_file_ctx_t *cc,
			 char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	TALLOC_FREE(cc->path);	/* Free old directories */

	cc->path = fr_realpath(cc->tmp_ctx, in, inlen);
	if (!cc->path) RETURN_COMMAND_ERROR();

	strlcpy(data, cc->path, COMMAND_OUTPUT_MAX);

	RETURN_OK(talloc_array_length(cc->path) - 1);
}

/*
 *	Clear the data buffer
 */
static size_t command_clear(command_result_t *result, UNUSED command_file_ctx_t *cc,
			    char *data, size_t UNUSED data_used, UNUSED char *in, UNUSED size_t inlen)
{
	memset(data, 0, COMMAND_OUTPUT_MAX);
	RETURN_NOOP(0);
}

/*
 *	Add a command by talloc'ing a table for it.
 */
static size_t command_radmin_add(command_result_t *result, command_file_ctx_t *cc,
				 char *data, size_t UNUSED data_used, char *in, UNUSED size_t inlen)
{
	char		*p, *name;
	char		*parent = NULL;
	fr_cmd_table_t	*table;
	char		buffer[8192];

	table = talloc_zero(cc->tmp_ctx, fr_cmd_table_t);

	strlcpy(buffer, in, sizeof(buffer));

	p = strchr(buffer, ':');
	if (!p) {
		fr_strerror_const("no ':name' specified");
		RETURN_PARSE_ERROR(0);
	}

	*p = '\0';
	p++;

	parent = talloc_strdup(cc->tmp_ctx, in);

	/*
	 *	Set the name and try to find the syntax.
	 */
	name = p;
	fr_skip_whitespace(p);

	if (isspace((uint8_t) *p)) {
		*p = '\0';
		p++;
	}

	fr_skip_whitespace(p);

	if (*p) {
		table->syntax = talloc_strdup(table, p);
	}
	table->parent = parent;
	table->name = name;
	table->help = NULL;
	table->func = command_func;
	table->tab_expand = NULL;
	table->read_only = true;

	if (fr_command_add(table, &command_head, NULL, NULL, table) < 0) {
		fr_strerror_const_push("ERROR: Failed adding command");
		RETURN_OK_WITH_ERROR();
	}

	if (fr_debug_lvl) command_print();

	RETURN_OK(snprintf(data, COMMAND_OUTPUT_MAX, "ok"));
}

/*
 *	Do tab completion on a command
 */
static size_t command_radmin_tab(command_result_t *result, command_file_ctx_t *cc,
				 char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	int		i;
	int		num_expansions;
	char const	*expansions[CMD_MAX_ARGV];
	char		*p = data, *end = p + COMMAND_OUTPUT_MAX, **argv;
	fr_cmd_info_t	info;
	size_t		len;

	info.argc = 0;
	info.max_argc = CMD_MAX_ARGV;
	info.argv = talloc_zero_array(cc->tmp_ctx, char const *, CMD_MAX_ARGV);
	info.box = talloc_zero_array(cc->tmp_ctx, fr_value_box_t *, CMD_MAX_ARGV);

	memcpy(&argv, &info.argv, sizeof(argv)); /* const issues */
	info.argc = fr_dict_str_to_argv(in, argv, CMD_MAX_ARGV);
	if (info.argc <= 0) {
		fr_strerror_const("Failed splitting input");
		RETURN_PARSE_ERROR(-(info.argc));
	}

	num_expansions = fr_command_tab_expand(cc->tmp_ctx, command_head, &info, CMD_MAX_ARGV, expansions);

	len = snprintf(p, end - p, "%d - ", num_expansions);
	if (is_truncated(len, end - p)) {
	oob:
		fr_strerror_const("Out of output buffer space for radmin command");
		RETURN_COMMAND_ERROR();
	}
	p += len;

	for (i = 0; i < num_expansions; i++) {
		len = snprintf(p, end - p, "'%s', ", expansions[i]);
		if (is_truncated(len, end - p)) goto oob;
		p += len;
	}

	/*
	 *	Remove the trailing ", "
	 */
	if (num_expansions > 0) {
		p -= 2;
		*p = '\0';
	}

	return p - data;
}

/** Parse and reprint a condition
 *
 */
static size_t command_condition_normalise(command_result_t *result, command_file_ctx_t *cc,
					  char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	ssize_t			slen;
	CONF_SECTION		*cs;
	size_t			len;
	xlat_exp_head_t		*head = NULL;

	cs = cf_section_alloc(NULL, NULL, "if", "condition");
	if (!cs) {
		fr_strerror_const("Out of memory");
		RETURN_COMMAND_ERROR();
	}
	cf_filename_set(cs, cc->filename);
	cf_lineno_set(cs, cc->lineno);

	fr_skip_whitespace(in);

	slen = xlat_tokenize_condition(cc->tmp_ctx, &head, &FR_SBUFF_IN(in, inlen), NULL, &cc->tmpl_rules);
	if (slen == 0) {
		fr_strerror_printf_push_head("ERROR failed to parse any input");
		talloc_free(cs);
		RETURN_OK_WITH_ERROR();
	}

	if (slen < 0) {
		fr_strerror_printf_push_head("ERROR offset %d", (int) -slen - 1);
		talloc_free(cs);
		RETURN_OK_WITH_ERROR();
	}

	if ((size_t) slen < inlen) {
		len = snprintf(data, COMMAND_OUTPUT_MAX, "ERROR passed in %zu, returned %zd", inlen, slen);

	} else {
		len = xlat_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), head, NULL);
	}

	talloc_free(head);
	talloc_free(cs);

	RETURN_OK(len);
}

static size_t command_count(command_result_t *result, command_file_ctx_t *cc,
			    char *data, UNUSED size_t data_used, UNUSED char *in, UNUSED size_t inlen)
{
	size_t		len;

	len = snprintf(data, COMMAND_OUTPUT_MAX, "%u", cc->test_count);
	if (is_truncated(len, COMMAND_OUTPUT_MAX)) {
		fr_strerror_const("Command count would overflow data buffer (shouldn't happen)");
		RETURN_COMMAND_ERROR();
	}

	RETURN_OK(len);
}

static size_t command_decode_pair(command_result_t *result, command_file_ctx_t *cc,
				  char *data, size_t data_used, char *in, size_t inlen)
{
	fr_test_point_pair_decode_t	*tp = NULL;
	void		*decode_ctx = NULL;
	char		*p;
	uint8_t		*to_dec;
	uint8_t		*to_dec_end;
	ssize_t		slen;

	fr_dict_attr_t	const *da;
	fr_pair_t	*head;

	da = fr_dict_attr_by_name(NULL, fr_dict_root(fr_dict_internal()), "request");
	fr_assert(da != NULL);
	head = fr_pair_afrom_da(cc->tmp_ctx, da);
	if (!head) {
		fr_strerror_const_push("Failed allocating memory");
		RETURN_COMMAND_ERROR();
	}

	p = in;

	slen = load_test_point_by_command((void **)&tp, in, "tp_decode_pair");
	if (!tp) {
		fr_strerror_const_push("Failed locating decoder testpoint");
		RETURN_COMMAND_ERROR();
	}

	p += slen;
	fr_skip_whitespace(p);

	if (tp->test_ctx && (tp->test_ctx(&decode_ctx, cc->tmp_ctx, dictionary_current(cc), NULL) < 0)) {
		fr_strerror_const_push("Failed initialising decoder testpoint");
		RETURN_COMMAND_ERROR();
	}

	/*
	 *	Hack because we consume more of the command string
	 *	so we need to check this again.
	 */
	if (*p == '-') {
		p = data;
		inlen = data_used;
	}

	/*
	 *	Decode hex from input text
	 */
	slen = hex_to_bin((uint8_t *)data, COMMAND_OUTPUT_MAX, p, inlen);
	if (slen <= 0) {
		CLEAR_TEST_POINT(cc);
		RETURN_PARSE_ERROR(-(slen));
	}

	to_dec = (uint8_t *)data;
	to_dec_end = to_dec + slen;

	ASAN_POISON_MEMORY_REGION(to_dec_end, COMMAND_OUTPUT_MAX - slen);

	/*
	 *	Run the input data through the test
	 *	point to produce fr_pair_ts.
	 */
	while (to_dec < to_dec_end) {
		slen = tp->func(head, &head->vp_group, cc->tmpl_rules.attr.namespace,
				(uint8_t *)to_dec, (to_dec_end - to_dec), decode_ctx);
		cc->last_ret = slen;
		if (slen <= 0) {
			ASAN_UNPOISON_MEMORY_REGION(to_dec_end, COMMAND_OUTPUT_MAX - slen);
			CLEAR_TEST_POINT(cc);
			RETURN_OK_WITH_ERROR();
		}
		if ((size_t)slen > (size_t)(to_dec_end - to_dec)) {
			fr_perror("%s: Internal sanity check failed at %d", __FUNCTION__, __LINE__);
			ASAN_UNPOISON_MEMORY_REGION(to_dec_end, COMMAND_OUTPUT_MAX - slen);
			CLEAR_TEST_POINT(cc);
			RETURN_COMMAND_ERROR();
		}
		to_dec += slen;
	}

	/*
	 *	Clear any spurious errors
	 */
	fr_strerror_clear();
	ASAN_UNPOISON_MEMORY_REGION(to_dec_end, COMMAND_OUTPUT_MAX - slen);

	/*
	 *	Output may be an error, and we ignore
	 *	it if so.
	 */
	slen = fr_pair_list_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), NULL, &head->vp_group);
	if (slen <= 0) {
		RETURN_OK_WITH_ERROR();
	}

	CLEAR_TEST_POINT(cc);
	RETURN_OK(slen);
}

static size_t command_decode_proto(command_result_t *result, command_file_ctx_t *cc,
				  char *data, size_t data_used, char *in, size_t inlen)
{
	fr_test_point_proto_decode_t	*tp = NULL;
	void		*decode_ctx = NULL;
	char		*p;
	uint8_t		*to_dec;
	uint8_t		*to_dec_end;
	ssize_t		slen;

	fr_dict_attr_t	const *da;
	fr_pair_t	*head;

	da = fr_dict_attr_by_name(NULL, fr_dict_root(fr_dict_internal()), "request");
	fr_assert(da != NULL);
	head = fr_pair_afrom_da(cc->tmp_ctx, da);
	if (!head) {
		fr_strerror_const_push("Failed allocating memory");
		RETURN_COMMAND_ERROR();
	}

	p = in;

	slen = load_test_point_by_command((void **)&tp, in, "tp_decode_proto");
	if (!tp) {
		fr_strerror_const_push("Failed locating decoder testpoint");
		RETURN_COMMAND_ERROR();
	}

	p += slen;
	fr_skip_whitespace(p);

	if (tp->test_ctx && (tp->test_ctx(&decode_ctx, cc->tmp_ctx, dictionary_current(cc), NULL) < 0)) {
		fr_strerror_const_push("Failed initialising decoder testpoint");
		RETURN_COMMAND_ERROR();
	}

	/*
	 *	Hack because we consume more of the command string
	 *	so we need to check this again.
	 */
	if (*p == '-') {
		p = data;
		inlen = data_used;
	}

	/*
	 *	Decode hex from input text
	 */
	slen = hex_to_bin((uint8_t *)data, COMMAND_OUTPUT_MAX, p, inlen);
	if (slen <= 0) {
		CLEAR_TEST_POINT(cc);
		RETURN_PARSE_ERROR(-(slen));
	}

	to_dec = (uint8_t *)data;
	to_dec_end = to_dec + slen;

	ASAN_POISON_MEMORY_REGION(to_dec_end, COMMAND_OUTPUT_MAX - slen);

	slen = tp->func(head, &head->vp_group,
			(uint8_t *)to_dec, (to_dec_end - to_dec), decode_ctx);
	cc->last_ret = slen;
	if (slen <= 0) {
		ASAN_UNPOISON_MEMORY_REGION(to_dec_end, COMMAND_OUTPUT_MAX - slen);
		CLEAR_TEST_POINT(cc);
		RETURN_OK_WITH_ERROR();
	}

	/*
	 *	Clear any spurious errors
	 */
	fr_strerror_clear();
	ASAN_UNPOISON_MEMORY_REGION(to_dec_end, COMMAND_OUTPUT_MAX - slen);

	/*
	 *	Output may be an error, and we ignore
	 *	it if so.
	 */

	/*
	 *	Print the pairs.
	 */
	slen = fr_pair_list_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), NULL, &head->vp_group);
	if (slen <= 0) {
		fr_assert(0);
		RETURN_OK_WITH_ERROR();
	}

	CLEAR_TEST_POINT(cc);
	RETURN_OK(slen);
}

/** Parse a dictionary attribute, writing "ok" to the data buffer is everything was ok
 *
 */
static size_t command_dictionary_attribute_parse(command_result_t *result, command_file_ctx_t *cc,
					  	 char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	if (fr_dict_parse_str(dictionary_current(cc), in, cc->tmpl_rules.attr.namespace) < 0) RETURN_OK_WITH_ERROR();

	RETURN_OK(strlcpy(data, "ok", COMMAND_OUTPUT_MAX));
}

/** Print the currently loaded dictionary
 *
 */
static size_t command_dictionary_dump(command_result_t *result, command_file_ctx_t *cc,
				      UNUSED char *data, size_t data_used, UNUSED char *in, UNUSED size_t inlen)
{
	fr_dict_debug(fr_log_fp, dictionary_current(cc));

	/*
	 *	Don't modify the contents of the data buffer
	 */
	RETURN_OK(data_used);
}

static CC_HINT(nonnull)
size_t command_encode_dns_label(command_result_t *result, command_file_ctx_t *cc,
				char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	size_t		need;
	ssize_t		ret;
	char		*p, *next;
	uint8_t		*enc_p;
	char		buffer[8192];

	strlcpy(buffer, in, sizeof(buffer));

	p = buffer;
	next = strchr(p, ',');
	if (next) *next = 0;

	enc_p = cc->buffer_start;

	while (true) {
		fr_value_box_t *box = talloc_zero(NULL, fr_value_box_t);

		fr_skip_whitespace(p);

		if (fr_value_box_from_str(box, box, FR_TYPE_STRING, NULL,
					  p, strlen(p),
					  &fr_value_unescape_double) < 0) {
			talloc_free(box);
			RETURN_OK_WITH_ERROR();
		}

		ret = fr_dns_label_from_value_box(&need,
						  cc->buffer_start, cc->buffer_end - cc->buffer_start, enc_p, true, box, NULL);
		talloc_free(box);

		if (ret < 0) RETURN_OK_WITH_ERROR();

		if (ret == 0) RETURN_OK(snprintf(data, COMMAND_OUTPUT_MAX, "need=%zd", need));

		enc_p += ret;

		/*
		 *	Go to the next input string
		 */
		if (!next) break;

		p = next + 1;
		next = strchr(p, ',');
		if (next) *next = 0;
	}

	if ((cc->fuzzer_dir >= 0) &&
	    (dump_fuzzer_data(cc->fuzzer_dir, in, cc->buffer_start, enc_p - cc->buffer_start) < 0)) {
		RETURN_COMMAND_ERROR();
	}

	RETURN_OK(hex_print(data, COMMAND_OUTPUT_MAX, cc->buffer_start, enc_p - cc->buffer_start));
}

static size_t command_decode_dns_label(command_result_t *result, command_file_ctx_t *cc,
				       char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	ssize_t slen, total, i, outlen;
	char *out, *end;
	fr_value_box_t *box = talloc_zero(NULL, fr_value_box_t);

	/*
	 *	Decode hex from input text
	 */
	total = hex_to_bin(cc->buffer_start, cc->buffer_end - cc->buffer_start, in, inlen);
	if (total <= 0) RETURN_PARSE_ERROR(-total);

	out = data;
	end = data + COMMAND_OUTPUT_MAX;

	for (i = 0; i < total; i += slen) {
		slen = fr_dns_label_to_value_box(box, box, cc->buffer_start, total, cc->buffer_start + i, false, NULL);
		if (slen <= 0) {
		error:
			talloc_free(box);
			RETURN_OK_WITH_ERROR();
		}

		/*
		 *	Separate names by commas
		 */
		if (i > 0) *(out++) = ',';

		/*
		 *	We don't print it with quotes.
		 */
		outlen = fr_value_box_print(&FR_SBUFF_OUT(out, end - out), box, NULL);
		if (outlen <= 0) goto error;
		out += outlen;

		fr_value_box_clear(box);
	}

	talloc_free(box);
	RETURN_OK(out - data);
}

static size_t command_encode_pair(command_result_t *result, command_file_ctx_t *cc,
				  char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	fr_test_point_pair_encode_t	*tp = NULL;

	fr_dcursor_t			cursor;
	void				*encode_ctx = NULL;
	ssize_t				slen;
	char				*p = in;

	uint8_t				*enc_p, *enc_end;
	fr_pair_list_t			head;
	fr_pair_t			*vp;
	bool				truncate = false;

	size_t				iterations = 0;
	fr_pair_parse_t			root, relative;

	fr_pair_list_init(&head);

	slen = load_test_point_by_command((void **)&tp, p, "tp_encode_pair");
	if (!tp) {
		fr_strerror_const_push("Failed locating encode testpoint");
		CLEAR_TEST_POINT(cc);
		RETURN_COMMAND_ERROR();
	}

	p += ((size_t)slen);
	fr_skip_whitespace(p);

	/*
	 *	The truncate torture test.
	 *
	 *	Increase the buffer one byte at a time until all items in the cursor
	 *	have been encoded.
	 *
	 *	The poisoned region at the end of the buffer will detect overruns
	 *	if we're running with asan.
	 *
	 */
	if (strncmp(p, "truncate", sizeof("truncate") - 1) == 0) {
		truncate = true;
		p += sizeof("truncate") - 1;
		fr_skip_whitespace(p);
	}

	if (tp->test_ctx && (tp->test_ctx(&encode_ctx, cc->tmp_ctx, dictionary_current(cc), NULL) < 0)) {
		fr_strerror_const_push("Failed initialising encoder testpoint");
		CLEAR_TEST_POINT(cc);
		RETURN_COMMAND_ERROR();
	}

	root = (fr_pair_parse_t) {
		.ctx = cc->tmp_ctx,
		.da = cc->tmpl_rules.attr.namespace,
		.list = &head,
		.dict = cc->tmpl_rules.attr.namespace->dict,
		.internal = fr_dict_internal(),
		.allow_exec = true
	};
	relative = (fr_pair_parse_t) { };

	slen = fr_pair_list_afrom_substr(&root, &relative, &FR_SBUFF_IN(p, inlen - (p - in)));
	if (slen <= 0) {
		CLEAR_TEST_POINT(cc);
		RETURN_OK_WITH_ERROR();
	}

	 PAIR_LIST_VERIFY_WITH_CTX(cc->tmp_ctx, &head);

	/*
	 *	Outer loop implements truncate test
	 */
	do {
		enc_p = cc->buffer_start;
		enc_end = truncate ? cc->buffer_start + iterations++ : cc->buffer_end;

		if (truncate) {
#ifdef HAVE_SANITIZER_LSAN_INTERFACE_H
			/*
			 *	Poison the region between the subset of the buffer
			 *	we're using and the end of the buffer.
			 */
			ASAN_POISON_MEMORY_REGION(enc_end, (cc->buffer_end) - enc_end);

			DEBUG("%s[%d]: Iteration %zu - Safe region %p-%p (%zu bytes), "
			      "poisoned region %p-%p (%zu bytes)", cc->filename, cc->lineno, iterations - 1,
			      enc_p, enc_end, enc_end - enc_p, enc_end, cc->buffer_end, cc->buffer_end - enc_end);
#else
			DEBUG("%s[%d]: Iteration %zu - Allowed region %p-%p (%zu bytes)",
			      cc->filename, cc->lineno, iterations - 1, enc_p, enc_end, enc_end - enc_p);
#endif
		}

		for (vp = fr_pair_dcursor_iter_init(&cursor, &head,
						    tp->next_encodable ? tp->next_encodable : fr_proto_next_encodable,
						    dictionary_current(cc));
		     vp;
		     vp = fr_dcursor_current(&cursor)) {
			slen = tp->func(&FR_DBUFF_TMP(enc_p, enc_end), &cursor, encode_ctx);
			cc->last_ret = slen;

			if (truncate) DEBUG("%s[%d]: Iteration %zu - Result %zd%s%s",
					    cc->filename, cc->lineno, iterations - 1, slen,
					    *fr_strerror_peek() != '\0' ? " - " : "",
					    *fr_strerror_peek() != '\0' ? fr_strerror_peek() : "");
			if (slen < 0) break;

			/*
			 *	Encoder indicated it encoded too much data
			 */
			if (slen > (enc_end - enc_p)) {
				fr_strerror_printf("Expected returned encoded length <= %zu bytes, got %zu bytes",
						   (enc_end - enc_p), (size_t)slen);
#ifdef HAVE_SANITIZER_LSAN_INTERFACE_H
				if (truncate) ASAN_UNPOISON_MEMORY_REGION(enc_end, (cc->buffer_end) - enc_end);
#endif
				fr_pair_list_free(&head);
				CLEAR_TEST_POINT(cc);
				RETURN_OK_WITH_ERROR();
			}

			enc_p += slen;

			if (slen == 0) break;

		}

#ifdef HAVE_SANITIZER_LSAN_INTERFACE_H
		/*
		 *	un-poison the region between the subset of the buffer
		 *	we're using and the end of the buffer.
		 */
		if (truncate) ASAN_UNPOISON_MEMORY_REGION(enc_end, (cc->buffer_end) - enc_end);
#endif
		/*
		 *	We consumed all the VPs, so presumably encoded the
		 *	complete pair list.
		 */
		if (!vp) break;
	} while (truncate && (enc_end < cc->buffer_end));

	/*
	 *	Last iteration result in an error
	 */
	if (slen < 0) {
		fr_pair_list_free(&head);
		CLEAR_TEST_POINT(cc);
		RETURN_OK_WITH_ERROR();
	}

	/*
	 *	Clear any spurious errors
	 */
	fr_strerror_clear();

	fr_pair_list_free(&head);

	CLEAR_TEST_POINT(cc);

	if ((cc->fuzzer_dir >= 0) &&
	    (dump_fuzzer_data(cc->fuzzer_dir, p, cc->buffer_start, enc_p - cc->buffer_start) < 0)) {
		RETURN_COMMAND_ERROR();
	}

	RETURN_OK(hex_print(data, COMMAND_OUTPUT_MAX, cc->buffer_start, enc_p - cc->buffer_start));
}

/** Encode a RADIUS attribute writing the result to the data buffer as space separated hexits
 *
 */
static size_t command_encode_raw(command_result_t *result, command_file_ctx_t *cc,
			         char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	size_t	len;
	char	buffer[8192];

	strlcpy(buffer, in, sizeof(buffer));

	len = encode_rfc(buffer, cc->buffer_start, cc->buffer_end - cc->buffer_start);
	if (len <= 0) RETURN_PARSE_ERROR(0);

	if (len >= (size_t)(cc->buffer_end - cc->buffer_start)) {
		fr_strerror_const("Encoder output would overflow output buffer");
		RETURN_OK_WITH_ERROR();
	}

	RETURN_OK(hex_print(data, COMMAND_OUTPUT_MAX, cc->buffer_start, len));
}

/** Parse a list of pairs
 *
 */
static size_t command_read_file(command_result_t *result, command_file_ctx_t *cc,
			    char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	ssize_t slen;
	fr_pair_list_t head;
	bool done = false;
	char *filename;
	FILE *fp;

	filename = talloc_asprintf(cc->tmp_ctx, "%s/%s", cc->path, in);

	fp = fopen(filename, "r");
	talloc_free(filename);

	if (!fp) {
		fr_strerror_printf("Failed opening %s - %s", in, fr_syserror(errno));
		RETURN_OK_WITH_ERROR();
	}

	fr_pair_list_init(&head);
	slen = fr_pair_list_afrom_file(cc->tmp_ctx, cc->tmpl_rules.attr.dict_def, &head, fp, &done, true);
	fclose(fp);
	if (slen < 0) {
		RETURN_OK_WITH_ERROR();
	}

	/*
	 *	Print the pairs.
	 */
	slen = fr_pair_list_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), NULL, &head);
	if (slen <= 0) {
		fr_assert(0);
		RETURN_OK_WITH_ERROR();
	}

	if (!done) {
		strlcpy(data + slen, "!DONE", COMMAND_OUTPUT_MAX - slen);
		slen += 5;
	}

	fr_pair_list_free(&head);

	RETURN_OK(slen);
}


static size_t command_returned(command_result_t *result, command_file_ctx_t *cc,
			       char *data, UNUSED size_t data_used, UNUSED char *in, UNUSED size_t inlen)
{
	RETURN_OK(snprintf(data, COMMAND_OUTPUT_MAX, "%zd", cc->last_ret));
}

static size_t command_encode_proto(command_result_t *result, command_file_ctx_t *cc,
				  char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	fr_test_point_proto_encode_t	*tp = NULL;

	void		*encode_ctx = NULL;
	ssize_t		slen;
	char		*p = in;

	fr_pair_list_t	head;
	fr_pair_parse_t	root, relative;

	fr_pair_list_init(&head);

	slen = load_test_point_by_command((void **)&tp, p, "tp_encode_proto");
	if (!tp) {
		fr_strerror_const_push("Failed locating encode testpoint");
		CLEAR_TEST_POINT(cc);
		RETURN_COMMAND_ERROR();
	}

	p += ((size_t)slen);
	fr_skip_whitespace(p);
	if (tp->test_ctx && (tp->test_ctx(&encode_ctx, cc->tmp_ctx, dictionary_current(cc), NULL) < 0)) {
		fr_strerror_const_push("Failed initialising encoder testpoint");
		CLEAR_TEST_POINT(cc);
		RETURN_COMMAND_ERROR();
	}

	root = (fr_pair_parse_t) {
		.ctx = cc->tmp_ctx,
		.da = cc->tmpl_rules.attr.namespace,
		.list = &head,
		.dict = cc->tmpl_rules.attr.namespace->dict,
		.internal = fr_dict_internal(),
		.allow_exec = true
	};
	relative = (fr_pair_parse_t) { };

	slen = fr_pair_list_afrom_substr(&root, &relative, &FR_SBUFF_IN(p, inlen - (p - in)));
	if (slen <= 0) {
		CLEAR_TEST_POINT(cc);
		RETURN_OK_WITH_ERROR();
	}

	slen = tp->func(cc->tmp_ctx, &head, cc->buffer_start, cc->buffer_end - cc->buffer_start, encode_ctx);
	fr_pair_list_free(&head);
	cc->last_ret = slen;
	if (slen < 0) {
		CLEAR_TEST_POINT(cc);
		RETURN_OK_WITH_ERROR();
	}
	/*
	 *	Clear any spurious errors
	 */
	fr_strerror_clear();

	CLEAR_TEST_POINT(cc);

	if ((cc->fuzzer_dir >= 0) &&
	    (dump_fuzzer_data(cc->fuzzer_dir, p, cc->buffer_start, slen) < 0)) {
		RETURN_COMMAND_ERROR();
	}

	RETURN_OK(hex_print(data, COMMAND_OUTPUT_MAX, cc->buffer_start, slen));
}

/** Command eof
 *
 * Mark the end of a test file if we're reading from stdin.
 *
 * Doesn't actually do anything, is just a placeholder for the command processing loop.
 */
static size_t command_eof(UNUSED command_result_t *result, UNUSED command_file_ctx_t *cc,
			  UNUSED char *data, UNUSED size_t data_used, UNUSED char *in, UNUSED size_t inlen)
{
	return 0;
}

/** Enable fuzzer output
 *
 * Any commands that produce potentially useful corpus seed data will write that out data
 * to files in the specified directory, using the md5 of the text input at as the file name.
 *
 */
static size_t command_fuzzer_out(command_result_t *result, command_file_ctx_t *cc,
				 UNUSED char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	int	fd;
	struct	stat sdir;
	char	*fuzzer_dir;
	bool	retry_dir = true;

	/*
	 *	Close any open fuzzer output dirs
	 */
	if (cc->fuzzer_dir >= 0) {
		close(cc->fuzzer_dir);
		cc->fuzzer_dir = -1;
	}

	if (in[0] == '\0') {
		fr_strerror_const("Missing directory name");
		RETURN_PARSE_ERROR(0);
	}

	fuzzer_dir = talloc_asprintf(cc->tmp_ctx, "%s/%s",
				     cc->config->fuzzer_dir ? cc->config->fuzzer_dir : cc->path, in);

again:
	fd = open(fuzzer_dir, O_RDONLY);
	if (fd < 0) {
		if (mkdir(fuzzer_dir, 0777) == 0) {
			fd = open(fuzzer_dir, O_RDONLY);
			if (fd >= 0) goto stat;
		/*
		 *	Prevent race if multiple unit_test_attribute instances
		 *	attempt to create the same output dir.
		 */
		} else if ((errno == EEXIST) && retry_dir) {
			retry_dir = false;	/* Only allow this once */
			goto again;
		}

		fr_strerror_printf("fuzzer-out \"%s\" doesn't exist: %s", fuzzer_dir, fr_syserror(errno));
		RETURN_PARSE_ERROR(0);
	}

stat:
	if (fstat(fd, &sdir) < 0) {
		close(fd);
		fr_strerror_printf("failed statting fuzzer-out \"%s\": %s", fuzzer_dir, fr_syserror(errno));
		RETURN_PARSE_ERROR(0);
	}

	if (!(sdir.st_mode & S_IFDIR)) {
		close(fd);
		fr_strerror_printf("fuzzer-out \"%s\" is not a directory", fuzzer_dir);
		RETURN_PARSE_ERROR(0);
	}
	cc->fuzzer_dir = fd;
	talloc_free(fuzzer_dir);

	return 0;
}

/** Exit gracefully with the specified code
 *
 */
static size_t command_exit(command_result_t *result, UNUSED command_file_ctx_t *cc,
			   UNUSED char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	if (!*in) RETURN_EXIT(0);

	RETURN_EXIT(atoi(in));
}

static size_t command_load_dictionary(command_result_t *result, command_file_ctx_t *cc,
				       UNUSED char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	char		*name, *tmp = NULL;
	char const     	*dir;
	char		*q;
	int		ret;

	fr_dict_global_ctx_set(cc->config->dict_gctx);

	if (in[0] == '\0') {
		fr_strerror_const("Missing dictionary name");
		RETURN_PARSE_ERROR(0);
	}

	q = strchr(in, ' ');
	if (q) {
		name = tmp = talloc_bstrndup(NULL, in, q - in);
		q++;
		dir = q;
	} else {
		name = in;
		dir = cc->path;
	}

	/*
	 *	When we're reading multiple files at the same time, they might all have a 'load-dictionary foo'
	 *	command.  In which case we don't complain.
	 */
	if (fr_dict_filename_loaded(cc->tmpl_rules.attr.dict_def, dir, name)) {
		RETURN_OK(0);
	}

	ret = fr_dict_read(UNCONST(fr_dict_t *, cc->tmpl_rules.attr.dict_def), dir, name);
	talloc_free(tmp);
	if (ret < 0) RETURN_COMMAND_ERROR();

	RETURN_OK(0);
}


/** Compare the data buffer to an expected value
 *
 */
static size_t command_match(command_result_t *result, command_file_ctx_t *cc,
			    char *data, size_t data_used, char *in, size_t inlen)
{
	if (strcmp(in, data) != 0) {
		if (write_fp) {
			strcpy(in, data);
			RETURN_OK(data_used);
		}

		mismatch_print(cc, "match", in, inlen, data, data_used, true);
		RETURN_MISMATCH(data_used);
	}

	/*
	 *	We didn't actually write anything, but this
	 *	keeps the contents of the data buffer around
	 *	for the next command to operate on.
	 */
	RETURN_OK(data_used);
}

/** Compare the data buffer against an expected expression
 *
 */
static size_t command_match_regex(command_result_t *result, command_file_ctx_t *cc,
				  char *data, size_t data_used, char *in, size_t inlen)
{
	ssize_t		slen;
	regex_t		*regex;
	int		ret;

	slen = regex_compile(cc->tmp_ctx, &regex, in, inlen, NULL, false, true);
	if (slen <= 0) RETURN_COMMAND_ERROR();

	ret = regex_exec(regex, data, data_used, NULL);
	talloc_free(regex);

	switch (ret) {
	case -1:
	default:
		RETURN_COMMAND_ERROR();

	case 0:
		mismatch_print(cc, "match-regex", in, inlen, data, data_used, false);
		RETURN_MISMATCH(data_used);

	case 1:
		RETURN_OK(data_used);
	}
}

/** Artificially limit the maximum packet size.
 *
 */
static size_t command_max_buffer_size(command_result_t *result, command_file_ctx_t *cc,
				      char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	unsigned long size;
	char *end;

	fr_skip_whitespace(in);

	if (*in != '\0') {
		size = strtoul(in, &end, 10);
		if ((size == ULONG_MAX) || *end || (size >= 65536)) {
			fr_strerror_const_push("Invalid integer");
			RETURN_COMMAND_ERROR();
		}
	} else {
		size = DEFAULT_BUFFER_SIZE;
	}

	if (poisoned_buffer_allocate(cc, &cc->buffer, size) < 0) RETURN_EXIT(1);
	cc->buffer_start = POISONED_BUFFER_START(cc->buffer);
	cc->buffer_end = POISONED_BUFFER_END(cc->buffer);

	RETURN_OK(snprintf(data, COMMAND_OUTPUT_MAX, "%ld", size));
}

/** Set or clear migration flags.
 *
 */
static size_t command_migrate(command_result_t *result, command_file_ctx_t *cc,
			      UNUSED char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	char *p;
	bool *out;

	fr_skip_whitespace(in);
	p = in;

	if (strncmp(p, "xlat_new_functions", sizeof("xlat_new_functions") - 1) == 0) {
		p += sizeof("xlat_new_functions") - 1;
		out = &cc->tmpl_rules.xlat.new_functions;

	} else {
		fr_strerror_const("Unknown migration flag");
		RETURN_PARSE_ERROR(0);
	}

	fr_skip_whitespace(p);
	if (*p != '=') {
		fr_strerror_const("Missing '=' after flag");
		RETURN_PARSE_ERROR(0);
	}
	p++;

	fr_skip_whitespace(p);
	if ((strcmp(p, "yes") == 0) || (strcmp(p, "true") == 0) || (strcmp(p, "1") == 0)) {
		*out = true;

	} else if ((strcmp(p, "no") == 0) || (strcmp(p, "false") == 0) || (strcmp(p, "0") == 0)) {
		*out = false;

	} else {
		fr_strerror_const("Invalid value for flag");
		RETURN_PARSE_ERROR(0);
	}

	RETURN_OK(0);
}

/** Skip the test file if we're missing a particular feature
 *
 */
static size_t command_need_feature(command_result_t *result, command_file_ctx_t *cc,
				   UNUSED char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	CONF_PAIR *cp;

	if (in[0] == '\0') {
		fr_strerror_printf("Prerequisite syntax is \"need-feature <feature>\".  "
				   "Use -f to print features");
		RETURN_PARSE_ERROR(0);
	}

	cp = cf_pair_find(cc->config->features, in);
	if (!cp || (strcmp(cf_pair_value(cp), "yes") != 0)) {
		DEBUG("Skipping, missing feature \"%s\"", in);
		RETURN_SKIP_FILE();
	}

	RETURN_NOOP(0);
}

/** Negate the result of a match command or any command which returns "OK"
 *
 */
static size_t command_no(command_result_t *result, command_file_ctx_t *cc,
			 char *data, size_t data_used, char *in, size_t inlen)
{
	data_used = process_line(result, cc, data, data_used, in, inlen);
	switch (result->rcode) {
	/*
	 *	OK becomes a command error
	 */
	case RESULT_OK:
		ERROR("%s[%d]: %.*s: returned 'ok', where we expected 'result-mismatch'",
		      cc->filename, cc->lineno, (int) inlen, in);
		RETURN_MISMATCH(data_used);

	/*
	 *	Mismatch becomes OK
	 */
	case RESULT_MISMATCH:
		RETURN_OK(data_used);

	/*
	 *	The rest are unchanged...
	 */
	default:
		break;
	}

	return data_used;
}

/** Parse an print an attribute pair or pair list.
 *
 */
static size_t command_pair_common(command_result_t *result, command_file_ctx_t *cc,
				  char *data, UNUSED size_t data_used, char *in, size_t inlen,
				  bool allow_compare)
{
	fr_pair_list_t 	head;
	ssize_t		slen;
	fr_dict_t const	*dict = dictionary_current(cc);
	fr_pair_parse_t	root, relative;

	fr_pair_list_init(&head);

	root = (fr_pair_parse_t) {
		.ctx = cc->tmp_ctx,
		.da = fr_dict_root(dict),
		.list = &head,
		.dict = dict,
		.internal = fr_dict_internal(),
		.allow_compare = allow_compare,
		.allow_exec = true
	};
	relative = (fr_pair_parse_t) { };

	slen = fr_pair_list_afrom_substr(&root, &relative, &FR_SBUFF_IN(in, inlen));
	if (slen <= 0) {
//		fr_strerror_printf_push_head("ERROR offset %d", (int) -slen);
		fr_pair_list_free(&head);
		RETURN_OK_WITH_ERROR();
	}

	/*
	 *	Output may be an error, and we ignore
	 *	it if so.
	 */

	slen = fr_pair_list_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), NULL, &head);
	if (slen <= 0) {
		fr_pair_list_free(&head);
		RETURN_OK_WITH_ERROR();
	}

	fr_pair_list_free(&head);
	RETURN_OK(slen);
}

static size_t command_pair(command_result_t *result, command_file_ctx_t *cc,
			   char *data, size_t data_used, char *in, size_t inlen)
{
	return command_pair_common(result, cc, data, data_used, in, inlen, false);
}

static size_t command_pair_compare(command_result_t *result, command_file_ctx_t *cc,
				   char *data, size_t data_used, char *in, size_t inlen)
{
	return command_pair_common(result, cc, data, data_used, in, inlen, true);
}


/** Dynamically load a protocol library
 *
 */
static size_t command_proto(command_result_t *result, command_file_ctx_t *cc,
			    UNUSED char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	ssize_t slen;

	if (*in == '\0') {
		fr_strerror_printf("Load syntax is \"proto <lib_name>\"");
		RETURN_PARSE_ERROR(0);
	}

	fr_dict_global_ctx_set(cc->config->dict_gctx);
	slen = load_proto_library(in);
	if (slen <= 0) RETURN_PARSE_ERROR(-(slen));

	RETURN_OK(0);
}

static size_t command_proto_dictionary(command_result_t *result, command_file_ctx_t *cc,
				       UNUSED char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	fr_dict_global_ctx_set(cc->config->dict_gctx);
	return dictionary_load_common(result, cc, in, NULL);
}

static size_t command_proto_dictionary_root(command_result_t *result, command_file_ctx_t *cc,
					    UNUSED char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	fr_dict_t const		*dict = dictionary_current(cc);
	fr_dict_attr_t const	*root_da = fr_dict_root(dict);
	fr_dict_attr_t const	*new_root;

	if (is_whitespace(in) || (*in == '\0')) {
		new_root = fr_dict_root(dict);
	} else {
		new_root = fr_dict_attr_by_name(NULL, fr_dict_root(dict), in);
		if (!new_root) {
			fr_strerror_printf("dictionary attribute \"%s\" not found in %s", in, root_da->name);
			RETURN_PARSE_ERROR(0);
		}
	}

	cc->tmpl_rules.attr.namespace = new_root;

	RETURN_OK(0);
}

/** Parse an reprint a tmpl expansion
 *
 */
static size_t command_tmpl(command_result_t *result, command_file_ctx_t *cc,
				     char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	ssize_t			slen;
	tmpl_t			*vpt;
	size_t			input_len = strlen(in), escaped_len;

	slen = tmpl_afrom_substr(cc->tmp_ctx, &vpt, &FR_SBUFF_IN(in, input_len), T_BARE_WORD,
				 &value_parse_rules_bareword_unquoted,
				 &(tmpl_rules_t) {
					 .attr = {
						 .dict_def = dictionary_current(cc),
						 .list_def = request_attr_request,
						 .allow_unresolved = cc->tmpl_rules.attr.allow_unresolved
					 },
					 .xlat = cc->tmpl_rules.xlat,
				 });
	if (slen == 0) {
		fr_strerror_printf_push_head("ERROR failed to parse any input");
		RETURN_OK_WITH_ERROR();
	}

	if (slen < 0) {
		fr_strerror_printf_push_head("ERROR offset %d", (int) -slen - 1);

	return_error:
		RETURN_OK_WITH_ERROR();
	}

	if (((size_t) slen != input_len)) {
		fr_strerror_printf_push_head("offset %d 'Too much text'", (int) slen);
		goto return_error;
	}

	escaped_len = tmpl_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), vpt, NULL);
	RETURN_OK(escaped_len);
}

/** Touch a file to indicate a test completed
 *
 */
static size_t command_touch(command_result_t *result, UNUSED command_file_ctx_t *cc,
			    UNUSED char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	if (fr_unlink(in) < 0) RETURN_COMMAND_ERROR();
	if (fr_touch(NULL, in, 0644, true, 0755) <= 0) RETURN_COMMAND_ERROR();

	RETURN_OK(0);
}

/** Callback for a tmpl rule parser
 *
 */
typedef ssize_t(*command_tmpl_rule_func)(TALLOC_CTX *ctx, tmpl_rules_t *rules, fr_sbuff_t *value);

static ssize_t command_tmpl_rule_allow_foreign(UNUSED TALLOC_CTX *ctx, tmpl_rules_t *rules, fr_sbuff_t *value)
{
	bool res;
	ssize_t slen;

	slen = fr_sbuff_out_bool(&res, value);
	rules->attr.allow_foreign = res;
	return slen;
}

static ssize_t command_tmpl_rule_allow_unknown(UNUSED TALLOC_CTX *ctx, tmpl_rules_t *rules, fr_sbuff_t *value)
{
	bool res;
	ssize_t slen;

	slen = fr_sbuff_out_bool(&res, value);
	rules->attr.allow_unknown = res;
	return slen;
}

static ssize_t command_tmpl_rule_allow_unresolved(UNUSED TALLOC_CTX *ctx, tmpl_rules_t *rules, fr_sbuff_t *value)
{
	bool res;
	ssize_t slen;

	slen = fr_sbuff_out_bool(&res, value);
	rules->attr.allow_unresolved = res;
	return slen;
}

static ssize_t command_tmpl_rule_attr_parent(UNUSED TALLOC_CTX *ctx, tmpl_rules_t *rules, fr_sbuff_t *value)
{
	fr_dict_attr_err_t	err;
	fr_slen_t		slen;

	slen = fr_dict_attr_by_oid_substr(&err,
					  &rules->attr.namespace,
					  rules->attr.dict_def ? fr_dict_root(rules->attr.dict_def) :
					  			 fr_dict_root(fr_dict_internal()),
					  value, NULL);
	if (err != FR_DICT_ATTR_OK) FR_SBUFF_ERROR_RETURN(value);
	return slen;
}

static ssize_t command_tmpl_rule_list_def(UNUSED TALLOC_CTX *ctx, tmpl_rules_t *rules, fr_sbuff_t *value)
{
	ssize_t slen;

	slen = tmpl_attr_list_from_substr(&rules->attr.list_def, value);

	if (slen == 0) {
		fr_strerror_printf("Invalid list specifier \"%pV\"",
				   fr_box_strvalue_len(fr_sbuff_current(value), fr_sbuff_remaining(value)));
	}

	return slen;
}

static ssize_t command_tmpl_rule_request_def(TALLOC_CTX *ctx, tmpl_rules_t *rules, fr_sbuff_t *value)
{
	fr_slen_t			 slen;

	slen = tmpl_request_ref_list_afrom_substr(ctx, NULL,
						  &rules->attr.request_def,
						  value);
	if (slen < 0) {
		fr_strerror_printf("Invalid request specifier \"%pV\"",
				   fr_box_strvalue_len(fr_sbuff_current(value), fr_sbuff_remaining(value)));
	}

	return slen;
}

static size_t command_tmpl_rules(command_result_t *result, command_file_ctx_t *cc,
				 UNUSED char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	fr_sbuff_t		sbuff = FR_SBUFF_IN(in, inlen);
	ssize_t			slen;
	command_tmpl_rule_func	func;
	void			*res;

	static fr_table_ptr_sorted_t tmpl_rule_func_table[] = {
		{ L("allow_foreign"),		(void *)command_tmpl_rule_allow_foreign		},
		{ L("allow_unknown"),		(void *)command_tmpl_rule_allow_unknown		},
		{ L("allow_unresolved"),	(void *)command_tmpl_rule_allow_unresolved	},
		{ L("attr_parent"),		(void *)command_tmpl_rule_attr_parent		},
		{ L("list_def"),		(void *)command_tmpl_rule_list_def		},
		{ L("request_def"),		(void *)command_tmpl_rule_request_def		}
	};
	static size_t tmpl_rule_func_table_len = NUM_ELEMENTS(tmpl_rule_func_table);

	while (fr_sbuff_extend(&sbuff)) {
		fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX, NULL);

		fr_sbuff_out_by_longest_prefix(&slen, &res, tmpl_rule_func_table, &sbuff, NULL);
		if (res == NULL) {
			fr_strerror_printf("Specified rule \"%pV\" is invalid",
					   fr_box_strvalue_len(fr_sbuff_current(&sbuff), fr_sbuff_remaining(&sbuff)));
			RETURN_COMMAND_ERROR();
		}
		func = (command_tmpl_rule_func)res;	/* -Wpedantic */

		fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX, NULL);

		if (!fr_sbuff_next_if_char(&sbuff, '=')) {
			fr_strerror_printf("Expected '=' after rule identifier, got \"%pV\"",
					   fr_box_strvalue_len(fr_sbuff_current(&sbuff), fr_sbuff_remaining(&sbuff)));
			RETURN_COMMAND_ERROR();
		}

		fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX, NULL);

		if (func(cc->tmp_ctx, &cc->tmpl_rules, &sbuff) <= 0) RETURN_COMMAND_ERROR();
	}

	return fr_sbuff_used(&sbuff);
}

static size_t command_value_box_normalise(command_result_t *result, command_file_ctx_t *cc,
					  char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	fr_value_box_t *box = talloc_zero(NULL, fr_value_box_t);
	fr_value_box_t *box2;
	char const	*value;
	size_t		match_len;
	ssize_t		slen;
	fr_type_t	type;

	match_len = parse_typed_value(result, cc, box, &value, in, strlen(in));
	if (match_len == 0) {
		talloc_free(box);
		return 0;	/* errors have already been updated */
	}

	type = box->type;

	/*
	 *	Don't print dates with enclosing quotation marks.
	 */
	if (type != FR_TYPE_DATE) {
		slen = fr_value_box_print_quoted(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), box,
						 T_DOUBLE_QUOTED_STRING);
	} else {
		slen = fr_value_box_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), box, NULL);
	}
	if (slen <= 0) {
		talloc_free(box);
		RETURN_OK_WITH_ERROR();
	}

	/*
	 *	Behind the scenes, parse the data
	 *	string.  We should get the same value
	 *	box as last time.
	 */
	box2 = talloc_zero(NULL, fr_value_box_t);
	if (fr_value_box_from_str(box2, box2, type, box->enumv,
				  data, slen,
				  &fr_value_unescape_double) < 0) {
		talloc_free(box2);
		talloc_free(box);
		RETURN_OK_WITH_ERROR();
	}

	/*
	 *	They MUST be identical
	 */
	if (fr_value_box_cmp(box, box2) != 0) {
		fr_strerror_const("ERROR value box reparsing failed.  Results not identical");
		fr_strerror_printf_push("out: %pV (as string %.*s)", box2, (int) slen, data);
		fr_strerror_printf_push("in: %pV (from string %s)", box, value);
		talloc_free(box2);
		talloc_free(box);
		RETURN_OK_WITH_ERROR();
	}

	/*
	 *	Store <type><value str...>
	 */
	if (cc->fuzzer_dir >= 0) {
		char fuzzer_buffer[1024];
		char *fuzzer_p = fuzzer_buffer, *fuzzer_end = fuzzer_p + sizeof(fuzzer_buffer);

		*fuzzer_p++ = (uint8_t)type;	/* Fuzzer uses first byte for type */

		strlcpy(fuzzer_p, data, slen > fuzzer_end - fuzzer_p ? fuzzer_end - fuzzer_p : slen);

		if (dump_fuzzer_data(cc->fuzzer_dir, fuzzer_buffer,
				     (uint8_t *)fuzzer_buffer, strlen(fuzzer_buffer)) < 0) {
			RETURN_COMMAND_ERROR();
		}
	}

	talloc_free(box2);
	talloc_free(box);
	RETURN_OK(slen);
}

static size_t command_write(command_result_t *result, command_file_ctx_t *cc,
			    char *data, size_t data_used, char *in, size_t inlen)
{
	int	fd;
	char	*path;
	bool	locked = false;

	path = talloc_bstrndup(cc->tmp_ctx, in, inlen);

	fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (fd < 0) {
		fr_strerror_printf("Failed opening \"%s\": %s", path, fr_syserror(errno));
	error:
		talloc_free(path);
		if (fd >= 0) {
			if (locked) (void)flock(fd, LOCK_UN);
			close(fd);
		}
		RETURN_COMMAND_ERROR();
	}

	if (flock(fd, LOCK_EX) < 0) {
		fr_strerror_printf("Failed locking \"%s\": %s", path, fr_syserror(errno));
		goto error;
	}
	locked = true;

	while (data_used) {
		ssize_t	ret;
		ret = write(fd, data, data_used);
		if (ret < 0) {
			fr_strerror_printf("Failed writing to \"%s\": %s", path, fr_syserror(errno));
			goto error;
		}
		data_used -= ret;
		data += ret;
	}
	(void)flock(fd, LOCK_UN);
	talloc_free(path);
	close(fd);

	RETURN_OK(data_used);
}

/** Parse an reprint and xlat expansion
 *
 */
static size_t command_xlat_normalise(command_result_t *result, command_file_ctx_t *cc,
				     char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	ssize_t			slen;
	xlat_exp_head_t		*head = NULL;
	size_t			input_len = strlen(in), escaped_len;
	fr_sbuff_parse_rules_t	p_rules = { .escapes = &fr_value_unescape_double };

	if (allow_purify) {
		fr_strerror_printf_push_head("ERROR cannot run 'xlat' when running with command-line argument '-p'");
		RETURN_OK_WITH_ERROR();
	}

	slen = xlat_tokenize(cc->tmp_ctx, &head, &FR_SBUFF_IN(in, input_len), &p_rules,
			     &(tmpl_rules_t) {
				     .attr = {
					     .dict_def = dictionary_current(cc),
					     .list_def = request_attr_request,
					     .allow_unresolved = cc->tmpl_rules.attr.allow_unresolved
				     },
				     .xlat = cc->tmpl_rules.xlat,
			     });
	if (slen == 0) {
		fr_strerror_printf_push_head("ERROR failed to parse any input");
		RETURN_OK_WITH_ERROR();
	}

	if (slen < 0) {
		fr_strerror_printf_push_head("ERROR offset %d", (int) -slen - 1);

	return_error:
		RETURN_OK_WITH_ERROR();
	}

	if (((size_t) slen != input_len)) {
		fr_strerror_printf_push_head("offset %d 'Too much text'", (int) slen);
		goto return_error;
	}

	escaped_len = xlat_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), head, &fr_value_escape_double);
	RETURN_OK(escaped_len);
}

/** Parse and reprint an xlat expression expansion
 *
 */
static size_t command_xlat_expr(command_result_t *result, command_file_ctx_t *cc,
				     char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	ssize_t			dec_len;
	xlat_exp_head_t		*head = NULL;
	size_t			input_len = strlen(in), escaped_len;
//	fr_sbuff_parse_rules_t	p_rules = { .escapes = &fr_value_unescape_double };

	dec_len = xlat_tokenize_expression(cc->tmp_ctx, &head, &FR_SBUFF_IN(in, input_len), NULL,
					   &(tmpl_rules_t) {
					   	.attr = {
							.dict_def = dictionary_current(cc),
							.allow_unresolved = cc->tmpl_rules.attr.allow_unresolved,
							.list_def = request_attr_request,
						}
					   });
	if (dec_len <= 0) {
		fr_strerror_printf_push_head("ERROR offset %d", (int) -dec_len);

	return_error:
		RETURN_OK_WITH_ERROR();
	}

	if (((size_t) dec_len != input_len)) {
		fr_strerror_printf_push_head("Passed in %zu characters, but only parsed %zd characters", input_len, dec_len);
		goto return_error;
	}

	escaped_len = xlat_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), head, &fr_value_escape_double);
	RETURN_OK(escaped_len);
}

/** Parse, purify, and reprint an xlat expression expansion
 *
 */
static size_t command_xlat_purify(command_result_t *result, command_file_ctx_t *cc,
				     char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	ssize_t			slen;
	xlat_exp_head_t		*head = NULL;
	size_t			input_len = strlen(in), escaped_len;
	tmpl_rules_t		t_rules = (tmpl_rules_t) {
						   .attr = {
							.dict_def = dictionary_current(cc),
							.allow_unresolved = cc->tmpl_rules.attr.allow_unresolved,
							.list_def = request_attr_request,
						   },
						   .xlat = cc->tmpl_rules.xlat,
						   .at_runtime = true,
					   };

	if (!el) {
		fr_strerror_const("Flag '-p' not used.  xlat_purify is disabled");
		goto return_error;
	}
	t_rules.xlat.runtime_el = el;

	slen = xlat_tokenize_expression(cc->tmp_ctx, &head, &FR_SBUFF_IN(in, input_len), NULL, &t_rules);
	if (slen == 0) {
		fr_strerror_printf_push_head("ERROR failed to parse any input");
		RETURN_OK_WITH_ERROR();
	}

	if (slen < 0) {
		fr_strerror_printf_push_head("ERROR offset %d", (int) -slen - 1);
	return_error:
		RETURN_OK_WITH_ERROR();
	}

	if (((size_t) slen != input_len)) {
		fr_strerror_printf_push_head("Passed in %zu characters, but only parsed %zd characters", input_len, slen);
		goto return_error;
	}

	if (fr_debug_lvl > 2) {
		DEBUG("Before purify --------------------------------------------------");
		xlat_debug_head(head);
	}

	if (xlat_purify(head, NULL) < 0) {
		fr_strerror_printf_push_head("ERROR purifying node - %s", fr_strerror());
		goto return_error;
	}

	if (fr_debug_lvl > 2) {
		DEBUG("After purify --------------------------------------------------");
		xlat_debug_head(head);
	}

	escaped_len = xlat_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), head, &fr_value_escape_double);
	RETURN_OK(escaped_len);
}


/** Parse, purify, and reprint an xlat expression expansion
 *
 */
static size_t command_xlat_purify_condition(command_result_t *result, command_file_ctx_t *cc,
					    char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	ssize_t			slen;
	xlat_exp_head_t		*head = NULL;
	size_t			input_len = strlen(in), escaped_len;
	tmpl_rules_t		t_rules = (tmpl_rules_t) {
						   .attr = {
							.dict_def = dictionary_current(cc),
							.allow_unresolved = cc->tmpl_rules.attr.allow_unresolved,
							.list_def = request_attr_request,
						   },
						   .xlat = cc->tmpl_rules.xlat,
						   .at_runtime = true,
					   };

	if (!el) {
		fr_strerror_const("Flag '-p' not used.  xlat_purify is disabled");
		goto return_error;
	}
	t_rules.xlat.runtime_el = el;

	slen = xlat_tokenize_condition(cc->tmp_ctx, &head, &FR_SBUFF_IN(in, input_len), NULL, &t_rules);
	if (slen == 0) {
		fr_strerror_printf_push_head("ERROR failed to parse any input");
		RETURN_OK_WITH_ERROR();
	}

	if (slen < 0) {
		fr_strerror_printf_push_head("ERROR offset %d", (int) -slen - 1);
	return_error:
		RETURN_OK_WITH_ERROR();
	}

	if (((size_t) slen != input_len)) {
		fr_strerror_printf_push_head("Passed in %zu characters, but only parsed %zd characters", input_len, slen);
		goto return_error;
	}

	if (fr_debug_lvl > 2) {
		DEBUG("Before purify --------------------------------------------------");
		xlat_debug_head(head);
	}

	if (xlat_purify(head, NULL) < 0) {
		fr_strerror_printf_push_head("ERROR purifying node - %s", fr_strerror());
		goto return_error;
	}

	if (fr_debug_lvl > 2) {
		DEBUG("After purify --------------------------------------------------");
		xlat_debug_head(head);
	}

	escaped_len = xlat_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), head, &fr_value_escape_double);
	RETURN_OK(escaped_len);
}


/** Parse an reprint and xlat argv expansion
 *
 */
static size_t command_xlat_argv(command_result_t *result, command_file_ctx_t *cc,
				char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	int		i, argc;
	char		*p;
	ssize_t		slen;
	xlat_exp_head_t	*head = NULL;
	xlat_exp_head_t **argv;
	size_t		len;
	size_t		input_len = strlen(in);
	char		buff[1024];

	if (allow_purify) {
		fr_strerror_printf_push_head("ERROR cannot run 'xlat_argv' when running with command-line argument '-p'");
		RETURN_OK_WITH_ERROR();
	}

	slen = xlat_tokenize_argv(cc->tmp_ctx, &head, &FR_SBUFF_IN(in, input_len),
				  NULL, NULL,
				  &(tmpl_rules_t) {
					  .attr = {
						  .dict_def = dictionary_current(cc),
						  .list_def = request_attr_request,
						  .allow_unresolved = cc->tmpl_rules.attr.allow_unresolved
					  },
				  }, true);
	if (slen <= 0) {
		fr_strerror_printf_push_head("ERROR offset %d", (int) -slen);
		RETURN_OK_WITH_ERROR();
	}

	argc = xlat_flatten_to_argv(cc->tmp_ctx, &argv, head);
	if (argc <= 0) {
		fr_strerror_printf_push("ERROR in argument %d", (int) -argc);
		RETURN_OK_WITH_ERROR();
	}

	for (i = 0, p = data; i < argc; i++) {
		(void)  xlat_print(&FR_SBUFF_OUT(buff, sizeof(buff)), argv[i], NULL);

		len = snprintf(p, data + COMMAND_OUTPUT_MAX - p, "[%d]{ %s }, ", i, buff);
		p += len;
	}

	p -= 2;
	*p = '\0';

	RETURN_OK(p - data);
}

static fr_table_ptr_sorted_t	commands[] = {
	{ L("#"),		&(command_entry_t){
					.func = command_comment,
					.usage = "#<string>",
					.description = "A comment - not processed"
				}},
	{ L("$INCLUDE "),	&(command_entry_t){
					.func = command_include,
					.usage = "$INCLUDE <relative_path>",
					.description = "Execute a test file"
				}},
	{ L("allow-unresolved "), &(command_entry_t){
					.func = command_allow_unresolved,
					.usage = "allow-unresolved yes|no",
					.description = "Allow or disallow unresolved attributes in xlats and references"
				}},
	{ L("attr.children"),	&(command_entry_t){
					.func = command_attr_children,
					.usage = "attr.children",
					.description = "Return the children of the named attribute",
				}},
	{ L("attr.flags"),	&(command_entry_t){
					.func = command_attr_flags,
					.usage = "attr.flags",
					.description = "Return the flags of the named attribute",
				}},
	{ L("attr.name"),	&(command_entry_t){
					.func = command_attr_name,
					.usage = "attr.name",
					.description = "Return the number of the named attribute",
				}},
#if 0
	{ L("attr.number"),	&(command_entry_t){
					.func = command_attr_number,
					.usage = "attr.number",
					.description = "Return the number of the named attribute",
				}},
#endif
	{ L("attr.oid"),	&(command_entry_t){
					.func = command_attr_oid,
					.usage = "attr.oid",
					.description = "Return the OID of the named attribute",
				}},
#if 0
	{ L("attr.ref"),	&(command_entry_t){
					.func = command_attr_ref,
					.usage = "attr.ref",
					.description = "Return the reference (if any) of the named attribute",
				}},
#endif
	{ L("attr.type"),	&(command_entry_t){
					.func = command_attr_type,
					.usage = "attr.type",
					.description = "Return the data type of the named attribute",
				}},
	{ L("calc "),		&(command_entry_t){
					.func = command_calc,
					.usage = "calc <type1> <value1> <operator> <type2> <value2> -> <output-type>",
					.description = "Perform calculations on value boxes",
				}},
	{ L("calc_nary "), 	&(command_entry_t){
					.func = command_calc_nary,
					.usage = "calc_nary op <type1> <value1> <type2> <value2> ... -> <output-type>",
					.description = "Perform calculations on value boxes",
				}},
	{ L("cast "),		&(command_entry_t){
					.func = command_cast,
					.usage = "cast (type) <value> -> <output-type>",
					.description = "Perform calculations on value boxes",
				}},
	{ L("cd "),		&(command_entry_t){
					.func = command_cd,
					.usage = "cd <path>",
					.description = "Change the directory for loading dictionaries and $INCLUDEs, writing the full path into the data buffer on success"
				}},
	{ L("clear"),		&(command_entry_t){
					.func = command_clear,
					.usage = "clear",
					.description = "Explicitly zero out the contents of the data buffer"
				}},
	{ L("command add "),	&(command_entry_t){
					.func = command_radmin_add,
					.usage = "command add <string>",
					.description = "Add a command to a radmin command tree"
				}},
	{ L("command tab "),	&(command_entry_t){
					.func = command_radmin_tab,
					.usage = "command tab <string>",
					.description = "Test a tab completion against a radmin command tree"
				}},
	{ L("condition "),	&(command_entry_t){
					.func = command_condition_normalise,
					.usage = "condition <string>",
					.description = "Parse and reprint a condition, writing the normalised condition to the data buffer on success"
				}},
	{ L("count"),		&(command_entry_t){
					.func = command_count,
					.usage = "count",
					.description = "Write the number of executed tests to the data buffer.  A test is any command that should return 'ok'"
				}},
	{ L("decode-dns-label "), &(command_entry_t){
					.func = command_decode_dns_label,
					.usage = "decode-dns-label (-|<hex_string>)",
					.description = "Decode one or more DNS labels, writing the decoded strings to the data buffer.",
				}},
	{ L("decode-pair"),	&(command_entry_t){
					.func = command_decode_pair,
					.usage = "decode-pair[.<testpoint_symbol>] (-|<hex_string>)",
					.description = "Produce an attribute value pair from a binary value using a specified protocol decoder.  Protocol must be loaded with \"load <protocol>\" first",
				}},
	{ L("decode-proto"),	&(command_entry_t){
					.func = command_decode_proto,
					.usage = "decode-proto[.<testpoint_symbol>] (-|<hex string>)",
					.description = "Decode a packet as attribute value pairs from a binary value using a specified protocol decoder.  Protocol must be loaded with \"load <protocol>\" first",
				}},
	{ L("dictionary "),	&(command_entry_t){
					.func = command_dictionary_attribute_parse,
					.usage = "dictionary <string>",
					.description = "Parse dictionary attribute definition, writing \"ok\" to the data buffer if successful",
				}},
	{ L("dictionary-dump"),	&(command_entry_t){
					.func = command_dictionary_dump,
					.usage = "dictionary-dump",
					.description = "Print the contents of the currently active dictionary to stdout",
				}},
	{ L("encode-dns-label "),	&(command_entry_t){
					.func = command_encode_dns_label,
					.usage = "encode-dns-label (-|string[,string])",
					.description = "Encode one or more DNS labels, writing a hex string to the data buffer.",
				}},
	{ L("encode-pair"),	&(command_entry_t){
					.func = command_encode_pair,
					.usage = "encode-pair[.<testpoint_symbol>] [truncate] (-|<attribute> = <value>[,<attribute = <value>])",
					.description = "Encode one or more attribute value pairs, writing a hex string to the data buffer.  Protocol must be loaded with \"load <protocol>\" first",
				}},
	{ L("encode-proto"),	&(command_entry_t){
					.func = command_encode_proto,
					.usage = "encode-proto[.<testpoint_symbol>] (-|<attribute> = <value>[,<attribute = <value>])",
					.description = "Encode one or more attributes as a packet, writing a hex string to the data buffer.  Protocol must be loaded with \"proto <protocol>\" first"
				}},
	{ L("eof"),		&(command_entry_t){
					.func = command_eof,
					.usage = "eof",
					.description = "Mark the end of a 'virtual' file.  Used to prevent 'need-feature' skipping all the content of a command stream or file",
				}},
	{ L("exit"),		&(command_entry_t){
					.func = command_exit,
					.usage = "exit[ <num>]",
					.description = "Exit with the specified error number.  If no <num> is provided, process will exit with 0"
				}},
	{ L("fuzzer-out"),	&(command_entry_t){
					.func = command_fuzzer_out,
					.usage = "fuzzer-out <dir>",
					.description = "Write encode-pair, encode-proto, and encode-dns-label output, and value input as separate files in the specified directory.  Text input will be sha1 hashed and base64 encoded to create the filename",
				}},
	{ L("load-dictionary "),&(command_entry_t){
					.func = command_load_dictionary,
					.usage = "load-dictionary <name> [<dir>]",
					.description = "Load an additional dictionary from the same directory as the input file.  "
						       "Optionally you can specify a full path via <dir>.  ",
				}},
	{ L("match"),		&(command_entry_t){
					.func = command_match,
					.usage = "match <string>",
					.description = "Compare the contents of the data buffer with an expected value"
				}},
	{ L("match-regex "),	&(command_entry_t){
					.func = command_match_regex,
					.usage = "match-regex <regex>",
					.description = "Compare the contents of the data buffer with a regular expression"
				}},
	{ L("max-buffer-size"),   &(command_entry_t){
					.func = command_max_buffer_size,
					.usage = "max-buffer-size[ <integer>]",
					.description = "Limit the maximum temporary buffer space available for any command which uses it"
				}},
	{ L("migrate "),	&(command_entry_t){
					.func = command_migrate,
					.usage = "migrate <flag>=<value>",
					.description = "Set migration flag"
				}},
	{ L("need-feature "),	&(command_entry_t){
					.func = command_need_feature,
					.usage = "need-feature <feature>",
					.description = "Skip the contents of the current file, or up to the next \"eof\" command if a particular feature is not available"
				}},
	{ L("no "), 		&(command_entry_t){
					.func = command_no,
					.usage = "no ...",
					.description = "Negate the result of a command returning 'ok'"
				}},
	{ L("pair "),		&(command_entry_t){
					.func = command_pair,
					.usage = "pair ... data ...",
					.description = "Parse a list of pairs",
				}},
	{ L("pair-compare "),		&(command_entry_t){
					.func = command_pair_compare,
					.usage = "pair-compare ... data ...",
					.description = "Parse a list of pairs, allowing comparison operators",
				}},
	{ L("proto "),		&(command_entry_t){
					.func = command_proto,
					.usage = "proto <protocol>",
					.description = "Switch the active protocol to the one specified, unloading the previous protocol",
				}},
	{ L("proto-dictionary "),&(command_entry_t){
					.func = command_proto_dictionary,
					.usage = "proto-dictionary <proto_name> [<proto_dir>]",
					.description = "Switch the active dictionary.  Root is set to the default dictionary path, or the one specified with -d.  <proto_dir> is relative to the root.",
				}},


	{ L("proto-dictionary-root "), &(command_entry_t){
					.func = command_proto_dictionary_root,
					.usage = "proto-dictionary-root[ <root_attribute>]",
					.description = "Set the root attribute for the current protocol dictionary.  "
						       "If no attribute name is provided, the root will be reset to the root of the current dictionary",
				}},
	{ L("raw "),		&(command_entry_t){
					.func = command_encode_raw,
					.usage = "raw <string>",
					.description = "Create nested attributes from OID strings and values"
				}},
	{ L("read_file "),		&(command_entry_t){
					.func = command_read_file,
					.usage = "read_file <filename>",
					.description = "Read a list of pairs from a file",
				}},
	{ L("returned"),		&(command_entry_t){
					.func = command_returned,
					.usage = "returned",
					.description = "Print the returned value to the data buffer"
				}},

	{ L("tmpl "),		&(command_entry_t){
					.func = command_tmpl,
					.usage = "parse <string>",
					.description = "Parse then print a tmpl expansion, writing the normalised tmpl expansion to the data buffer"
				}},

	{ L("tmpl-rules "),	&(command_entry_t){
					.func = command_tmpl_rules,
					.usage = "tmpl-rule [allow_foreign=yes] [allow_unknown=yes|no] [allow_unresolved=yes|no] [attr_parent=<oid>] [list_def=request|reply|control|session-state] [request_def=current|outer|parent]",
					.description = "Alter the tmpl parsing rules for subsequent tmpl parsing commands in the same command context"
				}},
	{ L("touch "),		&(command_entry_t){
					.func = command_touch,
					.usage = "touch <file>",
					.description = "Touch a file, updating its created timestamp.  Useful for marking the completion of a series of tests"
				}},
	{ L("value "),		&(command_entry_t){
					.func = command_value_box_normalise,
					.usage = "value <type> <string>",
					.description = "Parse a value of a given type from its presentation form, print it, then parse it again (checking printed/parsed versions match), writing printed form to the data buffer"
				}},
	{ L("write "),		&(command_entry_t){
					.func = command_write,
					.usage = "write <file>",
					.description = "Write the contents of the data buffer (as a raw binary string) to the specified file"
				}},
	{ L("xlat "),		&(command_entry_t){
					.func = command_xlat_normalise,
					.usage = "xlat <string>",
					.description = "Parse then print an xlat expansion, writing the normalised xlat expansion to the data buffer"
				}},

	{ L("xlat_argv "),	&(command_entry_t){
					.func = command_xlat_argv,
					.usage = "xlat_argv <string>",
					.description = "Parse then print an xlat expansion argv, writing the normalised xlat expansion arguments to the data buffer"
				}},

	{ L("xlat_expr "),	&(command_entry_t){
					.func = command_xlat_expr,
					.usage = "xlat_expr <string>",
					.description = "Parse then print an xlat expression, writing the normalised xlat expansion to the data buffer"
				}},

	{ L("xlat_purify "),	&(command_entry_t){
					.func = command_xlat_purify,
					.usage = "xlat_purify <string>",
					.description = "Parse, purify, then print an xlat expression, writing the normalised xlat expansion to the data buffer"
				}},

	{ L("xlat_purify_cond "),	&(command_entry_t){
					.func = command_xlat_purify_condition,
					.usage = "xlat_purify_cond <string>",
					.description = "Parse, purify, then print an xlat condition, writing the normalised xlat expansion to the data buffer"
				}},

};
static size_t commands_len = NUM_ELEMENTS(commands);

size_t process_line(command_result_t *result, command_file_ctx_t *cc, char *data, size_t data_used,
		    char *in, UNUSED size_t inlen)
{

	command_entry_t		*command;
	size_t			match_len;
	char			*p;

	p = in;
	fr_skip_whitespace(p);

	/*
	 *	Skip empty lines and comments.
	 */
	if (!*p || (*p == '#')) {
		/*
		 *	Dump the input to the output.
		 */
		if (write_fp) {
			fputs(in, write_fp);
			fputs("\n", write_fp);
		}

		RETURN_NOOP(data_used);
	}

	DEBUG2("%s[%d]: %s", cc->filename, cc->lineno, p);

	/*
	 *	Look up the command by longest prefix
	 */
	command = fr_table_value_by_longest_prefix(&match_len, commands, p, -1, NULL);
	if (!command) {
		fr_strerror_printf("Unknown command: %s", p);
		RETURN_COMMAND_ERROR();
	}

	p += match_len;						/* Jump to after the command */
	fr_skip_whitespace(p);					/* Skip any whitespace */

	/*
	 *	Feed the data buffer in as the command
	 */
	if ((p[0] == '-') && ((p[1] == ' ') || (p[1] == '\0'))) {
		data_used = command->func(result, cc, data, data_used, data, data_used);
	}
	else {
		data_used = command->func(result, cc, data, data_used, p, strlen(p));
	}

	/*
	 *	Dump the contents of the error stack
	 *	to the data buffer.
	 *
	 *	This is then what's checked in
	 *	subsequent match commands.
	 */
	if (result->error_to_data) data_used = strerror_concat(data, COMMAND_OUTPUT_MAX);

	fr_assert((size_t)data_used < COMMAND_OUTPUT_MAX);
	data[data_used] = '\0';			/* Ensure the data buffer is \0 terminated */

	if (data_used) {
		DEBUG2("%s[%d]: --> %s (%zu bytes in buffer)", cc->filename, cc->lineno,
		       fr_table_str_by_value(command_rcode_table, result->rcode, "<INVALID>"), data_used);
	} else {
		DEBUG2("%s[%d]: --> %s", cc->filename, cc->lineno,
		       fr_table_str_by_value(command_rcode_table, result->rcode, "<INVALID>"));
	}

	/*
	 *	Dump the input to the output.
	 */
	if (write_fp) {
		fputs(in, write_fp);
		fputs("\n", write_fp);
	};

	talloc_free_children(cc->tmp_ctx);

	return data_used;
}

static int _command_ctx_free(command_file_ctx_t *cc)
{
	if (fr_dict_free(&cc->test_internal_dict, __FILE__) < 0) {
		fr_perror("unit_test_attribute");
		return -1;
	}
	if (fr_dict_global_ctx_free(cc->test_gctx) < 0) {
		fr_perror("unit_test_attribute");
		return -1;
	}
	if (cc->fuzzer_dir >= 0) {
		close(cc->fuzzer_dir);
		cc->fuzzer_dir = -1;
	}
	return 0;
}

static command_file_ctx_t *command_ctx_alloc(TALLOC_CTX *ctx,
					     command_config_t const *config, char const *path, char const *filename)
{
	command_file_ctx_t *cc;

	cc = talloc_zero(ctx, command_file_ctx_t);
	talloc_set_destructor(cc, _command_ctx_free);

	cc->tmp_ctx = talloc_named_const(ctx, 0, "tmp_ctx");
	cc->path = talloc_strdup(cc, path);
	cc->filename = filename;
	cc->config = config;

	/*
	 *	Allocate a special buffer with poisoned regions
	 *	at either end.
	 */
	if (poisoned_buffer_allocate(cc, &cc->buffer, DEFAULT_BUFFER_SIZE) < 0) {
		talloc_free(cc);
		return NULL;
	}
	cc->buffer_start = POISONED_BUFFER_START(cc->buffer);
	cc->buffer_end = POISONED_BUFFER_END(cc->buffer);

	/*
	 *	Initialise a special temporary dictionary context
	 *
	 *	Any protocol dictionaries loaded by "test-dictionary"
	 *	go in this context, and don't affect the main
	 *	dictionary context.
	 */
	cc->test_gctx = fr_dict_global_ctx_init(cc, false, cc->config->dict_dir);
	if (!cc->test_gctx) {
		fr_perror("Failed allocating test dict_gctx");
		return NULL;
	}

	fr_dict_global_ctx_set(cc->test_gctx);
	if (fr_dict_internal_afrom_file(&cc->test_internal_dict, FR_DICTIONARY_INTERNAL_DIR, __FILE__) < 0) {
		fr_perror("Failed loading test dict_gctx internal dictionary");
		return NULL;
	}

	fr_dict_global_ctx_dir_set(cc->path);	/* Load new dictionaries relative to the test file */
	fr_dict_global_ctx_set(cc->config->dict_gctx);

	cc->fuzzer_dir = -1;

	cc->tmpl_rules.attr.list_def = request_attr_request;
	cc->tmpl_rules.attr.namespace = fr_dict_root(cc->config->dict);
	cc->tmpl_rules.attr.allow_unresolved = false; /* tests have to use real attributes */

	return cc;
}

static void command_ctx_reset(command_file_ctx_t *cc, TALLOC_CTX *ctx)
{
	talloc_free(cc->tmp_ctx);
	cc->tmp_ctx = talloc_named_const(ctx, 0, "tmp_ctx");
	cc->test_count = 0;

	if (fr_dict_free(&cc->test_internal_dict, __FILE__) < 0) {
		fr_perror("unit_test_attribute");
	}

	if (fr_dict_global_ctx_free(cc->test_gctx) < 0) fr_perror("unit_test_attribute");

	cc->test_gctx = fr_dict_global_ctx_init(cc, false, cc->config->dict_dir);
	if (fr_dict_internal_afrom_file(&cc->test_internal_dict, FR_DICTIONARY_INTERNAL_DIR, __FILE__) < 0) {
		fr_perror("Failed loading test dict_gctx internal dictionary");
	}

	if (cc->fuzzer_dir >= 0) {
		close(cc->fuzzer_dir);
		cc->fuzzer_dir = -1;
	}
}

static int process_file(bool *exit_now, TALLOC_CTX *ctx, command_config_t const *config,
			const char *root_dir, char const *filename, fr_dlist_head_t *lines)
{
	int		ret = 0;
	FILE		*fp;				/* File we're reading from */
	char		buffer[8192];			/* Command buffer */
	char		data[COMMAND_OUTPUT_MAX + 1];	/* Data written by previous command */
	ssize_t		data_used = 0;			/* How much data the last command wrote */
	static char	path[PATH_MAX] = "";
	command_line_range_t	*lr = NULL;
	bool		opened_fp = false;

	command_file_ctx_t	*cc;

	cc = command_ctx_alloc(ctx, config, root_dir, filename);

	/*
	 *	Open the file, or stdin
	 */
	if (strcmp(filename, "-") == 0) {
		fp = stdin;
		filename = "<stdin>";
		fr_assert(!root_dir);

	} else {
		if (root_dir && *root_dir) {
			snprintf(path, sizeof(path), "%s/%s", root_dir, filename);
		} else {
			strlcpy(path, filename, sizeof(path));
		}

		fp = fopen(path, "r");
		if (!fp) {
			ERROR("Error opening test file \"%s\": %s", path, fr_syserror(errno));
			ret = -1;
			goto finish;
		}

		filename = path;
		opened_fp = true;
	}

	if (lines && !fr_dlist_empty(lines)) lr = fr_dlist_head(lines);

	/*
	 *	Loop over lines in the file or stdin
	 */
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		command_result_t	result = { .rcode = RESULT_OK };	/* Reset to OK */
		char			*p = strchr(buffer, '\n');

		fr_strerror_clear();
		cc->lineno++;	/* The first line of the file becomes line 1 */

		if (lr) {
			if (cc->lineno > lr->end) {
				lr = fr_dlist_next(lines, lr);
				if (!lr) goto finish;
			}

			if (cc->lineno < lr->start) continue;
		}

		if (!p) {
			if (!feof(fp)) {
				ERROR("Line %d too long in %s/%s", cc->lineno, cc->path, cc->filename);
				ret = -1;
				goto finish;
			}
		} else {
			*p = '\0';
		}

		data_used = process_line(&result, cc, data, data_used, buffer, strlen(buffer));
		switch (result.rcode) {
		/*
		 *	Command completed successfully
		 */
		case RESULT_OK:
			cc->test_count++;
			continue;

		/*
		 *	Did nothing (not a test)
		 */
		case RESULT_NOOP:
			continue;

		/*
		 *	If this is a file, then break out of the loop
		 *	and cleanup, otherwise we need to find the
		 *	EOF marker in the input stream.
		 */
		case RESULT_SKIP_FILE:
			if (fp != stdin) goto finish;

			/*
			 *	Skip over the input stream until we
			 *	find an eof command, or the stream
			 *	is closed.
			 */
			while (fgets(buffer, sizeof(buffer), fp) != NULL) {
				command_entry_t	*command;
				size_t		match_len;

				command = fr_table_value_by_longest_prefix(&match_len, commands, buffer, -1, NULL);
				if (!command) {
					ERROR("%s[%d]: Unknown command: %s", cc->path, cc->lineno, p);
					ret = -1;
					goto finish;
				}

				if (command->func == command_eof) {
					command_ctx_reset(cc, ctx);
					break;
				}
			}
			goto finish;

		/*
		 *	Fatal error parsing a command
		 */
		case RESULT_PARSE_ERROR:
		case RESULT_COMMAND_ERROR:
			fr_perror("%s[%d]", filename, cc->lineno);
			ret = -1;
			goto finish;

		/*
		 *	Result didn't match what we expected
		 */
		case RESULT_MISMATCH:
		{
			ret = EXIT_FAILURE;
			goto finish;
		}

		case RESULT_EXIT:
			ret = result.ret;
			*exit_now = true;
			goto finish;

		default:
			/*
			 *	If this happens, fix the damn command.
			 */
			fr_assert_msg(false, "Command exited with invalid return code (%i)", result.rcode);
			ret = -1;
			goto finish;
		}
	}

finish:
	/* The explicit check is to quiet clang_analyzer */
	if (opened_fp) fclose(fp);

	/*
	 *	Free any residual resources we loaded.
	 */
	if (cc && (fr_dict_const_free(&cc->tmpl_rules.attr.dict_def, __FILE__) < 0)) {
		fr_perror("unit_test_attribute");
		ret = -1;
	}

	fr_dict_global_ctx_set(config->dict_gctx);	/* Switch back to the main dict ctx */
	unload_proto_library();
	talloc_free(cc);

	return ret;
}

static void usage(char const *name)
{
	INFO("usage: %s [options] (-|<filename>[:<lines>] [ <filename>[:<lines>]])", name);
	INFO("options:");
	INFO("  -d <confdir>       Set user dictionary path (defaults to " CONFDIR ").");
	INFO("  -D <dictdir>       Set main dictionary path (defaults to " DICTDIR ").");
	INFO("  -x                 Debugging mode.");
	INFO("  -f                 Print features.");
	INFO("  -c                 Print commands.");
	INFO("  -h                 Print help text.");
	INFO("  -M                 Show talloc memory report.");
	INFO("  -p                 Allow xlat_purify");
	INFO("  -r <receipt_file>  Create the <receipt_file> as a 'success' exit.");
	INFO("  -w <output_file>   Write 'corrected' output to <output_file>.");
	INFO("Where <filename> is a file containing one or more commands and '-' indicates commands should be read from stdin.");
	INFO("Ranges of <lines> may be specified in the format <start>[-[<end>]][,]");
}

static void features_print(CONF_SECTION *features)
{
	CONF_PAIR *cp;

	INFO("features:");
	for (cp = cf_pair_find(features, CF_IDENT_ANY);
	     cp;
	     cp = cf_pair_find_next(features, cp, CF_IDENT_ANY)) {
		INFO("  %s %s", cf_pair_attr(cp), cf_pair_value(cp));
	}
}

static void commands_print(void)
{
	size_t i;

	INFO("commands:");
	for (i = 0; i < commands_len; i++) {
		INFO("  %s:", ((command_entry_t const *)commands[i].value)->usage);
		INFO("    %s.", ((command_entry_t const *)commands[i].value)->description);
		INFO("%s", "");
	}
}

static int line_ranges_parse(TALLOC_CTX *ctx, fr_dlist_head_t *out, fr_sbuff_t *in)
{
	static bool		tokens[UINT8_MAX + 1] = { [','] = true , ['-'] = true };
	uint32_t		max = 0;
	command_line_range_t	*lr;
	fr_sbuff_parse_error_t	err;

	while (fr_sbuff_extend(in)) {
		fr_sbuff_adv_past_whitespace(in, SIZE_MAX, NULL);

		MEM(lr = talloc_zero(ctx, command_line_range_t));
		fr_dlist_insert_tail(out, lr);

		fr_sbuff_out(&err, &lr->start, in);
		if (err != FR_SBUFF_PARSE_OK) {
			ERROR("Invalid line start number");
		error:
			fr_dlist_talloc_free(out);
			return -1;
		}
		if (max > lr->start) {
			ERROR("Out of order line numbers (%u > %u) not allowed", max, lr->start);
			goto error;
		} else {
			max = lr->start;
		}
		lr->end = lr->start;	/* Default to a single line */
		fr_sbuff_adv_past_whitespace(in, SIZE_MAX, NULL);

	again:
		if (!fr_sbuff_extend(in)) break;
		if (!fr_sbuff_is_in_charset(in, tokens)) {
			ERROR("Unexpected text \"%pV\"",
			      fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));
			goto error;
		}

		fr_sbuff_switch(in, '\0') {
		/*
		 *	More ranges...
		 */
		case ',':
			fr_sbuff_next(in);
			fr_sbuff_adv_past_whitespace(in, SIZE_MAX, NULL);
			continue;

		/*
		 *	<start>-<end>
		 */
		case '-':
		{
			fr_sbuff_next(in);
			fr_sbuff_adv_past_whitespace(in, SIZE_MAX, NULL);

			/*
			 *	A bare '-' with no number means
			 *	run all remaining lines.
			 */
			if (fr_sbuff_extend(in) == 0) {
				lr->end = UINT32_MAX;
				return 0;
			}

			fr_sbuff_out(&err, &lr->end, in);
			if (err != FR_SBUFF_PARSE_OK) {
				ERROR("Invalid line end number");
				goto error;
			}
			if (lr->end < lr->start) {
				ERROR("Line end must be >= line start (%u < %u)", lr->end, lr->start);
				goto error;
			}
			if (max > lr->end) {
				ERROR("Out of order line numbers (%u > %u) not allowed", max, lr->end);
				goto error;
			} else {
				max = lr->end;
			}
			fr_sbuff_adv_past_whitespace(in, SIZE_MAX, NULL);
		}
			goto again;
		}
	}

	return 0;
}

static int process_path(bool *exit_now, TALLOC_CTX *ctx, command_config_t const *config, const char *path)
{
	char			*p, *dir = NULL, *file;
	int			ret = EXIT_SUCCESS;
	fr_sbuff_t		in = FR_SBUFF_IN(path, strlen(path));
	fr_sbuff_term_t		dir_sep = FR_SBUFF_TERMS(
		L("/"),
		L(":")
		);
	fr_sbuff_marker_t	file_start, file_end, dir_end;
	fr_dlist_head_t		lines;

	fr_sbuff_marker(&file_start, &in);
	fr_sbuff_marker(&file_end, &in);
	fr_sbuff_marker(&dir_end, &in);
	fr_sbuff_set(&file_end, fr_sbuff_end(&in));

	fr_dlist_init(&lines, command_line_range_t, entry);

	while (fr_sbuff_extend(&in)) {
		fr_sbuff_adv_until(&in, SIZE_MAX, &dir_sep, '\0');

		fr_sbuff_switch(&in, '\0') {
			case '/':
				fr_sbuff_set(&dir_end, &in);
				fr_sbuff_advance(&in, 1);
				fr_sbuff_set(&file_start, &in);
				break;

				case ':':
					fr_sbuff_set(&file_end, &in);
					fr_sbuff_advance(&in, 1);
					if (line_ranges_parse(ctx, &lines, &in) < 0) {
						return EXIT_FAILURE;
					}
					break;

					default:
						fr_sbuff_set(&file_end, &in);
						break;
		}
	}

	file = talloc_bstrndup(ctx,
			       fr_sbuff_current(&file_start), fr_sbuff_diff(&file_end, &file_start));
	if (fr_sbuff_used(&dir_end)) dir = talloc_bstrndup(ctx,
							   fr_sbuff_start(&in),
							   fr_sbuff_used(&dir_end));

	/*
	 *	Do things so that GNU Make does less work.
	 */
	if ((receipt_dir || receipt_file) &&
	    (strncmp(path, "src/tests/unit/", 15) == 0)) {
		p = strchr(path + 15, '/');
		if (!p) {
			printf("UNIT-TEST %s\n", path + 15);
		} else {
			char *q = strchr(p + 1, '/');

			*p = '\0';

			if (!q) {
				printf("UNIT-TEST %s - %s\n", path + 15, p + 1);
			} else {
				*q = '\0';

				printf("UNIT-TEST %s - %s\n", p + 1, q + 1);
				*q = '/';
			}

			*p = '/';
		}
	}

	/*
	 *	Rewrite this file if requested.
	 */
	if (write_filename) {
		write_fp = fopen(write_filename, "w");
		if (!write_fp) {
			ERROR("Failed opening %s: %s", write_filename, strerror(errno));
			return EXIT_FAILURE;
		}
	}

	ret = process_file(exit_now, ctx, config, dir, file, &lines);

	if ((ret == EXIT_SUCCESS) && receipt_dir && dir) {
		char *touch_file, *subdir;

		if (strncmp(dir, "src/", 4) == 0) {
			subdir = dir + 4;
		} else {
			subdir = dir;
		}

		touch_file = talloc_asprintf(ctx, "build/%s/%s", subdir, file);
		fr_assert(touch_file);

		p = strchr(touch_file, '/');
		fr_assert(p);

		if (fr_mkdir(NULL, touch_file, (size_t) (p - touch_file), S_IRWXU, NULL, NULL) < 0) {
			fr_perror("unit_test_attribute - failed to make directory %.*s - ",
				  (int) (p - touch_file), touch_file);
fail:
			if (write_fp) fclose(write_fp);
			return EXIT_FAILURE;
		}

		if (fr_touch(NULL, touch_file, 0644, true, 0755) <= 0) {
			fr_perror("unit_test_attribute - failed to create receipt file %s - ",
				  touch_file);
			goto fail;
		}

		talloc_free(touch_file);
	}

	talloc_free(dir);
	talloc_free(file);
	fr_dlist_talloc_free(&lines);

	if (ret != EXIT_SUCCESS) {
		if (write_fp) {
			fclose(write_fp);
			write_fp = NULL;
		}
		fail_file = path;
	}

	if (write_fp) {
		fclose(write_fp);
		if (rename(write_filename, path) < 0) {
			ERROR("Failed renaming %s: %s", write_filename, strerror(errno));
			return EXIT_FAILURE;
		}
	}

	return ret;
}

/**
 *
 * @hidecallgraph
 */
int main(int argc, char *argv[])
{
	int			c;
	CONF_SECTION		*cs;
	int			ret = EXIT_SUCCESS;
	TALLOC_CTX		*autofree;
	TALLOC_CTX		*thread_ctx;
	bool			exit_now = false;

	command_config_t	config = {
					.confdir = CONFDIR,
					.dict_dir = DICTDIR
				};

	char const		*name;
	bool			do_features = false;
	bool			do_commands = false;
	bool			do_usage = false;
	xlat_t			*xlat;
	char			*p;
	char const		*error_str = NULL, *fail_str = NULL;

	/*
	 *	Must be called first, so the handler is called last
	 */
	fr_atexit_global_setup();

	autofree = talloc_autofree_context();
	thread_ctx = talloc_new(autofree);

#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("unit_test_attribute");
		goto cleanup;
	}
#else
	fr_disable_null_tracking_on_free(autofree);
#endif

	/*
	 *	Sync wallclock and cpu time so that we can find
	 *	uses of fr_time_[to|from]_* where
	 *	fr_unix_time_[to|from]_* should be used.
	 *
	 *	If the wallclock/cpu offset is 0, then both sets
	 *	of macros produce the same result.
	 */
	fr_time_start();

	/*
	 *	Allocate a root config section so we can write
	 *	out features and versions.
	 */
	MEM(cs = cf_section_alloc(autofree, NULL, "unit_test_attribute", NULL));
	MEM(config.features = cf_section_alloc(cs, cs, "feature", NULL));
	dependency_features_init(config.features);	/* Add build time features to the config section */

	name = argv[0];

	default_log.dst = L_DST_STDOUT;
	default_log.fd = STDOUT_FILENO;
	default_log.print_level = false;

	while ((c = getopt(argc, argv, "cd:D:F:fxMhpr:S:w:")) != -1) switch (c) {
		case 'c':
			do_commands = true;
			break;

		case 'd':
			config.confdir = optarg;
			break;

		case 'D':
			config.dict_dir = optarg;
			break;

		case 'F':
			config.fuzzer_dir = optarg;
			break;

		case 'f':
			do_features = true;
			break;

		case 'x':
			fr_debug_lvl++;
			if (fr_debug_lvl > 2) default_log.print_level = true;
			break;

		case 'M':
			talloc_enable_leak_report();
			break;

		case 'r':
			p = strrchr(optarg, '/');
			if (!p || p[1]) {
				receipt_file = optarg;

				if ((fr_unlink(receipt_file) < 0)) {
					fr_perror("unit_test_attribute");
					EXIT_WITH_FAILURE;
				}

			} else {
				receipt_dir = optarg;
			}
			break;

		case 'p':
			allow_purify = true;
			break;

		case 'S':
			fprintf(stderr, "Invalid option to -S\n");
			EXIT_WITH_FAILURE;

		case 'w':
			write_filename = optarg;
			break;

		case 'h':
		default:
			do_usage = true;	/* Just set a flag, so we can process extra -x args */
			break;
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	if (do_usage) usage(name);
	if (do_features) features_print(config.features);
	if (do_commands) commands_print();
	if (do_usage || do_features || do_commands) {
		ret = EXIT_SUCCESS;
		goto cleanup;
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

#ifdef WITH_TLS
	/*
	 *	OpenSSL can only be initialised once during the lifetime
	 *	of a process.  Initialise it here so that we don't attempt
	 *	to unload and load it multiple times.
	 */
	if (fr_openssl_init() < 0) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}
#endif

	modules_init(NULL);

	dl_loader = dl_loader_init(autofree, NULL, false, false);
	if (!dl_loader) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

	config.dict_gctx = fr_dict_global_ctx_init(NULL, true, config.dict_dir);
	if (!config.dict_gctx) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_internal_afrom_file(&config.dict, FR_DICTIONARY_INTERNAL_DIR, __FILE__) < 0) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Always needed so we can load the list attributes
	 *	otherwise the tmpl_tokenize code fails.
	 */
	if (request_global_init() < 0) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Initialise the interpreter, registering operations.
	 *	Needed because some keywords also register xlats.
	 */
	if (unlang_global_init() < 0) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Create a dummy event list
	 */
	if (allow_purify) {
		el = fr_event_list_alloc(autofree, NULL, NULL);
		fr_assert(el != NULL);

		/*
		 *	Simulate thread specific instantiation
		 */
		if (xlat_instantiate() < 0) EXIT_WITH_FAILURE;
		if (xlat_thread_instantiate(thread_ctx, el) < 0) EXIT_WITH_FAILURE;
	}

	unlang_thread_instantiate(thread_ctx);

	xlat = xlat_func_register(NULL, "test", xlat_test, FR_TYPE_NULL);
	if (!xlat) {
		ERROR("Failed registering xlat");
		EXIT_WITH_FAILURE;
	}
	xlat_func_args_set(xlat, xlat_test_args);

	/*
	 *	And again WITHOUT arguments.
	 */
	xlat = xlat_func_register(NULL, "test_no_args", xlat_test, FR_TYPE_NULL);
	if (!xlat) {
		ERROR("Failed registering xlat");
		EXIT_WITH_FAILURE;
	}
	xlat_func_args_set(xlat, xlat_test_no_args);

	/*
	 *	Disable hostname lookups, so we don't produce spurious DNS
	 *	queries, and there's no chance of spurious failures if
	 *	it takes a long time to get a response.
	 */
	fr_hostname_lookups = fr_reverse_lookups = false;

	/*
	 *	Read test commands from stdin
	 */
	if ((argc < 2) && !receipt_dir) {
		if (write_filename) {
			ERROR("Can only use '-w' with input files");
			EXIT_WITH_FAILURE;
		}

		ret = process_file(&exit_now, autofree, &config, NULL, "-", NULL);

	} else if ((argc == 2) && (strcmp(argv[1], "-") == 0)) {
			char buffer[1024];

			/*
			 *	Read the list of filenames from stdin.
			 */
			while (fgets(buffer, sizeof(buffer) - 1, stdin) != NULL) {
				buffer[sizeof(buffer) - 1] = '\0';

				p = buffer;
				while (isspace((unsigned int) *p)) p++;

				if (!*p || (*p == '#')) continue;

				name = p;

				/*
				 *	Smash CR/LF.
				 *
				 *	Note that we don't care about truncated filenames.  The code below
				 *	will complain that it can't open the file.
				 */
				while (*p) {
					if (*p < ' ') {
						*p = '\0';
						break;
					}

					p++;
				}

				ret = process_path(&exit_now, autofree, &config, name);
				if ((ret != EXIT_SUCCESS) || exit_now) break;
			}

	} else if (argc > 1) {
		int i;

		/*
		 *	Read test commands from a list of files in argv[].
		 */
		for (i = 1; i < argc; i++) {
			ret = process_path(&exit_now, autofree, &config, argv[i]);
			if ((ret != EXIT_SUCCESS) || exit_now) break;
		}
	} /* nothing to do */

	/*
	 *	Try really hard to free any allocated
	 *	memory, so we get clean talloc reports.
	 */
cleanup:
#undef EXIT_WITH_FAILURE
#define EXIT_WITH_FAILURE \
do { \
	ret = EXIT_FAILURE; \
	error_str = fr_strerror(); \
	if (error_str) error_str = talloc_strdup(NULL, error_str); \
	goto fail; \
} while (0)

	/*
	 *	Ensure all thread local memory is cleaned up
	 *	at the appropriate time.  This emulates what's
	 *	done with worker/network threads in the
	 *	scheduler.
	 */
	fr_atexit_thread_trigger_all();

#ifdef WITH_TLS
	fr_openssl_free();
#endif

	/*
	 *	dl_loader check needed as talloc_free
	 *	returns -1 on failure.
	 */
	if (dl_loader && (talloc_free(dl_loader) < 0)) {
		fail_str = "cleaning up dynamically loaded libraries";
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_free(&config.dict, __FILE__) < 0) {
		fail_str = "cleaning up dictionaries";
		EXIT_WITH_FAILURE;
	}

	if (receipt_file && (ret == EXIT_SUCCESS) && (fr_touch(NULL, receipt_file, 0644, true, 0755) <= 0)) {
		fail_str = "creating receipt file";
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Explicitly free the autofree context
	 *	to make errors less confusing.
	 */
	if (talloc_free(autofree) < 0) {
		fail_str = "cleaning up all memory";
		EXIT_WITH_FAILURE;
	}

	if (ret != EXIT_SUCCESS) {
	fail:
		if (!fail_str) fail_str = "in an input file";
		if (!error_str) error_str = "";

		fprintf(stderr, "unit_test_attribute failed %s - %s\n", fail_str, error_str);

		/*
		 *	Print any command needed to run the test from the command line.
		 */
		p = getenv("UNIT_TEST_ATTRIBUTE");
		if (p) printf("%s %s\n", p, fail_file);
	}


	/*
	 *	Ensure our atexit handlers run before any other
	 *	atexit handlers registered by third party libraries.
	 */
	fr_atexit_global_trigger_all();

	return ret;
}
