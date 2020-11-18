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

#include <freeradius-devel/util/base.h>

typedef struct request_s request_t;

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/command.h>
#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/server/dependency.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/unlang/xlat.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/conf.h>

#include <ctype.h>

#ifdef HAVE_SANITIZER_LSAN_INTERFACE_H
#  include <sanitizer/asan_interface.h>
#endif

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <assert.h>
#include <libgen.h>
#include <limits.h>
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
	char const		*raddb_dir;
	char const		*dict_dir;
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

static ssize_t xlat_test(UNUSED TALLOC_CTX *ctx, UNUSED char **out, UNUSED size_t outlen,
			 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 UNUSED request_t *request, UNUSED char const *fmt)
{
	return 0;
}

static char		proto_name_prev[128];
static dl_t		*dl;
static dl_loader_t	*dl_loader;

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
	char *spaces;

	ERROR("%s failed at line %d of %s/%s", command, cc->lineno, cc->path, cc->filename);
	ERROR("  got      : %.*s", (int) got_len, got);
	ERROR("  expected : %.*s", (int) expected_len, expected);

	if (print_diff) {
		g = got;
		e = expected;

		while (*g && *e && (*g == *e)) {
			g++;
			e++;
		}

		spaces = talloc_zero_array(NULL, char, (e - expected) + 1);
		memset(spaces, ' ', talloc_array_length(spaces) - 1);
		ERROR("             %s^ differs here", spaces);
		talloc_free(spaces);
	}
}

/** Print hex string to buffer
 *
 */
static inline size_t hex_print(char *out, size_t outlen, uint8_t const *in, size_t inlen) CC_HINT(nonnull);

static inline size_t hex_print(char *out, size_t outlen, uint8_t const *in, size_t inlen)
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
			fr_strerror_printf("Would overflow output buffer");
			return -(p - in);
		}

		fr_skip_whitespace(p);

		if (!*p) break;

		c1 = memchr(hextab, tolower((int) *p++), sizeof(hextab));
		if (!c1) {
		bad_input:
			fr_strerror_printf("Invalid hex data starting at \"%s\"", p);
			return -(p - in);
		}

		c2 = memchr(hextab, tolower((int)*p++), sizeof(hextab));
		if (!c2) goto bad_input;

		*out_p++ = ((c1 - hextab) << 4) + (c2 - hextab);
	}

	return out_p - out;
}


static ssize_t encode_data(char *p, uint8_t *output, size_t outlen)
{
	ssize_t slen;

	if (!isspace((int) *p)) {
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
		fr_strerror_printf_push("Empty hex string");
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

/** Common dictionary load function
 *
 * Callers call fr_dict_global_ctx_set to set the context
 * the dictionaries will be loaded into.
 */
static int dictionary_load_common(command_result_t *result, command_file_ctx_t *cc, char *in, char const *default_subdir)
{
	char		*name, *tmp = NULL;
	char const	*dir;
	char		*q;
	int		ret;
	fr_dict_t	*dict;

	if (in[0] == '\0') {
		fr_strerror_printf("Missing dictionary name");
		RETURN_PARSE_ERROR(0);
	}

	/*
	 *	Decrease ref count if we're loading in a new dictionary
	 */
	if (cc->tmpl_rules.dict_def) fr_dict_const_free(&cc->tmpl_rules.dict_def);

	q = strchr(in, ' ');
	if (q) {
		name = tmp = talloc_bstrndup(NULL, in, q - in);
		q++;
		dir = q;
	} else {
		name = in;
		dir = default_subdir;
	}

	ret = fr_dict_protocol_afrom_file(&dict, name, dir);
	cc->tmpl_rules.dict_def = dict;
	talloc_free(tmp);
	if (ret < 0) RETURN_COMMAND_ERROR();

	/*
	 *	Dump the dictionary if we're in super debug mode
	 */
	if (fr_debug_lvl > 5) fr_dict_debug(cc->tmpl_rules.dict_def);

	RETURN_OK(0);
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
	fr_command_debug(stdout, command_head);

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

/** Determine if unresolved atttributes are allowed
 *
 */
static size_t command_allow_unresolved(command_result_t *result, command_file_ctx_t *cc,
				       UNUSED char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	fr_sbuff_t	our_in = FR_SBUFF_IN(in, inlen);

	if (fr_sbuff_out_bool(&cc->tmpl_rules.allow_unresolved, &our_in) == 0) {
		fr_strerror_printf("Invalid boolean value, must be \"yes\" or \"no\"");
		RETURN_COMMAND_ERROR();
	}

	RETURN_OK(0);
}

/** Parse an print an attribute pair
 *
 */
static size_t command_normalise_attribute(command_result_t *result, command_file_ctx_t *cc,
					  char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	fr_pair_list_t 	head;
	ssize_t		slen;

	fr_pair_list_init(&head);

	if (fr_pair_list_afrom_str(NULL, cc->tmpl_rules.dict_def ? cc->tmpl_rules.dict_def : cc->config->dict, in, &head) != T_EOL) {
		RETURN_OK_WITH_ERROR();
	}

	slen = fr_pair_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), head);
	talloc_list_free(&head);

	if (slen < 0) {
		fr_strerror_printf("Encoder output would overflow output buffer");
		RETURN_OK_WITH_ERROR();
	}

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

	table = talloc_zero(cc->tmp_ctx, fr_cmd_table_t);

	p = strchr(in, ':');
	if (!p) {
		fr_strerror_printf("no ':name' specified");
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

	if (isspace(*p)) {
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
		fr_strerror_printf_push("ERROR: Failed adding command");
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
		fr_strerror_printf("Failed splitting input");
		RETURN_PARSE_ERROR(-(info.argc));
	}

	num_expansions = fr_command_tab_expand(cc->tmp_ctx, command_head, &info, CMD_MAX_ARGV, expansions);

	len = snprintf(p, end - p, "%d - ", num_expansions);
	if (is_truncated(len, end - p)) {
	oob:
		fr_strerror_printf("Out of output buffer space");
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
	ssize_t			dec_len;
	fr_cond_t		*cond;
	CONF_SECTION		*cs;
	size_t			len;

	cs = cf_section_alloc(NULL, NULL, "if", "condition");
	if (!cs) {
		fr_strerror_printf("Out of memory");
		RETURN_COMMAND_ERROR();
	}
	cf_filename_set(cs, cc->filename);
	cf_lineno_set(cs, cc->lineno);

	dec_len = fr_cond_tokenize(cs, &cond,
				   cc->tmpl_rules.dict_def ? cc->tmpl_rules.dict_def : cc->config->dict,
				   &FR_SBUFF_IN(in, inlen));
	if (dec_len <= 0) {
		fr_strerror_printf_push_head("ERROR offset %d", (int) -dec_len);

	return_error:
		talloc_free(cs);
		RETURN_OK_WITH_ERROR();
	}

	if (fr_debug_lvl > DEBUG_ENABLED3) {
		if (cond->type == COND_TYPE_MAP) {
			if (cond->data.map->lhs) tmpl_debug(cond->data.map->lhs);
			if (cond->data.map->rhs) tmpl_debug(cond->data.map->rhs);
		}
	}

	in += dec_len;
	if (*in != '\0') {
		fr_strerror_printf_push_head("ERROR offset %d 'Too much text'", (int) dec_len);
		goto return_error;
	}

	len = cond_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), cond);
	talloc_free(cs);

	RETURN_OK(len);
}

static size_t command_count(command_result_t *result, command_file_ctx_t *cc,
			    char *data, UNUSED size_t data_used, UNUSED char *in, UNUSED size_t inlen)
{
	size_t		len;

	len = snprintf(data, COMMAND_OUTPUT_MAX, "%u", cc->test_count);
	if (is_truncated(len, COMMAND_OUTPUT_MAX)) {
		fr_strerror_printf("Command count would overflow data buffer (shouldn't happen)");
		RETURN_COMMAND_ERROR();
	}

	RETURN_OK(len);
}

static size_t command_decode_pair(command_result_t *result, command_file_ctx_t *cc,
				  char *data, size_t data_used, char *in, size_t inlen)
{
	fr_test_point_pair_decode_t	*tp = NULL;
	fr_cursor_t 	cursor;
	void		*decoder_ctx = NULL;
	char		*p, *end;
	uint8_t		*to_dec;
	uint8_t		*to_dec_end;
	fr_pair_list_t	head;
	fr_pair_t	*vp;
	ssize_t		slen;

	fr_pair_list_init(&head);
	p = in;

	slen = load_test_point_by_command((void **)&tp, in, "tp_decode_pair");
	if (!tp) {
		fr_strerror_printf_push("Failed locating decoder testpoint");
		RETURN_COMMAND_ERROR();
	}

	p += slen;
	fr_skip_whitespace(p);

	if (tp->test_ctx && (tp->test_ctx(&decoder_ctx, cc->tmp_ctx) < 0)) {
		fr_strerror_printf_push("Failed initialising decoder testpoint");
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
	fr_cursor_init(&cursor, &head);
	while (to_dec < to_dec_end) {
		slen = tp->func(cc->tmp_ctx, &cursor, cc->tmpl_rules.dict_def ? cc->tmpl_rules.dict_def : cc->config->dict,
				(uint8_t *)to_dec, (to_dec_end - to_dec), decoder_ctx);
		cc->last_ret = slen;
		if (slen <= 0) {
			fr_pair_list_free(&head);
			ASAN_UNPOISON_MEMORY_REGION(to_dec_end, COMMAND_OUTPUT_MAX - slen);
			CLEAR_TEST_POINT(cc);
			RETURN_OK_WITH_ERROR();
		}
		if ((size_t)slen > (size_t)(to_dec_end - to_dec)) {
			fr_perror("Internal sanity check failed at %d", __LINE__);
			ASAN_UNPOISON_MEMORY_REGION(to_dec_end, COMMAND_OUTPUT_MAX - slen);
			CLEAR_TEST_POINT(cc);
			RETURN_COMMAND_ERROR();
		}
		to_dec += slen;
	}

	/*
	 *	Clear any spurious errors
	 */
	fr_strerror();
	ASAN_UNPOISON_MEMORY_REGION(to_dec_end, COMMAND_OUTPUT_MAX - slen);

	/*
	 *	Set p to be the output buffer
	 */
	p = data;
	end = p + COMMAND_OUTPUT_MAX;

	/*
	 *	Output may be an error, and we ignore
	 *	it if so.
	 */
	if (head) {
		fr_cursor_init(&cursor, &head);

		for (vp = fr_cursor_head(&cursor);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			if ((slen = fr_pair_print(&FR_SBUFF_OUT(p, end), vp)) < 0) {
			oob:
				fr_strerror_printf("Out of output buffer space");
				CLEAR_TEST_POINT(cc);
				RETURN_COMMAND_ERROR();
			}
			p += slen;

			if (fr_cursor_next_peek(&cursor)) {
				slen = strlcpy(p, ", ", end - p);
				if (is_truncated((size_t)slen, end - p)) goto oob;
				p += slen;
			}
		}
		fr_pair_list_free(&head);
	} else { /* zero-length to_decibute */
		*p = '\0';
	}

	CLEAR_TEST_POINT(cc);
	RETURN_OK(p - data);
}

static size_t command_decode_proto(command_result_t *result, command_file_ctx_t *cc,
				  char *data, size_t data_used, char *in, size_t inlen)
{
	fr_test_point_proto_decode_t	*tp = NULL;
	fr_cursor_t 	cursor;
	void		*decoder_ctx = NULL;
	char		*p, *end;
	uint8_t		*to_dec;
	uint8_t		*to_dec_end;
	fr_pair_list_t	head;
	fr_pair_t	*vp;
	ssize_t		slen;

	p = in;
	fr_pair_list_init(&head);

	slen = load_test_point_by_command((void **)&tp, in, "tp_decode_proto");
	if (!tp) {
		fr_strerror_printf_push("Failed locating decoder testpoint");
		RETURN_COMMAND_ERROR();
	}

	p += slen;
	fr_skip_whitespace(p);

	if (tp->test_ctx && (tp->test_ctx(&decoder_ctx, cc->tmp_ctx) < 0)) {
		fr_strerror_printf_push("Failed initialising decoder testpoint");
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

	slen = tp->func(cc->tmp_ctx, &head,
			(uint8_t *)to_dec, (to_dec_end - to_dec), decoder_ctx);
	cc->last_ret = slen;
	if (slen <= 0) {
		ASAN_UNPOISON_MEMORY_REGION(to_dec_end, COMMAND_OUTPUT_MAX - slen);
		fr_pair_list_free(&head);
		CLEAR_TEST_POINT(cc);
		RETURN_OK_WITH_ERROR();
	}

	/*
	 *	Clear any spurious errors
	 */
	fr_strerror();
	ASAN_UNPOISON_MEMORY_REGION(to_dec_end, COMMAND_OUTPUT_MAX - slen);

	/*
	 *	Set p to be the output buffer
	 */
	p = data;
	end = p + COMMAND_OUTPUT_MAX;

	/*
	 *	Output may be an error, and we ignore
	 *	it if so.
	 */
	if (head) {
		fr_cursor_init(&cursor, &head);

		for (vp = fr_cursor_head(&cursor);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			if ((slen = fr_pair_print(&FR_SBUFF_OUT(p, end), vp)) < 0) {
			oob:
				fr_strerror_printf("Out of output buffer space");
				CLEAR_TEST_POINT(cc);
				RETURN_COMMAND_ERROR();
			}
			p += slen;

			if (fr_cursor_next_peek(&cursor)) {
				slen = strlcpy(p, ", ", end - p);
				if (is_truncated((size_t)slen, end - p)) goto oob;
				p += slen;
			}
		}
		fr_pair_list_free(&head);
	} else { /* zero-length to_decibute */
		*p = '\0';
	}

	CLEAR_TEST_POINT(cc);
	RETURN_OK(p - data);
}

/** Parse a dictionary attribute, writing "ok" to the data buffer is everything was ok
 *
 */
static size_t command_dictionary_attribute_parse(command_result_t *result, command_file_ctx_t *cc,
					  	 char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	if (fr_dict_parse_str(cc->config->dict, in, fr_dict_root(cc->config->dict)) < 0) RETURN_OK_WITH_ERROR();

	RETURN_OK(strlcpy(data, "ok", COMMAND_OUTPUT_MAX));
}

/** Print the currently loaded dictionary
 *
 */
static size_t command_dictionary_dump(command_result_t *result, command_file_ctx_t *cc,
				      UNUSED char *data, size_t data_used, UNUSED char *in, UNUSED size_t inlen)
{
	fr_dict_debug(cc->tmpl_rules.dict_def ? cc->tmpl_rules.dict_def : cc->config->dict);

	/*
	 *	Don't modify the contents of the data buffer
	 */
	RETURN_OK(data_used);
}

static size_t command_encode_dns_label(command_result_t *result, command_file_ctx_t *cc,
				       char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	size_t		need;
	ssize_t		ret;
	char		*p, *next;
	uint8_t		*enc_p;

	p = in;
	next = strchr(p, ',');
	if (next) *next = 0;

	enc_p = cc->buffer_start;

	while (p) {
		fr_type_t type = FR_TYPE_STRING;
		fr_value_box_t *box = talloc_zero(NULL, fr_value_box_t);

		fr_skip_whitespace(p);

		if (fr_value_box_from_str(box, box, &type, NULL, p, -1, '"', false) < 0) {
			talloc_free(box);
			RETURN_OK_WITH_ERROR();
		}

		ret = fr_dns_label_from_value_box(&need,
						  cc->buffer_start, cc->buffer_end - cc->buffer_start, enc_p, true, box);
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
		slen = fr_dns_label_to_value_box(box, box, cc->buffer_start, total, cc->buffer_start + i, false);
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
				  char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	fr_test_point_pair_encode_t	*tp = NULL;

	fr_cursor_t	cursor;
	void		*encoder_ctx = NULL;
	ssize_t		slen;
	char		*p = in;

	uint8_t		*enc_p, *enc_end;
	fr_pair_list_t	head;
	fr_pair_t	*vp;
	bool		truncate = false;

	size_t		iterations = 0;

	fr_pair_list_init(&head);
	slen = load_test_point_by_command((void **)&tp, p, "tp_encode_pair");
	if (!tp) {
		fr_strerror_printf_push("Failed locating encode testpoint");
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

	if (tp->test_ctx && (tp->test_ctx(&encoder_ctx, cc->tmp_ctx) < 0)) {
		fr_strerror_printf_push("Failed initialising encoder testpoint");
		CLEAR_TEST_POINT(cc);
		RETURN_COMMAND_ERROR();
	}

	if (fr_pair_list_afrom_str(cc->tmp_ctx, cc->tmpl_rules.dict_def ? cc->tmpl_rules.dict_def : cc->config->dict,
				   p, &head) != T_EOL) {
		CLEAR_TEST_POINT(cc);
		RETURN_OK_WITH_ERROR();
	}

	/*
	 *	Outer loop implements truncate test
	 */
	do {
		enc_p = cc->buffer_start;
		enc_end = truncate ? cc->buffer_start + iterations++ : cc->buffer_end;

		if (truncate) {

		}

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

		for (vp = fr_cursor_talloc_iter_init(&cursor, &head,
						     tp->next_encodable ? tp->next_encodable : fr_proto_next_encodable,
						     cc->tmpl_rules.dict_def ? cc->tmpl_rules.dict_def : cc->config->dict, fr_pair_t);
		     vp;
		     vp = fr_cursor_current(&cursor)) {
			slen = tp->func(&FR_DBUFF_TMP(enc_p, enc_end), &cursor, encoder_ctx);
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
	fr_strerror();

	fr_pair_list_free(&head);

	CLEAR_TEST_POINT(cc);

	RETURN_OK(hex_print(data, COMMAND_OUTPUT_MAX, cc->buffer_start, enc_p - cc->buffer_start));
}

/** Encode a RADIUS attribute writing the result to the data buffer as space separated hexits
 *
 */
static size_t command_encode_raw(command_result_t *result, command_file_ctx_t *cc,
			         char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	size_t	len;

	len = encode_rfc(in, cc->buffer_start, cc->buffer_end - cc->buffer_start);
	if (len <= 0) RETURN_PARSE_ERROR(0);

	if (len >= (size_t)(cc->buffer_end - cc->buffer_start)) {
		fr_strerror_printf("Encoder output would overflow output buffer");
		RETURN_OK_WITH_ERROR();
	}

	RETURN_OK(hex_print(data, COMMAND_OUTPUT_MAX, cc->buffer_start, len));
}

static size_t command_returned(command_result_t *result, command_file_ctx_t *cc,
			       char *data, UNUSED size_t data_used, UNUSED char *in, UNUSED size_t inlen)
{
	RETURN_OK(snprintf(data, COMMAND_OUTPUT_MAX, "%zd", cc->last_ret));
}

static size_t command_encode_proto(command_result_t *result, command_file_ctx_t *cc,
				  char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	fr_test_point_proto_encode_t	*tp = NULL;

	void		*encoder_ctx = NULL;
	ssize_t		slen;
	char		*p = in;

	fr_pair_list_t	head;
	fr_pair_list_init(&head);

	slen = load_test_point_by_command((void **)&tp, p, "tp_encode_proto");
	if (!tp) {
		fr_strerror_printf_push("Failed locating encode testpoint");
		CLEAR_TEST_POINT(cc);
		RETURN_COMMAND_ERROR();
	}

	p += ((size_t)slen);
	fr_skip_whitespace(p);
	if (tp->test_ctx && (tp->test_ctx(&encoder_ctx, cc->tmp_ctx) < 0)) {
		fr_strerror_printf_push("Failed initialising encoder testpoint");
		CLEAR_TEST_POINT(cc);
		RETURN_COMMAND_ERROR();
	}

	if (fr_pair_list_afrom_str(cc->tmp_ctx, cc->tmpl_rules.dict_def ? cc->tmpl_rules.dict_def : cc->config->dict,
				   p, &head) != T_EOL) {
		CLEAR_TEST_POINT(cc);
		RETURN_OK_WITH_ERROR();
	}

	slen = tp->func(cc->tmp_ctx, head, cc->buffer_start, cc->buffer_end - cc->buffer_start, encoder_ctx);
	fr_pair_list_free(&head);
	cc->last_ret = slen;
	if (slen < 0) {
		CLEAR_TEST_POINT(cc);
		RETURN_OK_WITH_ERROR();
	}
	/*
	 *	Clear any spurious errors
	 */
	fr_strerror();

	CLEAR_TEST_POINT(cc);

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

/** Exit gracefully with the specified code
 *
 */
static size_t command_exit(command_result_t *result, UNUSED command_file_ctx_t *cc,
			   UNUSED char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	if (!*in) RETURN_EXIT(0);

	RETURN_EXIT(atoi(in));
}

/** Compare the data buffer to an expected value
 *
 */
static size_t command_match(command_result_t *result, command_file_ctx_t *cc,
			    char *data, size_t data_used, char *in, size_t inlen)
{
	if (strcmp(in, data) != 0) {
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
			fr_strerror_printf_push("Invalid integer");
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

/** Parse a list of pairs
 *
 */
static size_t command_pair(command_result_t *result, command_file_ctx_t *cc,
			    char *data, UNUSED size_t data_used, char *in, size_t inlen)
{
	ssize_t slen;
	fr_pair_ctx_t ctx;
	fr_pair_t *vp;
	fr_pair_list_t head;
	char *p, *end;
	fr_cursor_t cursor;

	fr_pair_list_init(&head);
	ctx.ctx = cc->tmp_ctx;
	ctx.parent = fr_dict_root(cc->tmpl_rules.dict_def);
	ctx.cursor = &cursor;
	fr_cursor_init(&cursor, &head);

	p = in;
	end = in + inlen;

	while (p < end) {
		slen = fr_pair_ctx_afrom_str(&ctx, p, end - p);
		if (slen <= 0) RETURN_PARSE_ERROR(-(slen));

		p += slen;
		if (p >= end) break;

		if (*p == ',') {
			p++;
			continue;
		}
	}

	p = data;
	end = data + COMMAND_OUTPUT_MAX;
	for (vp = fr_cursor_init(&cursor, &head);
	     vp != NULL;
	     vp = fr_cursor_next(&cursor)) {
		if ((slen = fr_pair_print(&FR_SBUFF_OUT(p, end), vp)) <= 0) RETURN_OK_WITH_ERROR();
		p += (size_t)slen;

		if (p >= end) break;

		*(p++) = ',';
		*(p++) = ' ';
	}

	/*
	 *	Delete the trailing ", ".
	 */
	if (p > data) p -= 2;
	*p = 0;

	RETURN_OK(p - data);
}


/** Dynamically load a protocol library
 *
 */
static size_t command_proto(command_result_t *result, command_file_ctx_t *cc,
			    UNUSED char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	ssize_t slen;

	if (*in == '\0') {
		fr_strerror_printf("Load syntax is \"load <lib_name>\"");
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

static size_t command_test_dictionary(command_result_t *result, command_file_ctx_t *cc,
				      UNUSED char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	int ret;

	fr_dict_global_ctx_set(cc->test_gctx);
	ret = dictionary_load_common(result, cc, in, ".");
	fr_dict_global_ctx_set(cc->config->dict_gctx);

	return ret;
}

static size_t command_value_box_normalise(command_result_t *result, UNUSED command_file_ctx_t *cc,
					  char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	fr_value_box_t *box = talloc_zero(NULL, fr_value_box_t);
	fr_value_box_t *box2;
	fr_type_t	type;
	size_t		match_len;
	ssize_t		slen;
	char		*p;

	/*
	 *	Parse data types
	 */
	type = fr_table_value_by_longest_prefix(&match_len, fr_value_box_type_table, in, strlen(in), FR_TYPE_INVALID);
	if (type == FR_TYPE_INVALID) {
		RETURN_PARSE_ERROR(0);
	}
	p = in + match_len;
	fr_skip_whitespace(p);

	if (fr_value_box_from_str(box, box, &type, NULL, p, -1, '"', false) < 0) {
	error:
		talloc_free(box);
		RETURN_OK_WITH_ERROR();
	}

	/*
	 *	Don't print dates with enclosing quotation marks.
	 */
	if (type != FR_TYPE_DATE) {
		slen = fr_value_box_print_quoted(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), box,
						 T_DOUBLE_QUOTED_STRING);
	} else {
		slen = fr_value_box_print(&FR_SBUFF_OUT(data, COMMAND_OUTPUT_MAX), box, NULL);
	}
	if (slen <= 0) goto error;

	/*
	 *	Behind the scenes, parse the data
	 *	string.  We should get the same value
	 *	box as last time.
	 */
	box2 = talloc_zero(NULL, fr_value_box_t);
	if (fr_value_box_from_str(box2, box2, &type, NULL, data, slen, '"', false) < 0) {
		talloc_free(box2);
		talloc_free(box);
		RETURN_OK_WITH_ERROR();
	}

	/*
	 *	They MUST be identical
	 */
	if (fr_value_box_cmp(box, box2) != 0) {
		fr_strerror_printf("ERROR value box reparsing failed.  Results not identical");
		fr_strerror_printf_push("out: %pV", box2);
		fr_strerror_printf_push("in: %pV", box);
		talloc_free(box2);
		talloc_free(box);
		RETURN_OK_WITH_ERROR();
	}

	talloc_free(box2);
	talloc_free(box);
	RETURN_OK(slen);
}

static size_t command_write(command_result_t *result, command_file_ctx_t *cc,
			    char *data, size_t data_used, char *in, size_t inlen)
{
	FILE	*fp;
	char	*path;

	path = talloc_bstrndup(cc->tmp_ctx, in, inlen);
	fp = fopen(path, "w");
	if (!fp) {
		fr_strerror_printf("Failed opening \"%s\": %s", path, fr_syserror(errno));
	error:
		talloc_free(path);
		if (fp) fclose(fp);
		RETURN_COMMAND_ERROR();
	}

	if (fwrite(data, data_used, 1, fp) != 1) {
		fr_strerror_printf("Failed writing to \"%s\": %s", path, fr_syserror(errno));
		goto error;
	}

	talloc_free(path);
	fclose(fp);

	RETURN_OK(data_used);
}

/** Parse an reprint and xlat expansion
 *
 */
static size_t command_xlat_normalise(command_result_t *result, command_file_ctx_t *cc,
				     char *data, UNUSED size_t data_used, char *in, UNUSED size_t inlen)
{
	ssize_t			dec_len;
	xlat_exp_t		*head = NULL;
	size_t			input_len = strlen(in), escaped_len;
	fr_sbuff_parse_rules_t	p_rules = { .escapes = &fr_value_unescape_double };

	dec_len = xlat_tokenize(cc->tmp_ctx, &head, NULL, &FR_SBUFF_IN(in, input_len), &p_rules,
				&(tmpl_rules_t) {
					.dict_def = cc->tmpl_rules.dict_def ? cc->tmpl_rules.dict_def : cc->config->dict,
					.allow_unresolved = cc->tmpl_rules.allow_unresolved
				});
	if (dec_len <= 0) {
		fr_strerror_printf_push_head("ERROR offset %d", (int) -dec_len);

	return_error:
		RETURN_OK_WITH_ERROR();
	}

	if (((size_t) dec_len != input_len)) {
		fr_strerror_printf_push_head("offset %d 'Too much text'", (int) dec_len);
		goto return_error;
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
	xlat_exp_t	*head = NULL;
	xlat_exp_t const **argv;
	size_t		len;
	size_t		input_len = strlen(in);
	char		buff[1024];

	slen = xlat_tokenize_argv(cc->tmp_ctx, &head, NULL, &FR_SBUFF_IN(in, input_len),
				  NULL,
				  &(tmpl_rules_t) {
					.dict_def = cc->tmpl_rules.dict_def ? cc->tmpl_rules.dict_def : cc->config->dict,
					.allow_unresolved = cc->tmpl_rules.allow_unresolved
				  });
	if (slen <= 0) {
		fr_strerror_printf_push_head("ERROR offset %d", (int) -slen);
		RETURN_OK_WITH_ERROR();
	}

	argc = xlat_flatten_compiled_argv(cc->tmp_ctx, &argv, head);
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
	{ L("attribute "),	&(command_entry_t){
					.func = command_normalise_attribute,
					.usage = "attribute <attr> = <value>",
					.description = "Parse and reprint an attribute value pair, writing \"ok\" to the data buffer on success"
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
					.description = "Encode one or more attributes as a packet, writing a hex string to the data buffer.  Protocol must be loaded with \"load <protocol>\" first"
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
					.usage = "max-buffer-size[ <intger>]",
					.description = "Limit the maximum temporary buffer space available for any command which uses it"
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
	{ L("raw "),		&(command_entry_t){
					.func = command_encode_raw,
					.usage = "raw <string>",
					.description = "Create nested attributes from OID strings and values"
				}},
	{ L("returned"),		&(command_entry_t){
					.func = command_returned,
					.usage = "returned",
					.description = "Print the returned value to the data buffer"
				}},
	{ L("test-dictionary "),&(command_entry_t){
					.func = command_test_dictionary,
					.usage = "test-dictionary <proto_name> [<test_dir>]",
					.description = "Switch the active dictionary.  Root is set to the path containing the current test file (override with cd <path>).  <test_dir> is relative to the root.",
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
	if (*p == '\0') RETURN_NOOP(data_used);

	DEBUG2("%s[%d]: %s", cc->filename, cc->lineno, p);

	/*
	 *	Look up the command by longest prefix
	 */
	command = fr_table_value_by_longest_prefix(&match_len, commands, p, -1, NULL);
	if (!command) {
		fr_strerror_printf("Unknown command: %s", p);
		RETURN_COMMAND_ERROR();
	}

	/*
	 *	Skip processing the command
	 */
	if (command->func == command_comment) RETURN_NOOP(data_used);

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

	talloc_free_children(cc->tmp_ctx);

	return data_used;
}

static int _command_ctx_free(command_file_ctx_t *cc)
{
	fr_dict_free(&cc->test_internal_dict);
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
	cc->test_gctx = fr_dict_global_ctx_init(cc, cc->config->dict_dir);
	if (!cc->test_gctx) {
		fr_perror("Failed allocating test dict_gctx");
		return NULL;
	}

	fr_dict_global_ctx_set(cc->test_gctx);
	if (fr_dict_internal_afrom_file(&cc->test_internal_dict, FR_DICTIONARY_INTERNAL_DIR) < 0) {
		fr_perror("Failed loading test dict_gctx internal dictionary");
		return NULL;
	}

	fr_dict_global_ctx_dir_set(cc->path);	/* Load new dictionaries relative to the test file */
	fr_dict_global_ctx_set(cc->config->dict_gctx);

	return cc;
}

static void command_ctx_reset(command_file_ctx_t *cc, TALLOC_CTX *ctx)
{
	talloc_free(cc->tmp_ctx);
	cc->tmp_ctx = talloc_named_const(ctx, 0, "tmp_ctx");
	cc->test_count = 0;

	fr_dict_global_ctx_free(cc->test_gctx);
	cc->test_gctx = fr_dict_global_ctx_init(cc, cc->config->dict_dir);
}

static int process_file(bool *exit_now, TALLOC_CTX *ctx, command_config_t const *config,
			const char *root_dir, char const *filename, fr_dlist_head_t *lines)
{
	int		ret = 0;
	FILE		*fp;				/* File we're reading from */
	char		buffer[8192];			/* Command buffer */
	char		data[COMMAND_OUTPUT_MAX + 1];	/* Data written by previous command */
	ssize_t		data_used = 0;			/* How much data the last command wrote */
	static char	path[PATH_MAX] = { '\0' };
	command_line_range_t	*lr = NULL;

	command_file_ctx_t	*cc;

	cc = command_ctx_alloc(ctx, config, root_dir, filename);

	/*
	 *	Open the file, or stdin
	 */
	if (strcmp(filename, "-") == 0) {
		fp = stdin;
		filename = "<stdin>";
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
	}

	if (lines && !fr_dlist_empty(lines)) lr = fr_dlist_head(lines);

	/*
	 *	Loop over lines in the file or stdin
	 */
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		command_result_t	result = { .rcode = RESULT_OK };	/* Reset to OK */
		char			*p = strchr(buffer, '\n');

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
				ERROR("Line %d too long in %s", cc->lineno, cc->path);
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
			break;

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
		}
	}

finish:
	if (fp && (fp != stdin)) fclose(fp);

	/*
	 *	Free any residual resources we loaded.
	 */
	if (cc) fr_dict_const_free(&cc->tmpl_rules.dict_def);
	fr_dict_global_ctx_set(config->dict_gctx);	/* Switch back to the main dict ctx */
	unload_proto_library();
	talloc_free(cc);

	return ret;
}

static void usage(char const *name)
{
	INFO("usage: %s [options] (-|<filename>[:<lines>] [ <filename>[:<lines>]])", name);
	INFO("options:");
	INFO("  -d <raddb>         Set user dictionary path (defaults to " RADDBDIR ").");
	INFO("  -D <dictdir>       Set main dictionary path (defaults to " DICTDIR ").");
	INFO("  -x                 Debugging mode.");
	INFO("  -f                 Print features.");
	INFO("  -c                 Print commands.");
	INFO("  -h                 Print help text.");
	INFO("  -M                 Show talloc memory report.");
	INFO("  -r <receipt_file>  Create the <receipt_file> as a 'success' exit.");
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
		fr_sbuff_adv_past_whitespace(in, SIZE_MAX);

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
		fr_sbuff_adv_past_whitespace(in, SIZE_MAX);

	again:
		if (!fr_sbuff_extend(in)) break;
		if (!fr_sbuff_is_in_charset(in, tokens)) {
			ERROR("Unexpected text \"%pV\"",
			      fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));
			goto error;
		}

		switch (*fr_sbuff_current(in)) {
		/*
		 *	More ranges...
		 */
		case ',':
			fr_sbuff_next(in);
			fr_sbuff_adv_past_whitespace(in, SIZE_MAX);
			continue;

		/*
		 *	<start>-<end>
		 */
		case '-':
		{
			fr_sbuff_next(in);
			fr_sbuff_adv_past_whitespace(in, SIZE_MAX);

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
			fr_sbuff_adv_past_whitespace(in, SIZE_MAX);
		}
			goto again;
		}
	}

	return 0;
}

/**
 *
 * @hidecallgraph
 */
int main(int argc, char *argv[])
{
	int			c;
	char const		*receipt_file = NULL;
	int			*inst = &c;
	CONF_SECTION		*cs;
	int			ret = EXIT_SUCCESS;
	TALLOC_CTX		*autofree;
	dl_module_loader_t	*dl_modules = NULL;
	bool			exit_now = false;

	command_config_t	config = {
					.raddb_dir = RADDBDIR,
					.dict_dir = DICTDIR
				};

	char const		*name;
	bool			do_features = false;
	bool			do_commands = false;
	bool			do_usage = false;

	/*
	 *	Must be called first, so the handler is called last
	 */
	fr_thread_local_atexit_setup();

	autofree = talloc_autofree_context();

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

	while ((c = getopt(argc, argv, "cd:D:fxMhr:")) != -1) switch (c) {
		case 'c':
			do_commands = true;
			break;

		case 'd':
			config.raddb_dir = optarg;
			break;

		case 'D':
			config.dict_dir = optarg;
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
			receipt_file = optarg;
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

	if (receipt_file && (fr_unlink(receipt_file) < 0)) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

	dl_modules = dl_module_loader_init(NULL);
	if (!dl_modules) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

	dl_loader = dl_loader_init(autofree, NULL, false, false);
	if (!dl_loader) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

	config.dict_gctx = fr_dict_global_ctx_init(autofree, config.dict_dir);
	if (!config.dict_gctx) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_internal_afrom_file(&config.dict, FR_DICTIONARY_INTERNAL_DIR) < 0) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Load the custom dictionary
	 */
	if (fr_dict_read(config.dict, config.raddb_dir, FR_DICTIONARY_FILE) == -1) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Initialise the interpreter, registering operations.
	 *	Needed because some keywords also register xlats.
	 */
	if (unlang_init() < 0) return -1;

	if (xlat_register_legacy(inst, "test", xlat_test, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN) < 0) {
		ERROR("Failed registering xlat");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Read tests from stdin
	 */
	if (argc < 2) {
		ret = process_file(&exit_now, autofree, &config, name, "-", NULL);

	/*
	 *	...or process each file in turn.
	 */
	} else {
		int i;

		for (i = 1; i < argc; i++) {
			char			*dir = NULL, *file;
			fr_sbuff_t		in = FR_SBUFF_IN(argv[i], strlen(argv[i]));
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

			while (fr_sbuff_adv_until(&in, SIZE_MAX, &dir_sep, '\0')) {
				switch (*fr_sbuff_current(&in)) {
				case '/':
					fr_sbuff_set(&dir_end, &in);
					fr_sbuff_advance(&in, 1);
					fr_sbuff_set(&file_start, &in);
					break;

				case ':':
					fr_sbuff_set(&file_end, &in);
					fr_sbuff_advance(&in, 1);
					if (line_ranges_parse(autofree, &lines, &in) < 0) EXIT_WITH_FAILURE;
					break;

				default:
					fr_sbuff_set(&file_end, &in);
					break;
				}
			}

			file = talloc_bstrndup(autofree,
					       fr_sbuff_current(&file_start), fr_sbuff_diff(&file_end, &file_start));
			if (fr_sbuff_used(&dir_end)) dir = talloc_bstrndup(autofree,
									   fr_sbuff_start(&in),
									   fr_sbuff_used(&dir_end));

			ret = process_file(&exit_now, autofree, &config, dir, file, &lines);
			talloc_free(dir);
			talloc_free(file);
			fr_dlist_talloc_free(&lines);

			if ((ret != 0) || exit_now) break;
		}
	}

	/*
	 *	Try really hard to free any allocated
	 *	memory, so we get clean talloc reports.
	 */
cleanup:
	if (talloc_free(dl_modules) < 0) {
		fr_perror("unit_test_attribute - dl_modules - ");	/* Print free order issues */
	}
	if (talloc_free(dl_loader) < 0) {
		fr_perror("unit_test_attribute - dl_loader - ");	/* Print free order issues */
	}
	fr_dict_free(&config.dict);
	unlang_free();
	xlat_free();

	/*
	 *	Dictionaries get freed towards the end
	 *	because it breaks "autofree".
	 */
	if (fr_dict_global_ctx_free(config.dict_gctx) < 0) {
		fr_perror("unit_test_attribute");	/* Print free order issues */
	}

	if (receipt_file && (ret == EXIT_SUCCESS) && (fr_touch(NULL, receipt_file, 0644, true, 0755) <= 0)) {
		fr_perror("unit_test_attribute");
		ret = EXIT_FAILURE;
	}

	/*
	 *	Explicitly free the autofree context
	 *	to make errors less confusing.
	 */
	talloc_free(autofree);

	return ret;
}
