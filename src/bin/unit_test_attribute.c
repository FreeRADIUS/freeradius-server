/*
 * unit_test_attribute.c	RADIUS Attribute debugging tool.
 *
 * Version:	$Id$
 *
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
 * @copyright 2010 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/util/base.h>

typedef struct rad_request REQUEST;

#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/map.h>

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/command.h>
#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/server/dependency.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/xlat.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/conf.h>

#ifdef WITH_TACACS
#  include <freeradius-devel/tacacs/tacacs.h>
#endif

#include <ctype.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <limits.h>
#include <assert.h>
#include <sys/wait.h>

#define EXIT_WITH_FAILURE \
do { \
	ret = EXIT_FAILURE; \
	goto cleanup; \
} while (0)

#define COMMAND_OUTPUT_MAX	8192

#define RETURN_OK(_len) \
	do { \
		result->rcode = RESULT_OK; \
		return (_len); \
	} while (0)

#define RETURN_SKIP_FILE() \
	do { \
		result->rcode = RESULT_SKIP_FILE; \
		return 0; \
	} while (0)

#define RETURN_DRAIN_ERROR_STACK_TO_DATA() \
	do { \
		result->rcode = RESULT_DRAIN_ERROR_STACK_TO_DATA; \
		return 0; \
	} while (0)

#define RETURN_PARSE_ERROR(_offset) \
	do { \
		result->rcode = RESULT_PARSE_ERROR; \
		result->rcode = RESULT_PARSE_ERROR; \
		result->offset = _offset; \
		return 0; \
	} while (0)

#define RETURN_COMMAND_ERROR() \
	do { \
		result->rcode = RESULT_COMMAND_ERROR; \
		return 0; \
	} while (0)

#define RETURN_MISMATCH(_expected, _expected_len, _got, _got_len) \
	do { \
		result->rcode = RESULT_MISMATCH; \
		result->expected = _expected; \
		result->expected_len = _expected_len; \
		result->got = _got; \
		result->got_len = _got_len; \
		return 0; \
	} while (0)

typedef enum {
	RESULT_OK = 0,				//!< Not an error - Result as expected.
	RESULT_SKIP_FILE,			//!< Not an error - Skip the rest of this file, or until we
						///< reach an "eof" command.
	RESULT_DRAIN_ERROR_STACK_TO_DATA,	//!< Not an error.
	RESULT_PARSE_ERROR,			//!< Fatal error - Command syntax error.
	RESULT_COMMAND_ERROR,			//!< Fatal error - Command operation error.
	RESULT_MISMATCH,			//!< Fatal error - Result didn't match what we expected.
} command_rcode_t;

fr_table_num_sorted_t command_rcode_table[] = {
	{ "ok",				RESULT_OK				},
	{ "skip-file",			RESULT_SKIP_FILE			},
	{ "error-to-data",		RESULT_DRAIN_ERROR_STACK_TO_DATA	},
	{ "parse-error",		RESULT_PARSE_ERROR			},
	{ "command-error",		RESULT_COMMAND_ERROR			},
	{ "result-mismatch",		RESULT_MISMATCH				}
};
size_t command_rcode_table_len = NUM_ELEMENTS(command_rcode_table);

typedef struct {
	union {
		struct {
			char const	*expected;	//!< Output buffer contents we expected.
			size_t		expected_len;	//!< How long expected is.
			char const	*got;		//!< What we got.
			size_t		got_len;	//!< How long got is.
		};
		size_t	offset;				//!< Where we failed parsing the command.
	};
	command_rcode_t	rcode;
} command_result_t;

typedef struct {
	TALLOC_CTX	*tmp_ctx;		//!< Talloc context for test points.

	char const	*path;			//!< Current path we're operating in.
	int		lineno;			//!< Current line number.

	fr_dict_t 	*dict;			//!< Base dictionary.
	fr_dict_t	*proto_dict;		//!< Protocol specific dictionary.
	CONF_SECTION	*features;		//!< Enabled features.
} command_ctx_t;

/** Command to execute
 *
 * @param[out] result	Of executing the command.
 * @param[in] cc	Information about the file being processed.
 * @param[in,out] data	Output of this command, or the previous command.
 * @param[in] data_len	Length of data in the data buffer.
 * @param[in] in	Command text to process.
 */
typedef size_t (*command_func_t)(command_result_t *result, command_ctx_t *cc, char *data, size_t data_len, char *in);

static ssize_t xlat_test(UNUSED TALLOC_CTX *ctx, UNUSED char **out, UNUSED size_t outlen,
			 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 UNUSED REQUEST *request, UNUSED char const *fmt)
{
	return 0;
}

static char proto_name_prev[128];
static dl_t		*dl;
static dl_loader_t	*dl_loader;
static const char	*process_filename;
static int		process_lineno;

static int process_file(TALLOC_CTX *ctx, CONF_SECTION *features,
			fr_dict_t *dict, const char *root_dir, char const *filename);

/** Print hex string to buffer
 *
 */
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

static int encode_tlv(char *buffer, uint8_t *output, size_t outlen);

static char const hextab[] = "0123456789abcdef";

static int encode_data_string(char *buffer, uint8_t *output, size_t outlen)
{
	int length = 0;
	char *p;

	p = buffer + 1;

	while (*p && (outlen > 0)) {
		if (*p == '"') {
			return length;
		}

		if (*p != '\\') {
			*(output++) = *(p++);
			outlen--;
			length++;
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
		length++;
	}

	ERROR("String is not terminated");
	return 0;
}

static int encode_data_tlv(char *buffer, char **endptr,
			   uint8_t *output, size_t outlen)
{
	int depth = 0;
	int length;
	char *p;

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

	length = encode_tlv(p, output, outlen);
	if (length == 0) return 0;

	return length;
}

static int hex_to_bin(uint8_t *output, size_t outlen, char *in, size_t inlen)
{
	int length = 0;
	char *p = in;
	char *end = in + inlen;

	while (p < end) {
		char *c1, *c2;

		fr_skip_whitespace(p);

		if (!*p) break;

		if(!(c1 = memchr(hextab, tolower((int) p[0]), 16)) ||
		   !(c2 = memchr(hextab, tolower((int)  p[1]), 16))) {
			ERROR("Invalid data starting at \"%s\"\n", p);
			return 0;
		}

		*output = ((c1 - hextab) << 4) + (c2 - hextab);
		output++;
		length++;
		p += 2;

		outlen--;
		if (outlen == 0) {
			ERROR("Too much data");
			return 0;
		}
	}

	return length;
}


static int encode_data(char *p, uint8_t *output, size_t outlen)
{
	int length;

	if (!isspace((int) *p)) {
		ERROR("Invalid character following attribute definition");
		return 0;
	}

	fr_skip_whitespace(p);

	if (*p == '{') {
		int sublen;
		char *q;

		length = 0;

		do {
			fr_skip_whitespace(p);
			if (!*p) {
				if (length == 0) {
					ERROR("No data");
					return 0;
				}

				break;
			}

			sublen = encode_data_tlv(p, &q, output, outlen);
			if (sublen == 0) return 0;

			length += sublen;
			output += sublen;
			outlen -= sublen;
			p = q;
		} while (*q);

		return length;
	}

	if (*p == '"') {
		length = encode_data_string(p, output, outlen);
		return length;
	}

	length = hex_to_bin(output, outlen, p, strlen(p));

	if (length == 0) {
		ERROR("Empty string");
		return 0;
	}

	return length;
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

static int encode_tlv(char *buffer, uint8_t *output, size_t outlen)
{
	int attr;
	int length;
	char *p;

	attr = decode_attr(buffer, &p);
	if (attr == 0) return 0;

	output[0] = attr;
	output[1] = 2;

	if (*p == '.') {
		p++;
		length = encode_tlv(p, output + 2, outlen - 2);

	} else {
		length = encode_data(p, output + 2, outlen - 2);
	}

	if (length == 0) return 0;
	if (length > (255 - 2)) {
		ERROR("TLV data is too long");
		return 0;
	}

	output[1] += length;

	return length + 2;
}

static int encode_vsa(char *buffer, uint8_t *output, size_t outlen)
{
	int vendor;
	int length;
	char *p;

	vendor = decode_vendor(buffer, &p);
	if (vendor == 0) return 0;

	output[0] = 0;
	output[1] = (vendor >> 16) & 0xff;
	output[2] = (vendor >> 8) & 0xff;
	output[3] = vendor & 0xff;

	length = encode_tlv(p, output + 4, outlen - 4);
	if (length == 0) return 0;
	if (length > (255 - 6)) {
		ERROR("VSA data is too long");
		return 0;
	}


	return length + 4;
}

static int encode_evs(char *buffer, uint8_t *output, size_t outlen)
{
	int vendor;
	int attr;
	int length;
	char *p;

	vendor = decode_vendor(buffer, &p);
	if (vendor == 0) return 0;

	attr = decode_attr(p, &p);
	if (attr == 0) return 0;

	output[0] = 0;
	output[1] = (vendor >> 16) & 0xff;
	output[2] = (vendor >> 8) & 0xff;
	output[3] = vendor & 0xff;
	output[4] = attr;

	length = encode_data(p, output + 5, outlen - 5);
	if (length == 0) return 0;

	return length + 5;
}

static int encode_extended(char *buffer,
			   uint8_t *output, size_t outlen)
{
	int attr;
	int length;
	char *p;

	attr = decode_attr(buffer, &p);
	if (attr == 0) return 0;

	output[0] = attr;

	if (attr == 26) {
		length = encode_evs(p, output + 1, outlen - 1);
	} else {
		length = encode_data(p, output + 1, outlen - 1);
	}
	if (length == 0) return 0;
	if (length > (255 - 3)) {
		ERROR("Extended Attr data is too long");
		return 0;
	}

	return length + 1;
}

static int encode_long_extended(char *buffer,
				 uint8_t *output, size_t outlen)
{
	int attr;
	int length, total;
	char *p;

	attr = decode_attr(buffer, &p);
	if (attr == 0) return 0;

	/* output[0] is the extended attribute */
	output[1] = 4;
	output[2] = attr;
	output[3] = 0;

	if (attr == 26) {
		length = encode_evs(p, output + 4, outlen - 4);
		if (length == 0) return 0;

		output[1] += 5;
		length -= 5;
	} else {
		length = encode_data(p, output + 4, outlen - 4);
	}
	if (length == 0) return 0;

	total = 0;
	while (1) {
		int sublen = 255 - output[1];

		if (length <= sublen) {
			output[1] += length;
			total += output[1];
			break;
		}

		length -= sublen;

		memmove(output + 255 + 4, output + 255, length);
		memcpy(output + 255, output, 4);

		output[1] = 255;
		output[3] |= 0x80;

		output += 255;
		output[1] = 4;
		total += 255;
	}

	return total;
}

static int encode_rfc(char *buffer, uint8_t *output, size_t outlen)
{
	int attr;
	int length, sublen;
	char *p;

	attr = decode_attr(buffer, &p);
	if (attr == 0) return 0;

	length = 2;
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
	if (sublen == 0) return 0;
	if (sublen > (255 -2)) {
		ERROR("RFC Data is too long");
		return 0;
	}

	output[1] += sublen;
	return length + sublen;
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
			ERROR("Failed to link to library \"%s\": %s\n", dl_name, fr_strerror());
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
		ERROR("No protocol library loaded. Specify library with \"load <proto name>\"");
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
		ERROR("Test point (symbol \"%s\") not exported by library", buffer);
		unload_proto_library();
		return 0;
	}
	*symbol = dl_symbol;

	return p - command;
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
	printf("");

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
static size_t command_comment(UNUSED command_result_t *result, UNUSED command_ctx_t *cc,
			      UNUSED char *data, UNUSED size_t data_used, UNUSED char *in)
{
	return 0;
}

/** Execute another test file
 *
 */
static size_t command_include(command_result_t *result, command_ctx_t *cc,
			      UNUSED char *data, UNUSED size_t data_used, char *in)
{
	char *q;

	q = strrchr(cc->path, '/');
	if (q) {
		*q = '\0';
		if (process_file(cc->tmp_ctx, cc->features, cc->dict, cc->path, in) < 0) RETURN_COMMAND_ERROR();
		*q = '/';
		RETURN_OK(0);
	}

	if (process_file(cc->tmp_ctx, cc->features, cc->dict, NULL, in) < 0) RETURN_COMMAND_ERROR();

	RETURN_OK(0);
}

/** Parse an print an attribute pair
 *
 */
static size_t command_normalise_attribute(command_result_t *result, command_ctx_t *cc,
					  char *data, UNUSED size_t data_used, char *in)
{
	VALUE_PAIR 	*head = NULL;
	size_t		len;

	if (fr_pair_list_afrom_str(NULL, cc->proto_dict ? cc->proto_dict : cc->dict, in, &head) != T_EOL) {
		RETURN_DRAIN_ERROR_STACK_TO_DATA();
	}

	len = fr_pair_snprint(data, COMMAND_OUTPUT_MAX, head);
	if (is_truncated(len, COMMAND_OUTPUT_MAX)) {
		fr_strerror_printf("Encoder output would overflow output buffer");
		RETURN_DRAIN_ERROR_STACK_TO_DATA();
	}

	RETURN_OK(len);
}

/*
 *	Add a command by talloc'ing a table for it.
 */
static size_t command_radmin_add(command_result_t *result, command_ctx_t *cc,
				 char *data, size_t UNUSED data_used, char *in)
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
		fr_strerror_printf("ERROR: failed adding command - %s", fr_strerror());
		RETURN_DRAIN_ERROR_STACK_TO_DATA();
	}

	if (fr_debug_lvl) command_print();

	RETURN_OK(snprintf(data, COMMAND_OUTPUT_MAX, "ok"));
}

/*
 *	Do tab completion on a command
 */
static size_t command_radmin_tab(command_result_t *result, UNUSED command_ctx_t *cc,
				 char *data, UNUSED size_t data_used, char *in)
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
static size_t command_condition_normalise(command_result_t *result, command_ctx_t *cc,
					  char *data, UNUSED size_t data_used, char *in)
{
	ssize_t			dec_len;
	char const		*error = NULL;
	fr_cond_t		*cond;
	CONF_SECTION		*cs;
	size_t			len;

	cs = cf_section_alloc(NULL, NULL, "if", "condition");
	if (!cs) {
		ERROR("Out of memory");
		RETURN_COMMAND_ERROR();
	}
	cf_filename_set(cs, process_filename);
	cf_lineno_set(cs, process_lineno);

	dec_len = fr_cond_tokenize(cs, &cond, &error, cc->proto_dict ? cc->proto_dict : cc->dict, in);
	if (dec_len <= 0) {
		fr_strerror_printf("ERROR offset %d %s", (int) -dec_len, error);

	return_error:
		talloc_free(cs);
		RETURN_DRAIN_ERROR_STACK_TO_DATA();
	}

	in += dec_len;
	if (*in != '\0') {
		fr_strerror_printf("ERROR offset %d 'Too much text'", (int) dec_len);
		goto return_error;
	}

	len = cond_snprint(NULL, data, COMMAND_OUTPUT_MAX, cond);
	talloc_free(cs);

	RETURN_OK(len);
}

/** Compare the data buffer to an expected value
 *
 */
static size_t command_data(command_result_t *result, UNUSED command_ctx_t *cc,
			   char const *data, size_t data_used, char *in)
{
	if (strcmp(in, data) != 0) RETURN_MISMATCH(in, strlen(in), data, data_used);

	/*
	 *	We didn't actually write anything, but this
	 *	keeps the contents of the data buffer around
	 *	for the next command to operate on.
	 */
	RETURN_OK(data_used);
}

static size_t command_decode_pair(command_result_t *result, command_ctx_t *cc,
				  char *data, size_t data_used, char *in)
{
	fr_test_point_pair_decode_t	*tp = NULL;
	fr_cursor_t 	cursor;
	void		*decoder_ctx = NULL;
	char		*p, *end;
	uint8_t		*to_dec;
	uint8_t		*to_dec_end;
	VALUE_PAIR	*head = NULL, *vp;
	ssize_t		slen;
	size_t		len;

	p = in;

	slen = load_test_point_by_command((void **)&tp, in, "tp_decode");
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
	 *	Decode the previous output
	 */
	if (strcmp(p, "-") == 0) {
		len = hex_to_bin((uint8_t *)data, COMMAND_OUTPUT_MAX, data, data_used);
	/*
	 *	Decode hex from input text
	 */
	} else {
		len = hex_to_bin((uint8_t *)data, COMMAND_OUTPUT_MAX, p, strlen(p));
	}
	if (len == 0) {
		fr_strerror_printf_push("Failed decoding hex string");
		RETURN_PARSE_ERROR(0);	/* FIXME - Return actual offset */
	}
	to_dec = (uint8_t *)data;
	to_dec_end = to_dec + len;

	/*
	 *	Run the input data through the test
	 *	point to produce VALUE_PAIRs.
	 */
	fr_cursor_init(&cursor, &head);
	while (to_dec < to_dec_end) {
		slen = tp->func(cc->tmp_ctx, &cursor, cc->proto_dict ? cc->proto_dict : cc->dict,
				(uint8_t *)to_dec, (to_dec_end - to_dec), decoder_ctx);
		if (slen < 0) {
			fr_pair_list_free(&head);
			RETURN_DRAIN_ERROR_STACK_TO_DATA();
		}
		if ((size_t)slen > (size_t)(to_dec_end - to_dec)) {
			fr_perror("Internal sanity check failed at %d", __LINE__);
			RETURN_COMMAND_ERROR();
		}
		to_dec += slen;
	}

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
		for (vp = fr_cursor_head(&cursor);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			len = fr_pair_snprint(p, end - p, vp);
			if (is_truncated(len, end - p)) {
			oob:
				fr_strerror_printf("Out of output buffer space");
				RETURN_COMMAND_ERROR();
			}
			p += len;

			if (vp->next) {
				len = strlcpy(p, ", ", end - p);
				if (is_truncated(len, end - p)) goto oob;
				p += len;
			}
		}
		fr_pair_list_free(&head);
	} else { /* zero-length to_decibute */
		*p = '\0';
	}
	CLEAR_TEST_POINT(cc);

	RETURN_OK(p - data);
}

/** Incomplete - Will be used to decode packets
 *
 */
static size_t command_decode_proto(command_result_t *result, UNUSED command_ctx_t *cc,
				   UNUSED char *data, UNUSED size_t data_used, char *in)
{
	fr_test_point_proto_decode_t *tp = NULL;

	load_test_point_by_command((void **)&tp, in, "tp_decode");
	if (!tp) {
		result->rcode = RESULT_PARSE_ERROR;
		return 0;
	}

	return 0;
}

/** Parse a dictionary attribute, writing "ok" to the data buffer is everything was ok
 *
 */
static size_t command_dictionary_attribute_parse(command_result_t *result, command_ctx_t *cc,
					  	 char *data, UNUSED size_t data_used, char *in)
{
	if (fr_dict_parse_str(cc->dict, in, fr_dict_root(cc->dict)) < 0) RETURN_DRAIN_ERROR_STACK_TO_DATA();

	RETURN_OK(strlcpy(data, "ok", COMMAND_OUTPUT_MAX));
}

/** Print the currently loaded dictionary
 *
 */
static size_t command_dictionary_dump(UNUSED command_result_t *result, command_ctx_t *cc,
				      UNUSED char *data, UNUSED size_t data_used, UNUSED char *in)
{
	fr_dict_dump(cc->proto_dict ? cc->proto_dict : cc->dict);

	RETURN_OK(0);
}


/** Dynamically load a protocol dictionary
 *
 */
static size_t command_dictionary_load(command_result_t *result, command_ctx_t *cc,
				      UNUSED char *data, UNUSED size_t data_used, char *in)
{
	char *name, *dir, *tmp = NULL;
	char *q;
	int ret;

	if (in[0] == '\0') {
		fr_strerror_printf("Load-dictionary syntax is \"dictionary-load <proto_name> [<proto_dir>]\"");
		RETURN_PARSE_ERROR(0);
	}

	/*
	 *	Decrease ref count if we're loading in a new dictionary
	 */
	if (cc->proto_dict) fr_dict_free(&cc->proto_dict);

	q = strchr(in, ' ');
	if (q) {
		name = tmp = talloc_bstrndup(NULL, in, q - in);
		q++;
		dir = q;
	} else {
		name = in;
		dir = NULL;
	}

	ret = fr_dict_protocol_afrom_file(&cc->proto_dict, name, dir);
	talloc_free(tmp);
	if (ret < 0) RETURN_DRAIN_ERROR_STACK_TO_DATA();

	/*
	 *	Dump the dictionary if we're in super debug mode
	 */
	if (fr_debug_lvl > 5) fr_dict_dump(cc->proto_dict);

	RETURN_OK(0);
}

static size_t command_encode_pair(command_result_t *result, command_ctx_t *cc,
				  char *data, UNUSED size_t data_used, char *in)
{
	fr_test_point_pair_encode_t	*tp = NULL;

	fr_cursor_t	cursor;
	void		*encoder_ctx = NULL;
	ssize_t		slen;
	char		*p = in;

	uint8_t		encoded[(COMMAND_OUTPUT_MAX / 2) - 1];
	uint8_t		*enc_p = encoded, *enc_end = enc_p + sizeof(encoded);
	VALUE_PAIR	*head = NULL, *vp;

	slen = load_test_point_by_command((void **)&tp, p, "tp_encode");
	if (!tp) {
		fr_strerror_printf_push("Failed locating encode testpoint");
		RETURN_COMMAND_ERROR();
	}

	p += ((size_t)slen);
	fr_skip_whitespace(p);
	if (tp->test_ctx && (tp->test_ctx(&encoder_ctx, cc->tmp_ctx) < 0)) {
		fr_strerror_printf_push("Failed initialising encoder testpoint");
		RETURN_COMMAND_ERROR();
	}

	/*
	 *	Encode the previous output
	 */
	if (strcmp(p, "-") == 0) p = data;

	if (fr_pair_list_afrom_str(cc->tmp_ctx, cc->proto_dict ? cc->proto_dict : cc->dict, p, &head) != T_EOL) {
		RETURN_DRAIN_ERROR_STACK_TO_DATA();
	}

	fr_cursor_init(&cursor, &head);
	while ((vp = fr_cursor_current(&cursor))) {
		slen = tp->func(enc_p, enc_end - enc_p, &cursor, encoder_ctx);
		if (slen < 0) {
			fr_pair_list_free(&head);
			RETURN_DRAIN_ERROR_STACK_TO_DATA();
		}
		enc_p += slen;

		if (slen == 0) break;
	}
	fr_pair_list_free(&head);

	CLEAR_TEST_POINT(cc);

	RETURN_OK(hex_print(data, COMMAND_OUTPUT_MAX, encoded, enc_p - encoded));
}

/** Incomplete - Will be used to encode packets
 *
 */
static size_t command_encode_proto(command_result_t *result, UNUSED command_ctx_t *cc,
				   UNUSED char *data, UNUSED size_t data_used, char *in)
{
	fr_test_point_proto_encode_t *tp = NULL;

	load_test_point_by_command((void **)&tp, in, "tp_encode");
	if (!tp) {
		result->rcode = RESULT_PARSE_ERROR;
		return 0;
	}

	return 0;
}

/** Command eof
 *
 * Mark the end of a test file if we're reading from stdin.
 *
 * Doesn't actually do anything, is just a placeholder for the command processing loop.
 */
static size_t command_eof(UNUSED command_result_t *result, UNUSED command_ctx_t *cc,
			  UNUSED char *data, UNUSED size_t data_used, UNUSED char *in)
{
	return 0;
}

/** Dynamically load a protocol library
 *
 */
static size_t command_proto_load(command_result_t *result, UNUSED command_ctx_t *cc,
				 UNUSED char *data, UNUSED size_t data_used, char *in)
{
	ssize_t slen;

	if (*in == '\0') {
		fr_strerror_printf("Load syntax is \"load <lib_name>\"");
		RETURN_PARSE_ERROR(0);
	}

	slen = load_proto_library(in);
	if (slen <= 0) RETURN_PARSE_ERROR(-(slen));

	RETURN_OK(0);
}

/** Skip the test file if we're missing a particular feature
 *
 */
static size_t command_need_feature(command_result_t *result, command_ctx_t *cc,
				   UNUSED char *data, UNUSED size_t data_used, char *in)
{
	CONF_PAIR *cp;

	if (in[0] == '\0') {
		fr_strerror_printf("Prerequisite syntax is \"need-feature <feature>\".  "
				   "Use -f to print features");
		RETURN_PARSE_ERROR(0);
	}

	cp = cf_pair_find(cc->features, in);
	if (!cp || (strcmp(cf_pair_value(cp), "yes") != 0)) {
		DEBUG("Skipping, missing feature \"%s\"\n", in);
		RETURN_SKIP_FILE();
	}

	RETURN_OK(0);
}

/** Encode a RADIUS attribute writing the result to the data buffer as space separated hexits
 *
 */
static size_t command_encode_raw(command_result_t *result, UNUSED command_ctx_t *cc,
			         char *data, UNUSED size_t data_used, char *in)
{
	size_t	len;
	uint8_t	encoded[(COMMAND_OUTPUT_MAX / 2) - 1];

	len = encode_rfc(in, encoded, sizeof(encoded));
	if (len <= 0) RETURN_PARSE_ERROR(0);

	if (len >= (COMMAND_OUTPUT_MAX / 2)) {
		fr_strerror_printf("Encoder output would overflow output buffer");
		RETURN_DRAIN_ERROR_STACK_TO_DATA();
	}

	RETURN_OK(hex_print(data, COMMAND_OUTPUT_MAX, encoded, len));
}

/** Touch a file to indicate a test completed
 *
 */
static size_t command_touch(command_result_t *result, UNUSED command_ctx_t *cc,
			    UNUSED char *data, UNUSED size_t data_used, char *in)
{
	if (fr_file_unlink(in) < 0) RETURN_COMMAND_ERROR();
	if (fr_file_touch(in, 0644) < 0) RETURN_COMMAND_ERROR();

	RETURN_OK(0);
}

static size_t command_value_box_normalise(command_result_t *result, UNUSED command_ctx_t *cc,
					  char *data, UNUSED size_t data_used, char *in)
{
	fr_value_box_t *box = talloc_zero(NULL, fr_value_box_t);
	fr_value_box_t *box2;
	fr_type_t	type;
	size_t		match_len;
	size_t		len;
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
		talloc_free(box);
		RETURN_DRAIN_ERROR_STACK_TO_DATA();
	}

	/*
	 *	Don't print dates with enclosing quotation marks.
	 */
	if (type != FR_TYPE_DATE) {
		len = fr_value_box_snprint(data, COMMAND_OUTPUT_MAX, box, '"');
	} else {
		len = fr_value_box_snprint(data, COMMAND_OUTPUT_MAX, box, '\0');
	}

	/*
	 *	Behind the scenes, parse the data
	 *	string.  We should get the same value
	 *	box as last time.
	 */
	box2 = talloc_zero(NULL, fr_value_box_t);
	if (fr_value_box_from_str(box2, box2, &type, NULL, data, len, '"', false) < 0) {
		talloc_free(box2);
		talloc_free(box);
		RETURN_DRAIN_ERROR_STACK_TO_DATA();
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
		RETURN_DRAIN_ERROR_STACK_TO_DATA();
	}

	talloc_free(box2);
	talloc_free(box);
	RETURN_OK(len);
}

/** Parse an reprint and xlat expansion
 *
 */
static size_t command_xlat_normalise(command_result_t *result, command_ctx_t *cc,
				     char *data, UNUSED size_t data_used, char *in)
{
	ssize_t		dec_len;
	size_t		len;
	char		*fmt;
	xlat_exp_t	*head = NULL;
	size_t		input_len = strlen(in), escaped_len;
	char		buff[1024];

	/*
	 *	Process special chars, octal escape sequences and hex sequences
	 */
	MEM(fmt = talloc_array(NULL, char, input_len + 1));
	len = fr_value_str_unescape((uint8_t *)fmt, in, input_len, '\"');
	fmt[len] = '\0';

	dec_len = xlat_tokenize(fmt, &head, fmt,
				&(vp_tmpl_rules_t) { .dict_def = cc->proto_dict ? cc->proto_dict : cc->dict });
	if (dec_len <= 0) {
		fr_strerror_printf("ERROR offset %d '%s'", (int) -dec_len, fr_strerror());

	return_error:
		talloc_free(fmt);
		RETURN_DRAIN_ERROR_STACK_TO_DATA();
	}

	if (fmt[dec_len] != '\0') {
		fr_strerror_printf("ERROR offset %d 'Too much text'", (int) dec_len);
		goto return_error;
	}

	len = xlat_snprint(buff, sizeof(buff), head);
	escaped_len = fr_snprint(data, COMMAND_OUTPUT_MAX, buff, len, '"');
	talloc_free(fmt);

	RETURN_OK(escaped_len);
}

static int process_file(TALLOC_CTX *ctx, CONF_SECTION *features,
			fr_dict_t *dict, const char *root_dir, char const *filename)
{
	int				ret = 0;
	FILE				*fp;				/* File we're reading from */
	char				buffer[8192];			/* Command buffer */
	char				data[8192];			/* Data written by previous command */
	ssize_t				data_len = 0;			/* How much data the last command wrote */
	static char			path[PATH_MAX] = { '\0' };

	command_ctx_t			cc = {
						.tmp_ctx = talloc_named_const(ctx, 0, "tmp_ctx"),
						.lineno = 0,
						.path = path,
						.dict = dict,
						.features = features
					};

	static fr_table_ptr_sorted_t	commands[] = {
		{ "#",			command_comment				},
		{ "$INCLUDE ",		command_include				},
		{ "attribute ",		command_normalise_attribute		},
		{ "command add ",	command_radmin_add			},
		{ "command tab ",	command_radmin_tab			},
		{ "condition ",		command_condition_normalise		},
		{ "data",		command_data				},
		{ "decode-pair",	command_decode_pair			},
		{ "decode-proto",	command_decode_proto			},
		{ "dictionary ",	command_dictionary_attribute_parse	},
		{ "dictionary-dump",	command_dictionary_dump			},
		{ "dictionary-load ",	command_dictionary_load			},
		{ "encode-pair",	command_encode_pair			},
		{ "encode-proto",	command_encode_proto			},
		{ "eof",		command_eof				},
		{ "load ",		command_proto_load			},
		{ "need-feature ", 	command_need_feature			},
		{ "raw ",		command_encode_raw			},
		{ "touch ",		command_touch				},
		{ "value ",		command_value_box_normalise		},
		{ "xlat ",		command_xlat_normalise			},
	};
	static size_t commands_len = NUM_ELEMENTS(commands);

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
			ERROR("Error opening \"%s\": %s", path, fr_syserror(errno));
			ret = -1;
			goto done;
		}

		filename = path;
	}

	process_filename = filename;

	/*
	 *	Loop over lines in the file or stdin
	 */
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		char			*p = strchr(buffer, '\n');
		command_func_t		func;
		command_result_t	result = { .rcode = RESULT_OK };	/* Reset to OK */
		size_t			match_len;

		cc.lineno++;

		if (!p) {
			if (!feof(fp)) {
				ERROR("Line %d too long in %s", cc.lineno, cc.path);
				ret = -1;
				goto done;
			}
		} else {
			*p = '\0';
		}

		p = buffer;
		fr_skip_whitespace(p);
		if (*p == '\0') continue;				/* Blank line */

		process_lineno = cc.lineno;
		DEBUG2("%s[%d]: %s", filename, cc.lineno, p);

		/*
		 *	Look up the command by longest prefix
		 */
		func = fr_table_value_by_longest_prefix(&match_len, commands, p, -1, NULL);
		if (!func) {
		bad_input:
			ERROR("%s[%d]: Unknown command: %s", cc.path, cc.lineno, p);
			ret = -1;
			goto done;
		}

		if (func == command_comment) continue;			/* Skip comments */

		p += match_len;						/* Jump to after the command */
		fr_skip_whitespace(p);					/* Skip any whitespace */

		data_len = func(&result, &cc, data, data_len, p);	/* Call the command function */
		DEBUG2("%s[%d]: --> %s", filename, cc.lineno,
		       fr_table_str_by_value(command_rcode_table, result.rcode, "<INVALID>"));

		switch (result.rcode) {
		/*
		 *	Command completed successfully
		 */
		case RESULT_OK:
			continue;

		/*
		 *	If this is a file, then break out of the loop
		 *	and cleanup, otherwise we need to find the
		 *	EOF marker in the input stream.
		 */
		case RESULT_SKIP_FILE:
			if (fp != stdin) goto done;

			/*
			 *	Skip over the input stream until we
			 *	find an eof command, or the stream
			 *	is closed.
			 */
			while (fgets(buffer, sizeof(buffer), fp) != NULL) {
				func = fr_table_value_by_longest_prefix(&match_len, commands,
									buffer, -1, NULL);
				if (!func) goto bad_input;

				if (func == command_eof) break;
			}
			break;

		/*
		 *	Fatal error parsing a command
		 */
		case RESULT_PARSE_ERROR:
		case RESULT_COMMAND_ERROR:
			PERROR("%s[%d]", filename, cc.lineno);
			ret = -1;
			goto done;

		/*
		 *	Write out any errors in the error stack to
		 *	the data buffer, so they can be checked for
		 *	correctness.
		 */
		case RESULT_DRAIN_ERROR_STACK_TO_DATA:
			data_len = strerror_concat(data, sizeof(data));
			break;

		/*
		 *	Result didn't match what we expected
		 */
		case RESULT_MISMATCH:
		{
			char *g, *e, *g_p, *e_p;
			char *spaces;

			g = fr_asprintf(cc.tmp_ctx, "%pV",
					fr_box_strvalue_len(result.got, result.got_len));
			e = fr_asprintf(cc.tmp_ctx, "%pV",
					fr_box_strvalue_len(result.expected, result.expected_len));
			g_p = g;
			e_p = e;

			ERROR("Mismatch at line %d of %s", cc.lineno, cc.path);
			ERROR("  got      : %s", g);
			ERROR("  expected : %s", e);

			while (*g_p && *e_p && (*g_p == *e_p)) {
				g_p++;
				e_p++;
			}

			assert((size_t)(e_p - e) <= result.got_len);
			assert((size_t)(e_p - e) <= result.expected_len);

			spaces = talloc_zero_array(NULL, char, (e_p - e) + 1);
			memset(spaces, ' ', talloc_array_length(spaces) - 1);
			ERROR("             %s^ differs here", spaces);
			talloc_free(spaces);
			talloc_free(g);
			talloc_free(e);
			ret = -1;

			goto done;
		}
		}
	}

done:
	if (fp != stdin) fclose(fp);

	/*
	 *	Free any residual resources re loaded.
	 */
	TALLOC_FREE(cc.tmp_ctx);
	fr_dict_free(&cc.proto_dict);
	unload_proto_library();

	return ret;
}

static void usage(char *argv[])
{
	ERROR("usage: %s [OPTS] filename\n", argv[0]);
	ERROR("  -d <raddb>         Set user dictionary path (defaults to " RADDBDIR ").");
	ERROR("  -D <dictdir>       Set main dictionary path (defaults to " DICTDIR ").");
	ERROR("  -x                 Debugging mode.");
	ERROR("  -f                 Print features.");
	ERROR("  -M                 Show talloc memory report.");
	ERROR("  -r <receipt_file>  Create the <receipt_file> as a 'success' exit.");
}

int main(int argc, char *argv[])
{
	int			c;
	char const		*raddb_dir = RADDBDIR;
	char const		*dict_dir = DICTDIR;
	char const		*receipt_file = NULL;
	int			*inst = &c;
	CONF_SECTION		*cs, *features;
	fr_dict_t		*dict = NULL;
	int			ret = EXIT_SUCCESS;
	TALLOC_CTX		*autofree = talloc_autofree_context();
	dl_module_loader_t	*dl_modules = NULL;

#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("unit_test_attribute");
		goto cleanup;
	}
#endif
	/*
	 *	Allocate a root config section so we can write
	 *	out features and versions.
	 */
	MEM(cs = cf_section_alloc(autofree, NULL, "unit_test_attribute", NULL));
	MEM(features = cf_section_alloc(cs, cs, "feature", NULL));
	dependency_features_init(features);	/* Add build time features to the config section */

	while ((c = getopt(argc, argv, "d:D:fxMhr:")) != -1) switch (c) {
		case 'd':
			raddb_dir = optarg;
			break;

		case 'D':
			dict_dir = optarg;
			break;

		case 'f':
		{
			CONF_PAIR *cp;

			for (cp = cf_pair_find(features, CF_IDENT_ANY);
			     cp;
			     cp = cf_pair_find_next(features, cp, CF_IDENT_ANY)) {
				fprintf(stdout, "%s %s\n", cf_pair_attr(cp), cf_pair_value(cp));
			}
			goto cleanup;
		}

		case 'x':
			fr_debug_lvl++;
			default_log.dst = L_DST_STDOUT;
			default_log.fd = STDOUT_FILENO;
			break;

		case 'M':
			talloc_enable_leak_report();
			break;

		case 'r':
			receipt_file = optarg;
			break;

		case 'h':
		default:
			usage(argv);
			ret = EXIT_SUCCESS;
			goto cleanup;
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	if (receipt_file && (fr_file_unlink(receipt_file) < 0)) {
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

	dl_loader = dl_loader_init(autofree, NULL, NULL, false, false);
	if (!dl_loader) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_global_init(autofree, dict_dir) < 0) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_internal_afrom_file(&dict, FR_DICTIONARY_INTERNAL_DIR) < 0) {
		fr_perror("unit_test_attribute");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Load the custom dictionary
	 */
	if (fr_dict_read(dict, raddb_dir, FR_DICTIONARY_FILE) == -1) {
		PERROR("Failed initialising the dictionaries");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Initialise the interpreter, registering operations.
	 *	Needed because some keywords also register xlats.
	 */
	if (unlang_init() < 0) return -1;

	if (xlat_register(inst, "test", xlat_test, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true) < 0) {
		ERROR("Failed registering xlat");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Read tests from stdin
	 */
	if (argc < 2) {
		if (process_file(autofree, features, dict, NULL, "-") < 0) ret = EXIT_FAILURE;

	/*
	 *	...or process each file in turn.
	 */
	} else {
		int i;

		for (i = 1; i < argc; i++) if (process_file(autofree, features,
							    dict, NULL, argv[i]) < 0) ret = EXIT_FAILURE;
	}

	/*
	 *	Try really hard to free any allocated
	 *	memory, so we get clean talloc reports.
	 */
cleanup:
	if (dl_modules) talloc_free(dl_modules);
	fr_dict_free(&dict);
	unlang_free();
	xlat_free();
	fr_strerror_free();

	if (receipt_file && (ret == EXIT_SUCCESS) && (fr_file_touch(receipt_file, 0644) < 0)) {
		fr_perror("unit_test_attribute");
		ret = EXIT_FAILURE;
	}

	return ret;
}
