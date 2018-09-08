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
 * @copyright 2010  Alan DeKok <aland@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/util/base.h>

typedef struct REQUEST REQUEST;

#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/map.h>

#include <freeradius-devel/server/parser.h>
#include <freeradius-devel/server/xlat.h>
#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/dl.h>
#include <freeradius-devel/server/dependency.h>
#include <freeradius-devel/server/command.h>
#include <freeradius-devel/io/test_point.h>

#ifdef WITH_TACACS
#  include <freeradius-devel/tacacs/tacacs.h>
#endif

#include <ctype.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <assert.h>

#include <freeradius-devel/server/log.h>
extern fr_log_lvl_t rad_debug_lvl;

#include <sys/wait.h>
pid_t rad_fork(void);
pid_t rad_waitpid(pid_t pid, int *status);

pid_t rad_fork(void)
{
	return fork();
}

pid_t rad_waitpid(pid_t pid, int *status)
{
	return waitpid(pid, status, 0);
}

static ssize_t xlat_test(UNUSED TALLOC_CTX *ctx, UNUSED char **out, UNUSED size_t outlen,
			 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 UNUSED REQUEST *request, UNUSED char const *fmt)
{
	return 0;
}

static char proto_name_prev[128];
static void *dl_handle;

/** Concatenate error stack
 */
static inline void strerror_concat(char *out, size_t outlen)
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
}

/*
 *	End of hacks for xlat
 *
 **********************************************************************/

static int encode_tlv(char *buffer, uint8_t *output, size_t outlen);

static char const hextab[] = "0123456789abcdef";

static int encode_data_string(char *buffer,
			      uint8_t *output, size_t outlen)
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

	fprintf(stderr, "String is not terminated\n");
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
		fprintf(stderr, "No trailing '}' in string starting "
			"with \"%s\"\n",
			buffer);
		return 0;
	}

	*endptr = p + 1;
	*p = '\0';

	p = buffer + 1;
	while (isspace((int) *p)) p++;

	length = encode_tlv(p, output, outlen);
	if (length == 0) return 0;

	return length;
}

static int encode_hex(char *p, uint8_t *output, size_t outlen)
{
	int length = 0;
	while (*p) {
		char *c1, *c2;

		while (isspace((int) *p)) p++;

		if (!*p) break;

		if(!(c1 = memchr(hextab, tolower((int) p[0]), 16)) ||
		   !(c2 = memchr(hextab, tolower((int)  p[1]), 16))) {
			fprintf(stderr, "Invalid data starting at "
				"\"%s\"\n", p);
			return 0;
		}

		*output = ((c1 - hextab) << 4) + (c2 - hextab);
		output++;
		length++;
		p += 2;

		outlen--;
		if (outlen == 0) {
			fprintf(stderr, "Too much data\n");
			return 0;
		}
	}

	return length;
}


static int encode_data(char *p, uint8_t *output, size_t outlen)
{
	int length;

	if (!isspace((int) *p)) {
		fprintf(stderr, "Invalid character following attribute "
			"definition\n");
		return 0;
	}

	while (isspace((int) *p)) p++;

	if (*p == '{') {
		int sublen;
		char *q;

		length = 0;

		do {
			while (isspace((int) *p)) p++;
			if (!*p) {
				if (length == 0) {
					fprintf(stderr, "No data\n");
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

	length = encode_hex(p, output, outlen);

	if (length == 0) {
		fprintf(stderr, "Empty string\n");
		return 0;
	}

	return length;
}

static int decode_attr(char *buffer, char **endptr)
{
	long attr;

	attr = strtol(buffer, endptr, 10);
	if (*endptr == buffer) {
		fprintf(stderr, "No valid number found in string "
			"starting with \"%s\"\n", buffer);
		return 0;
	}

	if (!**endptr) {
		fprintf(stderr, "Nothing follows attribute number\n");
		return 0;
	}

	if ((attr <= 0) || (attr > 256)) {
		fprintf(stderr, "Attribute number is out of valid "
			"range\n");
		return 0;
	}

	return (int) attr;
}

static int decode_vendor(char *buffer, char **endptr)
{
	long vendor;

	if (*buffer != '.') {
		fprintf(stderr, "Invalid separator before vendor id\n");
		return 0;
	}

	vendor = strtol(buffer + 1, endptr, 10);
	if (*endptr == (buffer + 1)) {
		fprintf(stderr, "No valid vendor number found\n");
		return 0;
	}

	if (!**endptr) {
		fprintf(stderr, "Nothing follows vendor number\n");
		return 0;
	}

	if ((vendor <= 0) || (vendor > (1 << 24))) {
		fprintf(stderr, "Vendor number is out of valid range\n");
		return 0;
	}

	if (**endptr != '.') {
		fprintf(stderr, "Invalid data following vendor number\n");
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
		fprintf(stderr, "TLV data is too long\n");
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
		fprintf(stderr, "VSA data is too long\n");
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
		fprintf(stderr, "Extended Attr data is too long\n");
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
			fprintf(stderr, "Invalid data following "
				"attribute number\n");
			return 0;
		}

		if (attr < 245) {
			sublen = encode_extended(p + 1,
						 output + 2, outlen - 2);
		} else {

			/*
			 *	Not like the others!
			 */
			return encode_long_extended(p + 1, output, outlen);
		}
	}
	if (sublen == 0) return 0;
	if (sublen > (255 -2)) {
		fprintf(stderr, "RFC Data is too long\n");
		return 0;
	}

	output[1] += sublen;
	return length + sublen;
}

static void parse_condition(char const *input, char *output, size_t outlen)
{
	ssize_t dec_len;
	char const *error = NULL;
	fr_cond_t *cond;

	dec_len = fr_cond_tokenize(NULL, NULL, input, &cond, &error, FR_COND_ONE_PASS);
	if (dec_len <= 0) {
		snprintf(output, outlen, "ERROR offset %d %s", (int) -dec_len, error);
		return;
	}

	input += dec_len;
	if (*input != '\0') {
		talloc_free(cond);
		snprintf(output, outlen, "ERROR offset %d 'Too much text'", (int) dec_len);
		return;
	}

	cond_snprint(output, outlen, cond);

	talloc_free(cond);
}

static void parse_xlat(char const *input, char *output, size_t outlen)
{
	ssize_t		dec_len;
	char const	*error = NULL;
	char		*fmt;
	xlat_exp_t	*head;

	fmt = talloc_typed_strdup(NULL, input);
	dec_len = xlat_tokenize(fmt, fmt, &head, &error);

	if (dec_len <= 0) {
		snprintf(output, outlen, "ERROR offset %d '%s'", (int) -dec_len, error);
		talloc_free(fmt);
		return;
	}

	if (input[dec_len] != '\0') {
		snprintf(output, outlen, "ERROR offset %d 'Too much text'", (int) dec_len);
		talloc_free(fmt);
		return;
	}

	xlat_snprint(output, outlen, head);
	talloc_free(fmt);
}

static void unload_proto_library(void)
{
	if (dl_handle) {
		dlclose(dl_handle);
		dl_handle = NULL;
	}
}

static size_t load_proto_library(char const *proto_name)
{
	char dl_name[128];

	if (strcmp(proto_name_prev, proto_name) != 0) {
		/*
		 *	Ensure the old proto library is unloaded
		 */
		unload_proto_library();

		snprintf(dl_name, sizeof(dl_name), "libfreeradius-%s", proto_name);
		if (dl_handle) {
			dlclose(dl_handle);
			dl_handle = NULL;
		}

		dl_handle = dl_by_name(dl_name);
		if (!dl_handle) {
			fprintf(stderr, "Failed to link to library \"%s\": %s\n", dl_name, fr_strerror());
			unload_proto_library();
			return -1;
		}

		strlcpy(proto_name_prev, proto_name, sizeof(proto_name_prev));
	}

	return strlen(proto_name);
}

static size_t load_test_point_by_command(void **symbol, char *command, size_t offset, char const *dflt_symbol)
{
	char		buffer[128];
	char const	*p, *q;
	char const	*symbol_name;
	void		*dl_symbol;

	if (!dl_handle) {
		fprintf(stderr, "No protocol library loaded. Specify library with \"load <proto name>\"\n");
		exit(EXIT_FAILURE);
	}

	p = command + offset;
	q = strchr(p, '.');

	/*
	 *	Use the dflt_symbol name as the test point
	 */
	if (q) {
		symbol_name = q + 1;
	} else {
		snprintf(buffer, sizeof(buffer), "%s_%s", proto_name_prev, dflt_symbol);
		symbol_name = buffer;
	}

	dl_symbol = dlsym(dl_handle, symbol_name);
	if (!dl_symbol) {
		fprintf(stderr, "Test point (symbol \"%s\") not exported by library\n", symbol_name);
		unload_proto_library();
		exit(EXIT_FAILURE);
	}
	*symbol = dl_symbol;

	p += strlen(p);

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
	printf("\n");

	return 1;
}

static void command_print(void)
{
	void *walk_ctx = NULL;

	printf("Command hierarchy --------\n");
	fr_command_debug(stdout, command_head);

	printf("Command list --------\n");
	while (fr_command_walk(command_head, &walk_ctx, NULL, command_walk) == 1) {
		// do nothing
	}
}

/*
 *	Add a command by talloc'ing a table for it.
 */
static void command_add(TALLOC_CTX *ctx, char *input, char *output, size_t outlen)
{
	char *p, *name;
	char *parent = NULL;
	fr_cmd_table_t *table;

	table = talloc_zero(ctx, fr_cmd_table_t);

	p = strchr(input, ':');
	if (!p) {
		snprintf(output, outlen, "no ':name' specified");
		return;
	}

	*p = '\0';
	p++;


	if (input) parent = talloc_strdup(ctx, input);

	/*
	 *	Set the name and try to find the syntax.
	 */
	name = p;
	while (*p && !isspace((int) *p)) p++;

	if (isspace(*p)) {
		*p = '\0';
		p++;
	}

	while (*p && isspace((int) *p)) p++;

	if (*p) {
		table->syntax = talloc_strdup(table, p);
	}
	table->parent = parent;
	table->name = name;
	table->help = NULL;
	table->func = command_func;
	table->tab_expand = NULL;
	table->read_only = true;

	if (fr_command_add(ctx, &command_head, NULL, NULL, table) < 0) {
		snprintf(output, outlen, "ERROR: failed adding command - %s", fr_strerror());
		return;
	}

	if (rad_debug_lvl) command_print();

	snprintf(output, outlen, "ok");
	fflush(stdout);
}

/*
 *	Do tab completion on a command
 */
static void command_tab(TALLOC_CTX *ctx, char *input, char *output, size_t outlen)
{
	int i;
	int num_expansions;
	char const *expansions[CMD_MAX_ARGV];
	char *p, **argv;
	fr_cmd_info_t info;

	info.argc = 0;
	info.max_argc = CMD_MAX_ARGV;
	info.argv = talloc_zero_array(ctx, char const *, CMD_MAX_ARGV);
	info.box = talloc_zero_array(ctx, fr_value_box_t *, CMD_MAX_ARGV);

	memcpy(&argv, &info.argv, sizeof(argv)); /* const issues */
	info.argc = fr_dict_str_to_argv(input, argv, CMD_MAX_ARGV);
	if (info.argc <= 0) {
		snprintf(output, outlen, "Failed splitting input");
		return;
	}

	num_expansions = fr_command_tab_expand(ctx, command_head, &info, CMD_MAX_ARGV, expansions);

	snprintf(output, outlen, "%d - ", num_expansions);
	p = output + strlen(output);

	for (i = 0; i < num_expansions; i++) {
		snprintf(p, outlen - (p - output), "'%s', ", expansions[i]);
		p += strlen(p);
	}

	/*
	 *	Remove the trailing ", "
	 */
	if (num_expansions > 0) {
		p -= 2;
		*p = '\0';
	}
}

static void command_parse(TALLOC_CTX *ctx, char *input, char *output, size_t outlen)
{
	if (strncmp(input, "add ", 4) == 0) {
		command_add(ctx, input + 4, output, outlen);
		return;
	}

	if (strncmp(input, "tab ", 4) == 0) {
		command_tab(ctx, input + 4, output, outlen);
		return;
	}
	snprintf(output, outlen, "Unknown command '%s'", input);
}

static int process_file(CONF_SECTION *features, fr_dict_t *dict, const char *root_dir, char const *filename)
{
	int		lineno;
	size_t		i, outlen;
	ssize_t		len, data_len;
	FILE		*fp;
	char		input[8192], buffer[8192];
	char		output[8192];
	char		directory[8192];
	uint8_t		*attr, data[2048];
	TALLOC_CTX	*tp_ctx = talloc_init("tp_ctx");

	if (strcmp(filename, "-") == 0) {
		fp = stdin;
		filename = "<stdin>";
		directory[0] = '\0';

	} else {
		if (root_dir && *root_dir) {
			snprintf(directory, sizeof(directory), "%s/%s", root_dir, filename);
		} else {
			strlcpy(directory, filename, sizeof(directory));
		}

		fp = fopen(directory, "r");
		if (!fp) {
			fprintf(stderr, "Error opening %s: %s\n",
				directory, fr_syserror(errno));
			exit(EXIT_FAILURE);
		}

		filename = directory;
	}

	lineno = 0;
	*output = '\0';
	data_len = 0;

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		char			*p = strchr(buffer, '\n'), *q;
		char			test_type[128];
		VALUE_PAIR		*vp, *head = NULL;

		lineno++;

		if (!p) {
			if (!feof(fp)) {
				fprintf(stderr, "Line %d too long in %s\n",
					lineno, directory);
				goto error;
			}
		} else {
			*p = '\0';
		}

		/*
		 *	Comments, with hacks for User-Name[#]
		 */
		p = strchr(buffer, '#');
		if (p && ((p == buffer) ||
			  ((p > buffer) && (p[-1] != '[')))) *p = '\0';

		p = buffer;
		while (isspace((int) *p)) p++;
		if (!*p) continue;

		DEBUG2("%s[%d]: %s\n", filename, lineno, buffer);

		strlcpy(input, p, sizeof(input));

		q = strchr(p, ' ');
		if (q && ((size_t)(q - p) > (sizeof(test_type) - 1))) {
			fprintf(stderr, "Verb \"%.*s\" is too long\n", (int)(q - p), p);
			goto error;
		}

		if (!q) q = p + strlen(p);

		strlcpy(test_type, p, (q - p) + 1);

		if (strcmp(test_type, "load") == 0) {
			p += 5;
			load_proto_library(p);
			continue;
		}

		if (strcmp(test_type, "need-feature") == 0) {
			CONF_PAIR *cp;
			p += 12;

			if (*p != ' ') {
				fprintf(stderr, "Prerequisite syntax is \"need-feature <feature>\".  Use -f to print features");
				goto error;
			}
			p++;

			cp = cf_pair_find(features, p);
			if (!cp || (strcmp(cf_pair_value(cp), "yes") != 0)) {
				fprintf(stdout, "Skipping, missing feature \"%s\"\n", p);
				if (fp != stdin) fclose(fp);
				talloc_free(tp_ctx);
				return 0; /* Skip this file */
			}
			continue;
		}

		if (strcmp(test_type, "raw") == 0) {
			outlen = encode_rfc(p + 4, data, sizeof(data));
			if (outlen == 0) {
				fprintf(stderr, "Parse error in line %d of %s\n", lineno, directory);
			error:
				unload_proto_library();	/* Cleanup */
				talloc_free(tp_ctx);

				return -1;
			}

		print_hex:
			if (outlen == 0) {
				output[0] = 0;
				continue;
			}

			if (outlen >= (sizeof(output) / 2)) {
				outlen = (sizeof(output) / 2) - 1;
			}

			data_len = outlen;
			for (i = 0; i < outlen; i++) {
				if (sizeof(output) < (3*i)) break;

				snprintf(output + (3 * i), sizeof(output) - (3 * i) - 1, "%02x ", data[i]);
			}
			outlen = strlen(output);
			output[outlen - 1] = '\0';
			continue;
		}

		if (strcmp(test_type, "data") == 0) {
			/*
			 *	Handle "no data expected"
			 */
			if (((p[4] == '\0') || (p[5] == '\0')) && (output[0] != '\0')) {
				fprintf(stderr, "Mismatch at line %d of %s\n\tgot      : %s\n\texpected :\n",
					lineno, directory, output);
				goto error;
			}

			if (strcmp(p + 5, output) != 0) {
				fprintf(stderr, "Mismatch at line %d of %s\n\tgot      : %s\n\texpected : %s\n",
					lineno, directory, output, p + 5);
				goto error;
			}
			fr_strerror();	/* Clear the error buffer */
			continue;
		}

#ifdef WITH_TACACS
		/*
		 *	And some TACACS tests
		 */
		if (strcmp(test_type, "encode-tacacs") == 0) {
			RADIUS_PACKET *packet = talloc(NULL, RADIUS_PACKET);

			if (strcmp(p + 14, "-") == 0) {
				WARN("cannot encode as client");
				p = output;
			} else {
				p += 14;
			}

			if (fr_pair_list_afrom_str(packet, p, &head) != T_EOL) {
				strerror_concat(output, sizeof(output));

				talloc_free(packet);
				continue;
			}

			packet->vps = head;
			if (fr_tacacs_packet_encode(packet, NULL, 0) < 0) {
				strerror_concat(output, sizeof(output));
				talloc_free(packet);
				continue;
			}

			outlen = packet->data_len;
			memcpy(data, packet->data, outlen);
			talloc_free(packet);

			goto print_hex;
		}

		if (strcmp(test_type, "decode-tacacs") == 0) {
			fr_cursor_t cursor;
			RADIUS_PACKET *packet = talloc(NULL, RADIUS_PACKET);

			if (strcmp(p + 14, "-") == 0) {
				WARN("cannot decode as client");
				attr = data;
				len = data_len;
			} else {
				attr = data;
				len = encode_hex(p + 14, data, sizeof(data));
				if (len == 0) {
					fprintf(stderr, "Failed decoding hex string at line %d of %s\n", lineno, directory);
					goto error;
				}
			}

			packet->vps = NULL;
			packet->data = attr;
			packet->data_len = len;

			if (fr_tacacs_packet_decode(packet) < 0) {
				strerror_concat(output, sizeof(output));
				talloc_free(packet);
				continue;
			}

			fr_cursor_init(&cursor, &packet->vps);
			p = output;
			for (vp = fr_cursor_head(&cursor); vp; vp = fr_cursor_next(&cursor)) {
				fr_pair_snprint(p, sizeof(output) - (p - output), vp);
				p += strlen(p);

				if (vp->next) {
					strcpy(p, ", ");
					p += 2;
				}
			}

			talloc_free(packet);
			continue;
		}
#endif	/* WITH_TACACS */

		if (strcmp(test_type, "attribute") == 0) {
			p += 10;

			if (fr_pair_list_afrom_str(NULL, p, &head) != T_EOL) {
				strerror_concat(output, sizeof(output));
				continue;
			}

			fr_pair_snprint(output, sizeof(output), head);
			fr_pair_list_free(&head);
			continue;
		}

		if (strcmp(test_type, "dictionary") == 0) {
			p += 11;

			if (fr_dict_parse_str(dict, p, fr_dict_root(dict), 0) < 0) {
				strerror_concat(output, sizeof(output));
				continue;
			}

			strlcpy(output, "ok", sizeof(output));
			continue;
		}

		if (strcmp(test_type, "$INCLUDE") == 0) {
			p += 9;
			while (isspace((int) *p)) p++;

			q = strrchr(directory, '/');
			if (q) {
				*q = '\0';
				process_file(features, dict, directory, p);
				*q = '/';
			} else {
				process_file(features, dict, NULL, p);
			}
			continue;
		}

		if (strcmp(test_type, "condition") == 0) {
			p += 10;
			parse_condition(p, output, sizeof(output));
			continue;
		}

		if (strcmp(test_type, "xlat") == 0) {
			p += 5;
			parse_xlat(p, output, sizeof(output));
			continue;
		}

		if (strcmp(test_type, "attribute") == 0) {
			p += 10;

			if (fr_pair_list_afrom_str(NULL, p, &head) != T_EOL) {
				strerror_concat(output, sizeof(output));
				continue;
			}

			fr_pair_snprint(output, sizeof(output), head);
			fr_pair_list_free(&head);
			continue;
		}

		if (strcmp(test_type, "dictionary") == 0) {
			p += 11;

			if (fr_dict_parse_str(dict, p, fr_dict_root(dict), 0) < 0) {
				strerror_concat(output, sizeof(output));
				continue;
			}

			strlcpy(output, "ok", sizeof(output));
			continue;
		}

		if (strcmp(test_type, "$INCLUDE") == 0) {
			p += 9;
			while (isspace((int) *p)) p++;

			q = strrchr(directory, '/');
			if (q) {
				*q = '\0';
				process_file(features, dict, directory, p);
				*q = '/';
			} else {
				process_file(features, dict, NULL, p);
			}
			continue;
		}

		if (strcmp(test_type, "condition") == 0) {
			p += 10;
			parse_condition(p, output, sizeof(output));
			continue;
		}

		if (strcmp(test_type, "xlat") == 0) {
			p += 5;
			parse_xlat(p, output, sizeof(output));
			continue;
		}

		/*
		 *	Generic pair decode test point
		 */
		if (strncmp(test_type, "decode-pair", 11) == 0) {
			fr_test_point_pair_decode_t	*tp = NULL;
			ssize_t				dec_len = 0;
			fr_cursor_t 			cursor;
			void				*decoder_ctx = NULL;

			p += load_test_point_by_command((void **)&tp, test_type, 11, "tp_decode") + 1;
			if (tp->test_ctx) decoder_ctx = tp->test_ctx(tp_ctx);

			if (strcmp(p, "-") == 0) {
				attr = data;
				len = data_len;
			} else {
				attr = data;
				len = encode_hex(p, data, sizeof(data));
				if (len == 0) {
					fprintf(stderr, "Failed decoding hex string at line %d of %s\n",
						lineno, directory);
					goto error;
				}
			}

			fr_cursor_init(&cursor, &head);
			while (len > 0) {
				dec_len = tp->func(tp_ctx, &cursor, attr, len, decoder_ctx);
				if (dec_len < 0) {
					fr_pair_list_free(&head);
					break;
				}
				if (dec_len > len) {
					fprintf(stderr, "Internal sanity check failed at %d\n", __LINE__);
					goto error;
				}
				attr += dec_len;
				len -= dec_len;
			}

			/*
			 *	Output may be an error, and we ignore
			 *	it if so.
			 */
			if (head) {
				p = output;
				for (vp = fr_cursor_head(&cursor);
				     vp;
				     vp = fr_cursor_next(&cursor)) {
					fr_pair_snprint(p, sizeof(output) - (p - output), vp);
					p += strlen(p);

					if (vp->next) {
						strcpy(p, ", ");
						p += 2;
					}
				}

				fr_pair_list_free(&head);
			} else if (dec_len < 0) {
				char *out_p = output, *out_end = out_p + sizeof(output);
				char const *err;

				snprintf(output, sizeof(output), "%zd", dec_len);	/* Overwritten with real error */

				while ((err = fr_strerror_pop()) && (out_p < out_end)) {
					if (out_p != output) out_p += strlcpy(out_p, ": ", out_end - out_p);
					out_p += strlcpy(out_p, err, out_end - out_p);
				}
			} else { /* zero-length attribute */
				*output = '\0';
			}
			talloc_free_children(tp_ctx);
			continue;
		}

		/*
		 *	Generic pair encode test point
		 */
		if (strncmp(test_type, "encode-pair", 11) == 0) {
			fr_test_point_pair_encode_t	*tp = NULL;
			ssize_t				enc_len = 0;
			fr_cursor_t			cursor;
			void				*encoder_ctx = NULL;

			p += load_test_point_by_command((void **)&tp, test_type, 11, "tp_encode") + 1;
			if (tp->test_ctx) encoder_ctx = tp->test_ctx(tp_ctx);

			/*
			 *	Encode the previous output
			 */
			if (strcmp(p, "-") == 0) p = output;

			if (fr_pair_list_afrom_str(tp_ctx, p, &head) != T_EOL) {
				strerror_concat(output, sizeof(output));
				continue;
			}

			attr = data;
			fr_cursor_init(&cursor, &head);
			while ((vp = fr_cursor_current(&cursor))) {
				enc_len = tp->func(attr, data + sizeof(data) - attr, &cursor, encoder_ctx);
				if (enc_len < 0) {
					char *out_p = output, *out_end = out_p + sizeof(output);
					char const *err;

					snprintf(output, sizeof(output), "%zd", enc_len);	/* Overwritten with real error */

					while ((err = fr_strerror_pop()) && (out_p < out_end)) {
						if (out_p != output) out_p += strlcpy(out_p, ": ", out_end - out_p);
						out_p += strlcpy(out_p, err, out_end - out_p);
					}
					fr_pair_list_free(&head);
					talloc_free_children(tp_ctx);
					goto next;
				}

				attr += enc_len;
				if (enc_len == 0) break;
			}
			fr_pair_list_free(&head);

			outlen = attr - data;

			talloc_free_children(tp_ctx);
			goto print_hex;
		}

		/*
		 *	Generic proto decode test point
		 */
		if (strncmp(test_type, "decode-proto", 12) == 0) {
			fr_test_point_proto_decode_t *tp;

			load_test_point_by_command((void **)&tp, test_type, 12, "tp_decode");

			continue;
		}

		/*
		 *	Generic proto encode test point
		 */
		if (strncmp(test_type, "encode-proto", 12) == 0) {
			fr_test_point_proto_encode_t *tp;

			load_test_point_by_command((void **)&tp, test_type, 12, "tp_encode");

			continue;
		}

		/*
		 *	Test the command API
		 */
		if (strcmp(test_type, "command") == 0) {
			p += 8;
			command_parse(tp_ctx, p, output, sizeof(output));
			continue;
		}

		fprintf(stderr, "Unknown input at line %d of %s: %s\n", lineno, directory, p);

		goto error;

	next:
		continue;
	}

	if (fp != stdin) fclose(fp);

	unload_proto_library();	/* Cleanup */
	talloc_free(tp_ctx);

	return 0;
}

static void usage(void)
{
	fprintf(stderr, "usage: unit_test_attribute [OPTS] filename\n");
	fprintf(stderr, "  -d <raddb>             Set user dictionary directory (defaults to " RADDBDIR ").\n");
	fprintf(stderr, "  -D <dictdir>           Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");
	fprintf(stderr, "  -f                     Print features.\n");
	fprintf(stderr, "  -M                     Show talloc memory report.\n");
}

int main(int argc, char *argv[])
{
	int		c;
	char const	*raddb_dir = RADDBDIR;
	char const	*dict_dir = DICTDIR;
	int		*inst = &c;
	CONF_SECTION	*cs, *features;
	fr_dict_t	*dict = NULL;
	int		ret = EXIT_SUCCESS;

	TALLOC_CTX	*autofree = talloc_autofree_context();

#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("unit_test_attribute");
		goto done;
	}
#endif
	/*
	 *	Allocate a root config section so we can write
	 *	out features and versions.
	 */
	MEM(cs = cf_section_alloc(autofree, NULL, "unit_test_attribute", NULL));
	MEM(features = cf_section_alloc(cs, cs, "feature", NULL));
	dependency_features_init(features);	/* Add build time features to the config section */

	while ((c = getopt(argc, argv, "d:D:fxMh")) != EOF) switch (c) {
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
			goto done;
		}

		case 'x':
			fr_debug_lvl++;
			rad_debug_lvl = fr_debug_lvl;
			fr_log_fp = stdout;
			default_log.dst = L_DST_STDOUT;
			default_log.fd = STDOUT_FILENO;
			break;

		case 'M':
			talloc_enable_leak_report();
			break;

		case 'h':
		default:
			usage();
			ret = EXIT_FAILURE;
			goto done;
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("unit_test_attribute");
		ret = EXIT_FAILURE;
		goto done;
	}

	if (fr_dict_global_init(autofree, dict_dir) < 0) {
		fr_perror("unit_test_attribute");
		exit(EXIT_FAILURE);
	}

	if (fr_dict_from_file(&dict, FR_DICTIONARY_FILE) < 0) {
		fr_perror("unit_test_attribute");
		ret = EXIT_FAILURE;
		goto done;
	}

	if (fr_dict_read(dict, raddb_dir, FR_DICTIONARY_FILE) == -1) {
		fr_log_perror(&default_log, L_ERR, "Failed to initialize the dictionaries");
		ret = EXIT_FAILURE;
		goto done;
	}

	if (xlat_register(inst, "test", xlat_test, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true) < 0) {
		fprintf(stderr, "Failed registering xlat");
		ret = EXIT_FAILURE;
		goto done;
	}

	if (argc < 2) {
		if (process_file(features, dict, NULL, "-") < 0) ret = EXIT_FAILURE;
	} else {
		if (process_file(features, dict, NULL, argv[1]) < 0) ret = EXIT_FAILURE;
	}

	/*
	 *	Try really hard to free any allocated
	 *	memory, so we get clean talloc reports.
	 */
done:
	xlat_free();
	fr_strerror_free();

	return ret;
}
