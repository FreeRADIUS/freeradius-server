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
 * Copyright 2010  Alan DeKok <aland@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>

typedef struct REQUEST REQUEST;

#include <freeradius-devel/tmpl.h>
#include <freeradius-devel/map.h>

#include <freeradius-devel/parser.h>
#include <freeradius-devel/xlat.h>
#include <freeradius-devel/conf.h>
#include <freeradius-devel/radpaths.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/cf_parse.h>
#include <freeradius-devel/cf_util.h>
#include <freeradius-devel/dl.h>
#include <freeradius-devel/dependency.h>
#include <freeradius-devel/io/test_point.h>

#ifdef WITH_TACACS
#include "../modules/proto_tacacs/tacacs.h"
#endif

#include <ctype.h>

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

#include <assert.h>

#include <freeradius-devel/log.h>
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

static RADIUS_PACKET my_packet = {
	.sockfd = -1,
	.id = 0,
	.code = FR_CODE_ACCESS_ACCEPT,
	.vector = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
};


static char *my_secret = NULL;

static char proto_name_prev[128];
static void *dl_handle;

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
	ssize_t dec_len;
	char const *error = NULL;
	char *fmt = talloc_typed_strdup(NULL, input);
	xlat_exp_t *head;

	dec_len = xlat_tokenize(fmt, fmt, &head, &error);
	if (dec_len <= 0) {
		snprintf(output, outlen, "ERROR offset %d '%s'", (int) -dec_len, error);
		return;
	}

	if (input[dec_len] != '\0') {
		snprintf(output, outlen, "ERROR offset %d 'Too much text'", (int) dec_len);
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

		strcpy(proto_name_prev, proto_name);
	}

	return strlen(proto_name);
}

static size_t load_test_point_by_command(void **symbol, char *command, size_t offset, char const *dflt_symbol)
{
	char const *p, *q;
	char const *symbol_name;
	void *dl_symbol;

	if (!dl_handle) {
		fprintf(stderr, "No protocol library loaded. Specify library with \"load <proto name>\"\n");
		exit(EXIT_FAILURE);
	}

	p = command + offset;
	q = strchr(p, '.');

	/*
	 *	Use the dflt_symbol name as the test point
	 */
	if (!q) {
		symbol_name = dflt_symbol;
	} else {
		symbol_name = q + 1;
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

static void process_file(CONF_SECTION *features, fr_dict_t *dict, const char *root_dir, char const *filename)
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
				exit(EXIT_FAILURE);
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
			exit(EXIT_FAILURE);
		}

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
				exit(EXIT_FAILURE);
			}
			p++;

			cp = cf_pair_find(features, p);
			if (!cp || (strcmp(cf_pair_value(cp), "yes") != 0)) {
				fprintf(stdout, "Skipping, missing feature \"%s\"", p);
				return; /* Skip this file */
			}
			continue;
		}

		if (strcmp(test_type, "raw") == 0) {
			outlen = encode_rfc(p + 4, data, sizeof(data));
			if (outlen == 0) {
				fprintf(stderr, "Parse error in line %d of %s\n",
					lineno, directory);
				exit(EXIT_FAILURE);
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

				snprintf(output + 3*i, sizeof(output) - (3*i) - 1,
					 "%02x ", data[i]);
			}
			outlen = strlen(output);
			output[outlen - 1] = '\0';
			continue;
		}

		if (strcmp(test_type, "data") == 0) {
			if (strcmp(p + 5, output) != 0) {
				fprintf(stderr, "Mismatch at line %d of %s\n\tgot      : %s\n\texpected : %s\n",
					lineno, directory, output, p + 5);
				exit(EXIT_FAILURE);
			}
			continue;
		}

		if (strcmp(test_type, "encode") == 0) {
			vp_cursor_t cursor;
			fr_radius_ctx_t encoder_ctx = { .vector = my_packet.vector,
							.secret = my_secret };

			/*
			 *	Encode the previous output
			 */
			if (strcmp(p + 7, "-") == 0) {
				p = output;
			} else {
				p += 7;
			}

			if (fr_pair_list_afrom_str(NULL, p, &head) != T_EOL) {
				strlcpy(output, fr_strerror(), sizeof(output));
				continue;
			}

			attr = data;
			fr_pair_cursor_init(&cursor, &head);
			while ((vp = fr_pair_cursor_current(&cursor))) {
				len = fr_radius_encode_pair(attr, data + sizeof(data) - attr, &cursor, &encoder_ctx);
				if (len < 0) {
					fprintf(stderr, "Failed encoding %s: %s\n",
						vp->da->name, fr_strerror());
					exit(EXIT_FAILURE);
				}

				attr += len;
				if (len == 0) break;
			}

			fr_pair_list_free(&head);
			outlen = attr - data;
			goto print_hex;
		}

		if (strcmp(test_type, "decode") == 0) {
			ssize_t		my_len;
			vp_cursor_t 	cursor;
			fr_radius_ctx_t decoder_ctx = { .vector = my_packet.vector,
							.secret = my_secret };
			if (strcmp(p + 7, "-") == 0) {
				attr = data;
				len = data_len;
			} else {
				attr = data;
				len = encode_hex(p + 7, data, sizeof(data));
				if (len == 0) {
					fprintf(stderr, "Failed decoding hex string at line %d of %s\n", lineno, directory);
					exit(EXIT_FAILURE);
				}
			}

			fr_pair_cursor_init(&cursor, &head);
			my_len = 0;
			while (len > 0) {
				my_len = fr_radius_decode_pair(NULL, &cursor, fr_dict_root(fr_dict_internal), attr, len,
							       &decoder_ctx);
				if (my_len < 0) {
					fr_pair_list_free(&head);
					break;
				}

				if (my_len > len) {
					fprintf(stderr, "Internal sanity check failed at %d\n", __LINE__);
					exit(EXIT_FAILURE);
				}

				attr += my_len;
				len -= my_len;
			}

			/*
			 *	Output may be an error, and we ignore
			 *	it if so.
			 */
			if (head) {
				p = output;
				for (vp = fr_pair_cursor_first(&cursor);
				     vp;
				     vp = fr_pair_cursor_next(&cursor)) {
					fr_pair_snprint(p, sizeof(output) - (p - output), vp);
					p += strlen(p);

					if (vp->next) {strcpy(p, ", ");
						p += 2;
					}
				}

				fr_pair_list_free(&head);
			} else if (my_len < 0) {
				strlcpy(output, fr_strerror(), sizeof(output));

			} else { /* zero-length attribute */
				*output = '\0';
			}
			continue;
		}

		/*
		 *	And some DHCP tests
		 */
		if (strcmp(test_type, "encode-dhcp") == 0) {
			vp_cursor_t cursor;

			if (strcmp(p + 12, "-") == 0) {
				p = output;
			} else {
				p += 12;
			}

			if (fr_pair_list_afrom_str(NULL, p, &head) != T_EOL) {
				strlcpy(output, fr_strerror(), sizeof(output));
				continue;
			}

			fr_pair_cursor_init(&cursor, &head);

			attr = data;
			while ((vp = fr_pair_cursor_current(&cursor))) {
				len = fr_dhcpv4_encode_option(attr, sizeof(data) - (data -attr), &cursor, NULL);
				if (len < 0) {
					fprintf(stderr, "Failed encoding %s: %s\n",
						vp->da->name, fr_strerror());
					exit(EXIT_FAILURE);
				}
				attr += len;
			};

			fr_pair_list_free(&head);
			outlen = attr - data;
			goto print_hex;
		}

		if (strcmp(test_type, "decode-dhcp") == 0) {
			vp_cursor_t cursor;
			ssize_t my_len = 0;

			if (strcmp(p + 12, "-") == 0) {
				attr = data;
				len = data_len;
			} else {
				attr = data;
				len = encode_hex(p + 12, data, sizeof(data));
				if (len == 0) {
					fprintf(stderr, "Failed decoding hex string at line %d of %s\n", lineno, directory);
					exit(EXIT_FAILURE);
				}
			}

			{
				uint8_t const *end, *option_p;

				option_p = attr;
				end = option_p + len;

				fr_pair_cursor_init(&cursor, &head);

				/*
				 *	Loop over all the options data
				 */
				while (option_p < end) {
					vp = NULL;
					my_len = fr_dhcpv4_decode_option(NULL, &cursor,
								       fr_dict_root(fr_dict_internal), option_p,
								       end - option_p, NULL);
					if (my_len <= 0) {
						fr_pair_list_free(&head);
						break;
					}
					option_p += my_len;
				}
			}

			/*
			 *	Output may be an error, and we ignore
			 *	it if so.
			 */
			if (head) {
				p = output;
				for (vp = fr_pair_cursor_first(&cursor);
				     vp;
				     vp = fr_pair_cursor_next(&cursor)) {
					fr_pair_snprint(p, sizeof(output) - (p - output), vp);
					p += strlen(p);

					if (vp->next) {strcpy(p, ", ");
						p += 2;
					}
				}

				fr_pair_list_free(&head);
			} else if (my_len < 0) {
				strlcpy(output, fr_strerror(), sizeof(output));

			} else { /* zero-length attribute */
				*output = '\0';
			}
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
				strlcpy(output, fr_strerror(), sizeof(output));
				talloc_free(packet);
				continue;
			}

			packet->vps = head;
			if (tacacs_encode(packet, NULL) < 0) {
				strlcpy(output, fr_strerror(), sizeof(output));
				talloc_free(packet);
				continue;
			}

			outlen = packet->data_len;
			memcpy(data, packet->data, outlen);
			talloc_free(packet);

			goto print_hex;
		}

		if (strcmp(test_type, "decode-tacacs") == 0) {
			vp_cursor_t cursor;
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
					exit(EXIT_FAILURE);
				}
			}

			packet->vps = NULL;
			packet->data = attr;
			packet->data_len = len;

			if (tacacs_decode(packet) < 0) {
				strlcpy(output, fr_strerror(), sizeof(output));
				talloc_free(packet);
				continue;
			}

			fr_pair_cursor_init(&cursor, &packet->vps);
			p = output;
			for (vp = fr_pair_cursor_first(&cursor); vp; vp = fr_pair_cursor_next(&cursor)) {
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
				strlcpy(output, fr_strerror(), sizeof(output));
				continue;
			}

			fr_pair_snprint(output, sizeof(output), head);
			fr_pair_list_free(&head);
			continue;
		}

		if (strcmp(test_type, "dictionary") == 0) {
			p += 11;

			if (fr_dict_parse_str(dict, p, fr_dict_root(dict), 0) < 0) {
				strlcpy(output, fr_strerror(), sizeof(output));
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
			fr_test_point_pair_decode_t	*tp;
			ssize_t				dec_len = 0;
			vp_cursor_t 			cursor;
			void				*decoder_ctx;

			p += load_test_point_by_command((void **)&tp, test_type, 11, "tp_decode") + 1;
			decoder_ctx = tp->test_ctx(tp_ctx);

			if (strcmp(p, "-") == 0) {
				attr = data;
				len = data_len;
			} else {
				attr = data;
				len = encode_hex(p, data, sizeof(data));
				if (len == 0) {
					fprintf(stderr, "Failed decoding hex string at line %d of %s\n",
						lineno, directory);
					exit(EXIT_FAILURE);
				}
			}

			fr_pair_cursor_init(&cursor, &head);
			while (len > 0) {
				dec_len = tp->func(tp_ctx, &cursor, attr, len, decoder_ctx);
				if (dec_len < 0) {
					fr_pair_list_free(&head);
					break;
				}
				if (dec_len > len) {
					fprintf(stderr, "Internal sanity check failed at %d\n", __LINE__);
					exit(EXIT_FAILURE);
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
				for (vp = fr_pair_cursor_first(&cursor);
				     vp;
				     vp = fr_pair_cursor_next(&cursor)) {
					fr_pair_snprint(p, sizeof(output) - (p - output), vp);
					p += strlen(p);

					if (vp->next) {
						strcpy(p, ", ");
						p += 2;
					}
				}

				fr_pair_list_free(&head);
			} else if (dec_len < 0) {
				strlcpy(output, fr_strerror(), sizeof(output));
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
			fr_test_point_pair_encode_t	*tp;
			ssize_t				enc_len = 0;
			vp_cursor_t			cursor;
			void				*encoder_ctx;

			p += load_test_point_by_command((void **)&tp, test_type, 11, "tp_encode") + 1;
			encoder_ctx = tp->test_ctx(tp_ctx);

			/*
			 *	Encode the previous output
			 */
			if (strcmp(p, "-") == 0) p = output;

			if (fr_pair_list_afrom_str(tp_ctx, p, &head) != T_EOL) {
				strlcpy(output, fr_strerror(), sizeof(output));
				continue;
			}

			attr = data;
			fr_pair_cursor_init(&cursor, &head);
			while ((vp = fr_pair_cursor_current(&cursor))) {
				enc_len = tp->func(attr, data + sizeof(data) - attr, &cursor, encoder_ctx);
				if (enc_len < 0) {
					fprintf(stderr, "Failed encoding %s: %s\n", vp->da->name, fr_strerror());
					exit(EXIT_FAILURE);
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

		fprintf(stderr, "Unknown input at line %d of %s: %s\n", lineno, directory, p);

		exit(EXIT_FAILURE);
	}

	if (fp != stdin) fclose(fp);

	unload_proto_library();	/* Cleanup */
	talloc_free(tp_ctx);
}

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "usage: unit_test_attribute [OPTS] filename\n");
	fprintf(stderr, "  -d <raddb>             Set user dictionary directory (defaults to " RADDBDIR ").\n");
	fprintf(stderr, "  -D <dictdir>           Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");
	fprintf(stderr, "  -f                     Print features.\n");
	fprintf(stderr, "  -M                     Show talloc memory report.\n");

	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int		c;
	char const	*radius_dir = RADDBDIR;
	char const	*dict_dir = DICTDIR;
	int		*inst = &c;
	CONF_SECTION	*cs, *features;
	fr_dict_t	*dict = NULL;

	TALLOC_CTX	*autofree = talloc_init("main");

#ifndef NDEBUG
	if (fr_fault_setup(getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("unit_test_attribute");
		exit(EXIT_FAILURE);
	}
#endif
	/*
	 *	Allocate a root config section so we can write
	 *	out features and versions.
	 */
	MEM(cs = cf_section_alloc(autofree, NULL, "unit_test_attribute", NULL));
	MEM(features = cf_section_alloc(cs, cs, "feature", NULL));
	cf_section_add(cs, features);
	dependency_init_features(features);	/* Add build time features to the config section */

	while ((c = getopt(argc, argv, "d:D:fxMh")) != EOF) switch (c) {
		case 'd':
			radius_dir = optarg;
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
			exit(EXIT_SUCCESS);
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
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("unit_test_attribute");
		return 1;
	}

	if (fr_dict_from_file(autofree, &dict, dict_dir, FR_DICTIONARY_FILE, "radius") < 0) {
		fr_perror("unit_test_attribute");
		return 1;
	}

	if (fr_dict_read(dict, radius_dir, FR_DICTIONARY_FILE) == -1) {
		fr_log_perror(&default_log, L_ERR, "Failed to initialize the dictionaries");
		return 1;
	}

	if (xlat_register(inst, "test", xlat_test, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true) < 0) {
		fprintf(stderr, "Failed registering xlat");
		return 1;
	}

	my_secret = talloc_strdup(autofree, "testing123");

	if (argc < 2) {
		process_file(features, dict, NULL, "-");

	} else {
		process_file(features, dict, NULL, argv[1]);
	}

	/*
	 *	Try really hard to free any allocated
	 *	memory, so we get clean talloc reports.
	 */
	xlat_free();
	fr_strerror_free();
	talloc_free(autofree);

	return 0;
}
