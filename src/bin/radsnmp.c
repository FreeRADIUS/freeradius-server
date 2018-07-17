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

/*
 * $Id$
 *
 * @brief SNMP to request utility
 * @file src/bin/radsnmp.c
 *
 * @copyright 2015-2016 The FreeRADIUS server project
 * @copyright 2015-2016 Network RADIUS SARL <info@networkradius.com>
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/udp.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/uio.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <assert.h>

static char const *radsnmp_version = RADIUSD_VERSION_STRING_BUILD("radsnmp");

static bool stop;

#undef DEBUG
#define DEBUG(fmt, ...)		if (fr_log_fp && (fr_debug_lvl > 0)) fprintf(fr_log_fp, "radsnmp (debug): " fmt "\n", ## __VA_ARGS__)
#undef DEBUG2
#define DEBUG2(fmt, ...)	if (fr_log_fp && (fr_debug_lvl > 1)) fprintf(fr_log_fp, "radsnmp (debug): " fmt "\n", ## __VA_ARGS__)

#define ERROR(fmt, ...)		if (fr_log_fp) fprintf(fr_log_fp, "radsnmp (error): " fmt "\n", ## __VA_ARGS__)

typedef enum {
	RADSNMP_UNKNOWN = -1,				//!< Unknown command.
	RADSNMP_PING = 0,				//!< Check server is alive.
	RADSNMP_GET,					//!< Get an SNMP leaf value.
	RADSNMP_GETNEXT,				//!< Get next OID.
	RADSNMP_SET,					//!< Set OID.
	RADSNMP_EXIT					//!< Terminate gracefully.
} radsnmp_command_t;

static const FR_NAME_NUMBER radsnmp_command_str[] = {
	{ "PING", 	RADSNMP_PING },			//!< Liveness command from Net-SNMP
	{ "get",	RADSNMP_GET },			//!< Get the value of an OID.
	{ "getnext", 	RADSNMP_GETNEXT },		//!< Get the next OID in the tree.
	{ "set",	RADSNMP_SET },			//!< Set the value of an OID.
	{ "",		RADSNMP_EXIT },			//!< Terminate radsnmp.
	{  NULL , 	-1}
};

typedef struct radsnmp_conf {
	fr_dict_t		*dict;			//!< Radius protocol dictionary.
	fr_dict_attr_t const	*snmp_root;		//!< SNMP protocol root in the FreeRADIUS dictionary.
	fr_dict_attr_t const	*snmp_oid_root;		//!< First attribute to include at the start of OID responses.
	fr_dict_attr_t const	*snmp_op;		//!< SNMP operation.
	fr_dict_attr_t const	*snmp_type;		//!< SNMP type attribute.
	fr_dict_attr_t const	*snmp_failure;		//!< SNMP set error attribute.
	char const		*raddb_dir;		//!< Radius dictionary directory.
	char const		*dict_dir;		//!< Dictionary director.
	unsigned int		code;			//!< Request type.
	int			proto;			//!< Protocol TCP/UDP.
	char const		*proto_str;		//!< Protocol string.
	uint8_t			last_used_id;		//!< ID of the last request we sent.

	fr_ipaddr_t		server_ipaddr;		//!< Src IP address.
	uint16_t		server_port;		//!< Port to send requests to.

	unsigned int		retries;		//!< Number of retries.
	struct timeval		timeout;
	char			*secret;		//!< Shared secret.
} radsnmp_conf_t;

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_radius;

extern fr_dict_autoload_t radsnmp_dict[];
fr_dict_autoload_t radsnmp_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_extended_attribute_1;
static fr_dict_attr_t const *attr_freeradius_snmp_failure;
static fr_dict_attr_t const *attr_freeradius_snmp_operation;
static fr_dict_attr_t const *attr_freeradius_snmp_type;
static fr_dict_attr_t const *attr_message_authenticator;
static fr_dict_attr_t const *attr_vendor_specific;

extern fr_dict_attr_autoload_t radsnmp_dict_attr[];
fr_dict_attr_autoload_t radsnmp_dict_attr[] = {
	{ .out = &attr_extended_attribute_1, .name = "Extended-Attribute-1", .type = FR_TYPE_EXTENDED, .dict = &dict_radius },
	{ .out = &attr_freeradius_snmp_failure, .name = "FreeRADIUS-SNMP-Failure", .type = FR_TYPE_UINT8, .dict = &dict_radius },
	{ .out = &attr_freeradius_snmp_operation, .name = "FreeRADIUS-SNMP-Operation", .type = FR_TYPE_UINT8, .dict = &dict_radius },
	{ .out = &attr_freeradius_snmp_type, .name = "FreeRADIUS-SNMP-Type", .type = FR_TYPE_UINT8, .dict = &dict_radius },
	{ .out = &attr_message_authenticator, .name = "Message-Authenticator", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_vendor_specific, .name = "Vendor-Specific", .type = FR_TYPE_VSA, .dict = &dict_radius },
	{ NULL }
};

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "Usage: radsnmp [options] server[:port] [<secret>]\n");

	fprintf(stderr, "  <command>              One of auth, acct, status, coa, disconnect or auto.\n");
	fprintf(stderr, "  -4                     Use IPv4 address of server\n");
	fprintf(stderr, "  -6                     Use IPv6 address of server.\n");
	fprintf(stderr, "  -d <raddb>             Set user dictionary directory (defaults to " RADDBDIR ").\n");
	fprintf(stderr, "  -D <dictdir>           Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(stderr, "  -h                     Print usage help information.\n");
	fprintf(stderr, "  -l <file>              Log output to file.\n");
	fprintf(stderr, "  -r <retries>           If timeout, retry sending the packet 'retries' times.\n");
	fprintf(stderr, "  -S <file>              read secret from file, not command line.\n");
	fprintf(stderr, "  -t <timeout>           Wait 'timeout' seconds before retrying (may be a floating "
		"point number).\n");
	fprintf(stderr, "  -v                     Show program version information.\n");
	fprintf(stderr, "  -x                     Increase debug level.\n");

#ifdef WITH_TCP
	fprintf(stderr, "  -P <proto>             Use proto (tcp or udp) for transport.\n");
#endif

	exit(EXIT_FAILURE);
}

#define RESPOND_STATIC(_cmd) \
do {\
	DEBUG2("said: %s", _cmd);\
	if (write(STDOUT_FILENO, _cmd "\n", sizeof(_cmd)) < 0) return 1; \
} while (0)

static void rs_signal_stop(UNUSED int sig)
{
	stop = true;
}

/** Allocate a new request using values from radsnmp config
 *
 * @param conf radsnmp config.
 * @param fd the request will be sent on.
 * @return new request.
 */
static RADIUS_PACKET *radsnmp_alloc(radsnmp_conf_t *conf, int fd)
{
	RADIUS_PACKET *request;

	request = fr_radius_alloc(conf, true);

	request->code = conf->code;

	request->id = conf->last_used_id;
	conf->last_used_id = (conf->last_used_id + 1) & UINT8_MAX;

	memcpy(&request->dst_ipaddr, &conf->server_ipaddr, sizeof(request->dst_ipaddr));
	request->dst_port = conf->server_port;
	request->sockfd = fd;

	return request;
}

/** Builds attribute representing OID string and adds 'index' attributes where required
 *
 * Will convert an OID string in the format @verbatim .1.2.3.4.5.0 @endverbatim
 * into a pair with a #fr_dict_attr_t of the dictionary attribute matching the OID
 * string, as evaluated from the specified parent.
 *
 * If an OID component does not match a child of a previous OID component, but a child
 * with attribute number 0 exists, and a child with attribute number 1 also exists,
 * the child with attribute number 0 will be used as an 'index' pair, and will be
 * created with the value of the non matching OID component.
 *
 * Parsing will then resume using the child with attribute number 1.
 *
 * This allows traversals of SNMP tables to be represented by the sequence of pairs
 * and allows the full range of entry indexes which would not be possible if we represented
 * table index numbers as TLV attributes.
 *
 * @param[in] ctx	to allocate new pairs in.
 * @param[in] conf	radsnmp config.
 * @param[in] cursor	to add pairs to.
 * @param[in] oid	string to evaluate.
 * @param[in] type	SNMP value type.
 * @param[in] value	to assign to OID attribute (SET operations only).
 * @return
 *	- >0 on success (how much of the OID string we parsed).
 *	- <=0 on failure (where format error occurred).
 */
static ssize_t radsnmp_pair_from_oid(TALLOC_CTX *ctx, radsnmp_conf_t *conf, fr_cursor_t *cursor,
				     char const *oid, int type, char const *value)
{
	ssize_t			slen;
	char const		*p = oid;
	unsigned int		attr;
	fr_dict_attr_t const	*index_attr, *da;
	fr_dict_attr_t const	*parent = conf->snmp_root;
	VALUE_PAIR		*vp;
	int			ret;

	if (!oid) return 0;

	fr_cursor_tail(cursor);

	/*
	 *	Trim first.
	 */
	if (p[0] == '.') p++;

	/*
	 *	Support for indexes.  If we can't find an attribute
	 *	matching a child at a given level in the OID tree,
	 *	look for attribute 0 (type integer) at that level.
	 *	We use this to represent the index instead.
	 */
	for (;;) {
		unsigned int num = 0;

		slen = fr_dict_attr_by_oid(conf->dict, &parent, &attr, p);
		if (slen > 0) break;
		p += -(slen);

		if (fr_dict_oid_component(&num, &p) < 0) break;	/* Just advances the pointer */
		assert(attr == num);
		p++;

		/*
		 *	Check for an index attribute
		 */
		index_attr = fr_dict_attr_child_by_num(parent, 0);
		if (!index_attr) {
			fr_strerror_printf("Unknown OID component: No index attribute at this level");
			break;
		}

		if (index_attr->type != FR_TYPE_UINT32) {
			fr_strerror_printf("Index is not a \"integer\"");
			break;
		}

		/*
		 *	By convention SNMP entries are at .1
		 */
		parent = fr_dict_attr_child_by_num(parent, 1);
		if (!parent) {
			fr_strerror_printf("Unknown OID component: No entry attribute at this level");
			break;
		}

		/*
		 *	Entry must be a TLV type
		 */
		if (parent->type != FR_TYPE_TLV) {
			fr_strerror_printf("Entry is not \"tlv\"");
			break;
		}

		/*
		 *	We've skipped over the index attribute, and
		 *	the index number should be available in attr.
		 */
		MEM(vp = fr_pair_afrom_da(ctx, index_attr));
		vp->vp_uint32 = attr;

		fr_cursor_append(cursor, vp);
	}

	/*
	 *	We errored out processing the OID.
	 */
	if (slen <= 0) {
	error:
		fr_cursor_free_list(cursor);
		return slen;
	}

	fr_strerror();	/* Clear pending errors */

	/*
	 *	SNMP requests the leaf under the OID with .0.
	 */
	if (attr != 0) {
		da = fr_dict_attr_child_by_num(parent, attr);
		if (!da) {
			fr_strerror_printf("Unknown leaf attribute %i", attr);
			return -(slen);
		}
	} else {
		da = parent;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) {
		fr_strerror_printf("Failed allocating OID attribute");
		return -(slen);
	}

	/*
	 *	VALUE_PAIRs with no value need a 1 byte value buffer.
	 */
	if (!value) {
		switch (da->type) {
		/*
		 *	We can blame the authors of RFC 6929 for
		 *	this hack.  Apparently the presence or absence
		 *	of an attribute isn't considered a useful means
		 *	of conveying information, so empty TLVs are
		 *	disallowed.
		 */
		case FR_TYPE_TLV:
			fr_pair_to_unknown(vp);
			/* FALL-THROUGH */

		case FR_TYPE_OCTETS:
			fr_pair_value_memcpy(vp, (uint8_t const *)"\0", 1);
			break;

		case FR_TYPE_STRING:
			fr_pair_value_bstrncpy(vp, "\0", 1);
			break;

		/*
		 *	Fine to leave other values zeroed out.
		 */
		default:
			break;
		}

		fr_cursor_append(cursor, vp);
		return slen;
	}

	if (da->type == FR_TYPE_TLV) {
		fr_strerror_printf("TLVs cannot hold values");
		return -(slen);
	}

	ret = fr_pair_value_from_str(vp, value, strlen(value), '\0', true);
	if (ret < 0) {
		slen = -(slen);
		goto error;
	}

	vp = fr_pair_afrom_da(ctx, attr_freeradius_snmp_type);
	if (!vp) {
		slen = -(slen);
		goto error;
	}
	vp->vp_uint32 = type;

	fr_cursor_append(cursor, vp);

	return slen;
}

/** Write the result of a get or getnext operation back to net-snmp
 *
 * Returns three lines of output per attribute:
 * - OID string
 * - type
 * - value
 *
 * Index attributes (num 0) must be in order of depth (shallowest first).
 *
 * If no attributes were written, will write "NONE\n" to inform net-snmp
 * that no value was available at the specified OID.
 *
 * @param fd to write to.
 * @param root of the SNMP portion of the main dictionary.
 * @param type attribute.
 * @param head of list of attributes to convert and write.
 * @return
 *	- >=0 on success (the number of varbind responses written).
 *	- -1 on failure.
 */
static int radsnmp_get_response(int fd,
				fr_dict_attr_t const *root, fr_dict_attr_t const *type,
				VALUE_PAIR *head)
{
	fr_cursor_t		cursor;
	VALUE_PAIR		*vp, *type_vp;
	fr_dict_attr_t const	*parent = root;
	unsigned int		written = 0;

	ssize_t			slen;
	size_t			len;

	char			type_buff[32];	/* type */
	size_t			type_len = 0;
	char			oid_buff[256];
	char			value_buff[128];
	char			*p = oid_buff, *end = p + sizeof(oid_buff);

	struct iovec		io_vector[6];

	char			newline[] = "\n";

	type_buff[0] = '\0';

	/*
	 *	Print first part of OID string.
	 */
	slen = snprintf(oid_buff, sizeof(oid_buff), "%u.", parent->attr);
	if (is_truncated((size_t)slen, sizeof(oid_buff))) {
	oob:
		fr_strerror_printf("OID Buffer too small");
		return -1;
	}
	p += slen;

	/*
	 *	@fixme, this is very dependent on ordering
	 *
	 *	This code should be reworked when we have proper
	 *	attribute grouping to coalesce all related index
	 *	attributes under a single request OID.
	 */
	 for (vp = fr_cursor_init(&cursor, &head);
	      vp;
	      vp = fr_cursor_next(&cursor)) {
	      	fr_dict_attr_t const *common;
	      	/*
	      	 *	We only care about TLV attributes beneath our root
	      	 */
		if (!fr_dict_parent_common(root, vp->da, true)) continue;

		/*
		 *	Sanity checks to ensure we're processing attributes
		 *	in the right order.
		 */
		common = fr_dict_parent_common(parent, vp->da, true);
		if (!common) {
			fr_strerror_printf("Out of order index attributes.  \"%s\" is not a child of \"%s\"",
					   vp->da->name, parent->name);
			return -1;
		}

		/*
		 *	Index attribute
		 */
		if (vp->da->attr == 0) {
			/*
			 *	Print OID from last index/root up to the parent of
			 *	the index attribute.
			 */
			slen = fr_dict_print_attr_oid(p, end - p, parent, vp->da->parent);
			if (slen < 0) return -1;

			if (vp->vp_type != FR_TYPE_UINT32) {
				fr_strerror_printf("Index attribute \"%s\" is not of type \"integer\"", vp->da->name);
				return -1;
			}

			if (slen >= (end - p)) goto oob;
			p += slen;

			/*
			 *	Add the value of the index attribute as the next
			 *	OID component.
			 */
			len = snprintf(p, end - p, ".%i.", vp->vp_uint32);
			if (is_truncated(len, end - p)) goto oob;

			p += len;

			/*
			 *	Set the parent to be the attribute representing
			 *	the entry.
			 */
			parent = fr_dict_attr_child_by_num(vp->da->parent, 1);
			continue;
		}

		/*
		 *	Actual TLV attribute
		 */
		slen = fr_dict_print_attr_oid(p, end - p, parent, vp->da);
		if (slen < 0) return -1;

		/*
		 *	Next attribute should be the type
		 */
		type_vp = fr_cursor_next(&cursor);
		if (!type_vp || (type_vp->da != type)) {
			fr_strerror_printf("No %s found in response, or occurred out of order", type->name);
			return -1;
		}
		type_len = fr_pair_value_snprint(type_buff, sizeof(type_buff), type_vp, '\0');

		/*
		 *	Build up the vector
		 *
		 *	This represents output for a single varbind attribute
		 */
		io_vector[0].iov_base = oid_buff;
		io_vector[0].iov_len = strlen(oid_buff);
		io_vector[1].iov_base = newline;
		io_vector[1].iov_len = 1;
		io_vector[2].iov_base = type_buff;
		io_vector[2].iov_len = type_len;
		io_vector[3].iov_base = newline;
		io_vector[3].iov_len = 1;

		switch (vp->vp_type) {
		case FR_TYPE_OCTETS:
			memcpy(&io_vector[4].iov_base, &vp->vp_strvalue, sizeof(io_vector[4].iov_base));
			io_vector[4].iov_len = vp->vp_length;
			break;

		case FR_TYPE_STRING:
			memcpy(&io_vector[4].iov_base, &vp->vp_strvalue, sizeof(io_vector[4].iov_base));
			io_vector[4].iov_len = vp->vp_length;
			break;

		default:
			/*
			 *	We call fr_value_box_snprint with a NULL da pointer
			 *	because we always need return integer values not
			 *	value aliases.
			 */
			len = fr_value_box_snprint(value_buff, sizeof(value_buff), &vp->data, '\0');
			if (is_truncated(len, sizeof(value_buff))) {
				fr_strerror_printf("Insufficient fixed value buffer");
				return -1;
			}
			io_vector[4].iov_base = value_buff;
			io_vector[4].iov_len = len;
			break;
		}
		io_vector[5].iov_base = newline;
		io_vector[5].iov_len = 1;

		DEBUG2("said: %s", (char *)io_vector[0].iov_base);
		DEBUG2("said: %s", (char *)io_vector[2].iov_base);
		DEBUG2("said: %s", (char *)io_vector[4].iov_base);

		if (writev(fd, io_vector, sizeof(io_vector) / sizeof(*io_vector)) < 0) {
			fr_strerror_printf("Failed writing varbind result: %s", fr_syserror(errno));
			return -1;
		}

		/*
		 *	Reset in case we're encoding multiple values
		 */
		parent = root;
		p = oid_buff;
		type_buff[0] = '\0';
		written++;
	}

	if (!written && (write(fd, "NONE\n", 5)) < 0) {
		fr_strerror_printf("Failed writing get response: %s", fr_syserror(errno));
		return -1;
	}

	return written;
}

/** Write the result of a set operation back to net-snmp
 *
 * Writes "DONE\n" on success, or an error as described in man snmpd.conf
 * on error.
 *
 * @param fd to write to.
 * @param error attribute.
 * @param head of list of attributes to convert and write.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int radsnmp_set_response(int fd, fr_dict_attr_t const *error, VALUE_PAIR *head)
{
	VALUE_PAIR	*vp;
	char		buffer[64];
	size_t		len;
	struct iovec	io_vector[2];
	char		newline[] = "\n";

	vp = fr_pair_find_by_da(head, error, TAG_NONE);
	if (!vp) {
		if (write(fd, "DONE\n", 5) < 0) {
			fr_strerror_printf("Failed writing set response: %s", fr_syserror(errno));
			return -1;
		}
		return 0;
	}

	len = fr_pair_value_snprint(buffer, sizeof(buffer), vp, '\0');
	if (is_truncated(len, sizeof(buffer))) {
		assert(0);
		return -1;
	}

	io_vector[0].iov_base = buffer;
	io_vector[0].iov_len = len;
	io_vector[1].iov_base = newline;
	io_vector[1].iov_len = 1;

	DEBUG2("said: %s", buffer);

	if (writev(fd, io_vector, sizeof(io_vector) / sizeof(*io_vector)) < 0) {
		fr_strerror_printf("Failed writing set response: %s", fr_syserror(errno));
		return -1;
	}

	return 0;
}

static int radsnmp_send_recv(radsnmp_conf_t *conf, int fd)
{
	fr_strerror();

#define NEXT_LINE(_line, _buffer) \
{ \
	size_t _len; \
	if (stop) return 0; \
	errno = 0;\
	_line = fgets(_buffer, sizeof(_buffer), stdin); \
	if (_line) { \
		_len = strlen(_line); \
		if ((_len > 0) && (_line[_len - 1] == '\n')) _line[_len - 1] = '\0'; \
		DEBUG2("read: %s", _line); \
	} \
}
	/*
	 *	Read commands from pass_persist
	 */
	while (!stop) {
		radsnmp_command_t	command;

		char			buffer[256];
		char			*line;
		ssize_t			slen;

		fr_cursor_t		cursor;
		VALUE_PAIR		*vp;
		RADIUS_PACKET		*request;

		/*
		 *	Alloc a new request so we can start adding
		 *	new pairs to it.
		 */
		request = radsnmp_alloc(conf, fd);
		if (!request) {
			ERROR("Failed allocating request");
			return EXIT_FAILURE;
		}
		fr_cursor_init(&cursor, &request->vps);

		NEXT_LINE(line, buffer);

		/*
		 *	Determine the type of SNMP operation
		 */
		command = fr_str2int(radsnmp_command_str, line, RADSNMP_UNKNOWN);
		switch (command) {
		case RADSNMP_EXIT:
			DEBUG("Empty command, exiting");
			return 0;

		case RADSNMP_PING:
			RESPOND_STATIC("PONG");
			continue;

		case RADSNMP_SET:
		{
			char		value_buff[254];	/* RADIUS attribute length + 1 */
			char		*value;
			char		type_str[64];
			char		*p;
			fr_dict_enum_t	*type;

			NEXT_LINE(line, buffer);	/* Should be the OID */
			NEXT_LINE(value, value_buff);	/* Should be the value */

			p = strchr(value, ' ');
			if (!p) {
				ERROR("No SNMP type specified (or type/value string was malformed)");
				RESPOND_STATIC("NONE");
				continue;
			}

			if ((size_t)(p - value) >= sizeof(type_str)) {
				ERROR("SNMP Type string too long");
				RESPOND_STATIC("NONE");
				continue;
			}

			strlcpy(type_str, value, (p - value) + 1);

			type = fr_dict_enum_by_alias(attr_freeradius_snmp_type, type_str, -1);
			if (!type) {
				ERROR("Unknown type \"%s\"", type_str);
				RESPOND_STATIC("NONE");
				continue;
			}

			slen = radsnmp_pair_from_oid(conf, conf, &cursor, line, type->value->vb_uint32, p + 1);
		}
			break;

		case RADSNMP_GET:
		case RADSNMP_GETNEXT:
			NEXT_LINE(line, buffer);	/* Should be the OID */
			slen = radsnmp_pair_from_oid(conf, conf, &cursor, line, 0, NULL);
			break;

		default:
			ERROR("Unknown command \"%s\"", line);
			RESPOND_STATIC("NONE");
			talloc_free(request);
			continue;
		}

		/*
		 *	Deal with any errors from the GET/GETNEXT/SET command
		 */
		if (slen <= 0) {
			char *spaces, *text;

			fr_canonicalize_error(conf, &spaces, &text, slen, line);

			ERROR("Failed evaluating OID:");
			ERROR("%s", text);
			ERROR("%s^ %s", spaces, fr_strerror());

			talloc_free(spaces);
			talloc_free(text);
			talloc_free(request);
			RESPOND_STATIC("NONE");
			continue;
		}

		/*
		 *	Now add an attribute indicating what the
		 *	SNMP operation was
		 */
		vp = fr_pair_afrom_da(request, attr_freeradius_snmp_operation);
		if (!vp) {
			ERROR("Failed allocating SNMP operation attribute");
			return EXIT_FAILURE;
		}
		vp->vp_uint32 = (unsigned int)command;	/* Commands must match dictionary */
		fr_cursor_append(&cursor, vp);

		/*
		 *	Add message authenticator or the stats
		 *	request will be rejected.
		 */
		MEM(vp = fr_pair_afrom_da(request, attr_message_authenticator));
		fr_pair_value_memcpy(vp, (uint8_t const *)"\0", 1);
		fr_cursor_append(&cursor, vp);

		/*
		 *	Send the packet
		 */
		{
			RADIUS_PACKET	*reply = NULL;
			ssize_t		rcode;

			fd_set		set;

			unsigned int	ret;
			unsigned int	i;

			if (fr_radius_packet_encode(request, NULL, conf->secret) < 0) {
				ERROR("Failed encoding request: %s", fr_strerror());
				return EXIT_FAILURE;
			}
			if (fr_radius_packet_sign(request, NULL, conf->secret) < 0) {
				ERROR("Failed signing request: %s", fr_strerror());
				return EXIT_FAILURE;
			}

			/*
			 *	Print the attributes we're about to send
			 */
			if (fr_log_fp) fr_packet_header_print(fr_log_fp, request, false);
			if (fr_debug_lvl > 0) fr_pair_list_fprint(fr_log_fp, request->vps);
#ifndef NDEBUG
			if (fr_log_fp && (fr_debug_lvl > 3)) fr_radius_packet_print_hex(request);
#endif

			FD_ZERO(&set); /* clear the set */
			FD_SET(fd, &set);

			/*
			 *	Any connection issues cause us to exit, so
			 *	the connection can be re-initialised on the
			 *	next call.
			 */
			for (i = 0; i < conf->retries; i++) {
				rcode = write(request->sockfd, request->data, request->data_len);
				if (rcode < 0) {
					ERROR("Failed sending: %s", fr_syserror(errno));
					return EXIT_FAILURE;
				}

				rcode = select(fd + 1, &set, NULL, NULL, &conf->timeout);
				switch (rcode) {
				case -1:
					ERROR("Select failed: %s", fr_syserror(errno));
					return EXIT_FAILURE;

				case 0:
					DEBUG("Response timeout.  Retrying %d/%u...", i + 1, conf->retries);
					continue;	/* Timeout */

				case 1:
					reply = fr_radius_packet_recv(request, request->sockfd, UDP_FLAGS_NONE,
								      RADIUS_MAX_ATTRIBUTES, false);
					if (!reply) {
						ERROR("Failed receiving reply: %s", fr_strerror());
					recv_error:
						RESPOND_STATIC("NONE");
						talloc_free(request);
						continue;
					}
					if (fr_radius_packet_decode(reply, request,
								    RADIUS_MAX_ATTRIBUTES, false, conf->secret) < 0) {
						ERROR("Failed decoding reply: %s", fr_strerror());
						goto recv_error;
					}
					break;

				default:
					DEBUG("Invalid select() return value %zd", rcode);
					return EXIT_FAILURE;
				}
				break;
			}

			if (!reply) {
				ERROR("Server didn't respond");
				return EXIT_FAILURE;
			}

			/*
			 *	Print the attributes we received in response
			 */
			if (fr_log_fp) fr_packet_header_print(fr_log_fp, reply, true);
			if (fr_debug_lvl > 0) fr_pair_list_fprint(fr_log_fp, reply->vps);
#ifndef NDEBUG
			if (fr_log_fp && (fr_debug_lvl > 3)) fr_radius_packet_print_hex(reply);
#endif

			switch (command) {
			case RADSNMP_GET:
			case RADSNMP_GETNEXT:
				ret = radsnmp_get_response(STDOUT_FILENO, conf->snmp_oid_root,
							   attr_freeradius_snmp_type, reply->vps);
				switch (ret) {
				case -1:
					ERROR("Failed converting pairs to varbind response: %s", fr_strerror());
					return EXIT_FAILURE;

				case 0:
					DEBUG("Empty response");
					break;

				default:
					DEBUG("Returned %u varbind responses", ret);
					break;
				}
				break;

			case RADSNMP_SET:
				if (radsnmp_set_response(STDOUT_FILENO, attr_freeradius_snmp_failure, reply->vps) < 0) {
					ERROR("Failed writing SET response: %s", fr_strerror());
					return EXIT_FAILURE;
				}
				break;

			default:
				assert(0);
				return EXIT_FAILURE;
			}


			talloc_free(request);
		}
	}

	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	int		c;
	char		filesecret[256];
	FILE		*fp;
	int		force_af = AF_UNSPEC;
	radsnmp_conf_t *conf;
	int		ret;
	int		sockfd;
	TALLOC_CTX	*autofree = talloc_autofree_context();

	fr_log_fp = stderr;

	conf = talloc_zero(autofree, radsnmp_conf_t);
	conf->proto = IPPROTO_UDP;
	conf->dict_dir = DICTDIR;
	conf->raddb_dir = RADDBDIR;
	conf->secret = talloc_strdup(conf, "testing123");
	conf->timeout.tv_sec = 3;
	conf->retries = 5;

#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("radsnmp");
		exit(EXIT_FAILURE);
	}
#endif

	talloc_set_log_stderr();

	while ((c = getopt(argc, argv, "46c:d:D:f:Fhi:l:n:p:qr:sS:t:vx"
#ifdef WITH_TCP
		"P:"
#endif
		)) != EOF) switch (c) {
		case '4':
			force_af = AF_INET;
			break;

		case '6':
			force_af = AF_INET6;
			break;

		case 'D':
			conf->dict_dir = optarg;
			break;

		case 'd':
			conf->raddb_dir = optarg;
			break;

		case 'l':
		{
			int log_fd;

			if (strcmp(optarg, "stderr") == 0) {
				fr_log_fp = stderr;	/* stdout goes to netsnmp */
				break;
			}

			log_fd = open(optarg, O_WRONLY | O_APPEND | O_CREAT, 0640);
			if (log_fd < 0) {
				fprintf(stderr, "radsnmp: Failed to open log file %s: %s\n",
					optarg, fr_syserror(errno));
				exit(EXIT_FAILURE);
			}
			fr_log_fp = fdopen(log_fd, "a");
		}
			break;

#ifdef WITH_TCP
		case 'P':
			conf->proto_str = optarg;
			if (strcmp(conf->proto_str, "tcp") != 0) {
				if (strcmp(conf->proto_str, "udp") != 0) usage();
			} else {
				conf->proto = IPPROTO_TCP;
			}
			break;

#endif

		case 'r':
			if (!isdigit((int) *optarg)) usage();
			conf->retries = atoi(optarg);
			if ((conf->retries == 0) || (conf->retries > 1000)) usage();
			break;

		case 'S':
		{
			char *p;
			fp = fopen(optarg, "r");
			if (!fp) {
			       ERROR("Error opening %s: %s", optarg, fr_syserror(errno));
			       exit(EXIT_FAILURE);
			}
			if (fgets(filesecret, sizeof(filesecret), fp) == NULL) {
			       ERROR("Error reading %s: %s", optarg, fr_syserror(errno));
			       exit(EXIT_FAILURE);
			}
			fclose(fp);

			/* truncate newline */
			p = filesecret + strlen(filesecret) - 1;
			while ((p >= filesecret) &&
			      (*p < ' ')) {
			       *p = '\0';
			       --p;
			}

			if (strlen(filesecret) < 2) {
			       ERROR("Secret in %s is too short", optarg);
			       exit(EXIT_FAILURE);
			}
			talloc_free(conf->secret);
			conf->secret = talloc_strdup(conf, filesecret);
		}
		       break;

		case 't':
			if (fr_timeval_from_str(&conf->timeout, optarg) < 0) {
				ERROR("Failed parsing timeout value %s", fr_strerror());
				exit(EXIT_FAILURE);
			}
			break;

		case 'v':
			DEBUG("%s", radsnmp_version);
			exit(0);

		case 'x':
			fr_debug_lvl++;
			break;

		case 'h':
		default:
			usage();
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	if ((argc < 2)  || ((conf->secret == NULL) && (argc < 3))) {
		ERROR("Insufficient arguments");
		usage();
	}
	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("radsnmp");
		return EXIT_FAILURE;
	}

	if (fr_dict_autoload(radsnmp_dict) < 0) {
		fr_perror("radsnmp");
		exit(EXIT_FAILURE);
	}

	if (fr_dict_attr_autoload(radsnmp_dict_attr) < 0) {
		fr_perror("radsnmp");
		exit(EXIT_FAILURE);
	}

	if (fr_dict_read(dict_freeradius, conf->raddb_dir, FR_DICTIONARY_FILE) == -1) {
		fr_perror("radsnmp");
		exit(EXIT_FAILURE);
	}
	fr_strerror();	/* Clear the error buffer */

	if (fr_log_fp) setvbuf(fr_log_fp, NULL, _IONBF, 0);

	/*
	 *	Get the request type
	 */
	if (!isdigit((int) argv[2][0])) {
		int code;

		code = fr_str2int(fr_request_types, argv[2], -1);
		if (code < 0) {
			ERROR("Unrecognised request type \"%s\"", argv[2]);
			usage();
		}
		conf->code = (unsigned int)code;
	} else {
		conf->code = atoi(argv[2]);
	}

	/*
	 *	Resolve hostname.
	 */
	if (fr_inet_pton_port(&conf->server_ipaddr, &conf->server_port, argv[1], -1, force_af, true, true) < 0) {
		ERROR("%s", fr_strerror());
		exit(EXIT_FAILURE);
	}

	/*
	 *	Add the secret
	 */
	if (argv[3]) {
		talloc_free(conf->secret);
		conf->secret = talloc_strdup(conf, argv[3]);
	}

	conf->snmp_root = fr_dict_attr_child_by_num(attr_vendor_specific, VENDORPEC_FREERADIUS);
	if (!conf->snmp_root) {
		ERROR("Incomplete dictionary: Missing definition for Extended-Attribute-1(%i)."
		      "Vendor-Specific(%i).FreeRADIUS(%i)",
		      attr_extended_attribute_1->attr,
		      attr_vendor_specific->attr,
		      VENDORPEC_FREERADIUS);
	dict_error:
		talloc_free(conf);
		exit(EXIT_FAILURE);
	}

	conf->snmp_oid_root = fr_dict_attr_child_by_num(conf->snmp_root, 1);
	if (!conf->snmp_oid_root) {
		ERROR("Incomplete dictionary: Missing definition for 1.Extended-Attribute-1(%i)."
		      "Vendor-Specific(%i).FreeRADIUS(%i).FreeRADIUS-Iso(%i)",
		      attr_extended_attribute_1->attr,
		      attr_vendor_specific->attr,
		      VENDORPEC_FREERADIUS, 1);
		goto dict_error;
	}

	switch (conf->proto) {
#ifdef WITH_TCP
	case IPPROTO_TCP:
		sockfd = fr_socket_client_tcp(NULL, &conf->server_ipaddr, conf->server_port, true);
		break;
#endif

	default:
	case IPPROTO_UDP:
		sockfd = fr_socket_client_udp(NULL, NULL, &conf->server_ipaddr, conf->server_port, true);
		break;
	}
	if (sockfd < 0) {
		ERROR("Failed connecting to server %s:%hu", "foo", conf->server_port);
		ret = 1;
		goto finish;
	}

	fr_set_signal(SIGPIPE, rs_signal_stop);
	fr_set_signal(SIGINT, rs_signal_stop);
	fr_set_signal(SIGTERM, rs_signal_stop);
#ifdef SIGQUIT
	fr_set_signal(SIGQUIT, rs_signal_stop);
#endif

	DEBUG("%s - Starting pass_persist read loop", radsnmp_version);
	ret = radsnmp_send_recv(conf, sockfd);
	DEBUG("Read loop done");

finish:
	if (fr_log_fp) fflush(fr_log_fp);

	/*
	 *	Everything should be parented from conf
	 */
	talloc_free(conf);

	/*
	 *	...except the dictionaries
	 */
	fr_dict_autofree(radsnmp_dict);

	return ret;
}
