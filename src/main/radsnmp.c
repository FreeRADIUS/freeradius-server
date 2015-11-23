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
 * @brief map / template functions
 * @file main/radsnmp.c
 *
 * @copyright 2015 The FreeRADIUS server project
 * @copyright 2015 Network RADIUS SARL <info@networkradius.com>
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/conf.h>
#include <freeradius-devel/libradius.h>
#include <ctype.h>
#include <fcntl.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <assert.h>

static char const *radsnmp_version = "radsnmp version " RADIUSD_VERSION_STRING
#ifdef RADIUSD_VERSION_COMMIT
" (git #" STRINGIFY(RADIUSD_VERSION_COMMIT) ")"
#endif
", built on " __DATE__ " at " __TIME__;

static bool stop;

#undef DEBUG
#define DEBUG(fmt, ...)		if (fr_debug_lvl > 0) fprintf(fr_log_fp, "radsnmp (debug): " fmt "\n", ## __VA_ARGS__)
#undef DEBUG2
#define DEBUG2(fmt, ...)	if (fr_debug_lvl > 1) fprintf(fr_log_fp, "radsnmp (debug): " fmt "\n", ## __VA_ARGS__)

#define ERROR(fmt, ...)		fprintf(fr_log_fp, "radsnmp (error): " fmt "\n", ## __VA_ARGS__)

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
	fr_dict_attr_t const	*snmp_op;		//!< SNMP operation.
	char const		*radius_dir;		//!< Radius dictionary directory.
	char const		*dict_dir;		//!< Dictionary director.
	unsigned int		code;			//!< Request type.
	int			proto;			//!< Protocol TCP/UDP.
	char const		*proto_str;		//!< Protocol string.
	uint8_t			last_used_id;		//!< ID of the last request we sent.

	fr_ipaddr_t		server_ipaddr;		//!< Src IP address.
	uint16_t		server_port;		//!< Port to send requests to.

	unsigned int		retries;		//!< Number of retries.
	struct timeval		timeout;
	char const		*secret;		//!< Shared secret.
} radsnmp_conf_t;

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
	fprintf(stderr, "  -r <retries>           If timeout, retry sending the packet 'retries' times.\n");;
	fprintf(stderr, "  -S <file>              read secret from file, not command line.\n");
	fprintf(stderr, "  -t <timeout>           Wait 'timeout' seconds before retrying (may be a floating "
		"point number).\n");
	fprintf(stderr, "  -v                     Show program version information.\n");
	fprintf(stderr, "  -x                     Increase debug level.\n");

#ifdef WITH_TCP
	fprintf(stderr, "  -P <proto>             Use proto (tcp or udp) for transport.\n");
#endif

	exit(1);
}

#define RESPOND_STATIC(_cmd) \
do {\
	DEBUG2("send: %s", _cmd);\
	(void) write(STDOUT_FILENO, _cmd "\n", sizeof(_cmd));	\
} while (0)

static void rs_signal_stop(UNUSED int sig)
{
	stop = true;
}

static int radsnmp_send_recv(radsnmp_conf_t *conf, int fd)
{
	char			buffer[1024];
	char			*line;
	vp_cursor_t		cursor;
	VALUE_PAIR		*head = NULL;

	fr_strerror();

	/*
	 *	Read commands from pass_persist
	 */
	while (!stop) {
		radsnmp_command_t	command;
		fr_dict_attr_t const	*da, *index_da, *parent = conf->snmp_root;
		unsigned int		attr;
		size_t			len;
		VALUE_PAIR		*vp;

		head = NULL;
		fr_cursor_init(&cursor, &head);

		line = fgets(buffer, sizeof(buffer), stdin);
		if (!line) continue;	/* Probably interrupted by signal */

		len = strlen(line);
		if ((len > 0) && (line[len - 1] == '\n')) line[len - 1] = '\0';

		DEBUG2("recv: %s", line);

		command = fr_str2int(radsnmp_command_str, line, RADSNMP_UNKNOWN);
		switch (command) {
		case RADSNMP_EXIT:
			DEBUG("Empty command, exiting");
			return 0;

		case RADSNMP_PING:
			RESPOND_STATIC("PONG");
			continue;

		case RADSNMP_SET:
		case RADSNMP_GET:
		case RADSNMP_GETNEXT:
		{
			ssize_t		slen;
			char const	*p, *start;

			p = line = fgets(buffer, sizeof(buffer), stdin);

			/*
			 *	Trim trailing newline in OID
			 */
			len = strlen(line);
			if ((len > 0) && (line[len - 1] == '\n')) line[len - 1] = '\0';

			DEBUG2("recv: %s", line);

			/*
			 *	Trim first.
			 */
			if (p[0] == '.') p++;

			start = p;

			/*
			 *	Support for indexes.  If we can't find an attribute
			 *	matching a child at a given level in the OID tree,
			 *	look for attribute 0 (type integer) at that level.
			 *	We use this to represent the index instead.
			 */
			for (;;) {
				unsigned int num = 0;

				slen = fr_dict_attr_by_oid(conf->dict, &parent, NULL, &attr, p);
				if (slen > 0) break;
				p += -(slen);

				if (fr_dict_oid_component(&num, &p) < 0) break;	/* Just advances the pointer */
				assert(attr == num);
				p++;

				/*
				 *	Check for an index attribute
				 */
				index_da = fr_dict_attr_child_by_num(parent, 0);
				if (!index_da) {
					fr_strerror_printf("Unknown OID component: No index attribute at this level");
					break;
				}

				if (index_da->type != PW_TYPE_INTEGER) {
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
				if (parent->type != PW_TYPE_TLV) {
					fr_strerror_printf("Entry is not \"tlv\"");
					break;
				}

				/*
				 *	We've skipped over the index attribute, and
				 *	the index number should be available in attr.
				 */
				vp = fr_pair_afrom_da(NULL, index_da);
				vp->vp_integer = attr;

				fr_cursor_insert(&cursor, vp);
			}

			/*
			 *	We errored out processing the OID, print a
			 *	marker with how far we go.
			 */
			if (slen <= 0) {
				char *spaces, *text;
				char const *error;

				error = fr_strerror();
				fr_canonicalize_error(conf, &spaces, &text, start - p, start);

				ERROR("Failed evaluating OID:");
				ERROR("%s", text);
				ERROR("%s^ %s", spaces, error);

				talloc_free(spaces);
				talloc_free(text);

			error:
				RESPOND_STATIC("NONE");

				fr_pair_list_free(&head);
				continue;
			}

			fr_strerror();	/* Clear pending errors */

			/*
			 *	SNMP requests the leaf under the OID
			 *	with .0.
			 */
			if (attr != 0) {
				da = fr_dict_attr_child_by_num(parent, attr);
				if (!da) {
					ERROR("Unknown leaf attribute %i", attr);
					goto error;
				}
			} else {
				da = parent;
			}
		}
			break;

		default:
			ERROR("Unknown command \"%s\"", line);
			RESPOND_STATIC("NONE");
			continue;
		}

		/*
		 *	If we've gotten this far, we should have all the
		 *	index attributes in the list.
		 *
		 *	We now need to create an empty attribute of the
		 *	type we're retrieving, or a populated one of the
		 *	type we're setting.
		 */
		switch (command) {
		case RADSNMP_GETNEXT:
			break;

		case RADSNMP_GET:
			if (da->type == PW_TYPE_TLV) {
				ERROR("OID must specify a leaf, \"%s\" is a \"tlv\"", da->name);
				goto error;
			}

			vp = fr_pair_afrom_da(NULL, da);
			if (!vp) {
				ERROR("Failed allocating OID attribute");
				goto error;
			}

			switch (da->type) {
			case PW_TYPE_STRING:
				fr_pair_value_bstrncpy(vp, "\0", 1);
				break;

			case PW_TYPE_OCTETS:
				fr_pair_value_memcpy(vp, (uint8_t const *)"\0", 1);
				break;

			/*
			 *	Fine to leave other values zeroed out.
			 */
			default:
				break;
			}
			fr_cursor_insert(&cursor, vp);
			break;

		case RADSNMP_SET:
			vp = fr_pair_afrom_da(NULL, da);
			if (!vp) {
				ERROR("Failed allocating OID attribute");
				goto error;
			}

			break;

		default:
			exit(1);
		}

		vp = fr_pair_afrom_da(NULL, conf->snmp_op);
		if (!vp) {
			ERROR("Failed allocating SNMP operation attribute");
			goto error;
		}
		vp->vp_integer = (unsigned int)command;	/* Commands must match dictionary */
		fr_cursor_insert(&cursor, vp);

		DEBUG("OID resolves to leaf \"%s\"", da->name);

		vp = fr_pair_afrom_num(NULL, 0, PW_MESSAGE_AUTHENTICATOR);
		if (!vp) {
			ERROR("Failed allocating Message-Authenticator attribute");
			goto error;
		}
		fr_pair_value_memcpy(vp, (uint8_t const *)"\0", 1);
		fr_cursor_insert(&cursor, vp);

		/*
		 *	Send the packet
		 */
		{
			RADIUS_PACKET	*request, *reply = NULL;
			ssize_t		rcode;

			fd_set		set;

			unsigned int	i;

			request = rad_alloc(conf, true);
			request->vps = head;

			for (vp = fr_cursor_first(&cursor);
			     vp;
			     vp = fr_cursor_next(&cursor)) fr_pair_steal(request, vp);

			request->code = conf->code;

			request->id = conf->last_used_id;
			conf->last_used_id = (conf->last_used_id + 1) & UINT8_MAX;

			memcpy(&request->dst_ipaddr, &conf->server_ipaddr, sizeof(request->dst_ipaddr));
			request->dst_port = conf->server_port;
			request->sockfd = fd;

			if (rad_encode(request, NULL, conf->secret) < 0) {
				ERROR("Failed encoding request: %s", fr_strerror());
				RESPOND_STATIC("NONE");
				return 1;
			}
			if (rad_sign(request, NULL, conf->secret) < 0) {
				ERROR("Failed signing request: %s", fr_strerror());
				RESPOND_STATIC("NONE");
				return 1;
			}

			/*
			 *	Print the attributes we're about to send
			 */
			if (fr_log_fp) fr_packet_header_print(fr_log_fp, request, false);
			if (fr_debug_lvl > 0) fr_pair_list_fprint(fr_log_fp, head);
#ifndef NDEBUG
			if (fr_log_fp && (fr_debug_lvl > 3)) rad_print_hex(request);
#endif

			FD_ZERO(&set); /* clear the set */
			FD_SET(fd, &set);

			for (i = 0; i < conf->retries; i++) {
				rcode = write(request->sockfd, request->data, request->data_len);
				if (rcode < 0) {
					ERROR("Failed sending: %s", fr_syserror(errno));
					RESPOND_STATIC("NONE");
					return 1;
				}

				rcode = select(fd + 1, &set, NULL, NULL, &conf->timeout);
				switch (rcode) {
				case -1:
					ERROR("Select failed: %s", fr_syserror(errno));
					RESPOND_STATIC("NONE");
					return 1;

				case 0:
					DEBUG("Response timeout %i/%i", i + 1, conf->retries);
					continue;	/* Timeout */

				case 1:
					reply = rad_recv(request, request->sockfd, 0);
					if (!reply) {
						ERROR("Failed decoding reply: %s", fr_strerror());
						RESPOND_STATIC("NONE");
						return 1;
					}
					break;

				default:
					DEBUG("Invalid select() return value %zi", rcode);
					return 1;
				}
			}

			if (!reply) {
				ERROR("Server didn't respond");
				RESPOND_STATIC("NONE");
				return 1;
			}


			/*
			 *	Print the attributes we're about to send
			 */
			if (fr_log_fp) fr_packet_header_print(fr_log_fp, reply, true);
			if (fr_debug_lvl > 0) fr_pair_list_fprint(fr_log_fp, reply->vps);
#ifndef NDEBUG
			if (fr_log_fp && (fr_debug_lvl > 3)) rad_print_hex(reply);
#endif

			talloc_free(request);
		}
	}

	return 0;
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

	fr_log_fp = stderr;

	conf = talloc_zero(NULL, radsnmp_conf_t);
	conf->proto = IPPROTO_UDP;
	conf->dict_dir = DICTDIR;
	conf->radius_dir = RADDBDIR;
	conf->secret = "testing123";
	conf->timeout.tv_sec = 3;
	conf->retries = 5;

#ifndef NDEBUG
	if (fr_fault_setup(getenv("PANIC_ACTION"), argv[0]) < 0) {
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
			conf->radius_dir = optarg;
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
			conf->secret = filesecret;
		}
		       break;

		case 't':
			if (fr_timeval_from_str(&conf->timeout, optarg) < 0) {
				ERROR("Failed parsing timeout value: %s", fr_strerror());
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
		return 1;
	}

	if (fr_dict_init(conf, &conf->dict, conf->dict_dir, RADIUS_DICTIONARY, "radius") < 0) {
		fr_perror("radsnmp");
		return 1;
	}

	if (fr_dict_read(conf->dict, conf->radius_dir, RADIUS_DICTIONARY) == -1) {
		fr_perror("radsnmp");
		return 1;
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
		exit(1);
	}

	/*
	 *	Add the secret
	 */
	if (argv[3]) conf->secret = argv[3];

	{
		fr_dict_attr_t const *parent;

		parent = fr_dict_attr_child_by_num(fr_dict_root(conf->dict), PW_EXTENDED_ATTRIBUTE_1);
		if (!parent) {
			ERROR("Incomplete dictionary: Missing definition for Extended-Attribute-1");
		dict_error:
			talloc_free(conf);
			exit(1);
		}
		parent = fr_dict_attr_child_by_num(parent, PW_VENDOR_SPECIFIC);
		if (!parent) {
			ERROR("Incomplete dictionary: Missing definition for Extended-Attribute-1(%i)."
			      "Vendor-Specific(%i)", PW_EXTENDED_ATTRIBUTE_1, PW_VENDOR_SPECIFIC);
			goto dict_error;
		}

		parent = fr_dict_attr_child_by_num(parent, VENDORPEC_FREERADIUS);
		if (!parent) {
			ERROR("Incomplete dictionary: Missing definition for Extended-Attribute-1(%i)."
			      "Vendor-Specific(%i).FreeRADIUS(%i)", PW_EXTENDED_ATTRIBUTE_1, PW_VENDOR_SPECIFIC,
			      VENDORPEC_FREERADIUS);
			goto dict_error;
		}
		conf->snmp_root = parent;
	}

	conf->snmp_op = fr_dict_attr_by_name(conf->dict, "FreeRADIUS-SNMP-Operation");
	if (!conf->snmp_op) {
		ERROR("Incomplete dictionary: Missing definition for \"FreeRADIUS-SNMP-Operation\"");
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
		sockfd = fr_socket_client_udp(NULL, &conf->server_ipaddr, conf->server_port, true);
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

	return ret;
}
