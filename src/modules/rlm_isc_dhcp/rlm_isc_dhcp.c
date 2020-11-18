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
 * @file rlm_isc_dhcp.c
 * @brief Read ISC DHCP configuration files
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/server/map_proc.h>

static fr_dict_t const *dict_dhcpv4;

extern fr_dict_autoload_t rlm_isc_dhcp_dict[];
fr_dict_autoload_t rlm_isc_dhcp_dict[] = {
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ NULL }
};

static fr_dict_attr_t const *attr_client_hardware_address;
static fr_dict_attr_t const *attr_your_ip_address;
static fr_dict_attr_t const *attr_client_identifier;
static fr_dict_attr_t const *attr_server_name;
static fr_dict_attr_t const *attr_boot_filename;
static fr_dict_attr_t const *attr_server_ip_address;
static fr_dict_attr_t const *attr_server_identifier;

extern fr_dict_attr_autoload_t rlm_isc_dhcp_dict_attr[];
fr_dict_attr_autoload_t rlm_isc_dhcp_dict_attr[] = {
	{ .out = &attr_client_hardware_address, .name = "DHCP-Client-Hardware-Address", .type = FR_TYPE_ETHERNET, .dict = &dict_dhcpv4},
	{ .out = &attr_your_ip_address, .name = "DHCP-Your-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4},
	{ .out = &attr_client_identifier, .name = "DHCP-Client-Identifier", .type = FR_TYPE_OCTETS, .dict = &dict_dhcpv4},
	{ .out = &attr_server_name, .name = "DHCP-Server-Host-Name", .type = FR_TYPE_STRING, .dict = &dict_dhcpv4},
	{ .out = &attr_boot_filename, .name = "DHCP-Boot-Filename", .type = FR_TYPE_STRING, .dict = &dict_dhcpv4},
	{ .out = &attr_server_ip_address, .name = "DHCP-Server-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4},
	{ .out = &attr_server_identifier, .name = "DHCP-DHCP-Server-Identifier", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4},

	{ NULL }
};

typedef struct rlm_isc_dhcp_info_s rlm_isc_dhcp_info_t;

#define NO_SEMICOLON	(0)
#define YES_SEMICOLON	(1)
#define MAYBE_SEMICOLON (2)

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct {
	char const		*name;
	char const		*filename;
	bool			debug;
	bool			pedantic;
	rlm_isc_dhcp_info_t	*head;

	/*
	 *	While "host" blocks can appear anywhere, their
	 *	definitions are global.  We use these hashes for
	 *	dedup, and for assigning IP addresses in the `recv`
	 *	section.  We still need to have host hashes in the
	 *	subsections, so that we can apply options from the
	 *	bottom up.
	 */
	fr_hash_table_t		*hosts_by_ether;       	//!< by MAC address
	fr_hash_table_t		*hosts_by_uid;		//!< by client identifier
} rlm_isc_dhcp_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED | FR_TYPE_NOT_EMPTY, rlm_isc_dhcp_t, filename) },
	{ FR_CONF_OFFSET("debug", FR_TYPE_BOOL, rlm_isc_dhcp_t, debug) },
	{ FR_CONF_OFFSET("pedantic", FR_TYPE_BOOL, rlm_isc_dhcp_t, pedantic) },
	CONF_PARSER_TERMINATOR
};

#define IDEBUG if (state->debug) DEBUG

/*
 *	For developer debugging.  Likely not needed
 */
#define DDEBUG(...)

/*
 *	The parsing functions return:
 *	  <0 on error
 *	   0 for "I did nothing"
 *	   1 for "I did something"
 *
 *	This pattern allows us to distinguish things like empty files
 *	from full files, and empty subsections from full sections, etc.
 */

/**  Holds the state of the current tokenizer
 *
 */
typedef struct {
	rlm_isc_dhcp_t	*inst;		//!< module instance
	FILE		*fp;
	char const	*filename;
	int		lineno;
	char		*line;		//!< where the current line started

	int		braces;		//!< how many levels deep we are in a { ... }
	bool		saw_semicolon;	//!< whether we saw a semicolon
	bool		eof;		//!< are we at EOF?
	bool		allow_eof;	//!< do we allow EOF?  (i.e. braces == 0)
	bool		debug;		//!< internal developer debugging

	char		*buffer;	//!< read buffer
	size_t		bufsize;	//!< size of read buffer
	char		*ptr;		//!< pointer into read buffer

	char		*token;		//!< current token that we parsed
	int		token_len;	//!< length of the token

	char		string[256];	//!< double quoted strings go here, so we don't mangle the input buffer
} rlm_isc_dhcp_tokenizer_t;


typedef int (*rlm_isc_dhcp_parse_t)(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info);
typedef int (*rlm_isc_dhcp_apply_t)(rlm_isc_dhcp_t const *inst, request_t *request, rlm_isc_dhcp_info_t *info);

typedef enum rlm_isc_dhcp_type_t {
	ISC_INVALID = 0,		//!< we recognize it, but don't implement it
	ISC_NOOP,			//!< we don't do anything with it
	ISC_IGNORE,			//!< we deliberately ignore it
	ISC_GROUP,
	ISC_HOST,
	ISC_SUBNET,
	ISC_OPTION,
	ISC_HARDWARE_ETHERNET,
	ISC_FIXED_ADDRESS,
} rlm_isc_dhcp_type_t;

/** Describes the commands that we accept, including it's syntax (i.e. name), etc.
 *
 */
typedef struct {
	char const		*name;
	rlm_isc_dhcp_type_t	type;
	rlm_isc_dhcp_parse_t	parse;
	rlm_isc_dhcp_apply_t	apply;
	int			max_argc;
} rlm_isc_dhcp_cmd_t;

/** Holds information about the thing we parsed.
 *
 *	Note that this parser is forgiving.  We would rather accept
 *	things ISC DHCP doesn't accept, than reject things it accepts.
 *
 *	Since we only implement a tiny portion of it's configuration,
 *	we tend to accept all kinds of things, and then just ignore them.
 */
struct rlm_isc_dhcp_info_s {
	rlm_isc_dhcp_cmd_t const *cmd;
	int			argc;
	fr_value_box_t 		**argv;

	rlm_isc_dhcp_info_t	*parent;
	rlm_isc_dhcp_info_t	*next;
	void			*data;		//!< per-thing parsed data.

	/*
	 *	Only for things that have sections
	 */
	fr_hash_table_t		*hosts_by_ether;  //!< by MAC address
	fr_hash_table_t		*hosts_by_uid;	//!< by client identifier
	fr_pair_list_t		options;	//!< DHCP options
	fr_trie_t		*subnets;
	rlm_isc_dhcp_info_t	*child;
	rlm_isc_dhcp_info_t	**last;		//!< pointer to last child
};

static int read_file(rlm_isc_dhcp_t *inst, rlm_isc_dhcp_info_t *parent, char const *filename);
static int parse_section(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info);

static char const *spaces = "                                                                                ";

/** Refills the read buffer with one line from the file.
 *
 *	This function also takes care of suppressing blank lines, and
 *	lines which only contain comments.
 */
static int refill(rlm_isc_dhcp_tokenizer_t *state)
{
	char *p;

	if (state->eof) return 0;

	/*
	 *	We've run out of data to parse, reset to the start of
	 *	the buffer.
	 */
	if (!*state->ptr) state->ptr = state->buffer;

redo:
	state->lineno++;
	state->line = state->ptr;

	if (!fgets(state->ptr, state->bufsize - (state->ptr - state->buffer), state->fp)) {
		if (feof(state->fp)) {
			state->eof = true;
			return 0;
		}

		return -1;
	}

	/*
	 *	Skip leading spaces
	 */
	p = state->ptr;
	fr_skip_whitespace(p);

	/*
	 *	The line is all spaces, OR we've hit a comment.  Go
	 *	get more data.
	 */
	if (!*p || (*p == '#')) goto redo;

	/*
	 *	Point to the first non-space data.
	 */
	state->ptr = p;

	return 1;
}

static int skip_spaces(rlm_isc_dhcp_tokenizer_t *state, char *p)
{
	state->ptr = p;
	char *start = p;

	fr_skip_whitespace(state->ptr);

	/*
	 *	If we ran out of text on this line, re-fill the
	 *	buffer.  Note that refill() also takes care of
	 *	suppressing blank lines and comments.  refill() also
	 *	takes care of skipping leading spaces, too.
	 */
	if (!state->eof && !*state->ptr) {
		int ret;

		state->ptr = start;

		ret = refill(state);
		if (ret < 0) return -1;
	}

	/*
	 *	Set the semicolon flag as a "peek
	 *	ahead", so that the various other
	 *	parsers don't need to check it.
	 */
	if (*state->ptr == ';') state->saw_semicolon = true;

	return 0;
}



/*
 *	ISC's double quoted strings allow all kinds of extra magic, so
 *	we re-implement string parsing yet again.
 */
static int read_string(rlm_isc_dhcp_tokenizer_t *state)
{
	char *p = state->ptr + 1;
	char *q = state->string;

	while (true) {
		if (!*p) {
			fr_strerror_printf("unterminated string");
			return -1;
		}

		if (*p == '"') {
			p++;
			if (isspace((int) *p)) {
				if (skip_spaces(state, p) < 0) return -1;
				break;
			}
		}

		if ((size_t) (q - state->string) >= sizeof(state->string)) {
			fr_strerror_printf("string is too long");
			return -1;
		}

		if (*p != '\\') {
			*(q++) = *(p++);
			continue;
		}

		// @todo - all of ISC's string escapes, e.g. \x...
	}

	*q = '\0';

	state->token = state->string;
	state->token_len = (q - state->string);
	return 1;
}


/** Reads one token into state->token
 *
 *	Note that this function *destroys* the input buffer.  So if
 *	you need to read two tokens, you have to save the first one
 *	somewhere *outside* of the input buffer.
 */
static int read_token(rlm_isc_dhcp_tokenizer_t *state, fr_token_t hint, int semicolon, bool allow_rcbrace)
{
	char *p;

redo:
	/*
	 *	If the buffer is empty, re-fill it.
	 */
	if (!*state->ptr) {
		int ret;

		ret = refill(state);
		if (ret < 0) return ret;

		if (ret == 0) {
			if (!state->allow_eof) {
				fr_strerror_printf("Unexpected EOF");
				return -1;
			}

			return 0;
		}
	}

	/*
	 *	The previous token may have ended on a space
	 *	or semi-colon.  We skip those characters
	 *	before looking for the next token.
	 */
	while (isspace((int) *state->ptr) || (*state->ptr == ';') || (*state->ptr == ',')) state->ptr++;

	if (!*state->ptr) goto redo;

	/*
	 *	Start looking for the next token from where we left
	 *	off last time.
	 */
	state->token = state->ptr;
	state->saw_semicolon = false;

	/*
	 *	Special-case quoted strings.
	 */
	if (state->token[0] == '"') {
		if (hint != T_DOUBLE_QUOTED_STRING) {
			fr_strerror_printf("Unexpected '\"'");
			return -1;
		}

		return read_string(state);
	}

	for (p = state->token; *p != '\0'; p++) {
		/*
		 *	"end of word" character.  It might be allowed
		 *	here, or it might not be.
		 */
		if (*p == ';') {
			if (semicolon == NO_SEMICOLON) {
				fr_strerror_printf("unexpected ';'");
				return -1;
			}

			state->ptr = p;
			state->saw_semicolon = true;
			break;
		}

		/*
		 *	For lists of things and code definitions.
		 */
		if (*p == ',') {
			state->ptr = p;
			break;
		}

		/*
		 *	Allow braces / equal as single character
		 *	tokens if they're the first character we saw.
		 *	Otherwise, the characters are "end of word"
		 *	markers/
		 */
		if ((*p == '{') || (*p == '}') || (*p == '=')) {
			if (p == state->token) p++;

			state->ptr = p;
			break;
		}

		/*
		 *	If we find a comment, we ignore everything
		 *	until the end of the line.
		 */
		if (*p == '#') {
			*p = '\0';
			state->ptr = p;

			/*
			 *	Nothing here, get more text
			 */
			if (state->token == state->ptr) goto redo;
			break;
		}

		/*
		 *	Whitespace, we're done.
		 */
		if (isspace((int) *p)) {
			if (skip_spaces(state, p) < 0) return -1;
			break;
		}
	}

	/*
	 *	Protect the rest of the code from buffer overflows.
	 */
	state->token_len = p - state->token;

	if (state->token_len == 0) {
		fr_strerror_printf("FUCK");
		return -1;
	}

	if (state->token_len >= 256) {
		fr_strerror_printf("token too large");
		return -1;
	}

	/*
	 *	Double-check the token against what we were expected
	 *	to read.
	 */
	if (hint == T_LCBRACE) {
		if (*state->token != '{') {
			fr_strerror_printf("missing '{'");
			return -1;
		}

		if ((size_t) state->braces >= (sizeof(spaces) - 1)) {
			fr_strerror_printf("sections are nested too deep");
			return -1;
		}

		state->braces++;
		return 1;
	}

	if (hint == T_RCBRACE) {
		if (*state->token != '}') {
			fr_strerror_printf("missing '}'");
			return -1;
		}

		state->braces--;
		return 1;
	}

	/*
	 *	If we're inside of a section, we may also allow
	 *	right-brace as the first keyword.  In that case, it's
	 *	the end of the enclosing section.
	 */
	if (*state->token == '}') {
		if (!allow_rcbrace) {
			fr_strerror_printf("unexpected '}'");
			return -1;
		}

		state->braces--;
		return 1;
	}

	/*
	 *	Don't return left brace if we were looking for a
	 *	something else.
	 */
	if ((hint == T_BARE_WORD) || (hint == T_DOUBLE_QUOTED_STRING)) {
		if (*state->token == '{') {
			fr_strerror_printf("unexpected '{'");
			return -1;
		}
	}


	return 1;
}

/** Recursively match subwords inside of a command string.
 *
 */
static int match_subword(rlm_isc_dhcp_tokenizer_t *state, char const *cmd, rlm_isc_dhcp_info_t *info)
{
	int ret, type;
	int semicolon = NO_SEMICOLON;
	bool multi = false;
	char *p;
	char const *q;
	char const *next;
	char type_name[64];

	fr_skip_whitespace(cmd);

	if (!*cmd) return -1;	/* internal error */

	/*
	 *	Remember the next command.
	 */
	next = q = cmd;
	while (*next && !isspace((int) *next) && (*next != ',')) next++;
	if (!*next) semicolon = YES_SEMICOLON;

	/*
	 *	Matching an in-line word.
	 */
	if (islower((int) *q)) {
		ret = read_token(state, T_BARE_WORD, semicolon, false);
		if (ret <= 0) return -1;

		/*
		 *	Look for a verbatim word.
		 */
		for (p = state->token; p < (state->token + state->token_len); p++, q++) {
			if (*p != *q) {
			fail:
				fr_strerror_printf("Expected '%.*s', got unknown text '%.*s'",
						   state->token_len, state->token,
						   (int) (next - cmd), cmd);
				return -1;
			}
		}

		/*
		 *	Matched all of 'q', we're done.
		 */
		if (!*q) {
			DDEBUG("... WORD %.*s ", state->token_len, state->token);
			return 1;
		}

		/*
		 *	Matched all of this word in 'q', but there are
		 *	more words after this one..  Recurse.
		 */
		if (isspace((int) *q)) {
			return match_subword(state, next, info);
		}

		/*
		 *	Matched all of 'p', but there's more 'q'.  Fail.
		 *
		 *	e.g. got "foo", but expected "food".
		 */
		goto fail;
	}

	/*
	 *	SECTION must be the last thing in the command
	 */
	if (strcmp(q, "SECTION") == 0) {
		if (q[7] != '\0') return -1; /* internal error */

		ret = read_token(state, T_LCBRACE, NO_SEMICOLON, false);
		if (ret <= 0) return ret;

		ret = parse_section(state, info);
		if (ret < 0) return ret;

		/*
		 *	Empty sections are allowed.
		 */
		return 2;	/* SECTION */
	}

	/*
	 *	Uppercase words are INTEGER or STRING or IPADDR, which
	 *	are FreeRADIUS data types.
	 *
	 *	We copy the name here because some options allow for
	 *	multiple fields.
	 */
	p = type_name;
	while (*q && !isspace((int) *q) && (*q != ',')) {
		if ((p - type_name) >= (int) sizeof(type_name)) return -1; /* internal error */
		*(p++) = tolower((int) *(q++));
	}
	*p = '\0';

	/*
	 *	"fixed-address IPADDR," means it can take multiple IP
	 *	addresses.
	 *
	 *	@todo - pre-parse the field and save the strings
	 *	somewhere, so that we can create info->argv of the
	 *	right size.  Or, just create an array of 2 by default,
	 *	and then double it every time we run out... a little
	 *	more work, but it doesn't involve further mangling the
	 *	parser.
	 *
	 *	We could likely just manually parse state->ptr, look
	 *	until ';' or '\0', and count the words.  That would
	 *	work 99% of the time.
	 *
	 *	@todo - We should also note that the ISC default is to
	 *	allow hostnames, in which case it will add all IPs
	 *	associated with that hostname, while we will add only
	 *	one.  That could likely be fixed, too.
	 */
	if (*q == ',') {
		if (q[1]) return -1; /* internal error */
		multi = true;
		semicolon = MAYBE_SEMICOLON;
	}

	type = fr_table_value_by_str(fr_value_box_type_table, type_name, -1);
	if (type < 0) {
		fr_strerror_printf("unknown data type '%.*s'",
				   (int) (next - cmd), cmd);
		return -1;	/* internal error */
	}

redo_multi:
	/*
	 *	We were asked to parse a data type, so instead allow
	 *	just about anything.
	 *
	 *	@todo - if we get fancy, dynamically expand this, too.
	 *	ISC doesn't support it, but we can.
	 */
	ret = read_token(state, T_DOUBLE_QUOTED_STRING, semicolon, false);
	if (ret <= 0) return ret;

	DDEBUG("... DATA %.*s ", state->token_len, state->token);

	/*
	 *	BOOLs in ISC are "true", "false", or "ignore".
	 *
	 *	Isn't that smart?  "ignore" means "ignore this option
	 *	as if it was commented out".  So we do that.
	 *
	 *	I sure wish I was smart enough to allow 3 values for a
	 *	boolean data type.
	 */
	if ((type == FR_TYPE_BOOL) && (state->token_len == 6) &&
	    (strcmp(state->token, "ignore") == 0)) {
		talloc_free(info);
		return 2;
	}

	/*
	 *	Parse the data to its final form.
	 */
	info->argv[info->argc] = talloc_zero(info, fr_value_box_t);

	ret = fr_value_box_from_str(info, info->argv[info->argc], (fr_type_t *) &type, NULL,
				      state->token, state->token_len, 0, false);
	if (ret < 0) return ret;

	info->argc++;

	if (multi) {
		if (state->saw_semicolon) return 1;

		if (info->argc >= info->cmd->max_argc) {
			fr_strerror_printf("Too many arguments (%d > %d) for command '%s'",
					   info->argc, info->cmd->max_argc, info->cmd->name);
			return -1;
		}

		goto redo_multi;
	}

	/*
	 *	No more command to parse, return OK.
	 */
	if (!*next) return 1;

	/*
	 *	Keep matching more things
	 */
	return match_subword(state, next, info);
}

/*
 *	include FILENAME ;
 */
static int parse_include(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info)
{
	int ret;
	char *p, pathname[8192];
	char const *name = info->argv[0]->vb_strvalue;

	IDEBUG("%.*s include %s ;", state->braces, spaces, name);

	p = strrchr(state->filename, '/');
	if (p) {
		strlcpy(pathname, state->filename, sizeof(pathname));
		p = pathname + (p - state->filename) + 1;
		strlcpy(p, name, sizeof(pathname) - (p - pathname));

		name = pathname;
	}

	/*
	 *	Note that we read the included file into the PARENT's
	 *	list.  i.e. as if the file was included in-place.
	 */
	ret = read_file(state->inst, info->parent, name);
	if (ret < 0) return ret;

	/*
	 *	Even if the file was empty, we return "1" to indicate
	 *	that we successfully parsed the file.  Returning "0"
	 *	would indicate that the parent file was at EOF.
	 */
	return 1;
}


typedef struct {
	uint8_t			ether[6];
	rlm_isc_dhcp_info_t	*host;
} isc_host_ether_t;

static uint32_t host_ether_hash(void const *data)
{
	isc_host_ether_t const *self = data;

	return fr_hash(self->ether, sizeof(self->ether));
}

static int host_ether_cmp(void const *one, void const *two)
{
	isc_host_ether_t const *a = one;
	isc_host_ether_t const *b = two;

	return memcmp(a->ether, b->ether, 6);
}

typedef struct {
	fr_value_box_t		*client;
	rlm_isc_dhcp_info_t	*host;
} isc_host_uid_t;

static uint32_t host_uid_hash(void const *data)
{
	isc_host_uid_t const *self = data;

	return fr_hash(self->client->vb_octets, self->client->vb_length);
}

static int host_uid_cmp(void const *one, void const *two)
{
	isc_host_uid_t const *a = one;
	isc_host_uid_t const *b = two;

	if ( a->client->vb_length < b->client->vb_length) return -1;
	if ( a->client->vb_length > b->client->vb_length) return +1;

	return memcmp(a->client->vb_octets, b->client->vb_octets, a->client->vb_length);
}


/**	option space name [ [ code width number ] [ length width number ] [ hash size number ] ] ;
 *
 */
static int parse_option_space(UNUSED rlm_isc_dhcp_info_t *parent, UNUSED rlm_isc_dhcp_tokenizer_t *state,
			      UNUSED char *name)
{
	// @todo - register the named option space with inst->option_space
	//	   and create inst->option_space
	fr_strerror_printf("please implement 'option space name [ [ code width number ] [ length width number ] [ hash size number ] ]'");
	return -1;
}


/** Parse one type string.
 *

 *	boolean
 *	[signed|unsigned] integer [width]
 *		width is 8, 16, or 32
 *	ip-address
 *	ip6-address
 *	text
 *	string
 *	domain-list [compressed]
 *	encapsulate _identifier_
 */

#define TYPE_CHECK(name, type) if ((state->token_len == (sizeof(name) - 1)) && (memcmp(state->token, name, sizeof(name) - 1) == 0)) return type
static fr_type_t isc2fr_type(rlm_isc_dhcp_tokenizer_t *state)
{
	TYPE_CHECK("boolean", FR_TYPE_BOOL);
	TYPE_CHECK("integer", FR_TYPE_UINT32);
	TYPE_CHECK("ip-address", FR_TYPE_IPV4_ADDR);
	TYPE_CHECK("ip6-address", FR_TYPE_IPV6_ADDR);
	TYPE_CHECK("text", FR_TYPE_STRING);
	TYPE_CHECK("string", FR_TYPE_OCTETS);

	fr_strerror_printf("unknown type '%.*s'", state->token_len, state->token);
	return FR_TYPE_INVALID;
}


/** option new-name code new-code = definition ;
 *
 *	"new-name" can also be SPACE.NAME
 *
 */
static int parse_option_definition(rlm_isc_dhcp_info_t *parent, rlm_isc_dhcp_tokenizer_t *state,
				   char *name)
{
	int ret;
	char *p;
	fr_type_t type;
	fr_dict_attr_t const *da, *root;
	fr_value_box_t box;
	fr_dict_attr_flags_t flags;

	p = strchr(name, '.');
	if (p) {
		fr_strerror_printf("cannot (yet) define options in spaces");
	error:
		talloc_free(name);
		return -1;
	}

	if (parent != state->inst->head) {
		fr_strerror_printf("option definitions cannot be scoped");
		goto error;
	}

	/*
	 *	Grab the integer code value.
	 */
	ret = read_token(state, T_BARE_WORD, NO_SEMICOLON, false);
	if (ret <= 0) {
	error_ret:
		talloc_free(name);
		return ret;
	}

	type = FR_TYPE_UINT32;
	ret = fr_value_box_from_str(NULL, &box, &type, NULL,
				      state->token, state->token_len, 0, false);
	if (ret < 0) goto error;

	/*
	 *	Look for '='
	 */
	ret = read_token(state, T_BARE_WORD, NO_SEMICOLON, false);
	if (ret <= 0) goto error_ret;

	if ((state->token_len != 1) || (state->token[0] != '=')) {
		fr_strerror_printf("expected '=' after code definition got '%.*s'", state->token_len, state->token);
		goto error;
	}

	memset(&flags, 0, sizeof(flags));

	/*
	 *	Data type is:
	 *
	 *	TYPE
	 *	array of TYPE
	 *	{ TYPE, ... }
	 *
	 *	Note that it also supports
	 *
	 *	array of { TYPE, ... }
	 */
	ret = read_token(state, T_BARE_WORD, MAYBE_SEMICOLON, false);
	if (ret <= 0) goto error_ret;


	if ((state->token_len == 5) && (memcmp(state->token, "array", 5) == 0)) {
		flags.array = 1;

		ret = read_token(state, T_BARE_WORD, NO_SEMICOLON, false);
		if (ret <= 0) goto error_ret;

		if (! ((state->token_len == 2) && (memcmp(state->token, "of", 2) == 0))) {
			fr_strerror_printf("expected 'array of', not 'array %.*s'",
					   state->token_len, state->token);
			goto error;
		}

		/*
		 *	Grab the next token.  For now, it MUST have a semicolon
		 */
		ret = read_token(state, T_BARE_WORD, YES_SEMICOLON, false);
		if (ret <= 0) goto error_ret;
	}

	if ((state->token_len == 1) && (state->token[0] == '{')) {
		fr_strerror_printf("records are not supported in option definition");
		goto error;
	}

	/*
	 *	This check is needed only because we have
	 *	MAYBE_SEMICOLON above.  That's in order to allow
	 *	"array of.." statements to product an *array* error,
	 *	not a *semicolon* error.
	 */
	if (!state->saw_semicolon) {
		fr_strerror_printf("expected ';'");
		goto error;
	}

	type = isc2fr_type(state);
	if (type == FR_TYPE_INVALID) goto error;

	/*
	 *	Now that we've parsed everything, look up the name.
	 *	We forbid conflicts, but silently allow duplicates.
	 */
	da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_dhcpv4), name);
	if (da &&
	    ((da->attr != box.vb_uint32) || (da->type != type))) {
		fr_strerror_printf("cannot add different code / type for a pre-existing name '%s'", name);
		goto error;
	}

	/*
	 *	And look it up by code, too.
	 *
	 *	We allow multiple attributes of the same code / type,
	 *	but with different names.
	 */
	root = fr_dict_root(dict_dhcpv4);
	da = fr_dict_attr_child_by_num(root, box.vb_uint32);
	if (da && (da->type != type)) {
		fr_strerror_printf("cannot add different type for a pre-existing code %d", box.vb_uint32);
		goto error;
	}

	/*
	 *	Add it in.  Note that this function adds it by name
	 *	and by code.  So we don't *necessarily* have to do the
	 *	name/code checks above.  But doing so allows us to
	 *	have better error messages.
	 */
	ret = fr_dict_attr_add(fr_dict_unconst(dict_dhcpv4), root, name, box.vb_uint32, type, &flags);
	talloc_free(name);
	if (ret < 0) return ret;

	/*
	 *	Caller doesn't need to do anything else with the thing
	 *	we just parsed.
	 */
	return 2;
}

static int parse_option(rlm_isc_dhcp_info_t *parent, rlm_isc_dhcp_tokenizer_t *state,
			fr_dict_attr_t const *da, char *value)
{
	int ret;
	fr_pair_t *vp;
	fr_cursor_t cursor;

	/*
	 *	The attribute isn't an array, so it MUST have a
	 *	semicolon after it.
	 */
	if (!da->flags.array && !state->saw_semicolon) {
		fr_strerror_printf("expected ';' %s", state->ptr);
		return -1;
	}

	MEM(vp = fr_pair_afrom_da(parent, da));
	(void) fr_cursor_init(&cursor, &parent->options);

	/*
	 *	Add in the first value.
	 */
	ret = fr_pair_value_from_str(vp, value, talloc_array_length(value) - 1, '\0', false);
	if (ret < 0) {
		talloc_free(value);
		return ret;
	}

	vp->op = T_OP_EQ;

	fr_cursor_append(&cursor, vp);
	(void) fr_cursor_tail(&cursor);

	// @todo - print out ISC names...
	IDEBUG("%.*s option %s %s ", state->braces, spaces, da->name, value);
	talloc_free(value);

	/*
	 *	We've remembered the option in the parent option list.
	 *	There's no need to add it to the child list here.
	 */
	if (!da->flags.array) return 2;

	/*
	 *	For "array" types, loop through the remaining tokens.
	 */
	while (!state->saw_semicolon) {
		ret = read_token(state, T_DOUBLE_QUOTED_STRING, MAYBE_SEMICOLON, false);
		if (ret <= 0) return ret;

		MEM(vp = fr_pair_afrom_da(parent, da));

		ret = fr_pair_value_from_str(vp, state->token, state->token_len, '\0', false);
		if (ret < 0) return ret;

		vp->op = T_OP_EQ;

		fr_cursor_append(&cursor, vp);
		(void) fr_cursor_tail(&cursor);

		// @todo - print out ISC names...
		IDEBUG("%.*s option %s %.*ss ", state->braces, spaces, da->name, state->token_len, state->token);
	}

	/*
	 *	We've remembered the option in the parent option list.
	 *	There's no need to add it to the child list here.
	 */
	return 2;
}

/** Parse "option" command
 *
 *	In any sane system, commands which do different things should
 *	have different names.  In this syntax, it's all miracles and
 *	unicorns.
 *
 *	option NAME VALUE ;
 *	option new-name code new-code = definition ;
 *
 *	option space name [ [ code width number ] [ length width number ] [ hash size number ] ] ;
 */
static int parse_options(rlm_isc_dhcp_info_t *parent, rlm_isc_dhcp_tokenizer_t *state)
{
	int ret, argc = 0;
	char *argv[2];
	char name[FR_DICT_ATTR_MAX_NAME_LEN + 5];

	/*
	 *	Since read_token() mashes the input buffer, we have to save the tokens somewhere.
	 */
	while (!state->saw_semicolon) {
		ret = read_token(state, T_BARE_WORD, MAYBE_SEMICOLON, false);
		if (ret < 0) return ret;

		argv[argc++] = talloc_strndup(parent, state->token, state->token_len);

		if (argc == 2) break;
	}

	/*
	 *	Must have at least two arguments.
	 */
	if (argc < 2) {
		fr_strerror_printf("unexpected ';'");
		return -1;
	}

	/*
	 *	Define an option space.
	 */
	if (strcmp(argv[0], "space") == 0) {
		talloc_free(argv[0]);
		return parse_option_space(parent, state, argv[1]);
	}

	/*
	 *	Look up the name.  If the option is defined, then
	 *	parse the following options according to the data
	 *	type.  Which MAY be a "struct" data type, or an
	 *	"array" data type.
	 */
	if (state->saw_semicolon || (state->ptr[0] == ',')) {
		fr_dict_attr_t const *da;

		da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_dhcpv4), argv[0]);
		if (da) {
			talloc_free(argv[0]);
			return parse_option(parent, state, da, argv[1]);
		}

		/*
		 *	@todo - nuke this extra step once we have dictionary.isc defined.
		 */
		memcpy(name, "DHCP-", 5);
		strlcpy(name + 5, argv[0], sizeof(name) - 5);

		da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_dhcpv4), name);
		if (da) {
			talloc_free(argv[0]);
			return parse_option(parent, state, da, argv[1]);
		}
	}

	/*
	 *	The NAME isn't a known option.
	 *
	 *	It must be "option NAME code NUMBER = DEFINITION"
	 */
	if (strcmp(argv[1], "code") != 0) {
		fr_strerror_printf("unknown option '%s'", argv[0]);
		talloc_free(argv[0]);
		talloc_free(argv[1]);
		return -1;
	}

	talloc_free(argv[1]);
	return parse_option_definition(parent, state, argv[0]);
}


static int match_keyword(rlm_isc_dhcp_info_t *parent, rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_cmd_t const *tokens, int num_tokens)
{
	int start, end, half;
	int semicolon;
	int ret;
	char const *q = NULL;
	rlm_isc_dhcp_info_t *info;

	start = 0;
	end = num_tokens - 1;
	half = -1;

	/*
	 *	There are no super-short commands.
	 */
	if (state->token_len < 4) goto unknown;

	/*
	 *	Walk over the input token, doing a binary search on
	 *	the token list.
	 */
	while (start <= end) {
		half = (start + end) / 2;

		/*
		 *	Skips a function call, and is better for 99%
		 *	of the situations.  Since there are no 1 or 2
		 *	character keywords, this always works.
		 */
		ret = state->token[0] - tokens[half].name[0];
		if (ret != 0) goto recurse;

		ret = state->token[1] - tokens[half].name[1];
		if (ret != 0) goto recurse;

		ret = state->token[2] - tokens[half].name[2];
		if (ret != 0) goto recurse;

		/*
		 *	Compare all of the strings.
		 */
		ret = strncmp(state->token, tokens[half].name, state->token_len);

		/*
		 *	Exact match.  But maybe we have "foo" input,
		 *	and "food" command?
		 */
		if (ret == 0) {
			char c = tokens[half].name[state->token_len];

			/*
			 *	The token exactly matches the command.
			 */
			if (!c || isspace((int) c)) {
				q = &(tokens[half].name[state->token_len]);
				break;
			}

			/*
			 *	The token is "foo", but the command is
			 *	"food".  Go search the lower half of
			 *	the command table.
			 */
			ret = -1;
		}

	recurse:
		/*
		 *	Token is smaller than the command we checked,
		 *	go check the lower half of the table.
		 */
		if (ret < 0) {
			end = half - 1;
		} else {
			start = half + 1;
		}
	}

	/*
	 *	Nothing matched, it's a failure.
	 */
	if (!q) {
	unknown:
		fr_strerror_printf("unknown command '%.*s'", state->token_len, state->token);
		return -1;
	}

	fr_assert(half >= 0);

	/*
	 *	"option" has multiple parse possibilities, so we treat
	 *	it specially.
	 */
	if (tokens[half].type == ISC_OPTION) {
		return parse_options(parent, state);
	}

	/*
	 *	Print out more warnings / errors in pedantic mode.
	 */
	if (state->inst->pedantic && !tokens[half].parse) {
		if (tokens[half].type == ISC_INVALID) {
			ERROR("Command '%.*s' is not supported.",
			      state->token_len, state->token);
			return -1;
		}

		/*
		 *	Print out WARNING messages only in debug mode.
		 *	We don't need to spam the main log file every
		 *	time the server starts.
		 */
		if (DEBUG_ENABLED) {
			if (tokens[half].type == ISC_NOOP) {
				WARN("Command '%.*s' is not yet implemented.",
				     state->token_len, state->token);
			}

			if (tokens[half].type == ISC_IGNORE) {
				WARN("Ignoring command '%.*s'.  It is not relevant.",
				     state->token_len, state->token);
			}
		}
	}

	semicolon = YES_SEMICOLON; /* default to always requiring this */

	DDEBUG("... TOKEN %.*s ", state->token_len, state->token);

	info = talloc_zero(parent, rlm_isc_dhcp_info_t);
	fr_pair_list_init(&info->options);
	if (tokens[half].max_argc) {
		info->argv = talloc_zero_array(info, fr_value_box_t *, tokens[half].max_argc);
	}

	/*
	 *	Remember which command we parsed.
	 */
	info->parent = parent;
	info->cmd = &tokens[half];
	info->last = &(info->child);

	/*
	 *	There's more to this command,
	 *	go parse that, too.
	 */
	if (isspace((int) *q)) {
		if (state->saw_semicolon) goto unexpected;

		ret = match_subword(state, q, info);
		if (ret <= 0) return ret;

		/*
		 *	SUBSECTION must be at the end
		 */
		if (ret == 2) semicolon = NO_SEMICOLON;
	}

	/*
	 *	*q must be empty at this point.
	 */
	if ((semicolon == NO_SEMICOLON) && state->saw_semicolon) {
	unexpected:
		fr_strerror_printf("unexpected ';'");
		talloc_free(info);
		return -1;
	}

	if ((semicolon == YES_SEMICOLON) && !state->saw_semicolon) {
		fr_strerror_printf("missing ';'");
		talloc_free(info);
		return -1;
	}

	// @todo - print out the thing we parsed

	/*
	 *	Call the "parse" function which should do
	 *	validation, etc.
	 */
	if (tokens[half].parse) {
		ret = tokens[half].parse(state, info);
		if (ret <= 0) {
			talloc_free(info);
			return ret;
		}

		/*
		 *	The parse function took care of
		 *	remembering the "info" structure.  So
		 *	we don't add it to the parent list.
		 *
		 *	This process ensures that for some
		 *	things (e.g. hosts and subnets), we
		 *	have have O(1) lookups instead of
		 *	O(N).
		 *
		 *	It also means that the *rest* of the
		 *	commands we parse are in a relatively
		 *	tiny list, which makes the O(N)
		 *	processing of it fairly minor.
		 */
		if (ret == 2) return 1;
	}

	/*
	 *	Add the parsed structure to the tail of the
	 *	current list.  Note that this portion adds
	 *	only ONE command at a time.
	 */
	*(parent->last) = info;
	parent->last = &(info->next);

	/*
	 *	It's a match, and it's OK.
	 */
	return 1;
}

/** host NAME { ... }
 *
 *	Hosts are global, and are keyed by MAC `hardware ethernet`, and by
 *	`client-identifier`.
 */
static int parse_host(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info)
{
	isc_host_ether_t *my_ether, *old_ether;
	isc_host_uid_t *my_uid, *old_uid;
	rlm_isc_dhcp_info_t *ether, *child, *parent;
	fr_pair_t *vp;

	ether = NULL;
	my_uid = NULL;

	/*
	 *	A host MUST have at least one "hardware ethernet" in
	 *	it.
	 */
	for (child = info->child; child != NULL; child = child->next) {
		if (child->cmd->type == ISC_HARDWARE_ETHERNET) {
			if (ether) {
				fr_strerror_printf("cannot have two 'hardware ethernet' entries in a 'host'");
				return -1;
			}

			ether = child;
		}
	}

	if (!ether) {
		fr_strerror_printf("host %s does not contain a 'hardware ethernet' entry",
				   info->argv[0]->vb_strvalue);
		return -1;
	}

	/*
	 *	Point directly to the ethernet address.
	 */
	my_ether = talloc_zero(info, isc_host_ether_t);
	memcpy(my_ether->ether, &(ether->argv[0]->vb_ether), sizeof(my_ether->ether));
	my_ether->host = info;

	/*
	 *	We can't have duplicate ethernet addresses for hosts.
	 */
	old_ether = fr_hash_table_find_by_data(state->inst->hosts_by_ether, my_ether);
	if (old_ether) {
		fr_strerror_printf("'host %s' and 'host %s' contain duplicate 'hardware ethernet' fields",
				   info->argv[0]->vb_strvalue, old_ether->host->argv[0]->vb_strvalue);
		talloc_free(my_ether);
		return -1;
	}

	/*
	 *	The 'host' entry might not have a client identifier option.
	 */
	vp = fr_pair_find_by_da(&info->options, attr_client_identifier);
	if (vp) {
		my_uid = talloc_zero(info, isc_host_uid_t);
		my_uid->client = &vp->data;
		my_uid->host = info;

		old_uid = fr_hash_table_find_by_data(state->inst->hosts_by_uid, my_uid);
		if (old_uid) {
			fr_strerror_printf("'host %s' and 'host %s' contain duplicate 'option client-identifier' fields",
					   info->argv[0]->vb_strvalue, old_uid->host->argv[0]->vb_strvalue);
			talloc_free(my_ether);
			talloc_free(my_uid);
			return -1;
		}
	}

	/*
	 *	Insert into the ether hashes.
	 */
	if (fr_hash_table_insert(state->inst->hosts_by_ether, my_ether) < 0) {
		fr_strerror_printf("Failed inserting 'host %s' into hash table",
				   info->argv[0]->vb_strvalue);
		talloc_free(my_ether);
		if (my_uid) talloc_free(my_uid);
		return -1;
	}

	if (my_uid) {
		if (fr_hash_table_insert(state->inst->hosts_by_uid, my_uid) < 0) {
			fr_strerror_printf("Failed inserting 'host %s' into hash table",
					   info->argv[0]->vb_strvalue);
			talloc_free(my_uid);
			return -1;
		}
	}

	/*
	 *	The host doesn't have a parent, that's fine..
	 *
	 *	It typically should tho...
	 */
	if (!info->parent) return 2;

	parent = info->parent;

	/*
	 *	Add the host to the *parents* hash table.  That way
	 *	when we apply the parent, we can look up the host in
	 *	its hash table.  And avoid the O(N) issue of having
	 *	thousands of "host" entries in the parent->child list.
	 */
	if (!parent->hosts_by_ether) {
		parent->hosts_by_ether = fr_hash_table_create(parent, host_ether_hash, host_ether_cmp, NULL);
		if (!parent->hosts_by_ether) {
			return -1;
		}
	}

	if (fr_hash_table_insert(parent->hosts_by_ether, my_ether) < 0) {
		fr_strerror_printf("Failed inserting 'host %s' into hash table",
				   info->argv[0]->vb_strvalue);
		return -1;
	}

	/*
	 *	If we have a UID, insert into the UID hashes.
	 */
	if (my_uid) {
		if (!parent->hosts_by_uid) {
			parent->hosts_by_uid = fr_hash_table_create(parent, host_uid_hash, host_uid_cmp, NULL);
			if (!parent->hosts_by_uid) {
				return -1;
			}
		}


		if (fr_hash_table_insert(parent->hosts_by_uid, my_uid) < 0) {
			fr_strerror_printf("Failed inserting 'host %s' into hash table",
					   info->argv[0]->vb_strvalue);
			return -1;
		}
	}

	IDEBUG("%.*s host %s { ... }", state->braces, spaces, info->argv[0]->vb_strvalue);

	/*
	 *	We've remembered the host in the parent hosts hash.
	 *	There's no need to add it to the child list here.
	 */
	return 2;
}

/*
 *	Utter laziness
 */
#define vb_ipv4addr vb_ip.addr.v4.s_addr

/** subnet IPADDR netmask MASK { ... }
 *
 */
static int parse_subnet(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info)
{
	rlm_isc_dhcp_info_t *parent;
	int ret, bits;
	uint32_t netmask = info->argv[1]->vb_ipv4addr;

	/*
	 *	Check if argv[1] is a valid netmask
	 */
	if (!(netmask & (~netmask >> 1))) {
		fr_strerror_printf("invalid netmask '%pV'", info->argv[1]);
		return -1;
	}

	/*
	 *	192.168.2.1/16 is wrong.
	 */
	if ((info->argv[0]->vb_ipv4addr & netmask) != info->argv[0]->vb_ipv4addr) {
		fr_strerror_printf("subnet '%pV' does not match netmask '%pV'", info->argv[0], info->argv[1]);
		return -1;
	}

	/*
	 *	Get number of bits set in netmask.
	 */
	netmask = netmask - ((netmask >> 1) & 0x55555555);
	netmask = (netmask & 0x33333333) + ((netmask >> 2) & 0x33333333);
	netmask = (netmask + (netmask >> 4)) & 0x0F0F0F0F;
	netmask = netmask + (netmask >> 8);
	netmask = netmask + (netmask >> 16);
	bits = netmask & 0x0000003F;

	parent = info->parent;
	if (parent->subnets) {
		rlm_isc_dhcp_info_t *old;

		/*
		 *	Duplicate or overlapping "subnet" entries aren't allowd.
		 */
		old = fr_trie_lookup(parent->subnets, &(info->argv[0]->vb_ipv4addr), bits);
		if (old) {
			fr_strerror_printf("subnet %pV netmask %pV' overlaps with existing subnet", info->argv[0], info->argv[1]);
			return -1;

		}
	} else {
		parent->subnets = fr_trie_alloc(parent);
		if (!parent->subnets) return -1;
	}

	/*
	 *	Add the subnet to the *parents* trie.  That way when
	 *	we apply the parent, we can look up the subnet in its
	 *	trie.  And avoid the O(N) issue of having thousands of
	 *	"subnet" entries in the parent->child list.
	 */

	ret = fr_trie_insert(parent->subnets, &(info->argv[0]->vb_ipv4addr), bits, info);
	if (ret < 0) {
		fr_strerror_printf("Failed inserting 'subnet %pV netmask %pV' into trie",
				   info->argv[0], info->argv[1]);
		return -1;
	}

	/*
	 *	@todo - if there's no 'option subnet-mask', add one
	 *	from the netmask given here.  If there is an 'option
	 *	subnet-mask', then assume that the admin knows what
	 *	he's doing, and don't add one.
	 */

	IDEBUG("%.*s subnet %pV netmask %pV { ... }", state->braces, spaces, info->argv[0], info->argv[1]);

	/*
	 *	We've remembered the subnet in the parent trie.
	 *	There's no need to add it to the child list here.
	 */
	return 2;
}

static rlm_isc_dhcp_info_t *get_host(request_t *request, fr_hash_table_t *hosts_by_ether, fr_hash_table_t *hosts_by_uid)
{
	fr_pair_t *vp;
	isc_host_ether_t *ether, my_ether;
	rlm_isc_dhcp_info_t *host = NULL;

	/*
	 *	Look up the host first by client identifier.
	 *	If that doesn't match, use client hardware
	 *	address.
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, attr_client_identifier);
	if (vp) {
		isc_host_uid_t *client, my_client;

		my_client.client = &(vp->data);

		client = fr_hash_table_find_by_data(hosts_by_uid, &my_client);
		if (client) {
			host = client->host;
			goto done;
		}
	}


	vp = fr_pair_find_by_da(&request->request_pairs, attr_client_hardware_address);
	if (!vp) return NULL;

	memcpy(&my_ether.ether, vp->vp_ether, sizeof(my_ether.ether));

	ether = fr_hash_table_find_by_data(hosts_by_ether, &my_ether);
	if (!ether) return NULL;

	host = ether->host;

done:
	/*
	 *	@todo - check "fixed-address".  This host entry should
	 *	match ONLY if one of the addresses matches the network
	 *	on which the client is booting.  OR if there's no
	 *	'fixed-address' field.  OR if there's no 'yiaddr' in
	 *	the request.
	 */

	return host;
}


static int add_option_by_da(rlm_isc_dhcp_info_t *info, fr_dict_attr_t const *da)
{
	int ret;
	fr_pair_t *vp;
	fr_cursor_t cursor;

	if (!info->parent) return -1; /* internal error */

	MEM(vp = fr_pair_afrom_da(info->parent, da));

	ret = fr_value_box_copy(vp, &(vp->data), info->argv[0]);
	if (ret < 0) return ret;

	(void) fr_cursor_init(&cursor, &info->parent->options);
	(void) fr_cursor_tail(&cursor);
	fr_cursor_append(&cursor, vp);

	talloc_free(info);
	return 2;
}

#define member_size(type, member) sizeof(((type *)0)->member)

/** filename STRING
 *
 */
static int parse_filename(UNUSED rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info)
{
	if (info->argv[0]->vb_length > member_size(dhcp_packet_t, file)) {
		fr_strerror_printf("filename is too long");
		return -1;
	}

	return add_option_by_da(info, attr_boot_filename);
}

/** server-name STRING
 *
 */
static int parse_server_name(UNUSED rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info)
{
	if (info->argv[0]->vb_length > member_size(dhcp_packet_t, sname)) {
		fr_strerror_printf("filename is too long");
		return -1;
	}

	return add_option_by_da(info, attr_server_name);
}

/** server-identifier IPADDR
 *
 *
 *	This is really "option dhcp-server-identifier IPADDR"
 *	But whatever
 */
static int parse_server_identifier(UNUSED rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info)
{
	return add_option_by_da(info, attr_server_identifier);
}

/** next-server IPADDR
 *
 */
static int parse_next_server(UNUSED rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info)
{
	return add_option_by_da(info, attr_server_ip_address);
}

/*
 *  When a client is to be booted, its boot parameters are determined
 *  by consulting that client’s host declaration (if any), and then
 *  consulting any class declarations matching the client, followed by
 *  the pool, subnet and shared-network declarations for the IP
 *  address assigned to the client. Each of these declarations itself
 *  appears within a lexical scope, and all declarations at less
 *  specific lexical scopes are also consulted for client option
 *  declarations. Scopes are never considered twice, and if parameters
 *  are declared in more than one scope, the parameter declared in the
 *  most specific scope is the one that is used.
 *
 *  When dhcpd tries to find a host declaration for a client, it first
 *  looks for a host declaration which has a fixed-address declaration
 *  that lists an IP address that is valid for the subnet or shared
 *  network on which the client is booting. If it doesn’t find any
 *  such entry, it tries to find an entry which has no fixed-address
 *  declaration.
 */

/** Apply fixed IPs
 *
 */
static int apply_fixed_ip(rlm_isc_dhcp_t const *inst, request_t *request)
{
	int ret;
	rlm_isc_dhcp_info_t *host, *info;
	fr_pair_t *vp;
	fr_pair_t *yiaddr;

	/*
	 *	If there's already a fixed IP, don't do anything
	 */
	yiaddr = fr_pair_find_by_da(&request->reply_pairs, attr_your_ip_address);
	if (yiaddr) return 0;

	host = get_host(request, inst->hosts_by_ether, inst->hosts_by_uid);
	if (!host) return 0;

	/*
	 *	Find a "fixed-address" sub-statement.
	 */
	for (info = host->child; info != NULL; info = info->next) {
		fr_cursor_t cursor;

		if (!info->cmd) return -1; /* internal error */

		/*
		 *	Skip complex statements
		 */
		if (info->child) continue;

		if (info->cmd->type != ISC_FIXED_ADDRESS) continue;

		MEM(vp = fr_pair_afrom_da(request->reply_pairs, attr_your_ip_address));

		ret = fr_value_box_copy(vp, &(vp->data), info->argv[0]);
		if (ret < 0) return ret;

		/*
		 *	<sigh> I miss pair_add()
		 */
		(void) fr_cursor_init(&cursor, &request->reply_pairs);
		(void) fr_cursor_tail(&cursor);
		fr_cursor_append(&cursor, vp);

		/*
		 *	If we've found a fixed IP, then tell
		 *	the parent to stop iterating over
		 *	children.
		 */
		return 2;
	}

	return 0;
}

/** Apply all rules *except* fixed IP
 *
 */
static int apply(rlm_isc_dhcp_t const *inst, request_t *request, rlm_isc_dhcp_info_t *head)
{
	int ret, child_ret;
	rlm_isc_dhcp_info_t *info;
	fr_pair_t *yiaddr;

	ret = 0;
	yiaddr = fr_pair_find_by_da(&request->reply_pairs, attr_your_ip_address);

	/*
	 *	First, apply any "host" options
	 */
	if (head->hosts_by_ether) {
		rlm_isc_dhcp_info_t *host = NULL;

		host = get_host(request, head->hosts_by_ether, head->hosts_by_uid);
		if (!host) goto subnet;

		/*
		 *	Apply any options in the "host" section.
		 */
		child_ret = apply(inst, request, host);
		if (child_ret < 0) return child_ret;
		if (child_ret == 1) ret = 1;
	}

subnet:
	/*
	 *	Look in the trie for matching subnets, and apply any
	 *	subnets that match.
	 */
	if (head->subnets && yiaddr) {
		info = fr_trie_lookup(head->subnets, &yiaddr->vp_ipv4addr, 32);
		if (!info) goto recurse;

		child_ret = apply(inst, request, info);
		if (child_ret < 0) return child_ret;
		if (child_ret == 1) ret = 1;
	}

recurse:
	for (info = head->child; info != NULL; info = info->next) {
		if (!info->cmd) return -1; /* internal error */

		if (!info->cmd->apply) continue;

		child_ret = info->cmd->apply(inst, request, info);
		if (child_ret < 0) return child_ret;
		if (child_ret == 0) continue;

		ret = 1;
	}

	/*
	 *	Now that our children have added options, see if we
	 *	can add some, too.
	 */
	if (head->options) {
		fr_pair_t *vp = NULL;
		fr_cursor_t option_cursor;
		fr_cursor_t reply_cursor;

		(void) fr_cursor_init(&reply_cursor, &request->reply_pairs);
		(void) fr_cursor_tail(&reply_cursor);

		/*
		 *	Walk over the input list, adding the options
		 *	only if they don't already exist in the reply.
		 *
		 *	Yes, we know that this is O(R*P*D), complexity
		 *	is (reply VPs * option VPs * depth of options).
		 *
		 *	Unless we make the code a lot smarter, this is
		 *	the best we can do.  Since there are likely
		 *	only a few options (i.e. less than 100), this
		 *	is deemed to be OK.
		 *
		 *	In order to fix this, we would need to sort
		 *	all of the options first, sort the reply VPs,
		 *	then walk over the reply VPs, and look at each
		 *	option list in turn, seeing if there are
		 *	options that match.  This would likely be
		 *	faster.
		 */
		for (vp = fr_cursor_init(&option_cursor, &head->options);
		     vp != NULL;
		     vp = fr_cursor_next(&option_cursor)) {
			fr_pair_t *reply;

			reply = fr_pair_find_by_da(&request->reply_pairs, vp->da);
			if (reply) continue;

			/*
			 *	Copy all of the same options to the
			 *	reply.
			 */
			while (vp) {
				fr_pair_t *next, *copy;

				copy = fr_pair_copy(request->reply, vp);
				if (!copy) return -1;

				fr_cursor_append(&reply_cursor, copy);
				(void) fr_cursor_tail(&reply_cursor);

				next = fr_cursor_next_peek(&option_cursor);
				if (!next) break;
				if (next->da != vp->da) break;

				vp = fr_cursor_next(&option_cursor);
			}
		}

		/*
		 *	We applied some options.
		 */
		ret = 1;
	}

	return ret;
}

#define isc_not_done	ISC_NOOP, NULL, NULL
#define isc_ignore	ISC_IGNORE, NULL, NULL
#define isc_invalid	ISC_INVALID, NULL, NULL


/** Table of commands that we allow.
 *
 */
static const rlm_isc_dhcp_cmd_t commands[] = {
	{ "abandon-lease-time INTEGER",		isc_not_done, 1},
	{ "adaptive-lease-time-threshold INTEGER", isc_not_done, 1},
	{ "allow-booting BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "allow-bootp BOOL", 			isc_not_done, 1}, // boolean can be true, false or ignore
	{ "always-broadcast BOOL",		isc_not_done, 1},
	{ "always-reply-rfc1048 BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "authoritative",			isc_not_done, 0},
	{ "bind-local-address6 BOOL", 		isc_ignore,   1}, // boolean can be true, false or ignore
	{ "boot-unknown-clients BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "check-secs-byte-order BOOL",        	isc_not_done, 1}, // boolean can be true, false or ignore
	{ "class STRING SECTION",       		isc_invalid,  1}, // put systems into different classes
	{ "client-updates BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "ddns-domainname STRING", 		isc_not_done, 1}, // text string
	{ "ddns-dual-stack-mixed-mode BOOL",   	isc_not_done, 1}, // boolean can be true, false or ignore
	{ "ddns-guard-id-must-match BOOL",     	isc_not_done, 1}, // boolean can be true, false or ignore
	{ "ddns-hostname STRING", 		isc_not_done, 1}, // text string
	{ "ddns-local-address4 IPADDR",        	isc_not_done, 1}, // ipaddr or hostname
	{ "ddns-local-address6 IPADDR6",       	isc_not_done, 1}, // ipv6 addr
	{ "ddns-other-guard-is-dynamic BOOL",  	isc_not_done, 1}, // boolean can be true, false or ignore
	{ "ddns-rev-domainname STRING",        	isc_not_done, 1}, // text string
	{ "ddns-ttl UINT32", 			isc_not_done, 1}, // Lease time interval
	{ "ddns-update-style STRING,", 		isc_not_done, 1}, // string options. e.g: opt1, opt2 or opt3 [arg1, ... ]
	{ "ddns-updates BOOL", 			isc_not_done, 1}, // boolean can be true, false or ignore
	{ "declines BOOL", 			isc_not_done, 1}, // boolean can be true, false or ignore
	{ "default-lease-time INTEGER", 	isc_not_done, 1},
	{ "delayed-ack UINT16",			isc_invalid,  1},
	{ "dhcp-cache-threshold UINT8",        	isc_not_done, 1}, // integer uint8_t
	{ "dhcpv6-lease-file-name STRING",     	isc_ignore,   1}, // text string
	{ "dhcpv6-pid-file-name STRING",       	isc_ignore,   1}, // text string
	{ "dhcpv6-set-tee-times BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "do-forward-updates BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "do-reverse-updates BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "dont-use-fsync BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "duplicates BOOL", 			isc_not_done, 1}, // boolean can be true, false or ignore
	{ "dynamic-bootp BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "dynamic-bootp-lease-cutoff UINT32", 	isc_not_done, 1}, // Lease time interval
	{ "dynamic-bootp-lease-length UINT32", 	isc_not_done, 1}, // integer uint32_t
	{ "echo-client-id BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "filename STRING",			ISC_NOOP, parse_filename, NULL, 1},
	{ "fixed-address IPADDR,",		ISC_FIXED_ADDRESS, NULL, NULL, 16},
	{ "fqdn-reply BOOL", 			isc_not_done, 1}, // boolean can be true, false or ignore
	{ "get-lease-hostnames BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "group SECTION",			ISC_GROUP, NULL, NULL, 1},
	{ "hardware ethernet ETHER",		ISC_HARDWARE_ETHERNET, NULL, NULL, 1},
	{ "host STRING SECTION",		ISC_HOST, parse_host, NULL, 1},
	{ "ignore-client-uids BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "include STRING",			ISC_NOOP, parse_include, NULL, 1},
	{ "infinite-is-reserved BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore

	/*
	 *	Group configuration into sections?  Why the heck would
	 *	we do that?  A flat name space worked for Fortran 77.
	 *	It should be good enough for us here.
	 */
	{ "ldap-base-dn STRING", 		isc_ignore,   1}, // text string
	{ "ldap-debug-file STRING", 		isc_ignore,   1}, // text string
	{ "ldap-dhcp-server-cn STRING", 	isc_ignore,   1}, // text string
	{ "ldap-gssapi-keytab STRING", 		isc_ignore,   1}, // text string
	{ "ldap-gssapi-principal STRING", 	isc_ignore,   1}, // text string
	{ "ldap-init-retry STRING", 		isc_ignore,   1}, // domain name
	{ "ldap-method STRING,", 		isc_ignore,   1}, // string options. e.g: opt1, opt2 or opt3 [arg1, ... ]
	{ "ldap-password STRING", 		isc_ignore,   1}, // text string
	{ "ldap-port STRING", 			isc_ignore,   1}, // domain name
	{ "ldap-referrals BOOL", 		isc_ignore,   1}, // boolean can be true, false or ignore
	{ "ldap-server STRING", 		isc_ignore,   1}, // text string
	{ "ldap-ssl STRING,", 			isc_ignore,   1}, // string options. e.g: opt1, opt2 or opt3 [arg1, ... ]
	{ "ldap-tls-ca-dir STRING", 		isc_ignore,   1}, // text string
	{ "ldap-tls-ca-file STRING", 		isc_ignore,   1}, // text string
	{ "ldap-tls-cert STRING", 		isc_ignore,   1}, // text string
	{ "ldap-tls-ciphers STRING", 		isc_ignore,   1}, // text string
	{ "ldap-tls-crlcheck STRING,", 		isc_ignore,   1}, // string options. e.g: opt1, opt2 or opt3 [arg1, ... ]
	{ "ldap-tls-key STRING", 		isc_ignore,   1}, // text string
	{ "ldap-tls-randfile STRING", 		isc_ignore,   1}, // text string
	{ "ldap-tls-reqcert STRING,", 		isc_ignore,   1}, // string options. e.g: opt1, opt2 or opt3 [arg1, ... ]
	{ "ldap-username STRING", 		isc_ignore,   1}, // text string

	{ "lease-file-name STRING", 		isc_ignore,   1}, // text string
	{ "leasequery BOOL", 			isc_not_done, 1}, // boolean can be true, false or ignore
	{ "limit-addrs-per-ia UINT32", 		isc_not_done, 1}, // integer uint32_t
	{ "limit-prefs-per-ia UINT32", 		isc_not_done, 1}, // integer uint32_t
	{ "limited-broadcast-address IPADDR", 	isc_not_done, 1}, // ipaddr or hostname
	{ "local-address IPADDR", 		isc_ignore,   1}, // ipaddr or hostname
	{ "local-address6 IPADDR6", 		isc_ignore,   1}, // ipv6 addr
	{ "local-port UINT16", 			isc_ignore,   1}, // integer uint16_t
	{ "log-facility STRING,", 		isc_ignore,   1}, // string options. e.g: opt1, opt2 or opt3 [arg1, ... ]
	{ "log-threshold-high UINT8", 		isc_ignore,   1}, // integer uint8_t
	{ "log-threshold-low UINT8", 		isc_ignore,   1}, // integer uint8_t
	{ "match",				isc_invalid,  0}, // we don't do this at all yet
	{ "max-ack-delay UINT32",		isc_invalid,  1},
	{ "max-lease-time INTEGER",		isc_not_done, 1},
	{ "min-lease-time INTEGER",		isc_not_done, 1},
	{ "min-secs UINT8", 			isc_not_done, 1}, // integer uint8_t
	{ "next-server IPADDR", 		ISC_NOOP, parse_next_server, NULL, 1}, // ipaddr or hostname
	{ "not authoritative",			isc_not_done, 0},
	{ "omapi-key STRING", 			isc_ignore,   1}, // domain name
	{ "omapi-port UINT16", 			isc_ignore,   1}, // integer uint16_t
	{ "one-lease-per-client BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "option STRING STRING,",		ISC_OPTION, NULL, NULL, 16},
	{ "pid-file-name STRING", 		isc_ignore, 1}, // text string
	{ "ping-check BOOL", 			isc_not_done, 1}, // boolean can be true, false or ignore
	{ "ping-timeout UINT32", 		isc_not_done, 1}, // Lease time interval
	{ "pool SECTION",			isc_invalid, 0}, // sub pools
	{ "preferred-lifetime UINT32", 		isc_not_done, 1}, // Lease time interval
	{ "prefix-length-mode STRING,",        	isc_not_done, 1}, // string options. e.g: opt1, opt2 or opt3 [arg1, ... ]
	{ "range IPADDR IPADDR",		isc_not_done, 2},
	{ "release-on-roam BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "remote-port UINT16", 		isc_ignore,   1}, // integer uint16_t
	{ "server-id-check BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "server-identifier IPADDR", 		ISC_NOOP, parse_server_identifier, NULL, 1}, // ipaddr or host name
	{ "server-name STRING", 		ISC_NOOP, parse_server_name, NULL, 1}, // text string
	{ "shared-network STRING SECTION",	isc_not_done, 1},
	{ "site-option-space STRING", 		isc_invalid,  1}, // vendor option declaration statement
	{ "stash-agent-options BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "subnet IPADDR netmask IPADDR SECTION", ISC_SUBNET, parse_subnet, NULL, 2},
	{ "update-conflict-detection BOOL", 	isc_not_done, 1}, // boolean can be true, false or ignore
	{ "update-optimization BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "update-static-leases BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "use-host-decl-names BOOL", 		isc_not_done, 1}, // boolean can be true, false or ignore
	{ "use-lease-addr-for-default-route BOOL", isc_not_done, 1}, // boolean can be true, false or ignore
	{ "vendor-option-space STRING",		isc_invalid,  1}, // vendor option declaration
};

/** Parse a section { ... }
 *
 */
static int parse_section(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info)
{
	int ret;
	int entries = 0;

	/*
	 *	We allow "group" inside of "group".  But we don't
	 *	allow other sections to nest.
	 */
	if (info->cmd->type != ISC_GROUP) {
		rlm_isc_dhcp_info_t *parent;

		for (parent = info->parent; parent != NULL; parent = parent->parent) {
			char const *q;

			if (!parent->cmd) break; /* top level */

			if (parent->cmd != info->cmd) continue;

			/*
			 *	Be gentle to the end user
			 */
			q = parent->cmd->name;
			fr_skip_not_whitespace(q);

			fr_strerror_printf("cannot nest '%.*s' statements",
					   (int) (q - parent->cmd->name), parent->cmd->name);
			return -1;
		}
	}

	IDEBUG("%.*s {", state->braces - 1, spaces); /* "braces" was already incremented */
	state->allow_eof = false; /* can't have EOF in the middle of a section */

	while (true) {
		ret = read_token(state, T_BARE_WORD, YES_SEMICOLON, true);
		if (ret < 0) return ret;
		if (ret == 0) break;

		/*
		 *	End of section is allowed here.
		 */
		if (*state->token == '}') break;

		ret = match_keyword(info, state, commands, NUM_ELEMENTS(commands));
		if (ret < 0) return ret;
		if (ret == 0) break;

		entries = 1;
	}

	state->allow_eof = (state->braces == 0);

	IDEBUG("%.*s }", state->braces, spaces);

	return entries;
}

/** Open a file and read it into a parent.
 *
 */
static int read_file(rlm_isc_dhcp_t *inst, rlm_isc_dhcp_info_t *parent, char const *filename)
{
	int ret;
	FILE *fp;
	rlm_isc_dhcp_tokenizer_t state;
	rlm_isc_dhcp_info_t **last = parent->last;
	char buffer[8192];

	/*
	 *	Read the file line by line.
	 *
	 *	The configuration file format is based off of
	 *	keywords, so we write a simple parser to check that.
	 */
	fp = fopen(filename, "r");
	if (!fp) {
		fr_strerror_printf("Error opening filename %s: %s", filename, fr_syserror(errno));
		return -1;
	}

	memset(&state, 0, sizeof(state));
	state.inst = inst;
	state.fp = fp;
	state.filename = filename;
	state.buffer = buffer;
	state.bufsize = sizeof(buffer);
	state.lineno = 0;

	state.braces = 0;
	state.ptr = buffer;
	state.token = NULL;

	state.debug = inst->debug;
	state.allow_eof = true;

	/*
	 *	Tell the state machine that the buffer is empty.
	 */
	*state.ptr = '\0';

	while (true) {
		ret = read_token(&state, T_BARE_WORD, YES_SEMICOLON, false);
		if (ret < 0) {
		fail:
			fr_strerror_printf("Failed reading %s:[%d] - %s",
					   filename, state.lineno,
					   fr_strerror());
			fclose(fp);
			return ret;
		}
		if (ret == 0) break;

		/*
		 *	This will automatically re-fill the buffer,
		 *	and find a matching token.
		 */
		ret = match_keyword(parent, &state, commands, NUM_ELEMENTS(commands));
		if (ret < 0) goto fail;
		if (ret == 0) break;
	}

	fclose(fp);

	/*
	 *	The input "last" pointer didn't change, so we didn't
	 *	read anything.
	 */
	if (!*last) return 0;

	return 1;
}

static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	int ret;
	rlm_isc_dhcp_t *inst = instance;
	rlm_isc_dhcp_info_t *info;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	inst->head = info = talloc_zero(inst, rlm_isc_dhcp_info_t);
	fr_pair_list_init(&info->options);
	info->last = &(info->child);

	inst->hosts_by_ether = fr_hash_table_create(inst, host_ether_hash, host_ether_cmp, NULL);
	if (!inst->hosts_by_ether) return -1;

	inst->hosts_by_uid = fr_hash_table_create(inst, host_uid_hash, host_uid_cmp, NULL);
	if (!inst->hosts_by_uid) return -1;

	ret = read_file(inst, info, inst->filename);
	if (ret < 0) {
		cf_log_err(conf, "%s", fr_strerror());
		return -1;
	}

	if (ret == 0) {
		cf_log_warn(conf, "No configuration read from %s", inst->filename);
		return 0;
	}

	return 0;
}

static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_isc_dhcp_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_isc_dhcp_t);
	int			ret;

	ret = apply_fixed_ip(inst, request);
	if (ret < 0) RETURN_MODULE_FAIL;
	if (ret == 0) RETURN_MODULE_NOOP;

	if (ret == 2) RETURN_MODULE_UPDATED;

	RETURN_MODULE_OK;
}

static unlang_action_t CC_HINT(nonnull) mod_post_auth(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_isc_dhcp_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_isc_dhcp_t);
	int			ret;

	ret = apply(inst, request, inst->head);
	if (ret < 0) RETURN_MODULE_FAIL;
	if (ret == 0) RETURN_MODULE_NOOP;

	// @todo - check for subnet mask option.  If none exists, use one from the enclosing network?

	RETURN_MODULE_OK;
}

extern module_t rlm_isc_dhcp;
module_t rlm_isc_dhcp = {
	.magic		= RLM_MODULE_INIT,
	.name		= "isc_dhcp",
	.type		= 0,
	.inst_size	= sizeof(rlm_isc_dhcp_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,

	.methods = {
		[MOD_AUTHORIZE]	= mod_authorize,
		[MOD_POST_AUTH]	= mod_post_auth,
	},
};
