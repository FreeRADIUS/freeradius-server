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
 * @copyright 2019 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/rad_assert.h>

#include <freeradius-devel/server/map_proc.h>

static fr_dict_t *dict_dhcpv4;

extern fr_dict_autoload_t rlm_isc_dhcp_dict[];
fr_dict_autoload_t rlm_isc_dhcp_dict[] = {
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ NULL }
};

static fr_dict_attr_t const *attr_client_hardware_address;
static fr_dict_attr_t const *attr_your_ip_address;
static fr_dict_attr_t const *attr_client_identifier;

extern fr_dict_attr_autoload_t rlm_isc_dhcp_dict_attr[];
fr_dict_attr_autoload_t rlm_isc_dhcp_dict_attr[] = {
	{ .out = &attr_client_hardware_address, .name = "DHCP-Client-Hardware-Address", .type = FR_TYPE_ETHERNET, .dict = &dict_dhcpv4},
	{ .out = &attr_your_ip_address, .name = "DHCP-Your-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4},
	{ .out = &attr_client_identifier, .name = "DHCP-Client-IDentifier", .type = FR_TYPE_OCTETS, .dict = &dict_dhcpv4},
	{ NULL }
};

typedef struct rlm_isc_dhcp_info_t rlm_isc_dhcp_info_t;

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
	rlm_isc_dhcp_info_t	*head;
} rlm_isc_dhcp_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED | FR_TYPE_NOT_EMPTY, rlm_isc_dhcp_t, filename) },
	{ FR_CONF_OFFSET("debug", FR_TYPE_BOOL, rlm_isc_dhcp_t, debug) },
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
typedef struct rlm_isc_dhcp_tokenizer_t {
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
} rlm_isc_dhcp_tokenizer_t;


typedef int (*rlm_isc_dhcp_parse_t)(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info);
typedef int (*rlm_isc_dhcp_apply_t)(rlm_isc_dhcp_t *inst, REQUEST *request, rlm_isc_dhcp_info_t *info);

typedef enum rlm_isc_dhcp_type_t {
	ISC_INVALID = 0,		//!< we recognize it, but don't implement it
	ISC_NOOP,			//!< we parse and ignore it
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
typedef struct rlm_isc_dhcp_cmd_t {
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
struct rlm_isc_dhcp_info_t {
	rlm_isc_dhcp_cmd_t const *cmd;
	int			argc;
	fr_value_box_t 		**argv;

	rlm_isc_dhcp_info_t	*parent;
	rlm_isc_dhcp_info_t	*next;
	void			*data;		//!< per-thing parsed data.

	/*
	 *	Only for things that have sections
	 */
	fr_hash_table_t		*hosts;		//!< by MAC address
	fr_hash_table_t		*client_identifiers; //!< by client identifier
	VALUE_PAIR		*options;	//!< DHCP options
	fr_trie_t		*subnets;
	rlm_isc_dhcp_info_t	*child;
	rlm_isc_dhcp_info_t	**last;		//!< pointer to last child
};

static int read_file(rlm_isc_dhcp_info_t *parent, char const *filename, bool debug);
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

	if (!fgets(state->ptr, (state->buffer + state->bufsize) - state->ptr, state->fp)) {
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
	while (isspace((int) *p)) p++;

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

/** Reads one token into state->token
 *
 *	Note that this function *destroys* the input buffer.  So if
 *	you need to read two tokens, you have to save the first one
 *	somewhere *outside* of the input buffer.
 */
static int read_token(rlm_isc_dhcp_tokenizer_t *state, FR_TOKEN hint, int semicolon, bool allow_rcbrace)
{
	char *p;

redo:
	/*
	 *	If the buffer is empty, re-fill it.
	 */
	if (!*state->ptr) {
		int rcode;
		
		rcode = refill(state);
		if (rcode < 0) return rcode;

		if (rcode == 0) {
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
		 *	For lists of things.
		 */
		if (*p == ',') {
			state->ptr = p;
			break;
		}

		/*
		 *	Allow braces as single character tokens if
		 *	they're the first character we saw.
		 *	Otherwise, they are "end of word" markers/
		 */
		if ((*p == '{') || (*p == '}')) {
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
		 *	Be nice and eat trailing spaces, too.
		 */
		if (isspace((int) *p)) {
			state->ptr = p;
			char *start = p;

		skip_spaces:
			while (isspace((int) *state->ptr)) state->ptr++;
			
			/*
			 *	If we ran out of text on this line,
			 *	re-fill the buffer.  Note that
			 *	refill() also takes care of
			 *	suppressing blank lines and comments.
			 */
			if (!state->eof && !*state->ptr) {
				int rcode;

				state->ptr = start;

				rcode = refill(state);
				if (rcode < 0) return -1;
				goto skip_spaces;
			}

			/*
			 *	Set the semicolon flag as a "peek
			 *	ahead", so that the various other
			 *	parsers don't need to check it.
			 */
			if (*state->ptr == ';') state->saw_semicolon = true;

			break;
		}
	}

	/*
	 *	Protect the rest of the code from buffer overflows.
	 */
	state->token_len = p - state->token;

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
	int rcode, type;
	int semicolon = NO_SEMICOLON;
	bool multi = false;
	char *p;
	char const *q;
	char const *next;
	char type_name[64];

	while (isspace((int) *cmd)) cmd++;

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
		rcode = read_token(state, T_BARE_WORD, semicolon, false);
		if (rcode <= 0) return -1;

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

		rcode = read_token(state, T_LCBRACE, NO_SEMICOLON, false);
		if (rcode <= 0) return rcode;

		rcode = parse_section(state, info);
		if (rcode < 0) return rcode;

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

	type = fr_str2int(fr_value_box_type_table, type_name, -1);
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
	rcode = read_token(state, T_DOUBLE_QUOTED_STRING, semicolon, false);
	if (rcode <= 0) return rcode;

	DDEBUG("... DATA %.*s ", state->token_len, state->token);

	/*
	 *	Parse the data to its final form.
	 */
	info->argv[info->argc] = talloc_zero(info, fr_value_box_t);

	rcode = fr_value_box_from_str(info, info->argv[info->argc], (fr_type_t *) &type, NULL,
				      state->token, state->token_len, 0, false);
	if (rcode < 0) return rcode;

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
	int rcode;
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
	rcode = read_file(info->parent, name, state->debug);
	if (rcode < 0) return rcode;

	/*
	 *	Even if the file was empty, we return "1" to indicate
	 *	that we successfully parsed the file.  Returning "0"
	 *	would indicate that the parent file was at EOF.
	 */
	return 1;
}

static int match_keyword(rlm_isc_dhcp_info_t *parent, rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_cmd_t const *tokens, int num_tokens)
{
	int start, end, half;
	int semicolon;
	int rcode;
	char const *q = NULL;
	rlm_isc_dhcp_info_t *info;

	start = 0;
	end = num_tokens - 1;
	half = -1;

	/*
	 *	Walk over the input token, doing a binary search on
	 *	the token list.
	 */
	while (start <= end) {
		half = (start + end) / 2;

		rcode = strncmp(state->token, tokens[half].name, state->token_len);

		/*
		 *	Exact match.  But maybe we have "foo" input,
		 *	and "food" command?
		 */
		if (rcode == 0) {
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
			rcode = -1;
		}

		/*
		 *	Token is smaller than the command we checked,
		 *	go check the lower half of the table.
		 */
		if (rcode < 0) {
			end = half - 1;
		} else {
			start = half + 1;
		}
	}

	/*
	 *	Nothing matched, it's a failure.
	 */
	if (!q) {
		fr_strerror_printf("unknown command '%.*s'", state->token_len, state->token);
		return -1;
	}

	rad_assert(half >= 0);

	semicolon = YES_SEMICOLON; /* default to always requiring this */

	DDEBUG("... TOKEN %.*s ", state->token_len, state->token);

	info = talloc_zero(parent, rlm_isc_dhcp_info_t);
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

		rcode = match_subword(state, q, info);
		if (rcode <= 0) return rcode;

		/*
		 *	SUBSECTION must be at the end
		 */
		if (rcode == 2) semicolon = NO_SEMICOLON;
	}

	/*
	 *	*q must be empty at this point.
	 */
	if ((semicolon == NO_SEMICOLON) && state->saw_semicolon) {
	unexpected:
		fr_strerror_printf("Syntax error in %s at line %d: Unexpected ';'",
				   state->filename, state->lineno);
		talloc_free(info);
		return -1;
	}

	if ((semicolon == YES_SEMICOLON) && !state->saw_semicolon) {
		fr_strerror_printf("Syntax error in %s at line %d: Missing ';'",
				   state->filename, state->lineno);
		talloc_free(info);
		return -1;
	}

	// @todo - print out the thing we parsed

	/*
	 *	Call the "parse" function which should do
	 *	validation, etc.
	 */
	if (tokens[half].parse) {
		rcode = tokens[half].parse(state, info);
		if (rcode <= 0) {
			talloc_free(info);
			return rcode;
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
		if (rcode == 2) return 1;
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

typedef struct isc_host_ether_t {
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

typedef struct isc_host_client_t {
	fr_value_box_t		*client;
	rlm_isc_dhcp_info_t	*host;
} isc_host_client_t;

static uint32_t host_client_hash(void const *data)
{
	isc_host_client_t const *self = data;

	return fr_hash(self->client->vb_octets, self->client->vb_length);
}

static int host_client_cmp(void const *one, void const *two)
{
	isc_host_client_t const *a = one;
	isc_host_client_t const *b = two;

	if ( a->client->vb_length < b->client->vb_length) return -1;
	if ( a->client->vb_length > b->client->vb_length) return +1;

	return memcmp(a->client->vb_octets, b->client->vb_octets, a->client->vb_length);
}

static int parse_host(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info)
{
	isc_host_ether_t *self, *old;
	rlm_isc_dhcp_info_t *child, *parent;

	/*
	 *	A host MUST have at least one "hardware ethernet" in
	 *	it.
	 *
	 *	@todo - complain if there are multiple ones...
	 */
	for (child = info->child; child != NULL; child = child->next) {
		/*
		 *	@todo - Use enums or something.  Yes, this is
		 *	fugly.
		 */
		if (child->cmd->type == ISC_HARDWARE_ETHERNET) {
			break;
		}
	}

	if (!child) {
		fr_strerror_printf("host %s does not contain a 'hardware ethernet' field",
				   info->argv[0]->vb_strvalue);
		return -1;
	}

	/*
	 *	Point directly to the ethernet address.
	 */
	self = talloc_zero(info, isc_host_ether_t);
	memcpy(self->ether, &(child->argv[0]->vb_ether), sizeof(self->ether));
	self->host = info;

	/*
	 *	Add the host to the *parents* hash table.  That way
	 *	when we apply the parent, we can look up the host in
	 *	its hash table.  And avoid the O(N) issue of having
	 *	thousands of "host" entries in the parent->child list.
	 */
	parent = info->parent;
	if (!parent->hosts) {
		parent->hosts = fr_hash_table_create(parent, host_ether_hash, host_ether_cmp, NULL);
		if (!parent->hosts) return -1;
	}

	/*
	 *	Duplicate "host" entries aren't allowd.
	 *
	 *	@todo - maybe they are?  And we just apply all of them?
	 */
	old = fr_hash_table_finddata(parent->hosts, self);
	if (old) {
		fr_strerror_printf("'host %s' and 'host %s' contain duplicate 'hardware ethernet' fields",
				   info->argv[0]->vb_strvalue, old->host->argv[0]->vb_strvalue);
		return -1;
	}

	if (fr_hash_table_insert(parent->hosts, self) < 0) {
		fr_strerror_printf("Failed inserting 'host %s' into hash table",
				   info->argv[0]->vb_strvalue);
		return -1;
	}

	IDEBUG("%.*s host %s { ... }", state->braces, spaces, info->argv[0]->vb_strvalue);

	/*
	 *	We've remembered the host in the parent hosts hash.
	 *	There's no need to add it to the child list here.
	 */
	return 2;
}

static int parse_option(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info)
{
	int i, rcode;
	VALUE_PAIR *vp;
	fr_dict_attr_t const *da;
	vp_cursor_t cursor;
	rlm_isc_dhcp_info_t *parent;
	char name[256 + 5];

	/*
	 *	Add the option to the *parents* option list.  That way
	 *	when we apply the parent, we just copy all of the VPs
	 *	instead of walking through the children.
	 */
	parent = info->parent;

	memcpy(name, "DHCP-", 5);
	memcpy(name + 5, info->argv[0]->vb_strvalue, info->argv[0]->vb_length + 1);

	da = fr_dict_attr_by_name(dict_dhcpv4, name);
	if (!da) {
		fr_strerror_printf("unknown option '%s'", info->argv[0]->vb_strvalue);
		return -1;
	}

	if ((info->argc > 2) && !da->flags.array) {
		fr_strerror_printf("option '%s' cannot have multiple values", info->argv[0]->vb_strvalue);
		return -1;
	}

	vp = fr_pair_afrom_da(parent, da);
	if (!vp) {
		fr_strerror_printf("out of memory");
		return -1;
	}

	(void) fr_pair_cursor_init(&cursor, &parent->options);

	/*
	 *	Add in all of the options
	 */
	for (i = 1; i < info->argc; i++) {
		rcode = fr_pair_value_from_str(vp, info->argv[1]->vb_strvalue, info->argv[1]->vb_length,
					       '\0', false);
		if (rcode < 0) return rcode;

		vp->op = T_OP_EQ;

		fr_pair_cursor_append(&cursor, vp);
		(void) fr_pair_cursor_tail(&cursor);

		IDEBUG("%.*s option %s %s ", state->braces, spaces, info->argv[1]->vb_strvalue, info->argv[1]->vb_strvalue);
	}

	/*
	 *	Hosts are looked up by client identifier, too.
	 *
	 *	The client-identifier option exists within the host,
	 *	BUT we have to add the host to the grandparent of the
	 *	option.
	 *
	 *	Note that we still leave the option in the parents
	 *	option list.  That way the client identifier is always
	 *	returned to the client, as per RFC 6842.
	 */
	if (da == attr_client_identifier && parent->cmd && (parent->cmd->type == ISC_HOST)) {
		isc_host_client_t *self, *old;
		rlm_isc_dhcp_info_t *host;

		/*
		 *	Add our parent (the host) to the hosts parent
		 *	client identifier hash table.
		 */
		host = parent;
		parent = host->parent;
		if (!parent) goto done; /* internal error */

		if (!parent->client_identifiers) {
			parent->client_identifiers = fr_hash_table_create(parent, host_client_hash, host_client_cmp, NULL);
			if (!parent->client_identifiers) return -1;
		}

		self = talloc_zero(host, isc_host_client_t);
		self->client = &vp->data;
		self->host = host;

		/*
		 *	Duplicate "client identifier" entries aren't allowd.
		 *
		 *	@todo - maybe they are?  And we just apply all of them?
		 */
		old = fr_hash_table_finddata(parent->client_identifiers, self);
		if (old) {
			fr_strerror_printf("'host %s' and 'host %s' contain duplicate 'option client-identifier' fields",
					   info->argv[0]->vb_strvalue, old->host->argv[0]->vb_strvalue);
			return -1;
		}

		if (fr_hash_table_insert(parent->client_identifiers, self) < 0) {
			fr_strerror_printf("Failed inserting 'option client identifier' into parent hash table");
			return -1;
		}
	}

done:
	/*
	 *	We don't need this any more.
	 */
	talloc_free(info);

	/*
	 *	We've remembered the option in the parent option list.
	 *	There's no need to add it to the child list here.
	 */
	return 2;
}

/*
 *	Utter laziness
 */
#define vb_ipv4addr vb_ip.addr.v4.s_addr

static int parse_subnet(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info)
{
	rlm_isc_dhcp_info_t *parent;
	int rcode, bits;
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

	rcode = fr_trie_insert(parent->subnets, &(info->argv[0]->vb_ipv4addr), bits, info);
	if (rcode < 0) {
		fr_strerror_printf("Failed inserting 'subnet %pV netmask %pV' into trie",
				   info->argv[0], info->argv[1]);
		return -1;
	}

	IDEBUG("%.*s subnet %pV netmask %pV { ... }", state->braces, spaces, info->argv[0], info->argv[1]);

	/*
	 *	We've remembered the subnet in the parent trie.
	 *	There's no need to add it to the child list here.
	 */
	return 2;
}

static rlm_isc_dhcp_info_t *get_host(REQUEST *request, rlm_isc_dhcp_info_t *head)
{
	VALUE_PAIR *vp;
	isc_host_ether_t *ether, my_ether;
	rlm_isc_dhcp_info_t *host = NULL;

	/*
	 *	Look up the host first by client identifier.
	 *	If that doesn't match, use client hardware
	 *	address.
	 */
	vp = fr_pair_find_by_da(request->packet->vps, attr_client_identifier, TAG_ANY);
	if (vp) {
		isc_host_client_t *client, my_client;

		my_client.client = &(vp->data);

		client = fr_hash_table_finddata(head->client_identifiers, &my_client);
		if (client) {
			host = client->host;
			goto done;
		}
	}


	vp = fr_pair_find_by_da(request->packet->vps, attr_client_hardware_address, TAG_ANY);
	if (!vp) return NULL;

	memcpy(&my_ether.ether, vp->vp_ether, sizeof(my_ether.ether));

	ether = fr_hash_table_finddata(head->hosts, &my_ether);
	if (!ether) return NULL;

	host = ether->host;

done:
	/*
	 *	@todo - check "fixed-address".  This host entry should
	 *	match ONLY if one of the addresses matches the network
	 *	on which the client is booting.
	 */

	return host;
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
static int apply_fixed_ip(rlm_isc_dhcp_t *inst, REQUEST *request, rlm_isc_dhcp_info_t *head)
{
	int rcode, child_rcode;
	rlm_isc_dhcp_info_t *info;
	VALUE_PAIR *yiaddr;

	/*
	 *	If there's already a fixed IP, don't do anything
	 */
	yiaddr = fr_pair_find_by_da(request->reply->vps, attr_your_ip_address, TAG_ANY);
	if (yiaddr) return 0;

	rcode = 0;

	/*
	 *	The most specific entry is preferred over the most generic one.
	 */
	for (info = head->child; info != NULL; info = info->next) {
		if (!info->cmd) return -1; /* internal error */

		/*
		 *	Skip simple statements
		 */
		if (!info->child) continue;

		/*
		 *	Recurse for children which have subsections.
		 */
		child_rcode = apply_fixed_ip(inst, request, info);
		if (child_rcode < 0) return child_rcode;
		if (child_rcode == 0) continue;

		/*
		 *	We've found a "fixed address" statement and
		 *	applied it.  Don't look for another one.
		 */
		if (child_rcode == 2) return child_rcode;

		rcode = 1;
	}

	/*
	 *	If there's now a fixed IP, don't do anything
	 */
	yiaddr = fr_pair_find_by_da(request->reply->vps, attr_your_ip_address, TAG_ANY);
	if (yiaddr) return rcode;

	/*
	 *	Find any "host", and apply the fixed IP.
	 */
	if (head->hosts) {
		VALUE_PAIR *vp;
		rlm_isc_dhcp_info_t *host;

		host = get_host(request, head);
		if (!host) return 0;

		/*
		 *	Find a "fixed address" sub-statement.
		 */
		for (info = host->child; info != NULL; info = info->next) {
			vp_cursor_t cursor;

			if (!info->cmd) return -1; /* internal error */

			/*
			 *	Skip complex statements
			 */
			if (info->child) continue;

			// @todo - this is getting increasingly retarded
			if (info->cmd->type == ISC_FIXED_ADDRESS) continue;

			vp = fr_pair_afrom_da(request->reply->vps, attr_your_ip_address);
			if (!vp) return -1;

			rcode = fr_value_box_copy(vp, &(vp->data), info->argv[0]);
			if (rcode < 0) return rcode;

			/*
			 *	<sigh> I miss pair_add()
			 */
			(void) fr_pair_cursor_init(&cursor, &request->reply->vps);
			(void) fr_pair_cursor_tail(&cursor);
			fr_pair_cursor_append(&cursor, vp);

			/*
			 *	If we've found a fixed IP, then tell
			 *	the parent to stop iterating over
			 *	children.
			 */
			return 2;
		}
	}

	return rcode;
}

/** Apply all rules *except* fixed IP
 *
 */
static int apply(rlm_isc_dhcp_t *inst, REQUEST *request, rlm_isc_dhcp_info_t *head)
{
	int rcode, child_rcode;
	rlm_isc_dhcp_info_t *info;
	VALUE_PAIR *yiaddr;

	rcode = 0;
	yiaddr = fr_pair_find_by_da(request->reply->vps, attr_your_ip_address, TAG_ANY);

	/*
	 *	First, apply any "host" options
	 */
	if (head->hosts) {
		rlm_isc_dhcp_info_t *host = NULL;

		host = get_host(request, head);
		if (!host) goto subnet;

		/*
		 *	Apply any options in the "host" section.
		 *
		 *	@todo - only apply the options if there's no
		 *	YIADDR, OR the YIADDR matches one of the
		 *	addresses listed in `fixed address`.
		 */
		child_rcode = apply(inst, request, host);
		if (child_rcode < 0) return child_rcode;
		if (child_rcode == 1) rcode = 1;
	}

subnet:
	/*
	 *	Look in the trie for matching subnets, and apply any
	 *	subnets that match.
	 */
	if (head->subnets && yiaddr) {
		info = fr_trie_lookup(head->subnets, &yiaddr->vp_ipv4addr, 32);
		if (!info) goto recurse;

		child_rcode = apply(inst, request, info);
		if (child_rcode < 0) return child_rcode;
		if (child_rcode == 1) rcode = 1;

		// @todo - look for subnet mask.  If one doesn't
		// exist, use the mask from the subnet declaration.
	}

recurse:
	for (info = head->child; info != NULL; info = info->next) {
		if (!info->cmd) return -1; /* internal error */

		if (!info->cmd->apply) continue;

		child_rcode = info->cmd->apply(inst, request, info);
		if (child_rcode < 0) return child_rcode;
		if (child_rcode == 0) continue;

		rcode = 1;
	}

	/*
	 *	Now that our children have added options, see if we
	 *	can add some, too.
	 */
	if (head->options) {
		VALUE_PAIR *vp = NULL;
		vp_cursor_t option_cursor;
		vp_cursor_t reply_cursor;

		(void) fr_pair_cursor_init(&reply_cursor, &request->reply->vps);
		(void) fr_pair_cursor_tail(&reply_cursor);

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
		for (vp = fr_pair_cursor_init(&option_cursor, &head->options);
		     vp != NULL;
		     vp = fr_pair_cursor_next(&option_cursor)) {
			VALUE_PAIR *reply;

			reply = fr_pair_find_by_da(request->reply->vps, vp->da, TAG_ANY);
			if (reply) continue;

			/*
			 *	Copy all of the same options to the
			 *	reply.
			 */
			while (vp) {
				VALUE_PAIR *next, *copy;

				copy = fr_pair_copy(request->reply, vp);
				if (!copy) return -1;

				fr_pair_cursor_append(&reply_cursor, copy);
				(void) fr_pair_cursor_tail(&reply_cursor);

				next = fr_pair_cursor_next_peek(&option_cursor);
				if (!next) break;
				if (next->da != vp->da) break;

				vp = fr_pair_cursor_next(&option_cursor);
			}
		}

		/*
		 *	We applied some options.
		 */
		rcode = 1;
	}

	return rcode;
}


/** Table of commands that we allow.
 *
 */
static const rlm_isc_dhcp_cmd_t commands[] = {
	{ "agent-id IPADDR", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname
	{ "all-subnets-local BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "allow-booting BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "allow-bootp BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "always-reply-rfc1048 BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "arp-cache-timeout UINT32", ISC_NOOP, NULL, NULL, 1}, // integer uint32_t
	{ "associated-ip IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "auto-config UINT8", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t
	{ "bcms-controller-address IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "bcms-controller-names STRING", ISC_NOOP, NULL, NULL, 1}, // domain list
	{ "bind-local-address6 BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "boot-size UINT16", ISC_NOOP, NULL, NULL, 1}, // integer uint16_t
	{ "boot-unknown-clients BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "bootfile-name STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "broadcast-address IPADDR", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname
	{ "capwap-ac-v4 IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "check-secs-byte-order BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "circuit-id STRING", ISC_NOOP, NULL, NULL, 1}, // vendor option declaration statement
	{ "client-last-transaction-time UINT32", ISC_NOOP, NULL, NULL, 1}, // integer uint32_t
	{ "client-updates BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "cookie-servers IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "ddns-domainname STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ddns-dual-stack-mixed-mode BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "ddns-guard-id-must-match BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "ddns-hostname STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ddns-local-address4 IPADDR", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname
	{ "ddns-local-address6 IPADDR6", ISC_NOOP, NULL, NULL, 1}, // ipv6 addr
	{ "ddns-other-guard-is-dynamic BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "ddns-rev-domainname STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ddns-ttl UINT32", ISC_NOOP, NULL, NULL, 1}, // Lease interval
	{ "ddns-update-style STRING,,", ISC_NOOP, NULL, NULL, 1}, // string options. e.g: opt1, opt2 or opt3 [arg1, ... ]
	{ "ddns-updates BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "declines BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "default-ip-ttl UINT8", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t
	{ "default-tcp-ttl UINT8", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t
	{ "default-url STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "dhcp-cache-threshold UINT8", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t
	{ "dhcp-client-identifier STRING", ISC_NOOP, NULL, NULL, 1}, // vendor option declaration statement
	{ "dhcp-lease-time UINT32", ISC_NOOP, NULL, NULL, 1}, // integer uint32_t
	{ "dhcp-max-message-size UINT16", ISC_NOOP, NULL, NULL, 1}, // integer uint16_t
	{ "dhcp-message STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "dhcp-message-type UINT8", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t
	{ "dhcp-option-overload UINT8", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t
	{ "dhcp-parameter-request-list UINT8,", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t [arg1, ... ]
	{ "dhcp-rebinding-time UINT32", ISC_NOOP, NULL, NULL, 1}, // integer uint32_t
	{ "dhcp-renewal-time UINT32", ISC_NOOP, NULL, NULL, 1}, // integer uint32_t
	{ "dhcp-requested-address IPADDR", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname
	{ "dhcp-server-identifier IPADDR", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname
	{ "dhcpv6-lease-file-name STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "dhcpv6-pid-file-name STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "dhcpv6-set-tee-times BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "do-forward-updates BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "do-reverse-updates BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "DOCSIS-device-class UINT32", ISC_NOOP, NULL, NULL, 1}, // integer uint32_t
	{ "domain-name STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "domain-name-servers IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "domain-search STRING,", ISC_NOOP, NULL, NULL, 1}, // domain list [arg1, ... ]
	{ "dont-use-fsync BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "duplicates BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "dynamic-bootp BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "dynamic-bootp-lease-cutoff UINT32", ISC_NOOP, NULL, NULL, 1}, // Lease interval
	{ "dynamic-bootp-lease-length UINT32", ISC_NOOP, NULL, NULL, 1}, // integer uint32_t
	{ "echo-client-id BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "extensions-path STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "finger-server IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "fixed-address IPADDR,",		 ISC_FIXED_ADDRESS, NULL, NULL, 16},
	{ "font-servers IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "fqdn VENDOR_ENCAPSULATED,", ISC_NOOP, NULL, NULL, 1}, // vendor option declaration [arg1, ... ]
	{ "fqdn-reply BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "geoconf-civic STRING", ISC_NOOP, NULL, NULL, 1}, // vendor option declaration statement
	{ "get-lease-hostnames BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "group SECTION",			ISC_GROUP, NULL, NULL, 1},
	{ "hardware ethernet ETHER",		ISC_HARDWARE_ETHERNET, NULL, NULL, 1},
	{ "host STRING SECTION",		ISC_HOST, parse_host, NULL, 1},
	{ "host-name STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ieee802-3-encapsulation BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "ien116-name-servers IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "ignore-client-uids BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "impress-servers IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "include STRING",			ISC_NOOP, parse_include, NULL, 1},
	{ "infinite-is-reserved BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "interface-mtu UINT16", ISC_NOOP, NULL, NULL, 1}, // integer uint16_t
	{ "ip-forwarding BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "ipv4-address-andsf IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "irc-server IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "ldap-base-dn STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ldap-debug-file STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ldap-dhcp-server-cn STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ldap-gssapi-keytab STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ldap-gssapi-principal STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ldap-init-retry STRING", ISC_NOOP, NULL, NULL, 1}, // domain name
	{ "ldap-method STRING,,", ISC_NOOP, NULL, NULL, 1}, // string options. e.g: opt1, opt2 or opt3 [arg1, ... ]
	{ "ldap-password STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ldap-port STRING", ISC_NOOP, NULL, NULL, 1}, // domain name
	{ "ldap-referrals BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "ldap-server STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ldap-ssl STRING,,", ISC_NOOP, NULL, NULL, 1}, // string options. e.g: opt1, opt2 or opt3 [arg1, ... ]
	{ "ldap-tls-ca-dir STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ldap-tls-ca-file STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ldap-tls-cert STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ldap-tls-ciphers STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ldap-tls-crlcheck STRING,,", ISC_NOOP, NULL, NULL, 1}, // string options. e.g: opt1, opt2 or opt3 [arg1, ... ]
	{ "ldap-tls-key STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ldap-tls-randfile STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ldap-tls-reqcert STRING,,", ISC_NOOP, NULL, NULL, 1}, // string options. e.g: opt1, opt2 or opt3 [arg1, ... ]
	{ "ldap-username STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "lease-file-name STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "leasequery BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "limit-addrs-per-ia UINT32", ISC_NOOP, NULL, NULL, 1}, // integer uint32_t
	{ "limit-prefs-per-ia UINT32", ISC_NOOP, NULL, NULL, 1}, // integer uint32_t
	{ "limited-broadcast-address IPADDR", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname
	{ "link-selection IPADDR", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname
	{ "loader-configfile STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "loader-pathprefix STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "loader-reboottime UINT32", ISC_NOOP, NULL, NULL, 1}, // integer uint32_t
	{ "local-address IPADDR", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname
	{ "local-address6 IPADDR6", ISC_NOOP, NULL, NULL, 1}, // ipv6 addr
	{ "local-port UINT16", ISC_NOOP, NULL, NULL, 1}, // integer uint16_t
	{ "log-facility STRING,,", ISC_NOOP, NULL, NULL, 1}, // string options. e.g: opt1, opt2 or opt3 [arg1, ... ]
	{ "log-servers IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "log-threshold-high UINT8", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t
	{ "log-threshold-low UINT8", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t
	{ "lpr-servers IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "mask-supplier BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "max-dgram-reassembly UINT16", ISC_NOOP, NULL, NULL, 1}, // integer uint16_t
	{ "merit-dump STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "min-secs UINT8", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t
	{ "mobile-ip-home-agent IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "name-service-search UINT16,", ISC_NOOP, NULL, NULL, 1}, // integer uint16_t [arg1, ... ]
	{ "nds-context STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "nds-servers IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "nds-tree-name STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "netbios-dd-server IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "netbios-name-servers IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "netbios-node-type UINT8", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t
	{ "netbios-scope STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "netinfo-server-address IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "netinfo-server-tag STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "next-server IPADDR", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname
	{ "nis-domain STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "nis-servers IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "nisplus-domain STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "nisplus-servers IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "nntp-server IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "non-local-source-routing BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "not authoritative",			ISC_NOOP, NULL, NULL, 0},
	{ "ntp-servers IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "nwip-domain STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "nwip-suboptions VENDOR_ENCAPSULATED,", ISC_NOOP, NULL, NULL, 1}, // vendor option declaration [arg1, ... ]
	{ "omapi-key STRING", ISC_NOOP, NULL, NULL, 1}, // domain name
	{ "omapi-port UINT16", ISC_NOOP, NULL, NULL, 1}, // integer uint16_t
	{ "one-lease-per-client BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "option STRING STRING,",		ISC_OPTION, parse_option, NULL, 16},
	{ "option-6rd UINT8,", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t [arg1, ... ]
	{ "pana-agent IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "path-mtu-aging-timeout UINT32", ISC_NOOP, NULL, NULL, 1}, // integer uint32_t
	{ "path-mtu-plateau-table UINT16,", ISC_NOOP, NULL, NULL, 1}, // integer uint16_t [arg1, ... ]
	{ "pcode STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "perform-mask-discovery BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "pid-file-name STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "ping-check BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "ping-timeout UINT32", ISC_NOOP, NULL, NULL, 1}, // Lease interval
	{ "policy-filter IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "pop-server IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "preferred-lifetime UINT32", ISC_NOOP, NULL, NULL, 1}, // Lease interval
	{ "prefix-length-mode STRING,,", ISC_NOOP, NULL, NULL, 1}, // string options. e.g: opt1, opt2 or opt3 [arg1, ... ]
	{ "pxe-client-id UINT8,", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t [arg1, ... ]
	{ "pxe-interface-id UINT8,", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t [arg1, ... ]
	{ "pxe-system-type UINT16,", ISC_NOOP, NULL, NULL, 1}, // integer uint16_t [arg1, ... ]
	{ "range IPADDR IPADDR",		 ISC_NOOP, NULL, NULL, 2},
	{ "rdnss-selection UINT8,", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t [arg1, ... ]
	{ "relay-agent-information VENDOR_ENCAPSULATED,", ISC_NOOP, NULL, NULL, 1}, // vendor option declaration [arg1, ... ]
	{ "relay-port PORT", ISC_NOOP, NULL, NULL, 1}, // Zero-lenght option
	{ "release-on-roam BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "remote-id STRING", ISC_NOOP, NULL, NULL, 1}, // vendor option declaration statement
	{ "remote-port UINT16", ISC_NOOP, NULL, NULL, 1}, // integer uint16_t
	{ "resource-location-servers IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "root-path STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "router-discovery BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "router-solicitation-address IPADDR", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname
	{ "routers IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "server-id-check BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "server-name STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "shared-network STRING SECTION",	 ISC_NOOP, NULL, NULL, 1},
	{ "sip-ua-cs-domains STRING,", ISC_NOOP, NULL, NULL, 1}, // domain list [arg1, ... ]
	{ "site-option-space STRING", ISC_NOOP, NULL, NULL, 1}, // vendor option declaration statement
	{ "slp-directory-agent BOOL,", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore [arg1, ... ]
	{ "slp-service-scope BOOL,", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore [arg1, ... ]
	{ "smtp-server IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "stash-agent-options BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "static-routes IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "streettalk-directory-assistance-server IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "streettalk-server IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "subnet IPADDR netmask IPADDR SECTION",ISC_SUBNET, parse_subnet, NULL, 2},
	{ "subnet-mask IPADDR", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname
	{ "subnet-selection IPADDR", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname
	{ "swap-server IPADDR", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname
	{ "tcode STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "tcp-keepalive-garbage BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "tcp-keepalive-interval UINT32", ISC_NOOP, NULL, NULL, 1}, // integer uint32_t
	{ "tftp-server-address IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "tftp-server-name STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "time-offset INT32", ISC_NOOP, NULL, NULL, 1}, // integer int32_t
	{ "time-servers IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "trailer-encapsulation BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "uap-servers STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "update-conflict-detection BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "update-optimization BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "update-static-leases BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "use-host-decl-names BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "use-lease-addr-for-default-route BOOL", ISC_NOOP, NULL, NULL, 1}, // oolean should be true, false or ignore
	{ "user-class STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "v4-access-domain STRING", ISC_NOOP, NULL, NULL, 1}, // domain name
	{ "v4-captive-portal STRING", ISC_NOOP, NULL, NULL, 1}, // text string
	{ "v4-lost STRING", ISC_NOOP, NULL, NULL, 1}, // domain name
	{ "v4-portparams UINT8,", ISC_NOOP, NULL, NULL, 1}, // integer uint8_t [arg1, ... ]
	{ "vendor-class-identifier STRING", ISC_NOOP, NULL, NULL, 1}, // vendor option declaration statement
	{ "vendor-encapsulated-options VENDOR_ENCAPSULATED,", ISC_NOOP, NULL, NULL, 1}, // vendor option declaration [arg1, ... ]
	{ "vendor-option-space VENDOR_ENCAPSULATED", ISC_NOOP, NULL, NULL, 1}, // vendor option declaration
	{ "vivco VENDOR_ENCAPSULATED,", ISC_NOOP, NULL, NULL, 1}, // vendor option declaration [arg1, ... ]
	{ "vivso VENDOR_ENCAPSULATED,", ISC_NOOP, NULL, NULL, 1}, // vendor option declaration [arg1, ... ]
	{ "www-server IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
	{ "x-display-manager IPADDR,", ISC_NOOP, NULL, NULL, 1}, // ipaddr or hostname [arg1, ... ]
};

/** Parse a section { ... }
 *
 */
static int parse_section(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info)
{
	int rcode;
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
			while (*q && !isspace((int) *q)) q++;

			fr_strerror_printf("cannot nest '%.*s' statements",
					   (int) (q - parent->cmd->name), parent->cmd->name);
			return -1;
		}
	}

	IDEBUG("%.*s {", state->braces - 1, spaces); /* "braces" was already incremented */
	state->allow_eof = false; /* can't have EOF in the middle of a section */

	while (true) {
		rcode = read_token(state, T_BARE_WORD, YES_SEMICOLON, true);
		if (rcode < 0) return rcode;
		if (rcode == 0) break;

		/*
		 *	End of section is allowed here.
		 */
		if (*state->token == '}') break;

		rcode = match_keyword(info, state, commands, sizeof(commands) / sizeof(commands[0]));
		if (rcode < 0) return rcode;
		if (rcode == 0) break;

		entries = 1;
	}

	state->allow_eof = (state->braces == 0);

	IDEBUG("%.*s }", state->braces, spaces);

	return entries;
}

/** Open a file and read it into a parent.
 *
 */
static int read_file(rlm_isc_dhcp_info_t *parent, char const *filename, bool debug)
{
	int rcode;
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
	state.fp = fp;
	state.filename = filename;
	state.buffer = buffer;
	state.bufsize = sizeof(buffer);
	state.lineno = 0;

	state.braces = 0;
	state.ptr = buffer;
	state.token = NULL;

	state.debug = debug;
	state.allow_eof = true;

	/*
	 *	Tell the state machine that the buffer is empty.
	 */
	*state.ptr = '\0';

	while (true) {
		rcode = read_token(&state, T_BARE_WORD, true, false);
		if (rcode < 0) {
		fail:
			if (!state.token) {
				fr_strerror_printf("Failed reading %s:[%d] - %s",
						   filename, state.lineno,
						   fr_strerror());
			} else {
				fr_strerror_printf("Failed reading %s:[%d] offset %d - %s",
						   filename, state.lineno,
						   (int) (state.token - state.line),
						   fr_strerror());
			}
			fclose(fp);
			return rcode;
		}
		if (rcode == 0) break;

		/*
		 *	This will automatically re-fill the buffer,
		 *	and find a matching token.
		 */
		rcode = match_keyword(parent, &state, commands, sizeof(commands) / sizeof(commands[0]));
		if (rcode < 0) goto fail;
		if (rcode == 0) break;
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
	int rcode;
	rlm_isc_dhcp_t *inst = instance;
	rlm_isc_dhcp_info_t *info;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	inst->head = info = talloc_zero(inst, rlm_isc_dhcp_info_t);
	info->last = &(info->child);

	rcode = read_file(info, inst->filename, inst->debug);
	if (rcode < 0) {
		cf_log_err(conf, "%s", fr_strerror());
		return -1;
	}

	if (rcode == 0) {
		cf_log_warn(conf, "No configuration read from %s", inst->filename);
		return 0;
	}

	return 0;
}


static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, UNUSED void *thread, REQUEST *request)
{
	int rcode;
	rlm_isc_dhcp_t *inst = instance;

	rcode = apply_fixed_ip(inst, request, inst->head);
	if (rcode < 0) return RLM_MODULE_FAIL;
	if (rcode == 0) return RLM_MODULE_NOOP;

	if (rcode == 2) return RLM_MODULE_UPDATED;

	return RLM_MODULE_OK;
}


static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, UNUSED void *thread, REQUEST *request)
{
	int rcode;
	rlm_isc_dhcp_t *inst = instance;

	rcode = apply(inst, request, inst->head);
	if (rcode < 0) return RLM_MODULE_FAIL;
	if (rcode == 0) return RLM_MODULE_NOOP;

	// @todo - check for subnet mask option.  If none exists, use one from the enclosing network?

	return RLM_MODULE_OK;
}

extern rad_module_t rlm_isc_dhcp;
rad_module_t rlm_isc_dhcp = {
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
