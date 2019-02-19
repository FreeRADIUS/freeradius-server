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

extern fr_dict_attr_autoload_t rlm_isc_dhcp_dict_attr[];
fr_dict_attr_autoload_t rlm_isc_dhcp_dict_attr[] = {
	{ .out = &attr_client_hardware_address, .name = "DHCP-Client-Hardware-Address", .type = FR_TYPE_ETHERNET, .dict = &dict_dhcpv4},
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

/** Describes the commands that we accept, including it's syntax (i.e. name), etc.
 *
 */
typedef struct rlm_isc_dhcp_cmd_t {
	char const		*name;
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
	VALUE_PAIR		*options;	//!< DHCP options
	fr_trie_t		*subnets;
	rlm_isc_dhcp_info_t	*child;
	rlm_isc_dhcp_info_t	**last;		//!< pointer to last child
};

static int read_file(rlm_isc_dhcp_info_t *parent, char const *filename, bool debug);
static int parse_section(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info);
static int apply(rlm_isc_dhcp_t *inst, REQUEST *request, rlm_isc_dhcp_info_t *head);

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

	type = fr_str2int(fr_value_box_type_names, type_name, -1);
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
			fr_strerror_printf("Too many arguments (%d) for command '%s'",
					   info->cmd->max_argc, info->cmd->name);
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

static int match_keyword(rlm_isc_dhcp_info_t *parent, rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_cmd_t const *tokens)
{
	int i;

	for (i = 0; tokens[i].name != NULL; i++) {
		char const *q;
		char *p;
		int semicolon;
		int rcode;
		rlm_isc_dhcp_info_t *info;

		p = state->token;

		/*
		 *	We've gone past the name and not found it.
		 *	Oops.
		 */
		if (*p < tokens[i].name[0]) break;

		/*
		 *	Not yet reached the correct name, don't do a
		 *	full strcmp()
		 */
		if (*p > tokens[i].name[0]) continue;

		q = tokens[i].name;

		while (p < (state->token + state->token_len)) {
			if (*p != *q) break;

			p++;
			q++;
		}

		/*
		 *	Not a match, go to the next token in the list.
		 */
		if (p < (state->token + state->token_len)) continue;

		semicolon = YES_SEMICOLON; /* default to always requiring this */

		DDEBUG("... TOKEN %.*s ", state->token_len, state->token);

		info = talloc_zero(parent, rlm_isc_dhcp_info_t);
		if (tokens[i].max_argc) {
			info->argv = talloc_zero_array(info, fr_value_box_t *, tokens[i].max_argc);
		}

		/*
		 *	Remember which command we parsed.
		 */
		info->parent = parent;
		info->cmd = &tokens[i];
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
		if (tokens[i].parse) {
			rcode = tokens[i].parse(state, info);
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

	fr_strerror_printf("unknown command '%.*s'", state->token_len, state->token);

	return -1;
}

typedef struct isc_host_t {
	uint8_t			ether[6];
	rlm_isc_dhcp_info_t	*info;
} isc_host_t;

static uint32_t host_hash(void const *data)
{
	isc_host_t const *host = data;

	return fr_hash(host->ether, sizeof(host->ether));
}

static int host_cmp(void const *one, void const *two)
{
	isc_host_t const *a = one;
	isc_host_t const *b = two;

	return memcmp(a->ether, b->ether, 6);
}

static int parse_host(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info)
{
	isc_host_t *host, *old;
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
		if (strncmp(child->cmd->name, "hardware ethernet ", 18) == 0) {
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
	host = talloc_zero(info, isc_host_t);
	memcpy(host->ether, &(child->argv[0]->vb_ether), sizeof(host->ether));
	host->info = info;

	/*
	 *	Add the host to the *parents* hash table.  That way
	 *	when we apply the parent, we can look up the host in
	 *	its hash table.  And avoid the O(N) issue of having
	 *	thousands of "host" entries in the parent->child list.
	 */
	parent = info->parent;
	if (!parent->hosts) {
		parent->hosts = fr_hash_table_create(parent, host_hash, host_cmp, NULL);
		if (!parent->hosts) return -1;
	}

	/*
	 *	Duplicate "host" entries aren't allowd.
	 */
	old = fr_hash_table_finddata(parent->hosts, host);
	if (old) {
		fr_strerror_printf("'host %s' and 'host %s' contain duplicate 'hardware ethernet' fields",
				   info->argv[0]->vb_strvalue, old->info->argv[0]->vb_strvalue);
		return -1;
	}

	if (fr_hash_table_insert(parent->hosts, host) < 0) {
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
	FR_TOKEN op;
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

	/*
	 *	Add versus set, for options with multiple parameters.
	 */
	if (info->argc == 2) {
		op = T_OP_SET;
	} else {
		op = T_OP_ADD;
	}

	(void) fr_pair_cursor_init(&cursor, &parent->options);

	/*
	 *	Add in all of the options
	 */
	for (i = 1; i < info->argc; i++) {
		rcode = fr_pair_value_from_str(vp, info->argv[1]->vb_strvalue, info->argv[1]->vb_length,
					       '\0', false);
		if (rcode < 0) return rcode;

		vp->op = op;

		fr_pair_cursor_append(&cursor, vp);

		IDEBUG("%.*s option %s %s ", state->braces, spaces, info->argv[1]->vb_strvalue, info->argv[1]->vb_strvalue);
	}

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


/*
 *	Apply functions
 */
static int apply(rlm_isc_dhcp_t *inst, REQUEST *request, rlm_isc_dhcp_info_t *head)
{
	int rcode, child_rcode;
	rlm_isc_dhcp_info_t *info;

	rcode = 0;

	/*
	 *	First, apply any "host" options
	 */
	if (head->hosts) {
		isc_host_t *host, my_host;
		VALUE_PAIR *vp;

		vp = fr_pair_find_by_da(request->packet->vps, attr_client_hardware_address, TAG_ANY);
		if (!vp) goto options;

		memcpy(&my_host.ether, vp->vp_ether, sizeof(my_host.ether));

		host = fr_hash_table_finddata(head->hosts, &my_host);
		if (!host) goto options;

		/*
		 *	@todo - call a new apply_host()
		 *	function, which will look for matching
		 *	"fixed-address".
		 *
		 *	If there's no "fixed-address", it will
		 *	apply all the rules.
		 *
		 *	If there is a "fixed-address", it will
		 *	apply the host rules only if one of
		 *	the addresses is valid for the network
		 *	to which the client is connected.
		 */
		child_rcode = apply(inst, request, host->info);
		if (child_rcode < 0) return child_rcode;
		if (child_rcode == 1) rcode = 1;
	}

options:
	if (head->options) {
		VALUE_PAIR *copy = NULL;

		rcode = fr_pair_list_copy(request->reply, &copy, head->options);
		if (rcode < 0) {
			RDEBUG("Failed copying some options: %s", fr_strerror());
		}

		/*
		 *	All of the options are ":=".  We evaluate /
		 *	add options from the top down, so using ":="
		 *	lets child options over-ride parent options.
		 */
		fr_pair_list_move(&request->reply->vps, &copy);
		fr_pair_list_free(&copy);
	}

	/*
	 *	Look in the trie for matching subnets, and apply any
	 *	subnets that match.
	 *
	 *	@todo - figure out which subnet to choose?  Maybe
	 *	based on the assigned IP, or maybe something else...
	 */
	if (head->subnets) {
		info = fr_trie_lookup(head->subnets, "0000", 32);
		if (!info) goto recurse;

		child_rcode = apply(inst, request, info);
		if (child_rcode < 0) return child_rcode;
		if (child_rcode == 1) rcode = 1;
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

	return rcode;
}


/** Table of commands that we allow.
 *
 */
static const rlm_isc_dhcp_cmd_t commands[] = {
	{ "abandon-lease-time INTEGER",		NULL, NULL, 1},
	{ "adaptive-lease-time-threshold INTEGER", NULL, NULL, 1},
	{ "always-broadcast BOOL",		NULL, NULL, 1},
	{ "authoritative",			NULL, NULL, 0},
	{ "default-lease-time INTEGER", 	NULL, NULL, 1},
	{ "delayed-ack UINT16",			NULL, NULL, 1},
	{ "filename STRING",			NULL, NULL, 1},
	{ "fixed-address IPADDR,",		NULL, NULL, 16},
	{ "group SECTION",			NULL, NULL, 1},
	{ "hardware ethernet ETHER",		NULL, NULL, 1},
	{ "host STRING SECTION",		parse_host, NULL, 1},
	{ "include STRING",			parse_include, NULL, 1},
	{ "min-lease-time INTEGER",		NULL, NULL, 1},
	{ "max-ack-delay UINT32",		NULL, NULL, 1},
	{ "max-lease-time INTEGER",		NULL, NULL, 1},
	{ "not authoritative",			NULL, NULL, 0},
	{ "option STRING STRING,",		parse_option, NULL, 16},
	{ "range IPADDR IPADDR",		NULL, NULL, 2},
	{ "shared-network STRING SECTION",	NULL, NULL, 1},
	{ "subnet IPADDR netmask IPADDR SECTION", parse_subnet, NULL, 2},
	{ NULL, NULL }
};

/** Parse a section { ... }
 *
 */
static int parse_section(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info)
{
	int rcode;
	int entries = 0;

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

		rcode = match_keyword(info, state, commands);
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
		rcode = match_keyword(parent, &state, commands);
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

static rlm_rcode_t CC_HINT(nonnull) mod_process(void *instance, UNUSED void *thread, REQUEST *request)
{
	int rcode;
	rlm_isc_dhcp_t *inst = instance;

	rcode = apply(inst, request, inst->head);
	if (rcode < 0) return RLM_MODULE_FAIL;
	if (rcode == 0) return RLM_MODULE_NOOP;

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
		[MOD_AUTHORIZE]	= mod_process,
		[MOD_POST_AUTH]	= mod_process,
	},
};
