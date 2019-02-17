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

typedef struct rlm_isc_dhcp_info_t rlm_isc_dhcp_info_t;

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

	int		braces;		//!< how many levels deep we are in a { ... }
	bool		semicolon;	//!< whether we saw a semicolong
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
	fr_hash_table_t		*host_table;	//!< by MAC address
	rlm_isc_dhcp_info_t	*child;
	rlm_isc_dhcp_info_t	**last;		//!< pointer to last child
};

static int read_file(rlm_isc_dhcp_info_t *parent, char const *filename, bool debug);
static int parse_section(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info);
static int apply(rlm_isc_dhcp_t *inst, REQUEST *request, rlm_isc_dhcp_info_t *head);

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
static int read_token(rlm_isc_dhcp_tokenizer_t *state, FR_TOKEN hint, bool semicolon, bool allow_rcbrace)
{
	char *p;
	int lineno;

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
				fr_strerror_printf("Failed reading %s line %d: Unexpected EOF",
						   state->filename, state->lineno);
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
	while (isspace((int) *state->ptr) || (*state->ptr == ';')) state->ptr++;

	if (!*state->ptr) goto redo;

	/*
	 *	Start looking for the next token from where we left
	 *	off last time.
	 */
	state->token = state->ptr;
	state->semicolon = false;

	/*
	 *	Remember which line this input was read from.  Any
	 *	refill later will change the line number.
	 */
	lineno = state->lineno;

	for (p = state->token; *p != '\0'; p++) {
		/*
		 *	"end of word" character.  It might be allowed
		 *	here, or it might not be.
		 */
		if (*p == ';') {
			if (!semicolon) {
				fr_strerror_printf("Syntax error in %s at line %d: Unexpected ';'",
						   state->filename, state->lineno);
				return -1;			
			}

			state->ptr = p;
			state->semicolon = true;
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
			if (*state->ptr == ';') state->semicolon = true;

			break;
		}
	}

	/*
	 *	Protect the rest of the code from buffer overflows.
	 */
	state->token_len = p - state->token;

	if (state->token_len >= 256) {
		fr_strerror_printf("Token too large");
		return -1;
	}

	/*
	 *	Double-check the token against what we were expected
	 *	to read.
	 */
	if (hint == T_LCBRACE) {
		if (*state->token != '{') {
			fr_strerror_printf("Failed reading %s line %d - Missing '{'",
					   state->filename, lineno);
			return -1;
		}

		state->braces++;
		return 1;
	}

	if (hint == T_RCBRACE) {
		if (*state->token != '}') {
			fr_strerror_printf("Failed reading %s line %d - Missing '}'",
					   state->filename, lineno);
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
			fr_strerror_printf("Failed reading %s line %d - Unexpected '}'",
					   state->filename, lineno);
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
			fr_strerror_printf("Failed reading %s line %d - Unexpected '{'",
					   state->filename, lineno);
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
	bool semicolon = false;
	char *p;
	char const *q;
	char const *next;
	char type_name[64];

	while (isspace((int) *cmd)) cmd++;

	if (!*cmd) return -1;	/* internal error */

	/*
	 *	Remember the next command.
	 */
	next = cmd;
	while (*next && !isspace((int) *next)) next++;
	if (!*next) semicolon = true;

	q = cmd;

	/*
	 *	Matching an in-line word.
	 */
	if (islower((int) *q)) {
		char const *start = q;

		rcode = read_token(state, T_BARE_WORD, semicolon, false);
		if (rcode <= 0) return rcode;

		/*
		 *	Look for a verbatim word.
		 */
		for (p = state->token; p < (state->token + state->token_len); p++, q++) {
			if (*p != *q) {
			fail:
				fr_strerror_printf("Expected '%s', not '%.*s'",
						   start, state->token_len, state->token);
				return -1;
			}
		}

		/*
		 *	Matched all of 'q', we're done.
		 */
		if (!*q) {
			IDEBUG("... WORD %.*s ", state->token_len, state->token);
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

		rcode = read_token(state, T_LCBRACE, false, false);
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
	 */
	p = type_name;
	while (*q && !isspace((int) *q)) {
		if ((p - type_name) >= (int) sizeof(type_name)) return -1; /* internal error */
		*(p++) = tolower((int) *(q++));
	}
	*p = '\0';

	type = fr_str2int(fr_value_box_type_names, type_name, -1);
	if (type < 0) {
		fr_strerror_printf("Unknown data type '%s'", cmd);
		return -1;
	}

	/*
	 *	We were asked to parse a data type, so instead allow
	 *	just about anything.
	 *
	 *	@todo - if we get fancy, dynamically expand this, too.
	 *	ISC doesn't support it, but we can.
	 */
	rcode = read_token(state, T_DOUBLE_QUOTED_STRING, semicolon, false);
	if (rcode <= 0) return rcode;

	IDEBUG("... DATA %.*s ", state->token_len, state->token);

	/*
	 *	Parse the data to its final form.
	 */
	info->argv[info->argc] = talloc_zero(info, fr_value_box_t);

	rcode = fr_value_box_from_str(info, info->argv[info->argc], (fr_type_t *) &type, NULL,
				      state->token, state->token_len, 0, false);
	if (rcode < 0) return rcode;

	info->argc++;

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

	IDEBUG("include %s ;", name);

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
		bool semicolon;
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

		semicolon = true; /* default to always requiring this */

		IDEBUG("... TOKEN %.*s ", state->token_len, state->token);

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
			if (state->semicolon) goto unexpected;

			rcode = match_subword(state, q, info);
			if (rcode <= 0) return rcode;

			/*
			 *	SUBSECTION must be at the end
			 */
			if (rcode == 2) semicolon = false;
		}

		/*
		 *	*q must be empty at this point.
		 */
		if (!semicolon && state->semicolon) {
		unexpected:
			fr_strerror_printf("Syntax error in %s at line %d: Unexpected ';'",
					   state->filename, state->lineno);
			talloc_free(info);
			return -1;
		}

		if (semicolon && !state->semicolon) {
			fr_strerror_printf("Syntax error in %s at line %d: Missing ';'",
					   state->filename, state->lineno);
			talloc_free(info);
			return -1;
		}

		/*
		 *	Call the "parse" function which should do
		 *	validation, etc.
		 */
		rcode = 0;
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

	DEBUG("input '%.*s' did not match anything", state->token_len, state->token);

	/*
	 *	No match.
	 */
	return 0;
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

	parent = info->parent;

	if (!parent->host_table) {
		parent->host_table = fr_hash_table_create(parent, host_hash, host_cmp, NULL);
		if (!parent->host_table) return -1;
	}

	old = fr_hash_table_finddata(parent->host_table, host);
	if (old) {
		fr_strerror_printf("'host %s' and 'host %s' contain duplicate 'hardware ethernet' fields",
				   info->argv[0]->vb_strvalue, old->info->argv[0]->vb_strvalue);
		return -1;
	}

	if (fr_hash_table_insert(parent->host_table, host) < 0) {
		fr_strerror_printf("Failed inserting 'host %s' into hash table",
				   info->argv[0]->vb_strvalue);
		return -1;
	}

	IDEBUG("host %s { ... }", info->argv[0]->vb_strvalue);

	/*
	 *	We've remembered the host in the parent host_table.
	 *	There's no need to add it to the linked list here.
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
	if (head->host_table) {
		isc_host_t *host, my_host;

		// @todo - figure out what ether attribute to
		// use... maybe in inst->ether, and copy it here.
		memset(&my_host, 0, sizeof(my_host));

		host = fr_hash_table_finddata(head->host_table, &my_host);
		if (host) {
			child_rcode = apply(inst, request, host->info);
			if (child_rcode < 0) return child_rcode;
			if (child_rcode == 1) rcode = 1;
		}
	}

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
	{ "fixed-address STRING",		NULL, NULL, 1},
	{ "group SECTION",			NULL, NULL, 1},
	{ "hardware ethernet ETHER",		NULL, NULL, 1},
	{ "host STRING SECTION",		parse_host, NULL, 1},
	{ "include STRING",			parse_include, NULL, 1},
	{ "min-lease-time INTEGER",		NULL, NULL, 1},
	{ "max-ack-delay UINT32",		NULL, NULL, 1},
	{ "max-lease-time INTEGER",		NULL, NULL, 1},
	{ "not authoritative",			NULL, NULL, 0},
	{ "shared-network STRING SECTION",	NULL, NULL, 1},
	{ "subnet IPADDR netmask IPADDR SECTION", NULL, NULL, 2},
	{ NULL, NULL }
};

/** Parse a section { ... }
 *
 */
static int parse_section(rlm_isc_dhcp_tokenizer_t *state, rlm_isc_dhcp_info_t *info)
{
	int rcode;
	int entries = 0;

	IDEBUG("{");
	state->allow_eof = false; /* can't have EOF in the middle of a section */

	while (true) {
		rcode = read_token(state, T_BARE_WORD, true, true);
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

	IDEBUG("}");

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
		cf_log_err(conf, "No configuration read from %s", inst->filename);
		return -1;
	}

	return -1;
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
