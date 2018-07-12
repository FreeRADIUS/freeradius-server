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
 * @file command.c
 * @brief Internal commands for the server
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/command.h>
#include <freeradius-devel/server/rad_assert.h>

/*
 *	Registration hooks for radmin.
 */
static int fr_command_register(UNUSED char const *name, UNUSED void *ctx, UNUSED fr_cmd_table_t *table)
{
	return 0;
}

fr_command_register_hook_t fr_command_register_hook = fr_command_register;

typedef struct fr_cmd_argv_t {
	char		*name;
	fr_type_t	type;
	struct fr_cmd_argv_t *next;
	struct fr_cmd_argv_t *child;
} fr_cmd_argv_t;

struct fr_cmd_t {
	struct fr_cmd_t		*next;
	struct fr_cmd_t		*child;				//!< if there are subcommands
	char const		*name;
	char const		*syntax;			//!< only for terminal nodes
	char const		*help;				//!< @todo - long / short help

	int			syntax_argc;			//!< syntax split out into arguments
	fr_cmd_argv_t		*syntax_argv;			//!< arguments and types

	void			*ctx;
	fr_cmd_func_t		func;
	fr_cmd_tab_t		tab_expand;

	bool			read_only;
	bool			intermediate;			//!< intermediate commands can't have callbacks
	bool			auto_allocated;
	bool			live;				//!< is this entry live?
};


static int fr_command_verify_argv(fr_cmd_info_t *info, int start, int verify, int argc, fr_cmd_argv_t **argv_p, bool optional) CC_HINT(nonnull);
static bool fr_command_valid_name(char const *name);
static int split(char **input, char **output, bool syntax_string);

/*
 *	Hacks for simplicity.  These data types aren't allowed as
 *	parameters, so we can re-use them for something else.
 */

// our fixed string.  Any data type LESS than this must be a real data type
#define FR_TYPE_FIXED		FR_TYPE_ABINARY

#define FR_TYPE_VARARGS		FR_TYPE_TLV
#define FR_TYPE_OPTIONAL	FR_TYPE_STRUCT
#define FR_TYPE_ALTERNATE	FR_TYPE_EXTENDED
#define FR_TYPE_ALTERNATE_CHOICE FR_TYPE_LONG_EXTENDED

/** Find a command
 *
 * @param head the head of the list
 * @param name of the command to find
 * @param insert where the new command should be inserted
 * @return
 *	- NULL for "not found".  In which case "head" is the insertion point for the new command
 *	- !NULL for the command which was found.
 */
static fr_cmd_t *fr_command_find(fr_cmd_t **head, char const *name, fr_cmd_t ***insert)
{
	fr_cmd_t *cmd, **where = head;

	if (!head || !name) return NULL;

	if (!*head) {
		if (insert) *insert = head;
		return NULL;
	}

	for (cmd = *head; cmd != NULL; cmd = cmd->next) {
		int status;

		status = strcmp(cmd->name, name);

		/*
		 *	Not found yet.
		 */
		if (status < 0) {
			where = &(cmd->next);
			continue;
		}

		/*
		 *	Not in the list.
		 */
		if (status > 0) break;

		/*
		 *	Was found, return it.
		 */
		return cmd;
	}

	if (insert) *insert = where;

	return NULL;
}

/** Allocate an fr_cmd_t structure
 *
 *  We presume that this allocation is done after a call to fr_command_find()
 *
 *  @param ctx talloc ctx for the allocation
 *  @param head of the command list (singly linked)
 *  @param name of the command to allocate
 *  @return
 *	- fr_cmd_t structure which has been allocated.  Only "name" is filled in.
 */
static fr_cmd_t *fr_command_alloc(TALLOC_CTX *ctx, fr_cmd_t **head, char const *name)

{
	fr_cmd_t *cmd;

	MEM(cmd = talloc_zero(ctx, fr_cmd_t));
	cmd->name = talloc_strdup(ctx, name);
	cmd->intermediate = true;
	cmd->live = false;

	cmd->next = *head;
	*head = cmd;

	return cmd;
}


/*
 *	Validate a name (or syntax)
 */
static bool fr_command_valid_name(char const *name)
{
	char const *p;

	for (p = name; *p != '\0'; p++) {
		if (*p <= ' ') {
			fr_strerror_printf("Invalid control character in name");
			return false;
		}
		if (*p > 0x7e) {
			fr_strerror_printf("Invalid non-ASCII character");
			return false;
		}

		if ((*p == '[') || (*p == ']') ||
		    (*p == '"') || (*p == '\'') ||
		    (*p == '(') || (*p == ')') ||
		    (*p == '|') || (*p == '#')) {
			fr_strerror_printf("Invalid special character");
			return false;
		}
	}

	return true;
}

static bool fr_command_valid_syntax(fr_cmd_argv_t *argv)
{
	char const *p;
	bool lowercase = false;
	bool uppercase = false;

	argv->type = FR_TYPE_FIXED;

	if (!fr_command_valid_name(argv->name)) {
		return false;
	}

	for (p = argv->name; *p != '\0'; p++) {
		if (isupper((int) *p)) uppercase = true;
		if (islower((int) *p)) lowercase = true;
	}

	/*
	 *	No alphabetical characters, that's a
	 *	problem.
	 */
	if (!uppercase && !lowercase) {
		fr_strerror_printf("Syntax command '%s' has no alphabetical characters", argv->name);
		return false;
	}

	/*
	 *	Mixed case is not allowed in a syntax.
	 */
	if (uppercase && lowercase) {
		fr_strerror_printf("Syntax command '%s' has invalid mixed case", argv->name);
		return false;
	}

	/*
	 *	All-uppercase words MUST be valid data
	 *	types.
	 */
	if (uppercase) {
		fr_type_t type;

		type = fr_str2int(dict_attr_types, argv->name, FR_TYPE_INVALID);
		switch (type) {
		case FR_TYPE_ABINARY:
		case FR_TYPE_VALUE_BOX:
		case FR_TYPE_BAD:
		case FR_TYPE_STRUCTURAL:
			fr_strerror_printf("Syntax command '%s' has unknown data type", argv->name);
			return false;

		default:
			break;
		}

		argv->type = type;
	}

	return true;
}

/*
 *	Like split, but is alternation aware.
 */
static int split_alternation(char **input, char **output)
{
	char quote;
	char *str = *input;
	char *word;

	/*
	 *	String is empty, we're done.
	 */
	if (!*str) return 0;

	/*
	 *	Skip leading whitespace.
	 */
	while ((*str == ' ') ||
	       (*str == '\t') ||
	       (*str == '\r') ||
	       (*str == '\n'))
		*(str++) = '\0';

	/*
	 *	String is empty, we're done.
	 */
	if (!*str) return 0;

	/*
	 *	Remember the start of the word.
	 */
	word = str;

	if ((*str == '[') || (*str == '(')) {
		char end;
		quote = *(str++);
		int count = 0;

		if (quote == '[') {
			end = ']';
		} else {
			end = ')';
		}

		/*
		 *	Don't allow backslashes here.  This piece is
		 *	only for parsing syntax strings, which CANNOT
		 *	have quotes in them.
		 */
		while ((*str != end) || (count > 0)) {
			if (!*str) {
				fr_strerror_printf("String ends before closing brace.");
				return -1;
			}

			if (*str == quote) count++;
			if (*str == end) count--;

			str++;
		}

		/*
		 *	Skip the final "quotation" mark.
		 */
		str++;

		/*
		 *	[foo bar]baz is invalid.
		 */
		if ((*str != '\0') &&
		    (*str != ' ') &&
		    (*str != '|') &&
		    (*str != '\t')) {
			fr_strerror_printf("Invalid text after quoted string.");
			return -1;
		}
	} else {
		int count = 0;

		/*
		 *	Skip until we reach the next alternation,
		 *	ignoring | in nested alternation.
		 *
		 */
		while (*str) {
			if (*str == '(') {
				count++;
			} else if (*str == ')') {
				count--;
			} else if (count == 0) {
				if (*str == '|') break;
			}
			str++;
		}
	}

	/*
	 *	One of the above characters is after the word.
	 *	Over-write it with NUL.  If *str==0, then we leave it
	 *	alone, so that the next call to split() discovers it,
	 *	and returns NULL.
	 */
	if (*str) {
		/*
		 *	Skip trailing whitespace so that the caller
		 *	can peek at the next argument.
		 */
		while ((*str == ' ') ||
		       (*str == '|') ||
		       (*str == '\t')) {
			*(str++) = '\0';
		}
	}

	*input = str;
	*output = word;
	return 1;
}

static int split(char **input, char **output, bool syntax_string)
{
	char quote;
	char *str = *input;
	char *word;

	/*
	 *	String is empty, we're done.
	 */
	if (!*str) return 0;

	/*
	 *	Skip leading whitespace.
	 */
	while ((*str == ' ') ||
	       (*str == '\t') ||
	       (*str == '\r') ||
	       (*str == '\n'))
		*(str++) = '\0';

	/*
	 *	String is empty, we're done.
	 */
	if (!*str) return 0;

	/*
	 *	String is only comments, we're done.
	 */
	if (*str == '#') {
		*str = '\0';
		return 0;
	}

	/*
	 *	Remember the start of the word.
	 */
	word = str;

	/*
	 *	Quoted string?  Skip to the trailing quote.
	 *
	 *	But only if we're not parsing a syntax string.
	 */
	if (!syntax_string && ((*str == '"') || (*str == '\''))) {
		quote = *(str++);

		while (*str != quote) {
			if (!*str) {
				fr_strerror_printf("String is not terminated with a quotation character.");
				return -1;
			}

			/*
			 *	Skip backslashes and the following character
			 */
			if (*str == '\\') {
				str++;
				if (!*str) {
					fr_strerror_printf("Invalid backslash at end of string.");
					return -1;
				};
				str++;
				continue;
			}

			str++;
		}

		/*
		 *	Skip the final quotation mark.
		 */
		str++;

		/*
		 *	"foo"bar is invalid.
		 */
		if ((*str != '\0') &&
		    (*str != ' ') &&
		    (*str != '#') &&
		    (*str != '\t') &&
		    (*str != '\r') &&
		    (*str != '\n')) {
			fr_strerror_printf("Invalid text after quoted string.");
			return -1;
		}

	} else if (syntax_string && ((*str == '[') || (*str == '('))) {
		char end;
		quote = *(str++);
		int count = 0;

		if (quote == '[') {
			end = ']';
		} else {
			end = ')';
		}

		/*
		 *	Don't allow backslashes here.  This piece is
		 *	only for parsing syntax strings, which CANNOT
		 *	have quotes in them.
		 */
		while ((*str != end) || (count > 0)) {
			if (!*str) {
				fr_strerror_printf("String ends before closing brace.");
				return -1;
			}

			if (*str == quote) count++;
			if (*str == end) count--;

			str++;
		}

		/*
		 *	Skip the final "quotation" mark.
		 */
		str++;

		/*
		 *	[foo bar]baz is invalid.
		 */
		if ((*str != '\0') &&
		    (*str != ' ') &&
		    (*str != '#') &&
		    (*str != '\t') &&
		    (*str != '\r') &&
		    (*str != '\n')) {
			fr_strerror_printf("Invalid text after quoted string.");
			return -1;
		}
	} else {
		/*
		 *	Skip the next non-space characters.
		 */
		while (*str &&
		       (*str != ' ') &&
		       (*str != '#') &&
		       (*str != '\t') &&
		       (*str != '\r') &&
		       (*str != '\n'))
			str++;
	}

	/*
	 *	One of the above characters is after the word.
	 *	Over-write it with NUL.  If *str==0, then we leave it
	 *	alone, so that the next call to split() discovers it,
	 *	and returns NULL.
	 */
	if (*str) {
		/*
		 *	Skip trailing whitespace so that the caller
		 *	can peek at the next argument.
		 */
		while ((*str == ' ') ||
		       (*str == '\t') ||
		       (*str == '\r') ||
		       (*str == '\n'))
			*(str++) = '\0';
	}

	*input = str;
	*output = word;
	return 1;
}

static int fr_command_add_syntax(TALLOC_CTX *ctx, char *syntax, fr_cmd_argv_t **head)
{
	int i, rcode;
	char *name, *p;
	fr_cmd_argv_t **last, *prev;

	p = syntax;
	*head = NULL;
	last = head;
	prev = NULL;

	for (i = 0; i < CMD_MAX_ARGV; i++) {
		fr_cmd_argv_t *argv;

		rcode = split(&p, &name, true);
		if (rcode < 0) return rcode;

		if (rcode == 0) return i;

		/*
		 *	Check for varargs.  Which MUST NOT be
		 *	the first argument, and MUST be the
		 *	last argument, and MUST be preceded by
		 *	a known data type.
		 */
		if (strcmp(name, "...") == 0) {
			if (!prev || *p) {
				fr_strerror_printf("Varargs MUST be the last argument in the syntax list");
				return -1;
			}

			/*
			 *	The thing BEFORE the varags
			 *	MUST be a known data type.
			 */
			if (prev->type >= FR_TYPE_FIXED) {
				fr_strerror_printf("Varargs MUST be preceded by a data type.");
				return -1;
			}
			argv = talloc_zero(ctx, fr_cmd_argv_t);
			argv->name = name;
			argv->type = FR_TYPE_VARARGS;

		} else if (name[0] == '[') {
			/*
			 *	Optional things.  e.g. [foo bar]
			 */
			char *option = talloc_strdup(ctx, name + 1);
			char *q;
			fr_cmd_argv_t *child;

			q = option + strlen(option) - 1;
			if (*q != ']') {
				fr_strerror_printf("Optional syntax is not properly terminated");
				return -1;
			}

			*q = '\0';
			child = NULL;

			rcode = fr_command_add_syntax(option, option, &child);
			if (rcode < 0) return rcode;

			argv = talloc_zero(ctx, fr_cmd_argv_t);
			argv->name = name;
			argv->type = FR_TYPE_OPTIONAL;
			argv->child = child;

		} else if (name[0] == '(') {
			/*
			 *	Alternate things.  e.g. [foo bar]
			 */
			char *option = talloc_strdup(ctx, name + 1);
			char *q, *word;
			fr_cmd_argv_t *child, **last_child;

			q = option + strlen(option) - 1;
			if (*q != ')') {
				fr_strerror_printf("Alternate syntax is not properly terminated");
				return -1;
			}

			*q = '\0';
			child = NULL;
			last_child = &child;

			/*
			 *	Walk over the choices, creating
			 *	intermediate nodes for each one.  Then
			 *	placing the actual choices into
			 *	child->child.
			 */
			q = option;
			while (true) {
				fr_cmd_argv_t *choice, *sub;

				rcode = split_alternation(&q, &word);
				if (rcode < 0) return rcode;
				if (rcode == 0) break;

				sub = NULL;
				rcode = fr_command_add_syntax(option, word, &sub);
				if (rcode < 0) return rcode;

				choice = talloc_zero(option, fr_cmd_argv_t);
				choice->name = word;
				choice->type = FR_TYPE_ALTERNATE_CHOICE;
				choice->child = sub;

				*last_child = choice;
				last_child = &(choice->next);
			}

			argv = talloc_zero(ctx, fr_cmd_argv_t);
			argv->name = name;
			argv->type = FR_TYPE_ALTERNATE;
			argv->child = child;

		} else {
			argv = talloc_zero(ctx, fr_cmd_argv_t);
			argv->name = name;

			/*
			 *	Validates argv->name and sets argv->type
			 */
			if (!fr_command_valid_syntax(argv)) {
				talloc_free(argv);
				return -1;
			}
		}

		*last = argv;
		last = &(argv->next);
		prev = argv;
	}

	if (*p) {
		fr_strerror_printf("Too many arguments passed in syntax string");
		return -1;
	}

	return i;
}

/**  Add one command to the global command tree
 *
 *  We do not do any sanity checks on "name".  If it has spaces in it,
 *  or "special" characters, that's up to you.  We assume that other
 *  things in the server will sanity check them.
 *
 * @param talloc_ctx the talloc context
 * @param head pointer to the head of the table pointer.  Should point to NULL at the start.
 * @param name of the command to allocate.  Can be NULL for "top level" commands
 * @param ctx for any callback function
 * @param table of information about the current command
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_command_add(TALLOC_CTX *talloc_ctx, fr_cmd_t **head, char const *name, void *ctx, fr_cmd_table_t const *table)
{
	fr_cmd_t *cmd, **start;
	fr_cmd_t **insert;
	int argc = 0;
	fr_cmd_argv_t *syntax_argv;

	if (name && !fr_command_valid_name(name)) {
		return -1;
	}

	if (!name && !table->syntax) {
		fr_strerror_printf("Top-level commands MUST have a syntax");
		return -1;
	}

	start = head;
	syntax_argv = NULL;

	/*
	 *	If there are parent commands, ensure that entries for
	 *	them exist in the tree.  This check allows a table for
	 *	"foo" to add "show module foo", even if "show module"
	 *	does not yet exist.
	 */
	if (table->parent) {
		int i, rcode;
		char *p;
		char *parents[CMD_MAX_ARGV];

		p = talloc_strdup(talloc_ctx, table->parent);

		for (i = 0; i < CMD_MAX_ARGV; i++) {
			rcode = split(&p, &parents[i], true);
			if (rcode < 0) return -1;
			if (rcode == 0) break;

			if (!fr_command_valid_name(parents[i])) {
				fr_strerror_printf("Invalid command name '%s'", parents[i]);
				return -1;
			}

			/*
			 *	Find the head command.  If found,
			 *	go downwards into the child command.
			 */
			cmd = fr_command_find(start, parents[i], &insert);
			if (!cmd) {
				cmd = fr_command_alloc(talloc_ctx, insert, parents[i]);
				cmd->auto_allocated = true;
			}

			if (!cmd->intermediate) {
				fr_strerror_printf("Cannot add a subcommand to a pre-existing command.");
				return -1;
			}

			rad_assert(cmd->func == NULL);
			start = &(cmd->child);
		}

		if (i == CMD_MAX_ARGV) {
			fr_strerror_printf("Commands are too deep (max is %d)", CMD_MAX_ARGV);
			return -1;
		}
	}

	/*
	 *	@todo - check syntax, too!
	 *
	 *	i.e. we have a command "foo" which accepts syntax "bar
	 *	baz" we later try to add a command "foo bar" with
	 *	syntax "bad".  We don't find "bar" in the command
	 *	list, because it's buried inside of the syntax for
	 *	command "foo".  So we can have duplicate / conflicting
	 *	commands.
	 *
	 *	The simple answer, of course, is "don't do that".  The
	 *	harder solution is to check for it and error out.  But
	 *	we're lazy, so too bad.
	 */

	/*
	 *	Sanity check the syntax.
	 */
	if (table->syntax) {
		char *syntax = talloc_strdup(talloc_ctx, table->syntax);

		argc = fr_command_add_syntax(syntax, syntax, &syntax_argv);
		if (argc < 0) return -1;

		/*
		 *	Empty syntax should have table.syntax == NULL
		 */
		if (argc == 0) {
			talloc_free(syntax);
			fr_strerror_printf("Invalid empty string was supplied for syntax");
			return  -1;
		}

		if (argc == CMD_MAX_ARGV) {
			talloc_free(syntax);
			fr_strerror_printf("Too many arguments were supplied to the command.");
			return  -1;
		}

		/*
		 *	Handle top-level names.  The name is in the
		 *	syntax, not passed in to us.
		 */
		if (!name) {
			fr_cmd_argv_t *next;

			if (syntax_argv->type != FR_TYPE_FIXED) {
				talloc_free(syntax);
				fr_strerror_printf("Top-level commands MUST start with a fixed string.");
				return -1;
			}

			name = syntax_argv->name;
			next = syntax_argv->next;
			talloc_free(syntax_argv);
			syntax_argv = next;
			argc--;
		}
	}

	/*
	 *	"head" is now pointing to the list where we insert
	 *	this new command.  We now see if the "name" currently
	 *	exists.
	 */
	cmd = fr_command_find(start, name, &insert);

	/*
	 *	The command exists already.  We can't have TWO
	 *	commands of the same name, so it's likely an error.
	 */
	if (cmd) {
		/*
		 *	Not a callback, but an intermediary node.  We
		 *	can probably allow it.
		 */
		if (!table->func) {
			rad_assert(table->help != NULL);
			if (cmd->help != NULL) {
				fr_strerror_printf("Cannot change help for command %s %s",
						   table->parent, cmd->name);
				return -1;
			}
			rad_assert(cmd->intermediate);
			cmd->help = table->help;
			cmd->read_only = table->read_only;
			return 0;
		}

		if (!cmd->auto_allocated) {
			fr_strerror_printf("Cannot add duplicate command '%s'", cmd->name);
			return -1;
		}

		/*
		 *	Can't add new sub-commands to a
		 *	command which already has a
		 *	pre-defined syntax.
		 */
		if (!cmd->intermediate) {
			fr_strerror_printf("Cannot modify a pre-existing command '%s'", cmd->name);
			return -1;
		}

		/*
		 *	Convert the auto-allocated node to a
		 *	user-allocated one, and fill in the fields.
		 */
		cmd->auto_allocated = false;
	} else {
		/*
		 *	Allocate cmd and insert it into the current point.
		 */
		rad_assert(insert != NULL);
		cmd = fr_command_alloc(talloc_ctx, insert, name);
	}

	/*
	 *	@todo - strdup / memdup all of these??
	 *
	 *	Even tho "help" can be long.  TBH, memory is cheap.
	 *	But we really only need these dup'd for the test
	 *	suite.  For everything else, they can be static.
	 */

	cmd->ctx = ctx;
	cmd->help = table->help;
	cmd->func = table->func;

	cmd->intermediate = (cmd->func == NULL);

	cmd->tab_expand = table->tab_expand;
	cmd->read_only = table->read_only;

	if (syntax_argv) {
		cmd->syntax = table->syntax;
		cmd->syntax_argc = argc;
		cmd->syntax_argv = talloc_steal(cmd, syntax_argv);
	}

	cmd->live = true;

	return 0;
}


/**  Add multiple commands to the global command tree
 *
 *  e.g. for module "foo", add "show module foo", "set module foo",
 *  etc.
 *
 * @param talloc_ctx the talloc context
 * @param head pointer to the head of the table pointer.  Should point to NULL at the start.
 * @param name of the command to allocate
 * @param ctx for any callback function
 * @param table array of tables, terminated by "help == NULL"
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_command_add_multi(TALLOC_CTX *talloc_ctx, fr_cmd_t **head, char const *name, void *ctx, fr_cmd_table_t const *table)
{
	int i;

	for (i = 0; table[i].help != NULL; i++) {
		if (fr_command_add(talloc_ctx, head, name, ctx, &table[i]) < 0) return -1;
	}

	return 0;
}

/** A stack for walking commands.
 *
 */
typedef struct fr_cmd_stack_t {
	int		depth;
	char const     	**parents;
	fr_cmd_t	*entry[CMD_MAX_ARGV];
} fr_cmd_stack_t;


/**  Walk over a command hierarchy
 *
 * @param head the head of the hierarchy.  Call it with NULL to clean up `walk_ctx`
 * @param[in,out] walk_ctx to track across multiple function calls.  MUST point to a `void*` when starting
 * @param ctx for the callback
 * @param callback to call with fr_walk_info_t about each command
 * @return
 *	- <0 on error
 *	- 0 for nothing more to do.
 *	- 1 for "please call me again to get the next command".
 *	  and walk_ctx now points to data allocated by, and managed by this function.
 *	  It MUST be cleaned up via another call to this function.
 */
int fr_command_walk(fr_cmd_t *head, void **walk_ctx, void *ctx, fr_cmd_walk_t callback)
{
	int rcode;
	fr_cmd_stack_t *stack;
	fr_cmd_t *cmd = NULL;
	fr_cmd_walk_info_t info;

	if (!walk_ctx || !callback) {
		fr_strerror_printf("No walk_ctx or callback specified");
		return -1;
	}

	/*
	 *	Caller can tell us to stop walking by passing a NULL
	 *	"head" pointer after the first call.
	 */
	if (!head) {
		if (*walk_ctx) {
			stack = *walk_ctx;
		done:
			talloc_free(stack);
			*walk_ctx = NULL;
		}

		/*
		 *	If there's no "head", we just go "yeah, it's
		 *	fine..."
		 */
		return 0;
	}

	/*
	 *	Allocate a stack the first time we're called.  And
	 *	tell the caller to remember it so that we can keep
	 *	walking down the stack.
	 */
	if (!*walk_ctx) {
		stack = talloc_zero(NULL, fr_cmd_stack_t);
		stack->entry[0] = head;
		stack->depth = 0;
		*walk_ctx = stack;

		stack->parents = info.parents = talloc_zero_array(stack, char const *, CMD_MAX_ARGV);

		/*
		 *	If the head was auto-allocated, find the first
		 *	child which was user-defined.  Note that there
		 *	MUST be a child which is user-defined.
		 */
		if (head->auto_allocated) {
			cmd = head;

			while (cmd) {
				stack->entry[stack->depth] = cmd;

				/*
				 *	Finally a real child, stop.
				 */
				if (!cmd->auto_allocated) break;

				/*
				 *	This command was
				 *	auto-allocated, but it has no
				 *	real children which caused
				 *	that allocation.  What's that
				 *	all about?
				 */
				if (!cmd->child){
					fr_strerror_printf("Command '%s' has no children", cmd->name);
					return -1;
				}

				/*
				 *	One of the children MUST be real!
				 */
				info.parents[stack->depth] = cmd->name;
				stack->depth++;
				rad_assert(stack->depth < CMD_MAX_ARGV);
				cmd = cmd->child;
			}

			if (!cmd) {
				fr_strerror_printf("Failed to find real command on walk");
				return -1;
			}
		}

	} else {
		stack = *walk_ctx;
		info.parents = stack->parents;
	}


	/*
	 *	Grab this entry, which MUST exist.
	 */
	cmd = stack->entry[stack->depth];

	/*
	 *	Don't run the callback for auto-allocated entries.
	 */
	if (cmd->auto_allocated) goto check_child;

	/*
	 *	Fill in the structure.
	 */
	info.num_parents = stack->depth;
	info.name = cmd->name;
	info.syntax = cmd->syntax;
	info.help = cmd->help;

	/*
	 *	Run the callback, but only for user-defined commands.
	 */
	rcode = callback(ctx, &info);
	if (rcode <= 0) {
		talloc_free(stack);
		*walk_ctx = NULL;
		return rcode;
	}

check_child:
	/*
	 *	This command has children.  Go do those before running
	 *	the next command at the current level.
	 */
	if (cmd->child) {
		rad_assert(stack->depth < CMD_MAX_ARGV);
		info.parents[stack->depth] = cmd->name;
		stack->depth++;
		stack->entry[stack->depth] = cmd->child;

		/*
		 *	Skip auto-allocated children.
		 */
		if (cmd->child->auto_allocated) {
			cmd = cmd->child;
			goto check_child;
		}
		return 1;
	}

check_next:
	/*
	 *	Go to the next user-defined command at this level,
	 *	skipping any auto-allocated ones.
	 */
	cmd = cmd->next;
	if (cmd) {
		stack->entry[stack->depth] = cmd;
		return 1;
	}

	/*
	 *	At the top of the stack, see if we're done.
	 */
	if (stack->depth == 0) {
		if (!cmd) goto done;

		rad_assert(0 == 1);
	}

	/*
	 *	Done all of the commands at this depth, so we go up a
	 *	level and try to grab another command.
	 */
	stack->depth--;
	cmd = stack->entry[stack->depth];
	goto check_next;
}


/*
 *	This MAY be a partial match.  In which case walk down
 *	the current list, looking for commands which MAY
 *	match.
 */
static int fr_command_tab_expand_partial(fr_cmd_t *head, char const *partial, int max_expansions, char const **expansions)
{
	int i;
	size_t len;
	fr_cmd_t *cmd;

	len = strlen(partial);

	/*
	 *	We loop over 'cmd', but only increment 'i' if we found a matching command.
	 */
	for (i = 0, cmd = head; (i < max_expansions) && cmd != NULL; cmd = cmd->next) {
		if (strncmp(partial, cmd->name, len) != 0) continue;

		expansions[i++] = cmd->name;
	}

	return i;
}


static int fr_command_tab_expand_argv(TALLOC_CTX *ctx, fr_cmd_t *cmd, fr_cmd_info_t *info, char const *name, fr_cmd_argv_t *argv,
				      int max_expansions, char const **expansions)
{
	char const *p, *q;

	/*
	 *	If it's a real data type, run the defined callback to
	 *	expand it.
	 */
	if (argv->type < FR_TYPE_FIXED) {
		if (!cmd->tab_expand) {
			expansions[0] = argv->name;
			return 1;
		}

		return cmd->tab_expand(ctx, cmd->ctx, info, max_expansions, expansions);
	}

	/*
	 *	Don't expand "[foo]", instead see if we can expand the
	 *	"foo".
	 */
	if (argv->type == FR_TYPE_OPTIONAL) {
		return fr_command_tab_expand_argv(ctx, cmd, info, name, argv->child, max_expansions, expansions);
	}

	/*
	 *	Don't expand (foo|bar), instead see if we can expand
	 *	"foo" and "bar".
	 */
	if (argv->type == FR_TYPE_ALTERNATE) {
		int count, rcode;
		fr_cmd_argv_t *child;

		count = 0;
		for (child = argv->child; child != NULL; child = child->next) {
			if (count >= max_expansions) return count;

			rcode = fr_command_tab_expand_argv(ctx, cmd, info, name, child, max_expansions - count, &expansions[count]);
			if (!rcode) continue;

			count++;
		}

		return count;
	}

	rad_assert(argv->type == FR_TYPE_FIXED);

	/*
	 *	Not a full match, but we're at the last
	 *	keyword in the list.  Maybe it's a partial
	 *	match?
	 */
	for (p = name, q = argv->name;
	     (*p != '\0') && (*q != '\0');
	     p++, q++) {
		/*
		 *	Mismatch, can't expand.
		 */
		if (*p != *q) return 0;

		/*
		 *	Input is longer than string we're
		 *	trying to match.  We can't expand
		 *	that.
		 */
		if (p[1] && !q[1]) return 0;

		/*
		 *	Input is shorter than the string we're
		 *	trying to match.  Return the syntax
		 *	string as a suggested expansion.
		 *
		 *	@todo - return a string which is ALL
		 *	of the fixed strings.
		 *
		 *	e.g. "foo bar IPADDR". If they enter
		 *	"f<tab>", we should likely return "foo
		 *	bar", instead of just "foo".
		 */
		if (!p[1] && q[1]) {
			expansions[0] = argv->name;
			return 1;
		}
	}

	return 0;
}

/*
 *	We're at a leaf command, which has a syntax.  Walk down the
 *	syntax argv checking if it matches.  If we get a matching
 *	command, add that to the expansions array and return.  If we
 *	get a data type instead, do the callback to ask the caller to
 *	expand it.
 */
/*
 *	We're at a leaf command, which has a syntax.  Walk down the
 *	syntax argv checking if it matches.  If we get a matching
 *	command, add that to the expansions array and return.  If we
 *	get a data type instead, do the callback to ask the caller to
 *	expand it.
 */
static int fr_command_tab_expand_syntax(TALLOC_CTX *ctx, fr_cmd_t *cmd, int syntax_offset, fr_cmd_info_t *info,
					int max_expansions, char const **expansions)
{
	int rcode;
	fr_cmd_argv_t *argv = cmd->syntax_argv;

	rcode = fr_command_verify_argv(info, syntax_offset, info->argc - 1, info->argc - 1, &argv, false);
	if (rcode < 0) return -1;

	/*
	 *	We've found the last argv.  See if we need to expand it.
	 */
	return fr_command_tab_expand_argv(ctx, cmd, info, info->argv[syntax_offset + rcode], argv, max_expansions, expansions);
}


/** Get the commands && help at a particular level
 *
 * @param ctx talloc context for dynamically allocated expansions.  The caller should free it to free all expansions it created.
 *            Expansions added by this function are "const char *", and are managed by the command hierarchy.
 * @param head the head of the hierarchy.
 * @param info the structure describing the command to expand
 * @param max_expansions the maximum number of entries in the expansions array
 * @param expansions where the expansions will be stored.
 * @return
 *	- <0 on error
 *	- number of entries in the expansions array
 */
int fr_command_tab_expand(TALLOC_CTX *ctx, fr_cmd_t *head, fr_cmd_info_t *info, int max_expansions, char const **expansions)
{
	int i;
	fr_cmd_t *cmd, *start;

	if (!head) return 0;

	start = head;

	/*
	 *	Walk down the children until we find the correct
	 *	location.
	 */
	for (i = 0; i < info->argc; i++) {
		cmd = fr_command_find(&start, info->argv[i], NULL);

		/*
		 *	The command wasn't found in the list.  Walk
		 *	over the list AGAIN, doing tab expansions of
		 *	any partial matches.
		 */
		if (!cmd) {
			return fr_command_tab_expand_partial(start, info->argv[i], max_expansions, expansions);
		}

		if (cmd->intermediate) {
			rad_assert(cmd->child != NULL);
			start = cmd->child;
			continue;
		}

		if (!cmd->syntax) {
			if ((i + 1) == info->argc) return 0;

			return -1;
		}

		if (!cmd->live) return 0;

		/*
		 *	If there is a syntax, the command MUST be a
		 *	leaf node.
		 *
		 *	Skip the name
		 */
		rad_assert(cmd->func != NULL);
		return fr_command_tab_expand_syntax(ctx, cmd, i + 1, info, max_expansions, expansions);
	}

	cmd = start;

	/*
	 *	We've looked for "foo bar" and found it.  There should
	 *	be child commands under that hierarchy.  In which
	 *	case, show them as expansions.
	 */
	rad_assert(i == info->argc);
	rad_assert(cmd->child != NULL);

	for (i = 0, cmd = cmd->child; (i < max_expansions) && (cmd != NULL); i++, cmd = cmd->next) {
		expansions[i] = cmd->name;
	}

	return i;
}

/** Run a particular command
 *
 *  info->argc is left alone, as are all other fields.
 *  If you want to run multiple commands, call fr_command_clear(0, info)
 *  to zero out the relevant information.
 *
 * @param fp   where the output is sent
 * @param fp_err  where the error output is sent
 * @param info the structure describing the command to expand
 * @param read_only whether or not this command should be run in read-only mode.
 * @return
 *	- <0 on error
 *	- 0 the command was run successfully
 */
int fr_command_run(FILE *fp, FILE *fp_err, fr_cmd_info_t *info, bool read_only)
{
	int i, rcode;
	fr_cmd_t *cmd;
	fr_cmd_info_t my_info;

	cmd = NULL;

	/*
	 *	Asked to do nothing, do nothing.
	 */
	if (info->argc == 0) return 0;

	for (i = 0; i < info->argc; i++) {
		cmd = info->cmd[i];
		rad_assert(cmd != NULL);

		if (!cmd->read_only && read_only) {
			fr_strerror_printf("No permissions to run command '%s'", cmd->name);
			return -1;
		}

		if (!cmd->live) return 0;

		if (cmd->intermediate) continue;
		break;
	}

	if (!cmd) return 0;

	/*
	 *	Leaf nodes must have a callback.
	 */
	rad_assert(cmd->func != NULL);

	// @todo - add cmd->min_argc && cmd->max_argc, to track optional things, varargs, etc.

	/*
	 *	The arguments have already been verified by
	 *	fr_command_str_to_argv().
	 */
	my_info.argc = info->argc - i - 1;
	my_info.max_argc = info->max_argc - info->argc;
	my_info.runnable = true;
	my_info.argv = &info->argv[i + 1];
	my_info.box = &info->box[i + 1];
	rcode = cmd->func(fp, fp_err, cmd->ctx, &my_info);
	return rcode;
}


/** Get help text for a particular command.
 *
 * @param head the head of the hierarchy.
 * @param argc the number of arguments in argv
 * @param argv the arguments
 * @return
 *	- NULL on "no help text"
 *	- !NULL is the help text.  Do not free or access it.
 */
char const *fr_command_help(fr_cmd_t *head, int argc, char *argv[])
{
	int i;
	fr_cmd_t *cmd, *start;

	start = head;

	for (i = 0; i < argc; i++) {
		cmd = fr_command_find(&start, argv[i], NULL);
		if (!cmd) return NULL;

		if (!cmd->syntax && !cmd->func) {
			rad_assert(cmd->child != NULL);
			start = cmd->child;
			continue;
		}

		return cmd->help;
	}

	/*
	 *	Return intermediate node help, if that help exists.
	 */
	if (start) return start->help;

	return NULL;
}

static const char *tabs = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

static void fr_command_debug_node(FILE *fp, fr_cmd_t *cmd, int depth)
{
	fprintf(fp, "%.*s%s\n", depth, tabs, cmd->name);
	if (cmd->syntax) fprintf(fp, "%.*s  -> %s\n", depth, tabs, cmd->syntax);
	if (cmd->help) fprintf(fp,   "%.*s   ? %s\n", depth, tabs, cmd->help);
}

static void fr_command_debug_internal(FILE *fp, fr_cmd_t *head, int depth)
{
	fr_cmd_t *cmd;

	for (cmd = head; cmd != NULL; cmd = cmd->next) {
		fr_command_debug_node(fp, cmd, depth);
		if (cmd->child) {
			fr_command_debug_internal(fp, cmd->child, depth + 1);
		}
	}
}

void fr_command_debug(FILE *fp, fr_cmd_t *head)
{
	fr_command_debug_internal(fp, head, 0);
}


static void fr_command_list_node(FILE *fp, fr_cmd_t *cmd, int depth, char const **argv, int options)
{
	int i;

	for (i = 0; i < depth; i++) {
		fprintf(fp, "%s ", argv[i]);
	}

	if ((options & FR_COMMAND_OPTION_NAME) != 0) {
		fprintf(fp, ":");
	}

	if (!cmd->syntax) {
		fprintf(fp, "%s\n", cmd->name);
	} else {
		fprintf(fp, "%s\n", cmd->syntax);
	}

	if (cmd->help) {
		fprintf(fp, "\t%s\n", cmd->help);
	}
}

static void fr_command_list_internal(FILE *fp, fr_cmd_t *head, int depth, int max_depth, char const **argv, int options)
{
	fr_cmd_t *cmd;

	for (cmd = head; cmd != NULL; cmd = cmd->next) {
		if (cmd->child && ((depth + 1) < max_depth)) {
			argv[depth] = cmd->name;
			fr_command_list_internal(fp, cmd->child, depth + 1, max_depth, argv, options);
		} else {
			fr_command_list_node(fp, cmd, depth, argv, options);
		}
	}
}

void fr_command_list(FILE *fp, int max_depth, fr_cmd_t *head, int options)
{
	char const *argv[CMD_MAX_ARGV];

	if ((max_depth <= 0) || !head) return;
	if (max_depth > CMD_MAX_ARGV) max_depth = CMD_MAX_ARGV;

	if ((options & FR_COMMAND_OPTION_LIST_CHILD) != 0) {
		if (!head->child) {
			rad_assert(head->func != NULL);
			// @todo - skip syntax_argv as necessary
			fr_command_list_node(fp, head, 0, argv, options);
			return;
		}
		head = head->child;
	}

	fr_command_list_internal(fp, head, 0, max_depth, argv, options);
}


static int fr_command_verify_argv(fr_cmd_info_t *info, int start, int verify, int argc, fr_cmd_argv_t **argv_p, bool optional)
{
	char quote;
	int used = 0, rcode;
	fr_type_t type;
	fr_value_box_t *box, my_box;
	char const *name;
	fr_cmd_argv_t *argv = *argv_p;
	fr_cmd_argv_t *child;
	TALLOC_CTX *ctx = NULL;

redo:
	rad_assert(argv->type != FR_TYPE_ALTERNATE_CHOICE);

	/*
	 *	Don't eat too many arguments.
	 */
	if ((start + used) >= argc) {
		rad_assert(argv != NULL);

		/*
		 *	Skip trailing optional pieces.
		 */
		while (argv && (argv->type == FR_TYPE_OPTIONAL)) {
			argv = argv->next;
		}

		*argv_p = argv;
		return used;
	}

	/*
	 *	May be written to for things like
	 *	"combo_ipaddr".
	 */
	type = argv->type;
	name = info->argv[start + used];

	/*
	 *	Fixed strings.
	 *
	 *	Note that for optional parameters, we assume that they
	 *	always begin with fixed strings.
	 */
	if (type == FR_TYPE_FIXED) {
		if (strcmp(argv->name, info->argv[start + used]) != 0) {

			/*
			 *	This one didn't match, so we return
			 *	"no match", even if we consumed many
			 *	inputs.
			 */
			if (optional) return 0;

			return -1;
		}

		used++;
		goto next;
	}

	/*
	 *	Optional.  It's OK if there's no match.
	 */
	if (type == FR_TYPE_OPTIONAL) {
		child = argv->child;

		rcode = fr_command_verify_argv(info, start + used, verify, argc, &child, true);
		if (rcode < 0) return rcode;

		/*
		 *	No match, that's OK.  Skip it.
		 */
		if (rcode == 0) {
			goto next;
		}

		/*
		 *	We've used SOME of the input.
		 */
		used += rcode;

		/*
		 *	But perhaps not all of it.  If so, remember
		 *	how much we've used, and return that.
		 */
		if (child) {
			*argv_p = argv;
			return used;
		}

		/*
		 *	If we have used all of the optional thing, keep going.
		 */
		goto next;
	}

	/*
	 *	Try the alternates until we find a match.
	 */
	if (type == FR_TYPE_ALTERNATE) {
		child = NULL;

		for (child = argv->child; child != NULL; child = child->next) {
			fr_cmd_argv_t *sub;

			rad_assert(child->type == FR_TYPE_ALTERNATE_CHOICE);
			rad_assert(child->child != NULL);
			sub = child->child;

			rcode = fr_command_verify_argv(info, start + used, verify, argc, &sub, true);
			if (rcode <= 0) continue;

			/*
			 *	Only a partial match.  Return that.
			 */
			if (sub) {
				*argv_p = argv;
				return used + rcode;
			}

			used += rcode;
			goto next;
		}

		/*
		 *	We've gone through all of the alternates
		 *	without a match, that's an error.
		 */
		goto no_match;
	}

	rad_assert(type < FR_TYPE_FIXED);

	/*
	 *	Don't re-verify things we've already verified.
	 */
	if ((start + used) < verify) {
		used++;
		goto next;
	}

	quote = '\0';
	if (type == FR_TYPE_STRING) {
		if ((name[0] == '"') ||
		    (name[0] == '\'')) {
			quote = name[0];
		}
	}

	/*
	 *	Set up and/or cache value boxes
	 */
	if (info->box) {
		ctx = info->box;
		if (!info->box[start + used]) {
			info->box[start + used] = talloc_zero(ctx, fr_value_box_t);
		}

		box = info->box[start + used];
	} else {
		box = &my_box;
	}

	/*
	 *	Parse the data to be sure it's well formed.
	 */
	if (fr_value_box_from_str(ctx, box, &type,
				  NULL, name, -1, quote, true) < 0) {
		fr_strerror_printf("Failed parsing argument '%s' - %s",
				   name, fr_strerror());
		return -1;
	}

	if (box == &my_box) fr_value_box_clear(box);
	used++;

next:
	/*
	 *	Go to the next one, but only if we don't have varargs.
	 */
	if (!argv->next || (argv->next->type != FR_TYPE_VARARGS)) {
		argv = argv->next;
	}

	if (argv) {
		goto redo;
	}

	if ((start + used) < argc) {
no_match:
		fr_strerror_printf("No match for command %s", info->argv[start + used]);
		return -1;
	}

	*argv_p = NULL;
	return used;
}

/** Split a string in-place, updating argv[]
 *
 *  This function also respects the various data types (mostly).
 *  Strings can have quotes.  Nothing else can have quotes.
 *  Non-string data types are skipped and only parsed to data types by
 *  fr_command_run().
 *
 * @param head the head of the hierarchy.
 * @param info the structure describing the command to expand
 * @param str the string to split
 * @return
 *	- <0 on error.
 *	- total number of arguments in the argv[] array.  Always >= argc.
 */
int fr_command_str_to_argv(fr_cmd_t *head, fr_cmd_info_t *info, char *str)
{
	int i, argc, cmd_argc, syntax_argc;
	char *p;
	fr_cmd_t *cmd, *start;
	fr_cmd_argv_t *argv;

	if ((info->argc < 0) || (info->max_argc <= 0) || !str || !head) {
		fr_strerror_printf("Invalid arguments passed to parse routine.");
		return -1;
	}

	/*
	 *	Must have something to check.
	 */
	if (!head) {
		fr_strerror_printf("No commands to parse.");
		return -1;
	}

	p = str;
	info->runnable = false;

	/*
	 *	Split the input.
	 */
	for (i = info->argc; i < info->max_argc; i++) {
		int rcode;

		rcode = split(&p, &info->argv[i], false);
		if (rcode < 0) return -1;
		if (!rcode) break;
	}

	if (i == info->max_argc) {
	too_many:
		fr_strerror_printf("Too many arguments for command.");
		return -1;
	}

	argc = i;
	cmd_argc = -1;

	start = head;
	cmd = NULL;

	/*
	 *	Find the matching command.
	 */
	for (i = 0; i < argc; i++) {
		/*
		 *	Look for a child command.
		 */
		cmd = fr_command_find(&start, info->argv[i], NULL);
		if (!cmd) {
		no_such_command:
			fr_strerror_printf("No such command: %s", info->argv[i]);
			return -1;
		}

		if (!cmd->live) goto no_such_command;

		/*
		 *	Cache the command for later consumption.
		 */
		info->cmd[i] = cmd;

		/*
		 *	There's a child.  Go match it.
		 */
		if (cmd->intermediate) {
			rad_assert(cmd->child != NULL);
			rad_assert(cmd->func == NULL);
			start = cmd->child;
			continue;
		}

		rad_assert(cmd->func != NULL);
		cmd_argc = i;
		break;
	}

	/*
	 *	Walked the entire input without finding a runnable
	 *	command.  Ask for more input.
	 */
	if (i == argc) {
		info->argc = argc;
		return argc;
	}

	/*
	 *	Not found, that's an error.
	 */
	if (!cmd) return -1;

	rad_assert(cmd->func != NULL);
	rad_assert(cmd->child == NULL);
	rad_assert(cmd_argc >= 0);

	/*
	 *	Number of argv left, minus one for the command name.
	 */
	syntax_argc = (argc - i) - 1;

	/*
	 *	The command doesn't take any arguments.  Error out if
	 *	there are any.  Otherwise, return that the command is
	 *	runnable.
	 */
	if (!cmd->syntax) {
		if (syntax_argc > 0) {
			goto too_many;
		}

		info->runnable = true;
		info->argc = argc;
		return argc;
	}

	argv = cmd->syntax_argv;

	/*
	 *	If there are enough arguments to pass anything to the
	 *	command, and there are more arguments than we had on
	 *	input, do syntax checks on the new arguments.
	 */
	if ((argc > cmd_argc) && (argc > info->argc)) {
		int rcode;

		/*
		 *	This verifies the arguments, and updates argv
		 */
		rcode = fr_command_verify_argv(info, cmd_argc + 1, info->argc, argc, &argv, false);
		if (rcode < 0) return rcode;
	}

	info->runnable = (argv == NULL);
	info->argc = argc;
	return argc;
}

/** Clear out any value boxes etc.
 *
 * @param new_argc the argc to set inside of info
 * @param info the information with the current argc
 */
int fr_command_clear(int new_argc, fr_cmd_info_t *info)
{
	int i;

	if ((new_argc < 0) || (new_argc >= CMD_MAX_ARGV) ||
	    (new_argc > info->argc)) {
		fr_strerror_printf("Invalid argument");
		return -1;
	}

	if (new_argc == info->argc) return 0;

	for (i = new_argc; i < info->argc; i++) {
		if (info->box && info->box[i]) {
			fr_value_box_clear(info->box[i]);
		}
		if (info->cmd && info->cmd[i]) info->cmd[i] = NULL;
		info->argv[i] = NULL;
	}

	info->argc = new_argc;
	return 0;
}

/** Initialize an fr_cmd_info_t structure.
 *
 */
void fr_command_info_init(TALLOC_CTX *ctx, fr_cmd_info_t *info)
{
	memset(info, 0, sizeof(*info));

	info->argc = 0;
	info->max_argc = CMD_MAX_ARGV;
	info->argv = talloc_zero_array(ctx, char *, CMD_MAX_ARGV);
	info->box = talloc_zero_array(ctx, fr_value_box_t *, CMD_MAX_ARGV);
	info->cmd = talloc_zero_array(ctx, fr_cmd_t *, CMD_MAX_ARGV);
}


static int expand_thing(fr_cmd_argv_t *argv, int count, int max_expansions, char **expansions)
{
	fr_cmd_argv_t *child;

	if (count >= max_expansions) return count;

	if (argv->type == FR_TYPE_ALTERNATE) {
		child = NULL;

		for (child = argv->child; child != NULL; child = child->next) {
			fr_cmd_argv_t *sub;

			rad_assert(child->type == FR_TYPE_ALTERNATE_CHOICE);
			rad_assert(child->child != NULL);
			sub = child->child;

			count = expand_thing(sub, count, max_expansions, expansions);
		}

		return count;
	}

	if (argv->type == FR_TYPE_ALTERNATE) {
		for (child = argv->child; child != NULL; child = child->next) {
			fr_cmd_argv_t *sub;

			rad_assert(child->type == FR_TYPE_ALTERNATE_CHOICE);
			rad_assert(child->child != NULL);
			sub = child->child;

			count = expand_thing(sub, count, max_expansions, expansions);
		}

		return count;
	}

	/*
	 *	@todo - might want to do something smarter here?
	 */
	if (argv->type == FR_TYPE_OPTIONAL) {
		return expand_thing(argv->child, count, max_expansions, expansions);
	}

	if (argv->type != FR_TYPE_FIXED) return count;

	expansions[count] = strdup(argv->name);
	return count + 1;
}

static int expand_syntax(fr_cmd_argv_t *argv, char const *text, int start, char const **word_p,
			 int count, int max_expansions, char **expansions)
{
	char const *p, *q;
	char const *word = *word_p;

	/*
	 *	Loop over syntax_argv, looking for matches.
	 */
	for (/* nothing */ ; argv != NULL; argv = argv->next) {
		while (isspace((int) *word)) word++;

		if (!*word) {
		expand_syntax:
			return expand_thing(argv, count, max_expansions, expansions);
		}

		if (argv->type == FR_TYPE_VARARGS) return count;

		/*
		 *	Optional gets expanded, too.
		 */
		if (argv->type == FR_TYPE_OPTIONAL) {
			char const *my_word;

			my_word = word;

			count = expand_syntax(argv->child, text, start, &my_word, count, max_expansions, expansions);

			if (word != my_word) *word_p = word;
			continue;
		}

		if (argv->type == FR_TYPE_ALTERNATE) {
			fr_cmd_argv_t *child;

			for (child = argv->child; child != NULL; child = child->next) {
				fr_cmd_argv_t *sub;
				char const *my_word = word;

				rad_assert(child->type == FR_TYPE_ALTERNATE_CHOICE);
				rad_assert(child->child != NULL);
				sub = child->child;

				/*
				 *	See if the child eats any of
				 *	the input.  If so, use it.
				 */
				count = expand_syntax(sub, text, start, &my_word, count, max_expansions, expansions);
				if (my_word != word) {
					*word_p = word;
					break;
				}
			}

			continue;
		}

		/*
		 *	Handle quoted strings.
		 */
		if ((argv->type == FR_TYPE_STRING) &&
		    ((*word == '"') || (*word == '\''))) {
			char quote = *word++;

			while (*word && (*word != quote)) {
				if (*word == '\\') {
					if (!word[1]) return count;
					word++;
				}
				word++;
			}

			if (!*word || !isspace((int) *word)) return count;

			*word_p = word;
			continue;
		}

		/*
		 *	Skip data types (for now)
		 */
		if (argv->type < FR_TYPE_FIXED) {
			while (*word && !isspace((int) *word)) {
				word++;
			}

			if (!*word) return count;

			*word_p = word;
			continue;
		}

		/*
		 *	This should be the only remaining data type.
		 */
		rad_assert(argv->type == FR_TYPE_FIXED);

		/*
		 *	Try to find a matching argv
		 */
		p = word;
		q = argv->name;

		while (*p == *q) {
			p++;
			q++;
		}

		/*
		 *	We're supposed to expand the text at this
		 *	location, go do so.  Even if it doesn't match.
		 */
		if (((text + start) >= word) && ((text + start) <= p)) {
			goto expand_syntax;
		}

		/*
		 *	The only matching exit condition is *p is a
		 *	space, and *q is the NUL character.
		 */
		if (isspace((int) *p) && !*q) {
			*word_p = word;
			continue;
		}

		/*
		 *	No match, stop here.
		 */
		break;
	}

	*word_p = word;
	return count;
}


/** Do readline-style command completions
 *
 *  Most useful as part of readline tab expansions.  The expansions
 *  are strdup() strings, and MUST be free'd by the caller.
 *
 * @param head of the command tree
 * @param text the text to check
 * @param start offset in the text where the completions should start
 * @param max_expansions how many entries in the "expansions" array.
 * @param[in,out] expansions where the expansions are stored.
 * @return
 *	- <0 on error
 *	- >= 0 number of expansions in the array
 */
int fr_command_complete(fr_cmd_t *head, char const *text, int start,
			int max_expansions, char **expansions)
{
	char const *word, *p, *q;
	fr_cmd_t *cmd;
	int count;

	cmd = head;
	word = text;
	count = 0;

	/*
	 *	Try to do this without mangling "text".
	 */
	while (cmd) {
		while (isspace((int) *word)) word++;

		/*
		 *	End of the input.  Tab expand everything here.
		 */
		if (!*word) {
		expand:
			while (cmd && (count < max_expansions)) {
				expansions[count] = strdup(cmd->name);
				count++;
				cmd = cmd->next;
			}
			return count;
		}

		/*
		 *	Try to find a matching cmd->name
		 */
		p = word;
		q = cmd->name;

		while (*p == *q) {
			p++;
			q++;
		}

		/*
		 *	We're supposed to expand the text at this
		 *	location, go do so.  Even if it doesn't match.
		 */
		if (((text + start) >= word) && ((text + start) <= p)) {
			goto expand;
		}

		/*
		 *	The only matching exit condition is *p is a
		 *	space, and *q is the NUL character.
		 */
		if (!(isspace((int) *p) && !*q)) {
			cmd = cmd->next;
			continue;
		}

		if (cmd->intermediate) {
			rad_assert(cmd->child != NULL);
			word = p;
			cmd = cmd->child;
			continue;
		}

		/*
		 *	Skip the command name we matched.
		 */
		word = p;
		break;
	}

	/*
	 *	No match, can't do anything.
	 */
	if (!cmd) {
		return count;
	}

	/*
	 *	No syntax, can't do anything.
	 */
	if (!cmd->syntax) {
		return count;
	}

	return expand_syntax(cmd->syntax_argv, text, start, &word, count, max_expansions, expansions);
}

/** Do readline-style command completions
 *
 *  Most useful as part of readline tab expansions.  The expansions
 *  are strdup() strings, and MUST be free'd by the caller.
 *
 * @param fp where the help is printed
 * @param head of the command tree
 * @param text the text to check
 */
int fr_command_print_help(FILE *fp, fr_cmd_t *head, char const *text)
{
	char const *word, *p, *q;
	fr_cmd_t *cmd;

	cmd = head;
	word = text;

	/*
	 *	Try to do this without mangling "text".
	 */
	while (cmd) {
		while (isspace((int) *word)) word++;

		/*
		 *	End of the input.  Tab expand everything here.
		 */
		if (!*word) {
			while (cmd) {
				if (!cmd->help) {
					fprintf(fp, "%s\n", cmd->name);
				} else {
					fprintf(fp, "%-30s%s\n", cmd->name, cmd->help);
				}
				cmd = cmd->next;
			}
			return 0;
		}

		/*
		 *	Try to find a matching cmd->name
		 */
		p = word;
		q = cmd->name;

		while (*p == *q) {
			p++;
			q++;
		}

		/*
		 *	The only matching exit condition is *p is a
		 *	space, and *q is the NUL character.
		 */
		if (!(isspace((int) *p) && !*q)) {
			cmd = cmd->next;
			continue;
		}

		if (cmd->intermediate) {
			rad_assert(cmd->child != NULL);
			word = p;
			cmd = cmd->child;
			continue;
		}

		/*
		 *	Skip the command name we matched.
		 */
		break;
	}

	/*
	 *	No match, can't do anything.
	 */
	if (!cmd) {
		return 0;
	}

	if (!cmd->help) {
		fprintf(fp, "%s\n", cmd->name);
	} else {
		fprintf(fp, "%-30s%s\n", cmd->name, cmd->help);
	}

	return 0;
}
