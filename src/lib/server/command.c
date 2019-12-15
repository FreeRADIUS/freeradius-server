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
 * @copyright 2018 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/command.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/rad_assert.h>

#include <freeradius-devel/util/misc.h>

/*
 *	Registration hooks for radmin.
 */
static int fr_command_register(UNUSED TALLOC_CTX *talloc_ctx, UNUSED char const *name, UNUSED void *ctx, UNUSED fr_cmd_table_t *table)
{
	return 0;
}

fr_command_register_hook_t fr_command_register_hook = fr_command_register;

typedef struct fr_cmd_argv_s fr_cmd_argv_t;
struct fr_cmd_argv_s {
	char const     		*name;
	fr_type_t		type;
	fr_cmd_argv_t		*next;
	fr_cmd_argv_t		*child;
};

struct fr_cmd_s {
	char const		*name;

	struct fr_cmd_s		*next;
	struct fr_cmd_s		*child;				//!< if there are subcommands

	char const		*syntax;			//!< only for terminal nodes
	char const		*help;				//!< @todo - long / short help

	fr_cmd_argv_t		*syntax_argv;			//!< arguments and types

	void			*ctx;
	fr_cmd_func_t		func;
	fr_cmd_tab_t		tab_expand;

	bool			read_only;
	bool			intermediate;			//!< intermediate commands can't have callbacks
	bool			live;				//!< is this entry live?
	bool			added_name;			//!< was this name added?
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
#define FR_TYPE_ALTERNATE_CHOICE FR_TYPE_GROUP

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
	cmd->read_only = true;
	*head = cmd;

	return cmd;
}


/*
 *	Validate a name (or syntax)
 *
 *	We have to be careful here, because some commands are taken
 *	from module names, which can be almost anything.
 */
static bool fr_command_valid_name(char const *name)
{
	uint8_t const *p;

	for (p = (uint8_t const *) name; *p != '\0'; p++) {
		if (*p < ' ') {
			fr_strerror_printf("Invalid control character in name");
			return false;
		}

		if (((*p >= ' ') && (*p <= ',')) ||
		    ((*p >= ':') && (*p <= '@')) ||
		    ((*p >= '[') && (*p <= '^')) ||
		    ((*p > 'z') && (*p <= 0xf7)) ||
		    (*p == '`')) {
			fr_strerror_printf("Invalid special character");
			return false;
		}

		/*
		 *	Allow valid UTF-8 characters.
		 */
		if (fr_utf8_char(p, -1)) continue;

		fr_strerror_printf("Invalid non-UTF8 character in name");
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

		type = fr_table_value_by_str(fr_value_box_type_table, argv->name, FR_TYPE_INVALID);
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
				}
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

static int fr_command_add_syntax(TALLOC_CTX *ctx, char *syntax, fr_cmd_argv_t **head, bool allow_varargs)
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
			if (!allow_varargs) {
				fr_strerror_printf("Varargs MUST NOT be in an [...] or (...) syntax.");
				return -1;
			}

			if (!prev || *p) {
				fr_strerror_printf("Varargs MUST be the last argument in the syntax list.");
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
			allow_varargs = false;

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

			/*
			 *	varargs can't be inside an optional block
			 */
			rcode = fr_command_add_syntax(option, option, &child, false);
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

				/*
				 *	varargs can't be inside an alternation block
				 */
				rcode = fr_command_add_syntax(option, word, &sub, false);
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
 * @param head pointer to the head of the command table.
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
	int argc = 0, depth = 0;
	fr_cmd_argv_t *syntax_argv;

	/*
	 *	This is a place-holder for tab expansion.
	 */
	if (!table->name) {
		fr_strerror_printf("A name MUST be specified.");
		return -1;
	}

	if (!name && table->add_name) {
		fr_strerror_printf("An additional name must be specified");
		return -1;
	}

	if (name && !fr_command_valid_name(name)) {
		return -1;
	}

	if (!fr_command_valid_name(table->name)) {
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
				cmd->live = true;
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

		depth = i;
	}

	/*
	 *	Add an intermediate name, e.g. "network X"
	 */
	if (table->add_name) {
		fr_cmd_t **added_insert;

		/*
		 *	See if we need to create the automatic
		 *	place-holder command for help text.
		 */
		cmd = fr_command_find(start, "STRING", &added_insert);
		if (!cmd) {
			cmd = fr_command_alloc(talloc_ctx, added_insert, "STRING");
		}

		/*
		 *	In the place-holders children, see if we need
		 *	to add this subcommand.
		 */
		cmd = fr_command_find(&(cmd->child), table->name, &added_insert);
		if (!cmd) {
			cmd = fr_command_alloc(talloc_ctx, added_insert, table->name);

			if (table->syntax) cmd->syntax = talloc_strdup(cmd, table->syntax);
			if (table->help) cmd->help = talloc_strdup(cmd, table->help);
		}

		/*
		 *	Now insert or add the extended name to the command hierarchy.
		 */
		cmd = fr_command_find(start, name, &insert);
		if (!cmd) {
			cmd = fr_command_alloc(talloc_ctx, insert, name);
			cmd->added_name = true;
			cmd->live = true;
		}

		start = &(cmd->child);
		depth++;
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
	 *
	 *	The simple solution is to create a command line from
	 *	the parents + name + syntax, and then look it up.  If
	 *	it's found, that's an error.
	 */

	/*
	 *	Sanity check the syntax.
	 */
	if (table->syntax) {
		char *syntax = talloc_strdup(talloc_ctx, table->syntax);

		argc = fr_command_add_syntax(syntax, syntax, &syntax_argv, true);
		if (argc < 0) return -1;

		/*
		 *	Empty syntax should have table.syntax == NULL
		 */
		if (argc == 0) {
			talloc_free(syntax);
			fr_strerror_printf("Invalid empty string was supplied for syntax");
			return  -1;
		}

		if ((depth + argc) >= CMD_MAX_ARGV) {
			talloc_free(syntax);
			fr_strerror_printf("Too many arguments were supplied to the command.");
			return  -1;
		}
	}

	/*
	 *	"head" is now pointing to the list where we insert
	 *	this new command.  We now see if the "name" currently
	 *	exists.
	 */
	cmd = fr_command_find(start, table->name, &insert);

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

			/*
			 *	Suppress duplicates.
			 */
			if (cmd->help == table->help) return 0;

			if (cmd->help != NULL) {
				fr_strerror_printf("Cannot change help for command %s",
						   cmd->name);
				return -1;
			}
			rad_assert(cmd->intermediate);
			cmd->help = table->help;
			cmd->read_only = table->read_only;
			return 0;
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
	} else {
		/*
		 *	Allocate cmd and insert it into the current point.
		 */
		rad_assert(insert != NULL);
		cmd = fr_command_alloc(talloc_ctx, insert, table->name);
	}

	/*
	 *	Assume that the commands are loaded from static
	 *	structures.
	 *
	 *	@todo - add "delete command" for unloading modules?
	 *	otherwise after a module is removed, the command
	 *	remains, and points to nothing.
	 */
	cmd->ctx = ctx;
	cmd->help = table->help;
	cmd->func = table->func;

	cmd->intermediate = (cmd->func == NULL);

	cmd->tab_expand = table->tab_expand;
	cmd->read_only = table->read_only;

	if (syntax_argv) {
		cmd->syntax = table->syntax;
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
 * @param head pointer to the head of the command table.
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
typedef struct {
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
	} else {
		stack = *walk_ctx;
		info.parents = stack->parents;
	}

	/*
	 *	Grab this entry, which MUST exist.
	 */
	cmd = stack->entry[stack->depth];

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

	/*
	 *	This command has children.  Go do those before running
	 *	the next command at the current level.
	 */
	if (cmd->child) {
		rad_assert(stack->depth < CMD_MAX_ARGV);
		info.parents[stack->depth] = cmd->name;
		stack->depth++;
		stack->entry[stack->depth] = cmd->child;
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

		if (!cmd->syntax_argv) {
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


/*
 *	Magic parsing macros
 */
#define SKIP_NAME(name) do { p = word; q = name; while (*p && *q && (*p == *q)) { \
				p++; \
				q++; \
			} } while (0)
#define MATCHED_NAME	((!*p || isspace((int) *p)) && !*q)
#define TOO_FAR		(*p && (*q > *p))
#define MATCHED_START	((text + start) >= word) && ((text + start) <= p)

static int fr_command_run_partial(FILE *fp, FILE *fp_err, fr_cmd_info_t *info, bool read_only, int offset, fr_cmd_t *head)
{
	int i, rcode;
	fr_cmd_t *start, *cmd = NULL;
	fr_cmd_info_t my_info;

	rad_assert(head->intermediate);
	rad_assert(head->child != NULL);

	start = head->child;

	/*
	 *	Wildcard '*' is at 'offset + 1'.  Then the command to run is at 'offset + 2'.
	 */
	rad_assert(info->argc >= (offset + 2));

	/*
	 *	Loop from "start", trying to find a matching command.
	 */
	for (i = offset + 1; i < info->argc; i++) {
		char const *p, *q, *word;

		/*
		 *	Re-parse the input because "*" only picked up
		 *	the first command, not the rest of them.
		 */
		for (cmd = start; cmd != NULL; cmd = cmd->next) {
			if (!cmd->live) continue;

			word = info->argv[i];
			SKIP_NAME(cmd->name);

			if (!MATCHED_NAME) continue;

			if (cmd->intermediate) {
				info->cmd[i] = cmd;
				start = cmd->child;
				break;
			}

			/*
			 *	Not an intermediate command, we've got
			 *	to run it.
			 */
			break;
		}

		/*
		 *	Not found, die.
		 */
		if (!cmd) return 0;

		/*
		 *	Ignore read-only on intermediate commands.
		 *	Some may have been automatically allocated
		 */
		if (cmd->intermediate) continue;
		break;
	}

	if (!cmd) return 0;

	if (!cmd->live) return 0;

	if (!cmd->read_only && read_only) {
		fprintf(fp_err, "No permissions to run command '%s'\n", cmd->name);
		return -1;
	}

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

		if (cmd->added_name && (info->argv[i][0] == '*')) {
			rad_assert(i > 0);

			for (; cmd != NULL; cmd = cmd->next) {
				if (!cmd->live) continue;

				fprintf(fp, "%s %s\n", info->argv[i - 1], cmd->name);
				info->argv[i] = cmd->name;
				rcode = fr_command_run_partial(fp, fp_err, info, read_only, i, cmd);
				if (rcode < 0) return rcode;
			}

			return 0;
		}

		/*
		 *	Ignore read-only on intermediate commands.
		 *	Some may have been automatically allocated
		 */
		if (cmd->intermediate) continue;
		break;
	}

	if (!cmd) return 0;

	if (!cmd->live) return 0;

	if (!cmd->read_only && read_only) {
		fprintf(fp_err, "No permissions to run command '%s' help %s\n", cmd->name, cmd->help);
		return -1;
	}

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

		if (cmd->intermediate) {
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
		fprintf(fp, "%s %s\n", cmd->name, cmd->syntax);
	}

	if (cmd->help && ((options & FR_COMMAND_OPTION_HELP) != 0)) {
		fprintf(fp, "\t%s\n", cmd->help);
	}
}

static void fr_command_list_internal(FILE *fp, fr_cmd_t *head, int depth, int max_depth, char const **argv, int options)
{
	fr_cmd_t *cmd;

	for (cmd = head; cmd != NULL; cmd = cmd->next) {
		if (cmd->added_name) continue;

		// We DO print out commands are !cmd->live

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

	argv[0] = NULL;		/* not sure what argv is doing here... */

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

static char const *skip_word(char const *text)
{
	char quote;
	char const *word = text;

	if ((*word != '"') && (*word != '\'')) {
		fr_skip_not_whitespace(word);
		return word;
	}

	quote = *word;
	word++;
	while (*word && (*word != quote)) {
		if (*word != '\\') {
			word++;
			continue;
		}

		word++;
		if (!*word) return NULL;
		word++;
	}

	return word;
}


/** Check the syntax of a command, starting at `*text`
 *
 *  Note that we don't keep a stack of where we are for partial
 *  commands.  So we MUST re-parse the ENTIRE input every time.
 */
static int syntax_str_to_argv(int start_argc, fr_cmd_argv_t *start, fr_cmd_info_t *info,
			      char const **text, bool *runnable)
{
	int argc = start_argc;
	int rcode;
	bool child_done;
	char const *word, *my_word, *p, *q;
	fr_cmd_argv_t *argv = start;
	fr_cmd_argv_t *child;

	word = *text;
	*runnable = false;

	while (argv) {
		fr_skip_whitespace(word);

		if (!*word) goto done;

		/*
		 *	Parse / check data types.
		 */
		if (argv->type < FR_TYPE_FIXED) {
			size_t len, offset;
			char quote, *str;
			fr_type_t type;

			p = skip_word(word);
			if (!p) {
				fr_strerror_printf("Invalid string");
				return -1;
			}

			/*
			 *	An already-parsed data type.  Skip it.
			 */
			if (argc < info->argc) {
				rad_assert(info->box[argc] != NULL);
				word = p;
				argc++;
				goto next;
			}

			/*
			 *	Non-strings MUST not be quoted.
			 */
			if ((argv->type != FR_TYPE_STRING) &&
			    ((*word == '"') || (*word == '\''))) {
				fr_strerror_printf("Invalid quoted string at %s", word);
				return -1;
			}

			len = p - word;
			if ((*word == '"') || (*word == '\'')) {
				quote = *word;
				offset = 1;
			} else {
				quote = 0;
				offset = 0;
			}

			type = argv->type;
			if (!info->box) {
				fr_strerror_printf("No array defined for values");
				return -1;
			}

			if (!info->box[argc]) {
				info->box[argc] = talloc_zero(info->box, fr_value_box_t);
			}

			rcode = fr_value_box_from_str(info->box[argc], info->box[argc],
						      &type, NULL,
						      word + offset, len - (offset << 1), quote, false);
			if (rcode < 0) return -1;

			/*
			 *	Note that argv[i] is the *input* string.
			 *
			 *	The called function MUST check box[i]
			 *	for the actual value.
			 */
			info->argv[argc] = str = talloc_memdup(info->argv, word + offset, len + 1);
			str[len] = '\0';

			word = p;
			argc++;
			goto next;
		}

		/*
		 *	Fixed strings.  We re-validate these for the
		 *	heck of it.
		 */
		if (argv->type == FR_TYPE_FIXED) {
			SKIP_NAME(argv->name);

			/*
			 *	End of input text before we matched
			 *	the whole command.
			 */
			if (!*p && *q) {
				fr_strerror_printf("Input is too short for command: %s", argv->name);
				return -1;
			}

			/*
			 *	The only matching exit condition is *p is a
			 *	space, and *q is the NUL character.
			 */
			if (!MATCHED_NAME) {
				fr_strerror_printf("Unknown command at: %s", p);
				return -1;
			}

			/*
			 *	Otherwise keep looking for the next option.
			 */
			info->argv[argc] = argv->name;
			info->cmd[argc] = NULL;
			// assume that the value box has already been cleared

			word = p;
			argc++;
			goto next;
		}

		/*
		 *	Evaluate alternates in sequence until one
		 *	matches.  If none match, that's an error.
		 */
		if (argv->type == FR_TYPE_ALTERNATE) {
			my_word = word;

			for (child = argv->child; child != NULL; child = child->next) {
				fr_cmd_argv_t *sub;

				rad_assert(child->type == FR_TYPE_ALTERNATE_CHOICE);
				rad_assert(child->child != NULL);
				sub = child->child;

				/*
				 *	This can fail on things like
				 *	"(INTEGER|IPADDR)" where
				 *	"192.168.0.1" is not a valid
				 *	INTEGER, but it is a valid IPADDR.
				 */
				rcode = syntax_str_to_argv(argc, sub, info, &my_word, &child_done);
				if (rcode <= 0) continue;

				goto skip_child;
			}

			/*
			 *	We've gone through all of the alternates
			 *	without a match, that's an error.
			 */
			fr_strerror_printf("No matching command for input string %s", word);
			return -1;
		}

		/*
		 *	Evaluate an optional argument.  If nothing
		 *	matches, that's OK.
		 */
		if (argv->type == FR_TYPE_OPTIONAL) {
			child = argv->child;
			my_word = word;

			rcode = syntax_str_to_argv(argc, child, info, &my_word, &child_done);
			if (rcode < 0) return rcode;

			/*
			 *	Didn't match anything, skip it.
			 */
			if (rcode == 0) goto next;

		skip_child:
			/*
			 *	We've eaten more input, remember that,
			 */
			argc += rcode;
			word = my_word;

			/*
			 *	We used only *part* of it.  We're done here.
			 */
			if (!child_done) {
				word = my_word;
				goto done;
			}

			goto next;
		}

		/*
		 *	Not done yet!
		 */
		fr_strerror_printf("Internal sanity check failed");
		return -1;

	next:
		/*
		 *	Go to the next one, but only if we don't have varargs.
		 */
		if (!argv->next || (argv->next->type != FR_TYPE_VARARGS)) {
			argv = argv->next;
		}
	}

done:
	/*
	 *	End of input.  Skip any trailing optional pieces.
	 */
	if (!*word) {
		while (argv && (argv->type == FR_TYPE_OPTIONAL)) argv = argv->next;
	}

	if (!argv) *runnable = true;
	*text = word;
	return (argc - start_argc);
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
 * @param text the string to split
 * @return
 *	- <0 on error.
 *	- total number of arguments in the argv[] array.  Always >= argc.
 */
int fr_command_str_to_argv(fr_cmd_t *head, fr_cmd_info_t *info, char const *text)
{
	int argc, rcode;
	char const *word, *p, *q;
	fr_cmd_t *cmd;

	if ((info->argc < 0) || (info->max_argc <= 0)) {
		fr_strerror_printf("argc / max_argc must be greater than zero");
		return -1;
	}

	if (!text) {
		fr_strerror_printf("No string to split.");
		return -1;
	}

	/*
	 *	Must have something to check.
	 */
	if (!head) {
		fr_strerror_printf("No commands to parse.");
		return -1;
	}

	info->runnable = false;
	cmd = head;
	word = text;

	/*
	 *	Double-check the commands we may have already parsed.
	 */
	for (argc = 0; argc < info->argc; argc++) {
		cmd = info->cmd[argc];
		rad_assert(cmd != NULL);

		fr_skip_whitespace(word);

		if ((word[0] == '*') && isspace(word[1]) && cmd->added_name) {
			p = word + 1;
			goto skip_matched;
		}

		SKIP_NAME(cmd->name);

		/*
		 *	The only matching exit condition is *p is a
		 *	space, and *q is the NUL character.
		 */
		if (!MATCHED_NAME) {
			goto invalid;
		}

skip_matched:
		word = p;

		if (!cmd->intermediate) {
			argc++;
			goto check_syntax;
		}
	}

	/*
	 *	If we've found a cached command, go parse it's
	 *	children.
	 */
	if ((argc > 0) && cmd->intermediate) {
		cmd = cmd->child;
	}

	/*
	 *	Search the remaining text for matching commands.
	 */
	while (cmd) {
		fr_skip_whitespace(word);

		/*
		 *	Skip commands which we shouldn't know about...
		 */
		if (!cmd->live) {
			cmd = cmd->next;
			continue;
		}

		/*
		 *	End of the input.  Tab expand everything here.
		 */
		if (!*word) {
			info->argc = argc;
			return argc;
		}

		/*
		 *	Double-check using the cached cmd.
		 */
		if (argc < info->argc) {
			cmd = info->cmd[argc];
			if (!cmd) {
				fr_strerror_printf("No cmd at offset %d", argc);
				goto invalid;
			}
		}

		/*
		 *	Allow wildcards as a primitive "for" loop in
		 *	some special circumstances.
		 */
		if ((word[0] == '*') && isspace(word[1]) && cmd->added_name) {
			rad_assert(cmd->intermediate);
			rad_assert(cmd->child != NULL);

			info->argv[argc] = "*";
			info->cmd[argc] = cmd;
			word++;
			cmd = cmd->child;
			argc++;
			continue;
		}

		SKIP_NAME(cmd->name);

		/*
		 *	The only matching exit condition is *p is a
		 *	space, and *q is the NUL character.
		 */
		if (!MATCHED_NAME) {
			if (argc < info->argc) {
			invalid:
				fr_strerror_printf("Invalid internal state");
				return -1;
			}

			/*
			 *	We're looking for "abc" and we found
			 *	"def".  We know that "abc" can't occur
			 *	any more, so stop.
			 */
			if (TOO_FAR) {
				cmd = NULL;
				break;
			}

			/*
			 *	Otherwise keep searching for it.
			 */
			cmd = cmd->next;
			continue;
		}

		if (cmd->intermediate) {
			rad_assert(cmd->child != NULL);
			info->argv[argc] = cmd->name;
			info->cmd[argc] = cmd;
			word = p;
			cmd = cmd->child;
			argc++;
			continue;
		}

		/*
		 *	Skip the command name we matched.
		 */
		word = p;
		info->argv[argc] = cmd->name;
		info->cmd[argc] = cmd;
		argc++;
		break;
	}

	if (argc == info->max_argc) {
	too_many:
		fr_strerror_printf("Too many arguments for command.");
		return -1;
	}

	/*
	 *	We've walked off of the end of the list without
	 *	finding anything.
	 */
	if (!cmd) {
		fr_strerror_printf("No such command: %s", word);
		return -1;
	}

	rad_assert(cmd->func != NULL);
	rad_assert(cmd->child == NULL);

check_syntax:
	/*
	 *	The command doesn't take any arguments.  Error out if
	 *	there are any.  Otherwise, return that the command is
	 *	runnable.
	 */
	if (!cmd->syntax_argv) {
		fr_skip_whitespace(word);

		if (*word > 0) goto too_many;

		info->runnable = true;
		info->argc = argc;
		return argc;
	}

	/*
	 *	Do recursive checks on the input string.
	 */
	rcode = syntax_str_to_argv(argc, cmd->syntax_argv, info, &word, &info->runnable);
	if (rcode < 0) return rcode;

	argc += rcode;

	/*
	 *	Run out of options to parse, but there's still more
	 *	input.
	 */
	if (!info->runnable && *word) {
		fr_skip_whitespace(word);
		if (*word) goto too_many;
	}

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
			talloc_const_free(info->argv[i]);
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
	MEM(info->argv = talloc_zero_array(ctx, char const *, CMD_MAX_ARGV));
	MEM(info->box = talloc_zero_array(ctx, fr_value_box_t *, CMD_MAX_ARGV));
	MEM(info->cmd = talloc_zero_array(ctx, fr_cmd_t *, CMD_MAX_ARGV));
}


static int expand_all(fr_cmd_t *cmd, fr_cmd_info_t *info, fr_cmd_argv_t *argv, int count, int max_expansions, char const **expansions)
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

			count = expand_all(cmd, info, sub, count, max_expansions, expansions);
		}

		return count;
	}

	if (argv->type == FR_TYPE_ALTERNATE) {
		for (child = argv->child; child != NULL; child = child->next) {
			fr_cmd_argv_t *sub;

			rad_assert(child->type == FR_TYPE_ALTERNATE_CHOICE);
			rad_assert(child->child != NULL);
			sub = child->child;

			count = expand_all(cmd, info, sub, count, max_expansions, expansions);
		}

		return count;
	}

	/*
	 *	@todo - might want to do something smarter here?
	 */
	if (argv->type == FR_TYPE_OPTIONAL) {
		return expand_all(cmd, info, argv->child, count, max_expansions, expansions);
	}

	if ((argv->type < FR_TYPE_FIXED) && cmd->tab_expand) {
		int rcode;

		info->argv[info->argc] = "";
		info->box[info->argc] = NULL;
		info->argc++;

		rad_assert(count == 0);
		rcode = cmd->tab_expand(NULL, cmd->ctx, info, max_expansions - count, expansions + count);
		if (rcode < 0) return rcode;

		return count + rcode;
	}

	expansions[count] = strdup(argv->name);
	return count + 1;
}

static int expand_syntax(fr_cmd_t *cmd, fr_cmd_info_t *info, fr_cmd_argv_t *argv, char const *text, int start,
			 char const **word_p, int count, int max_expansions, char const **expansions)
{
	char const *p, *q;
	char const *word = *word_p;

	/*
	 *	Loop over syntax_argv, looking for matches.
	 */
	for (/* nothing */ ; argv != NULL; argv = argv->next) {
		fr_skip_whitespace(word);

		if (!*word) {
			return expand_all(cmd, info, argv, count, max_expansions, expansions);
		}

		if (argv->type == FR_TYPE_VARARGS) return count;

		if (count >= max_expansions) return count;

		/*
		 *	Optional gets expanded, too.
		 */
		if (argv->type == FR_TYPE_OPTIONAL) {
			char const *my_word;

			my_word = word;

			count = expand_syntax(cmd, info, argv->child, text, start, &my_word, count, max_expansions, expansions);

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
				count = expand_syntax(cmd, info, sub, text, start, &my_word, count, max_expansions, expansions);
				if (my_word != word) {
					*word_p = word;
					break;
				}
			}

			continue;
		}

		/*
		 *	Check data types.
		 */
		if (argv->type < FR_TYPE_FIXED) {
			int rcode;
			size_t len, offset;
			char quote, *my_word;
			fr_type_t type = argv->type;

			p = skip_word(word);

			if (!p) return count;

			if (MATCHED_START) {
				if (!cmd->tab_expand) {
					/*
					 *	Partial word on input.
					 *	Tell the caller the
					 *	full name.
					 */
					if (!*p || (isspace((int) *p))) {
					expand_name:
						expansions[count] = strdup(argv->name);
						count++;
					}

					return count;
				}

				/*
				 *	Give the function the partial
				 *	text which should be expanded.
				 */
				info->argv[info->argc] = word;
				info->box[info->argc] = NULL;
				info->argc++;

				/*
				 *	Expand this thing.
				 */
				rad_assert(count == 0);
				rcode = cmd->tab_expand(NULL, cmd->ctx, info, max_expansions - count, expansions + count);
				if (rcode < 0) return rcode;
				return count + rcode;
			}

			len = p - word;

			info->argv[info->argc] = my_word = talloc_zero_array(info->argv, char, len + 1);
			memcpy(my_word, word, len);
			my_word[len] = '\0';

			if (!info->box[info->argc]) {
				info->box[info->argc] = talloc_zero(info->box, fr_value_box_t);
			}

			if ((*word == '"') || (*word == '\'')) {
				quote = *word;
				offset = 1;
			} else {
				quote = 0;
				offset = 0;
			}

			rcode = fr_value_box_from_str(info->box[info->argc], info->box[info->argc],
						      &type, NULL,
						      word + offset, len - (offset << 1), quote, false);
			if (rcode < 0) return -1;
			info->argc++;
			*word_p = word = p;
			continue;
		}

		/*
		 *	This should be the only remaining data type.
		 */
		rad_assert(argv->type == FR_TYPE_FIXED);

		SKIP_NAME(argv->name);

		/*
		 *	The only matching exit condition is *p is a
		 *	space, and *q is the NUL character.
		 */
		if (MATCHED_NAME) {
			*word_p = word = p;
			info->argv[info->argc] = word;
			info->box[info->argc] = NULL;
			info->argc++;
			continue;
		}

		/*
		 *	Ran off of the end of the input before
		 *	matching all of the name.  The input is a
		 *	PARTIAL match.  Go fill it in.
		 */
		if (!*p || isspace((int) *p)) {
			goto expand_name;
		}

		/*
		 *	No match, stop here.
		 */
		break;
	}

	/*
	 *	Ran out of words to match.
	 */
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
			int max_expansions, char const **expansions)
{
	char const *word, *p, *q;
	fr_cmd_t *cmd;
	int count;
	fr_cmd_info_t *info;

	cmd = head;
	word = text;
	count = 0;

	info = talloc_zero(head, fr_cmd_info_t);
	fr_command_info_init(head, info);

	/*
	 *	Try to do this without mangling "text".
	 */
	while (cmd) {
		fr_skip_whitespace(word);

		/*
		 *	Skip commands which we shouldn't know about...
		 */
		if (!cmd->live) {
			cmd = cmd->next;
			continue;
		}

		/*
		 *	End of the input.  Tab expand everything here.
		 */
		if (!*word) {
		expand:
			while (cmd && (count < max_expansions)) {
				if (!cmd->live) goto next;

				SKIP_NAME(cmd->name);

				/*
				 *	Matched all of the input to
				 *	part of cmd->name.
				 */
				if (!*p || isspace((int) *p)) {
					expansions[count] = strdup(cmd->name);
					count++;
				}

			next:
				cmd = cmd->next;
			}

			talloc_free(info);
			return count;
		}

		SKIP_NAME(cmd->name);

		/*
		 *	We're supposed to expand the text at this
		 *	location, go do so.  Even if it doesn't match.
		 */
		if (MATCHED_START) {
			goto expand;
		}

		/*
		 *	The only matching exit condition is *p is a
		 *	space, and *q is the NUL character.
		 */
		if (!MATCHED_NAME) {
			if (TOO_FAR) return count;

			cmd = cmd->next;
			continue;
		}

		if (cmd->intermediate) {
			rad_assert(cmd->child != NULL);
			word = p;
			cmd = cmd->child;
			info->argv[info->argc] = cmd->name;
			info->argc++;
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
		talloc_free(info);
		return count;
	}

	/*
	 *	No syntax, can't do anything.
	 */
	if (!cmd->syntax_argv) {
		talloc_free(info);
		return count;
	}

	count = expand_syntax(cmd, info, cmd->syntax_argv, text, start, &word, count, max_expansions, expansions);
	fr_command_clear(0, info);
	talloc_free(info);
	return count;
}

static void print_help(FILE *fp, fr_cmd_t *cmd)
{
	if (!cmd->help) {
		fprintf(fp, "%s\n", cmd->name);
	} else {
		fprintf(fp, "%-30s%s\n", cmd->name, cmd->help);
	}
}

/** Do readline-style help completions
 *
 *  Most useful as part of readline.
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
		fr_skip_whitespace(word);

		/*
		 *	End of the input.  Tab expand everything here.
		 */
		if (!*word) {
			while (cmd) {
				print_help(fp, cmd);
				cmd = cmd->next;
			}
			return 0;
		}

		/*
		 *	Try to find a matching cmd->name
		 */
		SKIP_NAME(cmd->name);

		/*
		 *	Matched part of the name.  Print out help for this one.
		 */
		if (!*p && *q) {
			print_help(fp, cmd);
		}

		/*
		 *	The only matching exit condition is *p is a
		 *	space, and *q is the NUL character.
		 */
		if (!MATCHED_NAME) {
			if (TOO_FAR) return 0;

			cmd = cmd->next;
			continue;
		}

		/*
		 *	Done the input, but not the commands.
		 */
		if (!*p) {
			break;
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

	/*
	 *	For one command, try to print out the syntax, as it's
	 *	generally more useful than the help.
	 */
	if (!cmd->syntax) {
		print_help(fp, cmd);
	} else {
		fprintf(fp, "%-30s%s\n", cmd->name, cmd->syntax);
	}

	return 0;
}

/* See if partial string matches a full string.
 *
 * @param word the partial word to match
 * @param name the name which "word" might match
 * @return
 *	- false if they do not match
 *	- true if "word" is a prefix of "name"
 *
 */
bool fr_command_strncmp(const char *word, const char *name)
{
	char const *p, *q;

	if (!*word) return true;

	SKIP_NAME(name);

	/*
	 *	If we're done P (partial or full), that's a match.
	 */
	return (*p == '\0');
}
