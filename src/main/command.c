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

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/command.h>
#include <freeradius-devel/rad_assert.h>

#define MAX_STACK	(32)

struct fr_cmd_t {
	struct fr_cmd_t		*next;
	struct fr_cmd_t		*child;				//!< if there are subcommands
	char const		*name;
	char const		*syntax;			//!< only for terminal nodes
	char const		*help;				//!< @todo - long / short help ala recli

	int			syntax_argc;			//!< syntax split out into arguments
	char const		*syntax_argv[CMD_MAX_ARGV];		//!< syntax split out into arguments
	fr_type_t		syntax_types[CMD_MAX_ARGV];		//!< types for each argument

	void			*ctx;
	fr_cmd_func_t		func;
	fr_cmd_tab_t		tab_expand;

	bool			read_only;
	bool			intermediate;			//!< intermediate commands can't have callbacks
	bool			auto_allocated;
};


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
		    (*p == '(') || (*p == ')') ||
		    (*p == '|') || (*p == '#')) {
			fr_strerror_printf("Invalid special character");
			return false;
		}
	}

	return true;
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
	char *argv[CMD_MAX_ARGV];
	char *syntax;
	fr_type_t types[CMD_MAX_ARGV];

	if (name && !fr_command_valid_name(name)) {
		return -1;
	}

	if (!name && !table->syntax) {
		fr_strerror_printf("Top-level commands MUST have a syntax");
		return -1;
	}

	if (!table->func) {
		fr_strerror_printf("Command tables MUST define a callback function.");
		return -1;
	}

	memset(argv, 0, sizeof(argv));
	memset(types, 0, sizeof(types));
	start = head;

	/*
	 *	If there are parent commands, ensure that entries for
	 *	them exist in the tree.  This check allows a table for
	 *	"foo" to add "show module foo", even if "show module"
	 *	does not yet exist.
	 */
	if (table->parents) {
		int i;

		for (i = 0; table->parents[i] != NULL; i++) {
			/*
			 *	Don't go too deep.
			 */
			if (i >= MAX_STACK) {
				fr_strerror_printf("Commands are too deep (max is %d)", MAX_STACK);
				return -1;
			}

			/*
			 *	Find the head command.  If found,
			 *	go downwards into the child command.
			 */
			cmd = fr_command_find(start, table->parents[i], &insert);
			if (cmd) {
				start = &(cmd->child);
				continue;
			}

			cmd = fr_command_alloc(talloc_ctx, insert, table->parents[i]);
			cmd->intermediate = true;
			cmd->auto_allocated = true;

			/*
			 *	The entry now exists, point "head"
			 *	to the child and recurse to the next
			 *	table.
			 */
			start = &(cmd->child);
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
		int i;

		syntax = talloc_strdup(talloc_ctx, table->syntax);

		argc = fr_dict_str_to_argv(syntax, argv, CMD_MAX_ARGV);

		/*
		 *	Empty syntax should be NULL
		 */
		if (argc == 0) {
			talloc_free(syntax);
			fr_strerror_printf("Invalid empty string was supplied for syntax");
			return  -1;
		}

		for (i = 0; i < argc; i++) {
			char *p;
			bool lowercase = false;
			bool uppercase = false;

			if (!fr_command_valid_name(argv[i])) {
				return -1;
			}

			for (p = argv[i]; *p != '\0'; p++) {
				if (isupper((int) *p)) uppercase = true;
				if (islower((int) *p)) lowercase = true;
			}

			/*
			 *	No alphabetical characters, that's a
			 *	problem.
			 */
			if (!uppercase && !lowercase) {
				fr_strerror_printf("Syntax command %d does not contain alphabetical characters", i);
				return -1;
			}

			/*
			 *	Mixed case is not allowed in a syntax.
			 */
			if (uppercase && lowercase) {
				fr_strerror_printf("Syntax command %d has invalid mixed case", i);
				return -1;
			}

			/*
			 *	All-uppercase words MUST be valid data
			 *	types.
			 */
			if (uppercase) {
				fr_type_t type;

				type = fr_str2int(dict_attr_types, argv[i], FR_TYPE_INVALID);
				if (type == FR_TYPE_INVALID) {
					fr_strerror_printf("Syntax command %d has unknown data type", i);
					return -1;
				}

				types[i] = type;
			} else {
				types[i] = FR_TYPE_INVALID;
			}
		}

		/*
		 *	Handle top-level names.
		 */
		if (!name) {
			if (types[0] != FR_TYPE_INVALID) {
				talloc_free(syntax);
				fr_strerror_printf("Top-level commands MUST NOT start with a data type");
				return -1;
			}

			name = argv[0];
			for (i = 0; i < (argc - 1); i++) {
				argv[i] = argv[i + 1];
				types[i] = types[i + 1];
			}

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
			rad_assert(cmd->help == NULL);
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
		if (cmd->syntax) {
			fr_strerror_printf("Cannot change syntax of existing command '%s'", cmd->name);
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
	cmd->tab_expand = table->tab_expand;
	cmd->read_only = table->read_only;

	if (table->syntax && (argc > 0)) {
		cmd->syntax = table->syntax;
		(void) talloc_steal(cmd, syntax);
		cmd->syntax_argc = argc;
		memcpy(cmd->syntax_argv, argv, sizeof(cmd->syntax_argv));
		memcpy(cmd->syntax_types, types, sizeof(cmd->syntax_types));
	}

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
	fr_cmd_t	*entry[32];
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
				rad_assert(stack->depth < MAX_STACK);
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
		rad_assert(stack->depth < MAX_STACK);
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
	int i;
	char *p;
	char const *q;

	/*
	 *	If there are more input arguments than this command
	 *	has, then we can't do tab expansions.
	 *
	 *	@todo - allow for varargs
	 */
	if (info->argc > (syntax_offset + cmd->syntax_argc)) {
		return 0;
	}

	/*
	 *	Double-check intermediate strings, but skip
	 *	intermediate data types.
	 */
	for (i = syntax_offset; i < (info->argc - 1); i++) {
		int j = i - syntax_offset;

		if (cmd->syntax_types[j] != FR_TYPE_INVALID) continue;

		if (strcmp(info->argv[i], cmd->syntax_argv[j]) != 0) return -1;
	}

	/*
	 *	If it's a real data type, run the defined callback to
	 *	expand it.
	 */
	if (cmd->syntax_types[i - syntax_offset] != FR_TYPE_INVALID) {
		if (!cmd->tab_expand) {
			expansions[0] = cmd->syntax_argv[i - syntax_offset];
			return 1;
		}

		return cmd->tab_expand(ctx, cmd->ctx, info, max_expansions, expansions);
	}

	/*
	 *	Not a full match, but we're at the last
	 *	keyword in the list.  Maybe it's a partial
	 *	match?
	 *
	 *	@todo - allow for (a|b) in syntax,
	 *	which means creating a tree of allowed
	 *	syntaxes.  <sigh>
	 */
	for (p = info->argv[i], q = cmd->syntax_argv[i - syntax_offset];
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
			expansions[0] = cmd->syntax_argv[i - syntax_offset];
			return 1;
		}
	}

	return 0;
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

		start = cmd;

		/*
		 *	If there is a syntax, the command MUST be a
		 *	leaf node.
		 */
		if (cmd->syntax) {
			/*
			 *	Skip the name
			 */
			rad_assert(cmd->child == NULL);
			return fr_command_tab_expand_syntax(ctx, cmd, i + 1, info, max_expansions, expansions);
		}

		rad_assert(cmd->child != NULL);
		start = cmd->child;
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
 * @param fp   where the output is sent
 * @param head the head of the command hierarchy.
 * @param info the structure describing the command to expand
 * @return
 *	- <0 on error
 *	- 0 the command was run successfully
 */
int fr_command_run(FILE *fp, fr_cmd_t *head, fr_cmd_info_t *info)
{
	int i;
	fr_cmd_t *cmd, *start;

	start = head;

	/*
	 *	Asked to do nothing, do nothing.
	 */
	if (info->argc == 0) return 0;

	for (i = 0; i < info->argc; i++) {
		int rcode;
		fr_cmd_info_t my_info;

		cmd = fr_command_find(&start, info->argv[i], NULL);
		if (!cmd) {
			if (info->argc == 1) {
				fr_strerror_printf("No such command '%s'", info->argv[i]);
			} else {
				fr_strerror_printf("No such command '... %s'", info->argv[i]);
			}
			return -1;
		}

		if (!cmd->syntax) {
			if (cmd->func) {
				if (info->argc > (i + 1)) {
					fr_strerror_printf("Input has too many parameters for command.");
					return -1;
				}

				goto run;
			}

			rad_assert(cmd->child != NULL);
			start = cmd->child;
			continue;
		}

		/*
		 *	Too many or too few commands.  That's an
		 *	error.
		 *
		 *	@todo - allow varargs
		 *	@todo - return which argument was broken?
		 */
		if (info->argc != (i + 1 + cmd->syntax_argc)) {
			fr_strerror_printf("Input has too many or too few parameters for command");
			return -1;
		}

		/*
		 *	The arguments have already been verified by
		 *	fr_command_str_to_argv().
		 */
	run:
		my_info.argc = info->argc - i - 1;
		my_info.max_argc = info->max_argc - info->argc;
		my_info.runnable = true;
		my_info.argv = &info->argv[i + 1];
		my_info.box = &info->box[i + 1];
		rcode = cmd->func(fp, cmd->ctx, &my_info);

		// @todo - clean up value boxes, too!
		info->argc = 0;
		return rcode;
	}

	return 0;
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

static int split(char **input, char **output)
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
	 */
	if ((*str == '"') || (*str == '\'')) {
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
	if (*str) *(str++) = '\0';

	*input = str;
	*output = word;
	return 1;
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

	if ((info->argc < 0) || (info->max_argc <= 0) || !str) {
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

		rcode = split(&p, &info->argv[i]);
		if (rcode < 0) return -1;
		if (!rcode) break;
	}

	if (i == info->max_argc) {
		fprintf(stderr, "HERE %d\n", __LINE__);
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
			fr_strerror_printf("No matching command: %s", info->argv[i]);
			return -1;
		}

		/*
		 *	There's a child.  Go match it.
		 */
		if (cmd->child) {
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
			fprintf(stderr, "HERE %d\n", __LINE__);
			goto too_many;
		}

		info->runnable = true;
		info->argc = argc;
		return argc;
	}

	/*
	 *	Too many arguments for the command.  That's an error.
	 *
	 *	@todo - allow varargs
	 */
	if (syntax_argc > cmd->syntax_argc) {
		fprintf(stderr, "HERE %d - %d > %d\n", __LINE__, syntax_argc, cmd->syntax_argc);
		goto too_many;
	}

	/*
	 *	If there are enough arguments to pass anything to the
	 *	command, and there are more arguments than we had on
	 *	input, do syntax checks on the new arguments.
	 */
	if ((argc > cmd_argc) && (argc > info->argc)) {
		int start_argc;

		/*
		 *	Start checking at the first argument.  But
		 *	skip the arguments we were given on input.
		 */
		start_argc = cmd_argc + 1;
		if (start_argc < info->argc) start_argc = info->argc;

		for (i = start_argc; i < argc; i++) {
			int j;
			char quote;
			fr_type_t type;
			fr_value_box_t box;

			/*
			 *	Offset from the argument after the command.
			 */
			j = i - (cmd_argc + 1);

			/*
			 *	May be written to for things like
			 *	"combo_ipaddr".
			 */
			type = cmd->syntax_types[j];

			if (type == FR_TYPE_INVALID) {
				continue;
			}

			quote = '\0';
			if (type == FR_TYPE_STRING) {
				if ((info->argv[i][0] == '"') ||
				    (info->argv[i][0] == '\'')) {
					quote = info->argv[i][0];
				}
			}

			/*
			 *	Parse the data to be sure it's well formed.
			 */
			if (fr_value_box_from_str(NULL, &box, &type,
						  NULL, info->argv[i], -1, quote, true) < 0) {
				fr_strerror_printf("Failed parsing argument %d - %s",
						   i, fr_strerror());
				return -1;
			}

			fr_value_box_clear(&box);
		}
	}

	/*
	 *	Too few arguments to run the command.
	 */
	if (syntax_argc < cmd->syntax_argc) {
		info->argc = argc;
		return argc;
	}

	/*
	 *	It's just right.
	 */
	info->runnable = true;
	info->argc = argc;
	return argc;
}
