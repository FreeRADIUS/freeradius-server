/*
 * parse.c		Parse a policy language
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2004  Alan DeKok <aland@ox.org>
 */

#include "rlm_policy.h"

/*
 *	Explanations of what the lexical tokens are.
 */
static const LRAD_NAME_NUMBER policy_explanations[] = {
	{ "invalid input", POLICY_LEX_BAD },
	{ "end of file", POLICY_LEX_EOF },
	{ "end of line", POLICY_LEX_EOL },
	{ "whitespace", POLICY_LEX_WHITESPACE },
	{ "hash mark", POLICY_LEX_HASH },
	{ "left bracket", POLICY_LEX_L_BRACKET },
	{ "right bracket", POLICY_LEX_R_BRACKET },
	{ "{", POLICY_LEX_LC_BRACKET },
	{ "}", POLICY_LEX_RC_BRACKET },
	{ "comma", POLICY_LEX_COMMA },
	{ "logical AND", POLICY_LEX_L_AND },
	{ "logical OR", POLICY_LEX_L_OR },
	{ "AND", POLICY_LEX_AND },
	{ "OR", POLICY_LEX_OR },
	{ "logical NOT", POLICY_LEX_L_NOT },
	{ "assignment", POLICY_LEX_ASSIGN },
	{ "comparison", POLICY_LEX_CMP_EQUALS },
	{ "comparison", POLICY_LEX_CMP_NOT_EQUALS },
	{ "comparison", POLICY_LEX_LT },
	{ "comparison", POLICY_LEX_GT },
	{ "comparison", POLICY_LEX_LE },
	{ "comparison", POLICY_LEX_GT },
	{ "comparison", POLICY_LEX_RX_EQUALS },
	{ "comparison", POLICY_LEX_RX_NOT_EQUALS },
	{ "double quoted string", POLICY_LEX_DOUBLE_QUOTED_STRING },
	{ "single quoted string", POLICY_LEX_SINGLE_QUOTED_STRING },
	{ "back quoted string", POLICY_LEX_BACK_QUOTED_STRING },
	{ "bare word", POLICY_LEX_BARE_WORD },

	{ NULL, -1 }
};


const LRAD_NAME_NUMBER rlm_policy_tokens[] = {
	{ "EOF", POLICY_LEX_EOF },
	{ "#", POLICY_LEX_HASH },
	{ "(", POLICY_LEX_L_BRACKET },
	{ ")", POLICY_LEX_R_BRACKET },
	{ "{", POLICY_LEX_LC_BRACKET },
	{ "}", POLICY_LEX_RC_BRACKET },
	{ ",", POLICY_LEX_COMMA },
	{ "&&", POLICY_LEX_L_AND },
	{ "||", POLICY_LEX_L_OR },
	{ "&", POLICY_LEX_AND },
	{ "|", POLICY_LEX_OR },
	{ "!", POLICY_LEX_L_NOT },
	{ "=", POLICY_LEX_ASSIGN },
	{ "==", POLICY_LEX_CMP_EQUALS },
	{ "!=", POLICY_LEX_CMP_NOT_EQUALS },
	{ "<", POLICY_LEX_LT },
	{ ">", POLICY_LEX_GT },
	{ "<=", POLICY_LEX_LE },
	{ ">=", POLICY_LEX_GT },
	{ "=~", POLICY_LEX_RX_EQUALS },
	{ "!~", POLICY_LEX_RX_NOT_EQUALS },
	{ ".=", POLICY_LEX_CONCAT_EQUALS },
	{ ":=", POLICY_LEX_SET_EQUALS },
	{ "double quoted string", POLICY_LEX_DOUBLE_QUOTED_STRING },
	{ "single quoted string", POLICY_LEX_SINGLE_QUOTED_STRING },
	{ "back quoted string", POLICY_LEX_BACK_QUOTED_STRING },
	{ "bare word", POLICY_LEX_BARE_WORD },

	{ NULL, -1 }
};


/*
 *	Hand-coded lexical analysis of a string.
 *	Handed input string, updates token, possible a decoded
 *	string in buffer, and returns the pointer to the next token.
 *
 *	Lexical tokens cannot cross a string boundary.
 */
static const char *policy_lex_string(const char *input,
				     policy_lex_t *token,
				     char *buffer, size_t buflen)
{
	rad_assert(input != NULL);

	if (buffer) *buffer = '\0';
	
	switch (*input) {
	case '\0':
		*token = POLICY_LEX_EOL;
		return NULL;	/* nothing more to do */
		
	case ' ':
	case '\t':
	case '\r':
	case '\n':
		/*
		 *	Skip over all of the whitespace in one swell foop.
		 */
		*token = POLICY_LEX_WHITESPACE;
		while ((*input == ' ') || (*input == '\t') ||
		       (*input == '\r') || (*input == '\n')) input++;
		return input;	/* point to next non-whitespace character */
		
	case '#':		/* ignore everything to the end of the line */
		*token = POLICY_LEX_EOL;
		return NULL;

	case '(':
		*token = POLICY_LEX_L_BRACKET;
		return input + 1;
		
	case ')':
		*token = POLICY_LEX_R_BRACKET;
		return input + 1;
		
	case '{':
		*token = POLICY_LEX_LC_BRACKET;
		return input + 1;
		
	case '}':
		*token = POLICY_LEX_RC_BRACKET;
		return input + 1;
		
	case ',':
		*token = POLICY_LEX_COMMA;
		return input + 1;

	case '+':
		switch (input[1]) {
		case '=':
			*token = POLICY_LEX_PLUS_EQUALS;
			input++;
			break;

		default:
			*token = POLICY_LEX_PLUS;
			break;
		}
		return input + 1;

	case '-':
		switch (input[1]) {
		case '=':
			*token = POLICY_LEX_MINUS_EQUALS;
			input++;
			break;

		default:
			*token = POLICY_LEX_MINUS;
			break;
		}
		return input + 1;

	case '.':
		if (input[1] == '=') {
			*token = POLICY_LEX_CONCAT_EQUALS;
			return input + 2;
		}
		*token = POLICY_LEX_BAD;
		return input + 1;

	case ':':
		if (input[1] == '=') {
			*token = POLICY_LEX_SET_EQUALS;
			return input + 2;
		}
		*token = POLICY_LEX_BAD;
		return input + 1;

	case '&':
		switch (input[1]) {
		case '&':
			*token = POLICY_LEX_L_AND;
			input++;
			break;

		case '=':
			*token = POLICY_LEX_AND_EQUALS;
			input++;
			break;

		default:
			*token = POLICY_LEX_AND;
		}
		return input + 1;
		
	case '|':
		switch (input[1]) {
		case '|':
			*token = POLICY_LEX_L_OR;
			input++;
			break;

		case '=':
			*token = POLICY_LEX_OR_EQUALS;
			input++;
			break;

		default:
			*token = POLICY_LEX_OR;
		}
		return input + 1;
		
	case '!':
		switch (input[1]) {
		case '~':
			input++;
			*token = POLICY_LEX_RX_NOT_EQUALS;
			break;

		case '*':
			input++;
			*token = POLICY_LEX_CMP_FALSE;
			break;

		default:
			*token = POLICY_LEX_L_NOT;
		}
		return input + 1;
		
	case '=':
		switch (input[1]) {
		case '=':
			input++;
			*token = POLICY_LEX_CMP_EQUALS;
			break;

		case '~':
			input++;
			*token = POLICY_LEX_RX_EQUALS;
			break;

		case '*':
			input++;
			*token = POLICY_LEX_CMP_TRUE;
			break;

		default:
			*token = POLICY_LEX_ASSIGN;
		}
		return input + 1;
		
	case '<':
		if (input[1] == '=') {
			input++;
			*token = POLICY_LEX_LE;
		} else {
			*token = POLICY_LEX_LT;
		}
		return input + 1;
		
	case '>':
		if (input[1] == '=') {
			input++;
			*token = POLICY_LEX_GE;
		} else {
			*token = POLICY_LEX_GT;
		}
		return input + 1;

	case '"':
		if (buflen < 2) {
			*token = POLICY_LEX_BAD;
			return input + 1;
		}
		
		input++;
		while (*input != '"') {
			/*
			 *	Strings can't pass EOL.
			 */
			if (!*input) {
				return POLICY_LEX_BAD;
			}

			*(buffer++) = *(input++);
			buflen--;
			
			/*
			 *	FIXME: Print more warnings?
			 */
			if (buflen == 1) {
				break;
			}
		}
		*buffer = '\0';
		
		*token = POLICY_LEX_DOUBLE_QUOTED_STRING;
		return input + 1; /* skip trailing '"' */

	default:		/* bare word */
		break;
	}

	/*
	 *	It's a bare word, with nowhere to put it.  Die.
	 */
	if (!buffer) {
		*token = POLICY_LEX_BAD;
		return input + 1;
	}
	
	/*
	 *	Getting one character is stupid.
	 */
	if (buflen < 2) {
		*token = POLICY_LEX_BAD;
		return input + 1;
	}
	
	/*
	 *	Bare words are [-a-zA-Z0-9.]+
	 */
	while (*input) {
		if (!(((*input >= '0') && (*input <= '9')) ||
		      ((*input >= 'a') && (*input <= 'z')) ||
		      ((*input >= 'A') && (*input <= 'Z')) ||
		      (*input == '-') || (*input == '.') ||
		      (*input == ':') || (*input == '_'))) {
			break;
		}
		*(buffer++) = *(input++);
		buflen--;
		
		/*
		 *	FIXME: Print more warnings?
		 */
		if (buflen == 1) {
			break;
		}
	}
	*buffer = '\0';
	
	*token = POLICY_LEX_BARE_WORD;
	return input;
}


/*
 *	We want to lexically analyze a file, so we need a wrapper
 *	around the lexical analysis of strings.
 */
typedef struct policy_lex_file_t {
	FILE		*fp;
	const char	*parse;
	const char	*filename;
	int		lineno;
	int		debug;
	rbtree_t	*policies;
	policy_lex_t	token;
	char		buffer[1024];
} policy_lex_file_t;


#define POLICY_LEX_FLAG_RETURN_EOL  (1 << 0)
#define POLICY_LEX_FLAG_PEEK        (1 << 1)
#define POLICY_LEX_FLAG_PRINT_TOKEN (1 << 2)

#define debug_tokens if (lexer->debug & POLICY_DEBUG_PRINT_TOKENS) printf

/*
 *	Function to return a token saying what it read, and possibly
 *	a buffer of the quoted string or bare word.
 */
static policy_lex_t policy_lex_file(policy_lex_file_t *lexer,
				    int flags,
				    char *mystring, size_t mystringlen)
{
	policy_lex_t token = POLICY_LEX_BARE_WORD; /* to prime it */

	if (lexer->debug & POLICY_DEBUG_PRINT_TOKENS) {
		flags |= POLICY_LEX_FLAG_PRINT_TOKEN;
	}

	if (!lexer->fp) {
		return POLICY_LEX_EOF;
	}

	/*
	 *	Starting off, the buffer needs to be primed.
	 */
	if (!lexer->parse) {
		lexer->parse = fgets(lexer->buffer,
				     sizeof(lexer->buffer),
				     lexer->fp);
		
		if (!lexer->parse) {
			return POLICY_LEX_EOF;
		}

		lexer->lineno = 1;
	} /* buffer is primed, read stuff */

	if (lexer->token != POLICY_LEX_BAD) {
		token = lexer->token;
		lexer->token = POLICY_LEX_BAD;
		return token;
	}

	/*
	 *	Ignore whitespace, and keep filling the buffer
	 */
	while (lexer->parse) {
		const char *next;

		next = policy_lex_string(lexer->parse, &token,
					 mystring, mystringlen);
		switch (token) {
		case POLICY_LEX_WHITESPACE: /* skip whitespace */
			lexer->parse = next;
			continue;

		case POLICY_LEX_EOL: /* read another line */
			lexer->parse = fgets(lexer->buffer,
					     sizeof(lexer->buffer),
					     lexer->fp);
			lexer->lineno++;
			if (flags & POLICY_LEX_FLAG_RETURN_EOL) {
				return POLICY_LEX_EOL;
			}
			break;	/* read another token */

		default:	/* return the token */
			if (!(flags & POLICY_LEX_FLAG_PEEK)) {
				lexer->parse = next;
			}
			if (flags & POLICY_LEX_FLAG_PRINT_TOKEN) {
				debug_tokens("[%s token %s] ",
					     (flags & POLICY_LEX_FLAG_PEEK) ? "peek " : "",
					     lrad_int2str(rlm_policy_tokens,
							  token, "?"));
			}
			return token;
			break;
		}
	} /* loop until EOF */

	/*
	 *	Close it for the user.
	 */
	fclose(lexer->fp);
	lexer->fp = NULL;

	return POLICY_LEX_EOF;
}


/*
 *	Push a token back onto the input.
 *
 *	FIXME: Push words, too?
 */
static int policy_lex_push_token(policy_lex_file_t *lexer,
				 policy_lex_t token)
{
	if (lexer->token != POLICY_LEX_BAD) {
		rad_assert(0 == 1);
		return 0;
	}

	lexer->token = token;
	return 1;
}


/*
 *	Forward declarations.
 */
static int parse_block(policy_lex_file_t *lexer, policy_item_t **tail);


/*
 *	Map reserved words to tokens, and vice versa.
 */
const LRAD_NAME_NUMBER policy_reserved_words[] = {
	{ "if", POLICY_RESERVED_IF },
	{ "else", POLICY_RESERVED_ELSE },
	{ "debug", POLICY_RESERVED_DEBUG },
	{ "print", POLICY_RESERVED_PRINT },
	{ "policy", POLICY_RESERVED_POLICY },
	{ "control", POLICY_RESERVED_CONTROL },
	{ "request", POLICY_RESERVED_REQUEST },
	{ "reply", POLICY_RESERVED_REPLY },
	{ "proxy-request", POLICY_RESERVED_PROXY_REQUEST },
	{ "proxy-reply", POLICY_RESERVED_PROXY_REPLY },
	{ NULL, POLICY_RESERVED_UNKNOWN }
};


/*
 *	print foo
 *	print "foo"
 */
static int parse_print(policy_lex_file_t *lexer, policy_item_t **tail)
{
	policy_lex_t token;
	char mystring[1024];
	policy_print_t *this;

	debug_tokens("[PRINT] ");

	this = rad_malloc(sizeof(*this));
	memset(this, 0, sizeof(*this));

	this->item.type = POLICY_TYPE_PRINT;
	this->item.lineno = lexer->lineno;

	token = policy_lex_file(lexer, 0, mystring, sizeof(mystring));
	if ((token != POLICY_LEX_BARE_WORD) &&
	    (token != POLICY_LEX_DOUBLE_QUOTED_STRING)) {
		fprintf(stderr, "%s[%d]: Bad print command\n",
			lexer->filename, lexer->lineno);
		return 0;
	}

	this->rhs_type = token;
	this->rhs = strdup(mystring);

	*tail = (policy_item_t *) this;
	
	return 1;
}


/*
 *	Parse debugging statements
 */
static int parse_debug(policy_lex_file_t *lexer, policy_item_t **tail)
{
	int rcode = 0;
	policy_lex_t token;
	char buffer[32];

	tail = tail;		/* -Wunused */

	token = policy_lex_file(lexer, 0, buffer, sizeof(buffer));
	if (token != POLICY_LEX_BARE_WORD) {
		fprintf(stderr, "%s[%d]: Bad debug command\n",
			lexer->filename, lexer->lineno);
		return 0;
	}

	if (strcasecmp(buffer, "none") == 0) {
		lexer->debug = POLICY_DEBUG_NONE;
		rcode = 1;

	} else if (strcasecmp(buffer, "peek") == 0) {
		lexer->debug |= POLICY_DEBUG_PEEK;
		rcode = 1;

	} else if (strcasecmp(buffer, "print_tokens") == 0) {
		lexer->debug |= POLICY_DEBUG_PRINT_TOKENS;
		rcode = 1;

	} else if (strcasecmp(buffer, "print_policy") == 0) {
		lexer->debug |= POLICY_DEBUG_PRINT_POLICY;
		rcode = 1;

	} else if (strcasecmp(buffer, "evaluate") == 0) {
		lexer->debug |= POLICY_DEBUG_EVALUATE;
		rcode = 1;
	}

	if (rcode) {
		token = policy_lex_file(lexer, POLICY_LEX_FLAG_RETURN_EOL,
					NULL, 0);
		if (token != POLICY_LEX_EOL) {
			fprintf(stderr, "%s[%d]: Expected EOL\n",
				lexer->filename, lexer->lineno);
			return 0;
		}
	} else {
		fprintf(stderr, "%s[%d]: Bad debug command \"%s\"\n",
			lexer->filename, lexer->lineno, buffer);
		return 0;
	}

	return 1;
}

/*
 * (foo == bar), with nested conditionals.
 */
static int parse_condition(policy_lex_file_t *lexer, policy_item_t **tail)
{
	int rcode;
	policy_lex_t token, compare;
	char lhs[256], rhs[256];
	policy_condition_t *this;

	token = policy_lex_file(lexer, 0, lhs, sizeof(lhs));
	if (token != POLICY_LEX_L_BRACKET) {
		fprintf(stderr, "%s[%d]: Expected '(', got \"%s\"\n",
			lexer->filename, lexer->lineno,
			lrad_int2str(rlm_policy_tokens, token, lhs));
		return 0;
	}

	this = rad_malloc(sizeof(*this));
	memset(this, 0, sizeof(*this));

	this->item.type = POLICY_TYPE_CONDITIONAL;
	this->item.lineno = lexer->lineno;

	token = policy_lex_file(lexer, 0, lhs, sizeof(lhs));
	switch (token) {
	case POLICY_LEX_L_BRACKET:
		if (!policy_lex_push_token(lexer, token)) {
			rlm_policy_free_item((policy_item_t *) this);
			return 0;
		}
		
		this->compare = POLICY_LEX_L_BRACKET;
		this->child_condition = POLICY_LEX_L_BRACKET;
		rcode = parse_condition(lexer, &(this->child));
		if (!rcode) {
			rlm_policy_free_item((policy_item_t *) this);
			return rcode;
		}
		break;

	case POLICY_LEX_L_NOT:
		this->compare = POLICY_LEX_L_NOT;
		debug_tokens("[NOT] ");

		/*
		 *	FIXME: allow !foo, !foo=bar, etc.
		 *
		 *	Maybe we should learn how to use lex && yacc?
		 */

		rcode = parse_condition(lexer, &(this->child));
		if (!rcode) {
			rlm_policy_free_item((policy_item_t *) this);
			return rcode;
		}
		break;

	case POLICY_LEX_BARE_WORD:
	case POLICY_LEX_DOUBLE_QUOTED_STRING:
		this->lhs_type = token;

		/*
		 *	Got word.  May just be test for existence.
		 */
		token = policy_lex_file(lexer, POLICY_LEX_FLAG_PEEK, NULL, 0);
		if (token == POLICY_LEX_R_BRACKET) {
			debug_tokens("[TEST %s] ", lhs);
			this->lhs = strdup(lhs);
			this->compare = POLICY_LEX_CMP_TRUE;
			break;
		}

		compare = policy_lex_file(lexer, 0, rhs, sizeof(rhs));
		switch (compare) {
		case POLICY_LEX_CMP_EQUALS:
		case POLICY_LEX_CMP_NOT_EQUALS:
		case POLICY_LEX_RX_EQUALS:
		case POLICY_LEX_RX_NOT_EQUALS:
		case POLICY_LEX_LT:
		case POLICY_LEX_GT:
		case POLICY_LEX_LE:
		case POLICY_LEX_GE:
			break;

		default:
			fprintf(stderr, "%s[%d]: Invalid operator \"%s\"\n",
				lexer->filename, lexer->lineno,
				lrad_int2str(rlm_policy_tokens, compare, rhs));
			rlm_policy_free_item((policy_item_t *) this);
			return 0;
		}

		token = policy_lex_file(lexer, 0, rhs, sizeof(rhs));
		if ((token != POLICY_LEX_BARE_WORD) &&
		    (token != POLICY_LEX_DOUBLE_QUOTED_STRING)) {
			fprintf(stderr, "%s[%d]: Unexpected rhs token\n",
				lexer->filename, lexer->lineno);
			rlm_policy_free_item((policy_item_t *) this);
			return 0;
		}
		debug_tokens("[COMPARE (%s %s %s)] ",
		       lhs, lrad_int2str(rlm_policy_tokens, compare, "?"), rhs);
		this->lhs = strdup(lhs);
		this->compare = compare;
		this->rhs_type = token;
		this->rhs = strdup(rhs);
		break;

	default:
		fprintf(stderr, "%s[%d]: Unexpected lhs token\n",
			lexer->filename, lexer->lineno);
		rlm_policy_free_item((policy_item_t *) this);
		return 0;
	}

	token = policy_lex_file(lexer, 0, NULL, 0);
	if (token != POLICY_LEX_R_BRACKET) {
		fprintf(stderr, "%s[%d]: Expected ')', got \"%s\"\n",
			lexer->filename, lexer->lineno,
			lrad_int2str(rlm_policy_tokens, token, "?"));
		rlm_policy_free_item((policy_item_t *) this);
		return 0;
	}

	/*
	 *	After the end of condition, we MAY have && or ||
	 */
	token = policy_lex_file(lexer, POLICY_LEX_FLAG_PEEK, NULL, 0);
	if ((token == POLICY_LEX_L_AND) || (token == POLICY_LEX_L_OR)) {
		token = policy_lex_file(lexer, 0, NULL, 0); /* skip over it */
		debug_tokens("[%s] ",
		       lrad_int2str(rlm_policy_tokens, token, "?"));
		this->child_condition = token;
		rcode = parse_condition(lexer, &(this->child));
		if (!rcode) {
			rlm_policy_free_item((policy_item_t *) this);
			return 0;
		}
	}

	*tail = (policy_item_t *) this;

	return 1;
}


/*
 *	if (...) {...}
 *	if (...) {...} else {...}
 *	if (...) {...} else if ...
 */
static int parse_if(policy_lex_file_t *lexer, policy_item_t **tail)
{
	int rcode;
	policy_lex_t token;
	char mystring[256];
	policy_if_t *this;

	debug_tokens("[IF] ");

	this = rad_malloc(sizeof(*this));
	memset(this, 0, sizeof(*this));

	this->item.type = POLICY_TYPE_IF;
	this->item.lineno = lexer->lineno;

	rcode = parse_condition(lexer, &(this->condition));
	if (!rcode) {
		rlm_policy_free_item((policy_item_t *) this);
		return rcode;
	}

	rcode = parse_block(lexer, &(this->if_true));
	if (!rcode) {
		rlm_policy_free_item((policy_item_t *) this);
		return rcode;
	}

	token = policy_lex_file(lexer, POLICY_LEX_FLAG_PEEK,
				mystring, sizeof(mystring));
	if ((token == POLICY_LEX_BARE_WORD) &&
	    (lrad_str2int(policy_reserved_words, mystring,
			  POLICY_RESERVED_UNKNOWN) == POLICY_RESERVED_ELSE)) {
		debug_tokens("[ELSE] ");
		token = policy_lex_file(lexer, 0, mystring, sizeof(mystring));

		token = policy_lex_file(lexer, POLICY_LEX_FLAG_PEEK,
					mystring, sizeof(mystring));
		if ((token == POLICY_LEX_BARE_WORD) &&
		    (lrad_str2int(policy_reserved_words, mystring,
				  POLICY_RESERVED_UNKNOWN) == POLICY_RESERVED_IF)) {
			token = policy_lex_file(lexer, 0,
						mystring, sizeof(mystring));
			rcode = parse_if(lexer, &(this->if_false));
		} else {
			rcode = parse_block(lexer, &(this->if_false));
		}
		if (!rcode) {
			rlm_policy_free_item((policy_item_t *) this);
			return rcode;
		}
	}

	debug_tokens("\n");

	/*
	 *	Empty "if" condition, don't even bother remembering
	 *	it.
	 */
	if (!this->if_true && !this->if_false) {
		debug_tokens("Discarding empty \"if\" statement at line %d\n",
			     this->item.lineno);
		rlm_policy_free_item((policy_item_t *) this);
		return 1;
	}

	*tail = (policy_item_t *) this;
	
	return 1;
}


/*
 *	Parse a named policy "policy foo {...}"
 */
static int parse_named_policy(policy_lex_file_t *lexer, policy_item_t **tail)
{
	int rcode;
	policy_lex_t token;
	char mystring[256];
	policy_named_t *this;
	DICT_ATTR *dattr;

	tail = tail;		/* -Wunused */

	debug_tokens("[POLICY] ");

	this = rad_malloc(sizeof(*this));
	memset(this, 0, sizeof(*this));

	this->item.type = POLICY_TYPE_NAMED_POLICY;
	this->item.lineno = lexer->lineno;

	token = policy_lex_file(lexer, 0, mystring, sizeof(mystring));
	if (token != POLICY_LEX_BARE_WORD) {
		fprintf(stderr, "%s[%d]: Expected policy name, got \"%s\"\n",
			lexer->filename, lexer->lineno,
			lrad_int2str(rlm_policy_tokens, token, "?"));
		rlm_policy_free_item((policy_item_t *) this);
		return 0;
	}

	dattr = dict_attrbyname(mystring);
	if (dattr) {
		fprintf(stderr, "%s[%d]: Invalid policy name \"%s\": it is already defined as a dictionary attribute\n",
			lexer->filename, lexer->lineno, mystring);
		rlm_policy_free_item((policy_item_t *) this);
		return 0;
	}

	rcode = parse_block(lexer, &(this->policy));
	if (!rcode) {
		rlm_policy_free_item((policy_item_t *) this);
		return rcode;
	}
	this->name = strdup(mystring);

	/*
	 *	And insert it into the tree of policies.
	 *
	 *	For now, policy names aren't scoped, they're global.
	 */
	if (!rlm_policy_insert(lexer->policies, this->name, this->policy)) {
		fprintf(stderr, "Failed to insert %s\n", this->name);
		rlm_policy_free_item((policy_item_t *) this);
		return 0;
	}
	free(this);		/* FIXME: shouldn't have allocated it... */

	/*
	 *	Do NOT add it into the list here!  The above insertion
	 *	will take care of freeing it if anything goes wrong...
	 */

	return 1;
}



/*
 *	Parse a reference to a named policy "call foo"
 */
static int parse_call(policy_lex_file_t *lexer, policy_item_t **tail,
		      const char *name)
{
	policy_lex_t token;
	policy_call_t *this;

	debug_tokens("[CALL] ");

	token = policy_lex_file(lexer, 0, NULL, 0);
	if (token != POLICY_LEX_L_BRACKET) {
		fprintf(stderr, "%s[%d]: Expected left bracket, got \"%s\"\n",
			lexer->filename, lexer->lineno,
			lrad_int2str(rlm_policy_tokens, token, "?"));
		return 0;
	}

	token = policy_lex_file(lexer, 0, NULL, 0);
	if (token != POLICY_LEX_R_BRACKET) {
		fprintf(stderr, "%s[%d]: Expected right bracket, got \"%s\"\n",
			lexer->filename, lexer->lineno,
			lrad_int2str(rlm_policy_tokens, token, "?"));
		return 0;
	}

	this = rad_malloc(sizeof(*this));
	memset(this, 0, sizeof(*this));

	this->item.type = POLICY_TYPE_CALL;
	this->item.lineno = lexer->lineno;

	this->name = strdup(name);

	*tail = (policy_item_t *) this;

	return 1;
}



/*
 *	Edit/update/replace an attribute list
 */
static int parse_attribute_block(policy_lex_file_t *lexer,
				 policy_item_t **tail,
				 policy_reserved_word_t where)
{
	policy_lex_t token;
	policy_attributes_t *this;
	char buffer[32];
	
	token = policy_lex_file(lexer, 0, buffer, sizeof(buffer));
	switch (token) {
	case POLICY_LEX_ASSIGN:
	case POLICY_LEX_SET_EQUALS:
	case POLICY_LEX_CONCAT_EQUALS:
		break;

	default:
		fprintf(stderr, "%s[%d]: Unexpected token %s\n",
			lexer->filename, lexer->lineno,
			lrad_int2str(rlm_policy_tokens, token, "?"));
		return 0;	/* unknown */
	}
	
	this = rad_malloc(sizeof(*this));
	memset(this, 0, sizeof(*this));

	this->item.type = POLICY_TYPE_ATTRIBUTE_LIST;
	this->item.lineno = lexer->lineno;
	this->where = where;
	this->how = token;

	if (!parse_block(lexer, &(this->attributes))) {
		rlm_policy_free_item((policy_item_t *) this);
		return 0;
	}

	*tail = (policy_item_t *) this;
	return 1;
}


/*
 *	Parse one statement.  'foo = bar', or 'if (...) {...}', or '{...}',
 *	and so on.
 */
static int parse_statement(policy_lex_file_t *lexer, policy_item_t **tail)
{
	int rcode;
	policy_reserved_word_t reserved;
	policy_lex_t token, assign;
	char lhs[256], rhs[256];
	policy_assignment_t *this;

	/*
	 *	See what kind of token we have.
	 */
	token = policy_lex_file(lexer, 0, lhs, sizeof(lhs));
	switch (token) {
	case POLICY_LEX_LC_BRACKET:
		rcode = parse_block(lexer, tail);
		if (!rcode) {
			return 0;
		}
		break;

	case POLICY_LEX_BARE_WORD:
		reserved = lrad_str2int(policy_reserved_words,
					lhs,
					POLICY_RESERVED_UNKNOWN);
		switch (reserved) {
		case POLICY_RESERVED_IF:
			if (parse_if(lexer, tail)) {
				return 1;
			}
			return 0;
			break;
			
		case POLICY_RESERVED_CONTROL:
		case POLICY_RESERVED_REQUEST:
		case POLICY_RESERVED_REPLY:
		case POLICY_RESERVED_PROXY_REQUEST:
		case POLICY_RESERVED_PROXY_REPLY:
			if (parse_attribute_block(lexer, tail,
						  reserved))
				return 1;
			return 0;
			break;
			
		case POLICY_RESERVED_DEBUG:
			if (parse_debug(lexer, tail)) {
				return 1;
			}
			return 0;
			break;
			
		case POLICY_RESERVED_PRINT:
			if (parse_print(lexer, tail)) {
				return 1;
			}
			return 0;
			break;
			
		case POLICY_RESERVED_POLICY:
			if (parse_named_policy(lexer, tail)) {
				return 1;
			}
			return 0;
			break;

		case POLICY_RESERVED_UNKNOWN: /* wasn't a reserved word */
			if (rlm_policy_find(lexer->policies, lhs)) {
				if (parse_call(lexer, tail, lhs)) {
					return 1;
				}
			}

			/*
			 *	Maybe include another file.
			 */
			if (strcasecmp(lhs, "include") == 0) {
				/*
				 *	FIXME: add stuff
				 */
			} else {

				const DICT_ATTR *dattr;
				
				/*
				 *	Bare words MUST be dictionary attributes
				 */
				
				dattr = dict_attrbyname(lhs);
				if (!dattr) {
					fprintf(stderr, "%s[%d]: Expected attribute name, got \"%s\"\n",
						lexer->filename, lexer->lineno, lhs);
					return 0;
				}
				debug_tokens("%s[%d]: Got attribute %s\n",
					     lexer->filename, lexer->lineno,
					     lhs);
			}
			break;
			
		default:
			fprintf(stderr, "%s[%d]: Unexpected reserved word \"%s\"\n",
				lexer->filename, lexer->lineno, lhs);
			return 0;
		} /* switch over reserved words */
		break;
		
		/*
		 *	Return from nested blocks.
		 */
	case POLICY_LEX_RC_BRACKET:
		policy_lex_push_token(lexer, token);
		return 2;	/* magic */

	case POLICY_LEX_EOF:	/* nothing more to do */
		return 3;

	default:
		fprintf(stderr, "%s[%d]: Unexpected %s\n",
			lexer->filename, lexer->lineno,
			lrad_int2str(policy_explanations,
				     token, "string"));
		break;
	}

	/*
	 *	Parse a bare statement.
	 */
	assign = policy_lex_file(lexer, 0, rhs, sizeof(rhs));
	switch (assign) {
	case POLICY_LEX_ASSIGN:
	case POLICY_LEX_SET_EQUALS:
	case POLICY_LEX_AND_EQUALS:
	case POLICY_LEX_OR_EQUALS:
	case POLICY_LEX_PLUS_EQUALS:
		break;

	default:
		fprintf(stderr, "%s[%d]: Unexpected assign %s\n",
			lexer->filename, lexer->lineno,
			lrad_int2str(policy_explanations,
				     assign, "string"));
		return 0;
	}

	this = rad_malloc(sizeof(*this));
	memset(this, 0, sizeof(*this));

	this->item.type = POLICY_TYPE_ASSIGNMENT;
	this->item.lineno = lexer->lineno;

	token = policy_lex_file(lexer, 0, rhs, sizeof(rhs));
	if ((token != POLICY_LEX_BARE_WORD) &&
	    (token != POLICY_LEX_DOUBLE_QUOTED_STRING)) {
		fprintf(stderr, "%s[%d]: Unexpected rhs %s\n",
			lexer->filename, lexer->lineno,
			lrad_int2str(policy_explanations,
				     token, "string"));
		rlm_policy_free_item((policy_item_t *) this);
		return 0;
	}
	this->rhs_type = token;
	this->rhs = strdup(rhs);

	token = policy_lex_file(lexer, POLICY_LEX_FLAG_RETURN_EOL,
				rhs, sizeof(rhs));
	if (token != POLICY_LEX_EOL) {
		fprintf(stderr, "%s[%d]: Expected EOL\n",
			lexer->filename, lexer->lineno);
		rlm_policy_free_item((policy_item_t *) this);
		return 0;
	}
	debug_tokens("[ASSIGN %s %s %s]\n",
	       lhs, lrad_int2str(rlm_policy_tokens, assign, "?"), rhs);

	/*
	 *	Fill in the assignment struct
	 */
	this->lhs = strdup(lhs);
	this->assign = assign;

	*tail = (policy_item_t *) this;

	return 1;
}


/*
 *	Parse block of statements.  The block has already been checked
 *	to begin with a '{'.
 */
static int parse_block(policy_lex_file_t *lexer, policy_item_t **tail)
{
	int rcode;
	policy_lex_t token;

	debug_tokens("[BLOCK] ");

	token = policy_lex_file(lexer, 0, NULL, 0);
	if (token != POLICY_LEX_LC_BRACKET) {
		fprintf(stderr, "%s[%d]: Expected '{'\n",
			lexer->filename, lexer->lineno);
		return 0;
	}

	rcode = 0;
	while ((rcode = parse_statement(lexer, tail)) != 0) {
		if (rcode == 2) {
			token = policy_lex_file(lexer, 0, NULL, 0);
			if (token != POLICY_LEX_RC_BRACKET) {
				fprintf(stderr, "%s[%d]: Expected '}'\n",
					lexer->filename, lexer->lineno);
				return 0;
			}
			return 1;
		}
		rad_assert(*tail != NULL);
		/* parse_statement must fill this in */
		if (*tail) tail = &((*tail)->next);
	}
	debug_tokens("\n");

	/*
	 *	Parse statement failed.
	 */
	return 0;
}


/*
 *	Parse data from a file into a policy language.
 */
int rlm_policy_parse(rlm_policy_t *inst, const char *filename)
{
	int rcode;
	FILE *fp;
	policy_lex_file_t mylexer, *lexer;
	policy_item_t *list = NULL, **tail;
	
	fp = fopen(filename, "r");
	if (!fp) {
		fprintf(stderr, "Failed to open %s: %s\n",
			filename, strerror(errno));
		return 0;
	}

	lexer = &mylexer;
	memset(lexer, 0, sizeof(*lexer));
	lexer->filename = filename;
	lexer->fp = fp;
	lexer->token = POLICY_LEX_BAD;
	lexer->parse = NULL;	/* initial input */
	lexer->policies = inst->policies;

	tail = &list;
	while ((rcode = parse_statement(lexer, tail)) != 0) {
		if (rcode > 1) break;

		if (*tail) tail = &((*tail)->next);
		fflush(stdout);
	} /* until EOF or error */

	if (rcode == 2) {
		fprintf(stderr, "%s[%d]: Unexpected '}'\n",
			lexer->filename, lexer->lineno);
		return 0;
	}

	if (rcode == 0) {
		fprintf(stderr, "Failed to parse %s\n", filename);
		rlm_policy_free_item((policy_item_t *) &list);
		return 0;
	}

	debug_tokens("--------------------------------------------------\n");
	if (lexer->debug & POLICY_DEBUG_PRINT_POLICY) rlm_policy_print(list);

	
	/*
	 *	Throw away the policy outside of functions.
	 *
	 *	FIXME: Do more syntax checks...
	 */
	rlm_policy_free_item((policy_item_t *) list);

	return 1;
}
