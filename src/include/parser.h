#ifndef FR_PARSER_H
#define FR_PARSER_H

/*
 * parser.h	Structures and prototypes for parsing
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2013 Alan DeKok <aland@freeradius.org>
 */

RCSIDH(parser_h, "$Id$");

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_cond_t fr_cond_t;

typedef enum cond_op_t {
	COND_NONE = 0,
	COND_TRUE,
	COND_NOT = '!',
	COND_AND = '&',
	COND_OR = '|'
} cond_op_t;


/*
 *	Allow for the following structures:
 *
 *	FOO			no OP, RHS is NULL
 *	FOO OP BAR
 *	(COND)			no LHS/RHS, child is COND, child OP is TRUE
 *	(!(COND))		no LHS/RHS, child is COND, child OP is NOT
 *	(COND1 OP COND2)	no LHS/RHS, next is COND2, next OP is OP
 */
struct fr_cond_t {
	char		*lhs;
	char		*rhs;
	FR_TOKEN 	op;

	FR_TOKEN 	lhs_type;
	FR_TOKEN 	rhs_type;

	int		regex_i;

	cond_op_t	next_op;
	fr_cond_t	*next;
	cond_op_t	child_op;
	fr_cond_t  	*child;
};

ssize_t fr_condition_tokenize(TALLOC_CTX *ctx, const char *start, fr_cond_t **head, const char **error);

/*
 *	In xlat.c for now
 */
typedef struct xlat_exp xlat_exp_t;
ssize_t xlat_tokenize(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head,
		      const char **error);

#ifdef __cplusplus
}
#endif

#endif /* FR_PARSER_H */
