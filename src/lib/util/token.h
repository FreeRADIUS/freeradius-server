#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Tokenisation code and constants
 *
 * This is mostly for the attribute filter and user files.
 *
 * @file src/lib/util/token.h
 *
 * @copyright 2001,2006 The FreeRADIUS server project
 */
RCSIDH(token_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/table.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum fr_token {
	T_INVALID = 0,			/* invalid token */
	T_EOL,				/* end of line */
	T_LCBRACE,			/* { */
	T_RCBRACE,			/* } */
	T_LBRACE,			/* ( */
	T_RBRACE,			/* ) 		 5 */
	T_COMMA,			/* , */
	T_SEMICOLON,			/* ; */

	T_OP_INCRM,			/* ++ */
	T_OP_ADD,			/* += */
	T_OP_SUB,			/* -=  		10 */
	T_OP_SET,			/* := */
	T_OP_EQ,			/* = */
	T_OP_NE,			/* != */
	T_OP_GE,			/* >= */
	T_OP_GT,			/* > 		15 */
	T_OP_LE,			/* <= */
	T_OP_LT,			/* < */
	T_OP_REG_EQ,			/* =~ */
	T_OP_REG_NE,			/* !~ */
	T_OP_CMP_TRUE,			/* =* 		20 */
	T_OP_CMP_FALSE,			/* !* */
	T_OP_CMP_EQ,			/* == */
	T_HASH,				/* # */
	T_BARE_WORD,			/* bare word */
	T_DOUBLE_QUOTED_STRING,		/* "foo" 	25 */
	T_SINGLE_QUOTED_STRING,		/* 'foo' */
	T_BACK_QUOTED_STRING,		/* `foo` */
	T_TOKEN_LAST
} FR_TOKEN;

#define T_EQSTART	T_OP_ADD
#define	T_EQEND		(T_OP_CMP_EQ + 1)

/** Macro to use as dflt
 *
 */
#define FR_TABLE_NOT_FOUND	INT32_MIN

extern fr_table_num_ordered_t const fr_tokens_table[];
extern size_t fr_tokens_table_len;
extern fr_table_num_sorted_t const fr_token_quotes_table[];
extern size_t fr_token_quotes_table_len;
extern const char *fr_tokens[];
extern const char fr_token_quote[];
extern const bool fr_assignment_op[];
extern const bool fr_equality_op[];
extern const bool fr_str_tok[];

int		getword (char const **ptr, char *buf, int buflen, bool unescape);
FR_TOKEN	gettoken(char const **ptr, char *buf, int buflen, bool unescape);
FR_TOKEN	getop(char const **ptr);
FR_TOKEN	getstring(char const **ptr, char *buf, int buflen, bool unescape);
char const	*fr_token_name(int);
ssize_t		fr_skip_string(char const *start, char const *end);

#ifdef __cplusplus
}
#endif
