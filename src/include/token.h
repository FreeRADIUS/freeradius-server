#ifndef FR_TOKEN_H
#define FR_TOKEN_H

/*
 * @file token.h
 * @brief Tokenisation code and constants
 *
 * $Id$
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
 * Copyright 2001,2006  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSIDH(token_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef enum fr_token_t {
  T_OP_INVALID = 0,		/* invalid token */
  T_EOL,			/* end of line */
  T_LCBRACE,			/* { */
  T_RCBRACE,			/* } */
  T_LBRACE,			/* ( */
  T_RBRACE,			/* ) 		 5 */
  T_COMMA,			/* , */
  T_SEMICOLON,			/* ; */

  T_OP_ADD,			/* += */
  T_OP_SUB,			/* -= */
  T_OP_SET,			/* := 		10 */
  T_OP_EQ,			/* = */
  T_OP_NE,			/* != */
  T_OP_GE,			/* >= */
  T_OP_GT,			/* > */
  T_OP_LE,			/* <= 		15 */
  T_OP_LT,			/* < */
  T_OP_REG_EQ,			/* =~ */
  T_OP_REG_NE,			/* !~ */
  T_OP_CMP_TRUE,                /* =* */
  T_OP_CMP_FALSE,               /* !* 		20 */
  T_OP_CMP_EQ,			/* == */
  T_HASH,			/* # */
  T_BARE_WORD,			/* bare word */
  T_DOUBLE_QUOTED_STRING,	/* "foo" */
  T_SINGLE_QUOTED_STRING,	/* 'foo' 	25 */
  T_BACK_QUOTED_STRING,		/* `foo` */
  T_TOKEN_LAST
} FR_TOKEN;

#define T_EQSTART	T_OP_ADD
#define	T_EQEND		(T_OP_CMP_EQ + 1)

typedef struct FR_NAME_NUMBER {
	const char	*name;
	int		number;
} FR_NAME_NUMBER;

extern const FR_NAME_NUMBER fr_tokens[];

int fr_str2int(const FR_NAME_NUMBER *table, const char *name, int def);
int fr_substr2int(const FR_NAME_NUMBER *table, const char *name, int def, int len);
const char *fr_int2str(const FR_NAME_NUMBER *table, int number,
			 const char *def);


int		getword (const char **ptr, char *buf, int buflen);
int		getbareword (const char **ptr, char *buf, int buflen);
FR_TOKEN	gettoken(const char **ptr, char *buf, int buflen);
FR_TOKEN	getstring(const char **ptr, char *buf, int buflen);
const char	*fr_token_name(int);

#ifdef __cplusplus
}
#endif

#endif /* FR_TOKEN_H */
