#ifndef LRAD_TOKEN_H
#define LRAD_TOKEN_H

/*
 * token.h	Special tokens.
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2001  The FreeRADIUS server project
 */

typedef enum lrad_token_t {
  T_OP_INVALID = 0,		/* invalid token */
  T_EOL,			/* end of line */
  T_LCBRACE,			/* { */
  T_RCBRACE,			/* } */
  T_LBRACE,			/* ( */
  T_RBRACE,			/* ) */
  T_COMMA,			/* , */
  T_SEMICOLON,			/* ; */

  T_OP_ADD,			/* += */
  T_OP_SUB,			/* -= */
  T_OP_SET,			/* := */
  T_OP_EQ,			/* = */
  T_OP_NE,			/* != */
  T_OP_GE,			/* >= */
  T_OP_GT,			/* > */
  T_OP_LE,			/* <= */
  T_OP_LT,			/* < */
  T_OP_REG_EQ,			/* =~ */
  T_OP_REG_NE,			/* !~ */
  T_OP_CMP_TRUE,                /* =* */
  T_OP_CMP_FALSE,               /* !* */
  T_OP_CMP_EQ,			/* == */
  T_HASH,			/* # */
  T_BARE_WORD,			/* bare word */
  T_DOUBLE_QUOTED_STRING,	/* "foo" */
  T_SINGLE_QUOTED_STRING,	/* 'foo' */
  T_BACK_QUOTED_STRING,		/* `foo` */
  T_TOKEN_LAST
} LRAD_TOKEN;

#define T_EQSTART	T_OP_ADD
#define	T_EQEND		(T_OP_CMP_EQ + 1)

typedef struct LRAD_NAME_NUMBER {
	const char	*name;
	int		number;
} LRAD_NAME_NUMBER;

int lrad_str2int(const LRAD_NAME_NUMBER *table, const char *name, int def);
const char *lrad_int2str(const LRAD_NAME_NUMBER *table, int number,
			 const char *def);


int		getword (char **ptr, char *buf, int buflen);
int		getbareword (char **ptr, char *buf, int buflen);
LRAD_TOKEN	gettoken(char **ptr, char *buf, int buflen);

#endif /* LRAD_TOKEN_H */
