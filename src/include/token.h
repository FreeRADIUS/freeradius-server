/*
 * token.h	Special tokens.
 *
 * Version:	@(#)token.h  1.00  19-Jul-1999  miquels@cistron.nl
 *
 */

#define T_EOL		1
#define T_LCBRACE	2
#define T_RCBRACE	3
#define T_LBRACE	4
#define T_RBRACE	5
#define T_COMMA		6

#define T_EQSTART	7
#define T_OP_ADD	7
#define T_OP_SUB	8
#define T_OP_SET	9
#define T_OP_EQ		10
#define T_OP_NE		11
#define T_OP_GE		12
#define T_OP_GT		13
#define T_OP_LE		14
#define T_OP_LT		15
#define T_OP_REG_EQ    	16
#define T_OP_REG_NE    	17
#define T_EQEND		18

int	getword (char **ptr, char *buf, int buflen);
int	gettoken(char **ptr, char *buf, int buflen);

