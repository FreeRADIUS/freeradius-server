/*
 * token.h	Special tokens.
 *
 * $Id$
 *
 */

#define T_EOL		1
#define T_LCBRACE	2	/* { */
#define T_RCBRACE	3	/* } */
#define T_LBRACE	4	/* ( */
#define T_RBRACE	5	/* ) */
#define T_COMMA		6	/* , */
#define T_SEMICOLON	7	/* ; */

#define T_EQSTART	8
#define T_OP_ADD	8	/* += */
#define T_OP_SUB	9	/* -= */
#define T_OP_SET	10	/* := */
#define T_OP_EQ		11	/* = */
#define T_OP_NE		12	/* != */
#define T_OP_GE		13	/* >= */
#define T_OP_GT		14	/* > */
#define T_OP_LE		15	/* <= */
#define T_OP_LT		16	/* < */
#define T_OP_REG_EQ    	17	/* =~ */
#define T_OP_REG_NE    	18	/* !~ */
#define T_OP_CMP_EQ     19	/* == */
#define T_EQEND		20
#define T_HASH		21	/* # */

int	getword (char **ptr, char *buf, int buflen);
int	gettoken(char **ptr, char *buf, int buflen);
int	getcfword (char **ptr, char *buf, int buflen);
int	getcftoken(char **ptr, char *buf, int buflen);
