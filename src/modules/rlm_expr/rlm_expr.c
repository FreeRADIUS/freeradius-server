/*
 * rlm_expr.c
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
 * Copyright 2002  The FreeRADIUS server project
 * Copyright 2002  Alan DeKok <aland@ox.org>
 */

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"

static const char rcsid[] = "$Id$";

/*
 *	Define a structure for our module configuration.
 */
typedef struct rlm_expr_t {
	char *xlat_name;
} rlm_expr_t;

typedef enum expr_token_t {
  TOKEN_NONE = 0,
  TOKEN_INTEGER,
  TOKEN_ADD,
  TOKEN_SUBTRACT,
  TOKEN_XLAT
} expr_token_t;

/*
 *  Do xlat of strings!
 */ 
static int expr_xlat(void *instance, REQUEST *request, char *fmt, char *out, int outlen,
		                        RADIUS_ESCAPE_STRING func)
{
	int		result, x;
	const char	*p;	
	expr_token_t	this;
	rlm_expr_t	*inst = instance;

	/*
	 *  Loop over the input.
	 */
	result = 0;
	this = TOKEN_NONE;

	for (p = fmt; *p != '\0'; /* nothing */) {
		if ((*p == ' ') ||
		    (*p == '\t')) {
			p++;
			continue;
		}

		if (*p == '+') {
			if (this != TOKEN_NONE) {
				DEBUG2("rlm_expr: Invalid operator at \"%s\"", p);
				return 0;
			}
			this = TOKEN_ADD;
			p++;
			continue;
		}

		if (*p == '-') {
			if (this != TOKEN_NONE) {
				DEBUG2("rlm_expr: Invalid operator at \"%s\"", p);
				return 0;
			}
			this = TOKEN_SUBTRACT;
			p++;
			continue;
		}

		if ((p[0] == '%') && (p[1] == '{')) {
			int openbraces;
			char buffer[256];
			char answer[256];
			char *q;

			openbraces = 1;
			p += 2;
			buffer[0] = '%';
			buffer[1] = '{';

			for (q = buffer + 2; *p != '\0'; /* nothing */) {
				switch (*p) {
				default:
					break;

				case '{':
					openbraces++;
					break;

				case '}':
					openbraces--;
					break;
				
				case '\\':
					p++;
					if (!*p) {
						DEBUG2("rlm_expr: Trailing escape!\n");
						return 0;
					}
					
					/*
					 *  Copy the next character over
					 *  verbatim.
					 */
					*(q++) = *(p++);
					break;
				}

				*(q++) = *(p++);

				if (openbraces <= 0) {
					break;
				}
			}

			*q = '\0';

			if (openbraces != 0) {
				DEBUG2("rlm_expr: Mismatched braces!");
				return 0;
			}
			
			DEBUG2("rlm_expr: Calling xlat with %s\n",
			       buffer);

			/*
			 *  Recursive calls.
			 */
			radius_xlat(answer, sizeof(answer),
				    buffer, request, func);
			q = answer;

			/*
			 *  NOT a number: die!
			 */
			if ((*q < '0') || (*q > '9')) {
				DEBUG2("rlm_expr: Not a number at \"%s\"", q);
				return 0;
			}
			
			/*
			 *  This is doing it the hard way, but it also allows
			 *  us to increment 'p'.
			 */
			x = 0;
			while ((*q >= '0') && (*q <= '9')) {
				x *= 10;
				x += (*q - '0');
				q++;
			}
		} else {
			/*
			 *  NOT a number: die!
			 */
			if ((*p < '0') || (*p > '9')) {
				DEBUG2("rlm_expr: Not a number at \"%s\"", p);
				return 0;
			}
			
			/*
			 *  This is doing it the hard way, but it also allows
			 *  us to increment 'p'.
			 */
			x = 0;
			while ((*p >= '0') && (*p <= '9')) {
				x *= 10;
				x += (*p - '0');
				p++;
			}
		}

		DEBUG2("rlm_expr: %d %d\n", result, x);

		switch (this) {
		default:
		case TOKEN_NONE:
			result = x;
			break;
			
		case TOKEN_ADD:
			result += x;
			break;

		case TOKEN_SUBTRACT:
			result -= x;
			break;
		}

		/*
		 *  We've used this token.
		 */
		this = TOKEN_NONE;
	}

	snprintf(out, outlen, "%d", result);
	return strlen(out);
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int expr_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_expr_t	*inst;
	char		*xlat_name;
	
	/*
	 *	Set up a storage area for instance data
	 */
	
	inst = rad_malloc(sizeof(rlm_expr_t));
	memset(inst, 0, sizeof(rlm_expr_t));
		
	xlat_name = cf_section_name2(conf);
	if (xlat_name == NULL) 
		xlat_name = cf_section_name1(conf);
	if (xlat_name){ 
		inst->xlat_name = strdup(xlat_name);
		xlat_register(xlat_name, expr_xlat, inst); 
	} 
	*instance = inst;
	
	return 0;
}

/*
 *	Authenticate a user.  For now, do nothing.
 */
static int expr_authenticate(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;
	request = request;
	
	return RLM_MODULE_NOOP;
}

/*
 * Detach a instance free all ..
 */
static int expr_detach(void *instance)
{
	rlm_expr_t	*inst = instance;

	xlat_unregister(inst->xlat_name, expr_xlat);
	free(inst->xlat_name);

	free(inst);
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_expr = {
	"expr",				/* Name */
	RLM_TYPE_THREAD_SAFE,		/* type */
	NULL,				/* initialization */
	expr_instantiate,		/* instantiation */
	{
		expr_authenticate,	/* authentication */
		NULL,			/* authorization */
		NULL,			/* pre-accounting */
		NULL			/* accounting */
	},
	expr_detach,			/* detach */
	NULL,				/* destroy */
};
