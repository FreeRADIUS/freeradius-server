/*
 * print.c	Routines to print stuff.
 *
 * Version:	$Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/types.h>
#include	<time.h>
#include	<pwd.h>
#include	<ctype.h>
#include	<string.h>

#include	"libradius.h"

/*
 *	Convert a string to something printable.
 *	The output string has to be _at least_ 4x the size
 *	of the input string!
 */
void librad_safeprint(char *in, int inlen, char *out, int outlen)
{
	unsigned char	*str = (unsigned char *)in;
	int		done = 0;
	int		sp = 0;

	if (inlen < 0) inlen = strlen(str);

	while (inlen-- > 0 && (done + 3) < outlen) {
		/*
		 *	Hack: never print trailing zero.
		 *	Some clients send strings with an off-by-one
		 *	length (confused with strings in C).
		 */
		if (inlen == 0 && *str == 0)
			break;

		sp = 0;

		switch (*str) {
			case '\\':
				sp = '\\';
				break;
			case '\r':
				sp = 'r';
				break;
			case '\n':
				sp = 'n';
				break;
			case '\t':
				sp = 't';
				break;
			default:
				if (*str < 32 || (*str >= 128)){
					sprintf(out, "\\%03o", *str);
					done += 4;
					out  += 4;
				} else {
					*out++ = *str;
					done++;
				}
		}
		if (sp) {
			*out++ = '\\';
			*out++ = sp;
			done += 2;
		}
		str++;
	}
	*out = 0;
}


/*
 *	Print one attribute and value into a string.
 */
int vp_prints(char *out, int outlen, VALUE_PAIR *vp)
{
	DICT_VALUE	*v;
	char		buf[1024];
	char		*a;
	time_t		t;
	int		len;
	char		*orig = out;

	if (!vp) return 0;

	out[0] = 0;
	if (strlen(vp->name) + 3 > outlen) {
		return 0;
	}

	sprintf(out, "%s = ", vp->name);
	len = strlen(out);
	outlen -= len;
	out += len;

	switch (vp->type) {
		case PW_TYPE_STRING:
			if (vp->attribute == PW_NAS_PORT_ID)
				a = vp->strvalue;
			else {
				buf[0] = '"';
				librad_safeprint(vp->strvalue, vp->length,
					buf + 1, sizeof(buf) - 2);
				strcat(buf, "\"");
				a = buf;
			}
			break;
		case PW_TYPE_INTEGER:
			if ((v = dict_valbyattr(vp->attribute, vp->lvalue))
			    != NULL)
				a = v->name;
			else {
				sprintf(buf, "%d", vp->lvalue);
				a = buf;
			}
			break;
		case PW_TYPE_DATE:
			t = vp->lvalue;
			strftime(buf, sizeof(buf), "\"%b %e %Y\"",
				gmtime(&t));
			a = buf;
			break;
		case PW_TYPE_IPADDR:
			if (vp->strvalue[0])
				a = vp->strvalue;
			else
				a = ip_ntoa(NULL, vp->lvalue);
			break;
		case PW_TYPE_ABINARY:
#ifdef ASCEND_BINARY
		  a = buf;
		  print_abinary(vp, buf, sizeof(buf));
		  break;
#endif
		case PW_TYPE_OCTETS:
		  strcpy(buf, "0x");
		  a = buf + 2;
		  for (t = 0; t < vp->length; t++) {
		    sprintf(a, "%02x", vp->strvalue[t]);
		    a += 2;
		  }
		  a = buf;
		  break;

		default:
			a = "UNKNOWN-TYPE";
			break;
	}
	strncpy(out, a, outlen);
	out[outlen - 1] = 0;
	return strlen(orig);
}


/*
 *	Print one attribute and value.
 */
void vp_print(FILE *fp, VALUE_PAIR *vp)
{
	char	buf[1024];

	vp_prints(buf, sizeof(buf), vp);
	fputs(buf, fp);
}


/*
 *	Print a whole list of attributes, indented by a TAB
 *	and with a newline at the end.
 */
void vp_printlist(FILE *fp, VALUE_PAIR *vp)
{
	for (; vp; vp = vp->next) {
		fprintf(fp, "\t");
		vp_print(fp, vp);
		fprintf(fp, "\n");
	}
}

