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

	if (inlen < 0) inlen = strlen(in);

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
					snprintf(out, outlen, "\\%03o", *str);
					done += 4;
					out  += 4;
					outlen -= 4;
				} else {
					*out++ = *str;
					outlen--;
					done++;
				}
		}
		if (sp) {
			*out++ = '\\';
			*out++ = sp;
			outlen -= 2;
			done += 2;
		}
		str++;
	}
	*out = 0;
}


/*
 *  Print one value into a string.
 *  delimitst will define if strings and dates will be delimited by '"'
 */
int vp_prints_value(char * out, int outlen, VALUE_PAIR *vp, int delimitst)
{
	DICT_VALUE  *v;
	char        buf[1024];
	char        *a;
	time_t      t;

	out[0] = 0;
	if (!vp) return 0;

	switch (vp->type) {
		case PW_TYPE_STRING:
			if (vp->attribute == PW_NAS_PORT_ID)
				a = (char *)vp->strvalue;
			else {
				if (delimitst) {
				  buf[0] = '"';
				  librad_safeprint((char *)vp->strvalue,
					  vp->length, buf + 1, sizeof(buf) - 2);
				  strcat(buf, "\"");
				} else {
				  librad_safeprint((char *)vp->strvalue,
					  vp->length, buf, sizeof(buf));
				}

				a = buf;
			}
			break;
		case PW_TYPE_INTEGER:
			if ((v = dict_valbyattr(vp->attribute, vp->lvalue))
				!= NULL)
				a = v->name;
			else {
				snprintf(buf, sizeof(buf), "%u", vp->lvalue);
				a = buf;
			}
			break;
		case PW_TYPE_DATE:
			t = vp->lvalue;
			if (delimitst) {
			  strftime(buf, sizeof(buf), "\"%b %e %Y\"", gmtime(&t));
			} else {
			  strftime(buf, sizeof(buf), "%b %e %Y", gmtime(&t));
			}
			a = buf;
			break;
		case PW_TYPE_IPADDR:
			if (vp->strvalue[0])
				a = (char *)vp->strvalue;
			else
				a = ip_hostname((char *)vp->strvalue,
						sizeof(vp->strvalue),
						vp->lvalue);
			break;
		case PW_TYPE_ABINARY:
#ifdef ASCEND_BINARY
		  a = buf;
		  print_abinary(vp, (unsigned char *)buf, sizeof(buf));
		  break;
#else
		  /* FALL THROUGH */
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
			a = 0;
			break;
	}
	strNcpy(out, a?a:"UNKNOWN-TYPE", outlen);
	
	return strlen(out);
}


/*
 *	Print one attribute and value into a string.
 */
int vp_prints(char *out, int outlen, VALUE_PAIR *vp)
{
	int		len;

	out[0] = 0;
	if (!vp) return 0;

	if (strlen(vp->name) + 3 > (size_t)outlen) {
		return 0;
	}

	snprintf(out, outlen, "%s = ", vp->name);
	len = strlen(out);
	vp_prints_value(out + len, outlen - len, vp, 1);

	return strlen(out);
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

