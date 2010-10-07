/*
 * print.c	Routines to print stuff.
 *
 * Version:	$Id$
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 */

#include	<freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/libradius.h>

#include	<ctype.h>

/*
 *	Checks for utf-8, taken from:
 *
 *  http://www.w3.org/International/questions/qa-forms-utf-8
 *
 *	Note that we don't care about the length of the input string,
 *	because '\0' is an invalid UTF-8 character.
 */
int fr_utf8_char(const uint8_t *str)
{
	if (*str < 0x20) return 0;

	if (*str <= 0x7e) return 1; /* 1 */

	if (*str <= 0xc1) return 0;

	if ((str[0] >= 0xc2) &&	/* 2 */
	    (str[0] <= 0xdf) &&
	    (str[1] >= 0x80) &&
	    (str[1] <= 0xbf)) {
		return 2;
	}

	if ((str[0] == 0xe0) &&	/* 3 */
	    (str[1] >= 0xa0) &&
	    (str[1] <= 0xbf) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf)) {
		return 3;
	}

	if ((str[0] >= 0xe1) &&	/* 4a */
	    (str[0] <= 0xec) &&
	    (str[1] >= 0x80) &&
	    (str[1] <= 0xbf) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf)) {
		return 3;
	}

	if ((str[0] >= 0xee) &&	/* 4b */
	    (str[0] <= 0xef) &&
	    (str[1] >= 0x80) &&
	    (str[1] <= 0xbf) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf)) {
		return 3;
	}

	if ((str[0] == 0xed) &&	/* 5 */
	    (str[1] >= 0x80) &&
	    (str[1] <= 0x9f) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf)) {
		return 3;
	}

	if ((str[0] == 0xf0) &&	/* 6 */
	    (str[1] >= 0x90) &&
	    (str[1] <= 0xbf) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf) &&
	    (str[3] >= 0x80) &&
	    (str[3] <= 0xbf)) {
		return 4;
	}

	if ((str[0] >= 0xf1) &&	/* 6 */
	    (str[1] <= 0xf3) &&
	    (str[1] >= 0x80) &&
	    (str[1] <= 0xbf) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf) &&
	    (str[3] >= 0x80) &&
	    (str[3] <= 0xbf)) {
		return 4;
	}


	if ((str[0] == 0xf4) &&	/* 7 */
	    (str[1] >= 0x80) &&
	    (str[1] <= 0x8f) &&
	    (str[2] >= 0x80) &&
	    (str[2] <= 0xbf) &&
	    (str[3] >= 0x80) &&
	    (str[3] <= 0xbf)) {
		return 4;
	}

	/*
	 *	Invalid UTF-8 Character
	 */
	return 0;
}

/*
 *	Convert a string to something printable.  The output string
 *	has to be larger than the input string by at least 5 bytes.
 *	If not, the output is silently truncated...
 */
void fr_print_string(const char *in, size_t inlen, char *out, size_t outlen)
{
	const uint8_t	*str = (const uint8_t *) in;
	int		sp = 0;
	int		utf8 = 0;

	if (inlen == 0) inlen = strlen(in);

	/*
	 *	
	 */
	while ((inlen > 0) && (outlen > 4)) {
		/*
		 *	Hack: never print trailing zero.
		 *	Some clients send strings with an off-by-one
		 *	length (confused with strings in C).
		 */
		if ((inlen == 1) && (*str == 0)) break;

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
			case '"':
				sp = '"';
				break;
			default:
				sp = 0;
				break;
		}

		if (sp) {
			*out++ = '\\';
			*out++ = sp;
			outlen -= 2;
			str++;
			inlen--;
			continue;
		}

		utf8 = fr_utf8_char(str);
		if (!utf8) {
			snprintf(out, outlen, "\\%03o", *str);
			out  += 4;
			outlen -= 4;
			str++;
			inlen--;
			continue;
		}

		do {
			*out++ = *str++;
			outlen--;
			inlen--;
		} while (--utf8 > 0);
	}
	*out = 0;
}


/*
 *  Print one value into a string.
 *  delimitst will define if strings and dates will be delimited by '"'
 */
int vp_prints_value(char * out, size_t outlen, VALUE_PAIR *vp, int delimitst)
{
	DICT_VALUE  *v;
	char        buf[1024];
	const char  *a = NULL;
	size_t      len;
	time_t      t;
	struct tm   s_tm;

	out[0] = '\0';
	if (!vp) return 0;

	switch (vp->type) {
		case PW_TYPE_STRING:
			if ((delimitst == 1) && vp->flags.has_tag) {
				/* Tagged attribute: print delimter and ignore tag */
				buf[0] = '"';
				fr_print_string(vp->vp_strvalue,
						 vp->length, buf + 1, sizeof(buf) - 2);
				strcat(buf, "\"");
			} else if (delimitst == 1) {
				/* Non-tagged attribute: print delimter */
				buf[0] = '"';
				fr_print_string(vp->vp_strvalue,
						 vp->length, buf + 1, sizeof(buf) - 2);
				strcat(buf, "\"");

			} else if (delimitst < 0) { /* xlat.c */
				strlcpy(out, vp->vp_strvalue, outlen);
				return strlen(out);

			} else {
				/* Non-tagged attribute: no delimiter */
				fr_print_string(vp->vp_strvalue,
						 vp->length, buf, sizeof(buf));
			}
			a = buf;
			break;
		case PW_TYPE_INTEGER:
		        if ( vp->flags.has_tag ) {
			        /* Attribute value has a tag, need to ignore it */
				if ((v = dict_valbyattr(vp->attribute, vp->vendor, (vp->vp_integer & 0xffffff)))
				    != NULL)
				        a = v->name;
				else {
				        snprintf(buf, sizeof(buf), "%u", (vp->vp_integer & 0xffffff));
				        a = buf;
				}
			} else {
		case PW_TYPE_BYTE:
		case PW_TYPE_SHORT:
			        /* Normal, non-tagged attribute */
				if ((v = dict_valbyattr(vp->attribute, vp->vendor, vp->vp_integer))
				    != NULL)
				        a = v->name;
				else {
				        snprintf(buf, sizeof(buf), "%u", vp->vp_integer);
					a = buf;
				}
			}
			break;
		case PW_TYPE_DATE:
			t = vp->vp_date;
			if (delimitst == 1) {
			  len = strftime(buf, sizeof(buf), "\"%b %e %Y %H:%M:%S %Z\"",
					 localtime_r(&t, &s_tm));
			} else {
			  len = strftime(buf, sizeof(buf), "%b %e %Y %H:%M:%S %Z",
					 localtime_r(&t, &s_tm));
			}
			if (len > 0) a = buf;
			break;
		case PW_TYPE_SIGNED: /* Damned code for 1 WiMAX attribute */
			snprintf(buf, sizeof(buf), "%d", vp->vp_signed);
			a = buf;
			break;
		case PW_TYPE_IPADDR:
			a = inet_ntop(AF_INET, &(vp->vp_ipaddr),
				      buf, sizeof(buf));
			break;
		case PW_TYPE_ABINARY:
#ifdef ASCEND_BINARY
			a = buf;
			print_abinary(vp, buf, sizeof(buf));
			break;
#else
		  /* FALL THROUGH */
#endif
		case PW_TYPE_OCTETS:
			if (outlen <= (2 * (vp->length + 1))) return 0;

			strcpy(buf, "0x");

			fr_bin2hex(vp->vp_octets, buf + 2, vp->length);
			a = buf;
		  break;

		case PW_TYPE_IFID:
			a = ifid_ntoa(buf, sizeof(buf), vp->vp_octets);
			break;

		case PW_TYPE_IPV6ADDR:
			a = inet_ntop(AF_INET6,
				      (const struct in6_addr *) vp->vp_strvalue,
				      buf, sizeof(buf));
			break;

		case PW_TYPE_IPV6PREFIX:
		{
			struct in6_addr addr;

			/*
			 *	Alignment issues.
			 */
			memcpy(&addr, vp->vp_strvalue + 2, sizeof(addr));

			a = inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
			if (a) {
				char *p = buf + strlen(buf);
				snprintf(p, buf + sizeof(buf) - p - 1, "/%u",
					 (unsigned int) vp->vp_octets[1]);
			}
		}
			break;

		case PW_TYPE_ETHERNET:
			snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
				 vp->vp_ether[0], vp->vp_ether[1],
				 vp->vp_ether[2], vp->vp_ether[3],
				 vp->vp_ether[4], vp->vp_ether[5]);
			a = buf;
			break;

		case PW_TYPE_TLV:
			if (outlen <= (2 * (vp->length + 1))) return 0;

			strcpy(buf, "0x");

			fr_bin2hex(vp->vp_tlv, buf + 2, vp->length);
			a = buf;
		  break;

		default:
			a = "UNKNOWN-TYPE";
			break;
	}

	if (a != NULL) strlcpy(out, a, outlen);

	return strlen(out);
}

/*
 *  This is a hack, and has to be kept in sync with tokens.h
 */
static const char *vp_tokens[] = {
  "?",				/* T_OP_INVALID */
  "EOL",			/* T_EOL */
  "{",
  "}",
  "(",
  ")",
  ",",
  ";",
  "+=",
  "-=",
  ":=",
  "=",
  "!=",
  ">=",
  ">",
  "<=",
  "<",
  "=~",
  "!~",
  "=*",
  "!*",
  "==",
  "#",
  "<BARE-WORD>",
  "<\"STRING\">",
  "<'STRING'>",
  "<`STRING`>"
};

const char *vp_print_name(char *buffer, size_t bufsize, int attr, int vendor)
{
	size_t len = 0;

	if (!buffer) return NULL;

	if (vendor) {
		DICT_VENDOR *v;
		
		v = dict_vendorbyvalue(vendor);
		if (v) {
			snprintf(buffer, bufsize, "%s-", v->name);
		} else {
			snprintf(buffer, bufsize, "Vendor-%u-", vendor);
		}

		len = strlen(buffer);
		if (len == bufsize) {
			return NULL;
		}
	}

	snprintf(buffer + len, bufsize - len, "Attr-%u", attr & 0xffff);
	len += strlen(buffer + len);
	if (len == bufsize) {
		return NULL;
	}

	return buffer;
}


/*
 *	Print one attribute and value into a string.
 */
int vp_prints(char *out, size_t outlen, VALUE_PAIR *vp)
{
	size_t		len;
	const char	*token = NULL;
	const char	*name;
	char		namebuf[128];

	out[0] = 0;
	if (!vp) return 0;

	name = vp->name;

	if (!name || !*name) {
		if (!vp_print_name(namebuf, sizeof(namebuf), vp->attribute, vp->attribute)) {
			return 0;
		}
		name = namebuf;
	}

	if ((vp->operator > T_OP_INVALID) &&
	    (vp->operator < T_TOKEN_LAST)) {
		token = vp_tokens[vp->operator];
	} else {
		token = "<INVALID-TOKEN>";
	}

	if( vp->flags.has_tag ) {
		snprintf(out, outlen, "%s:%d %s ",
			 name, vp->flags.tag, token);

		len = strlen(out);
		vp_prints_value(out + len, outlen - len, vp, 1);

	} else {
	        snprintf(out, outlen, "%s %s ", name, token);
		len = strlen(out);
		vp_prints_value(out + len, outlen - len, vp, 1);

	}

	return len + strlen(out + len);
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

