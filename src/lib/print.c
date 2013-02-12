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
size_t fr_print_string(const char *in, size_t inlen, char *out, size_t outlen)
{
	const char	*start = out;
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

	return out - start;
}


/*
 *  Print one value into a string.
 *  delimitst will define if strings and dates will be delimited by '"'
 */
int vp_prints_value(char * out, size_t outlen, const VALUE_PAIR *vp, int delimitst)
{
	DICT_VALUE  *v;
	char        buf[1024];
	const char  *a = NULL;
	size_t      len;
	time_t      t;
	struct tm   s_tm;

	out[0] = '\0';
	if (!vp) return 0;

	if ((vp->type & PW_FLAG_LONG) != 0) goto do_tlv;

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
		case PW_TYPE_INTEGER64:
			snprintf(buf, sizeof(buf), "%llu", vp->vp_integer64);
			a = buf;
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
#ifdef WITH_ASCEND_BINARY
			a = buf;
			print_abinary(vp, buf, sizeof(buf), delimitst);
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
				      &vp->vp_ipv6addr,
				      buf, sizeof(buf));
			break;

		case PW_TYPE_IPV6PREFIX:
		{
			struct in6_addr addr;

			/*
			 *	Alignment issues.
			 */
			memcpy(&addr, &(vp->vp_ipv6prefix[2]), sizeof(addr));

			a = inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
			if (a) {
				char *p = buf + strlen(buf);
				snprintf(p, buf + sizeof(buf) - p - 1, "/%u",
					 (unsigned int) vp->vp_octets[1]);
			}
		}
			break;

		case PW_TYPE_IPV4PREFIX:
		{
			struct in_addr addr;

			/*
			 *	Alignment issues.
			 */
			memcpy(&addr, &(vp->vp_ipv4prefix[2]), sizeof(addr));

			a = inet_ntop(AF_INET, &addr, buf, sizeof(buf));
			if (a) {
				char *p = buf + strlen(buf);
				snprintf(p, buf + sizeof(buf) - p - 1, "/%u",
					 (unsigned int) (vp->vp_octets[1] & 0x3f));
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
	do_tlv:
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
 *  Almost identical to vp_prints_value, but escapes certain chars so the string
 *  may be used as a JSON value.
 *
 *  Returns < 0 if the buffer may be (or have been) too small to write the encoded
 *  JSON value to.
 */
int vp_prints_value_json(char *buffer, size_t bufsize, const VALUE_PAIR *vp)
{
	int s = 0;
	int len;
	char *p = buffer;
	const char *q;
 
	if (!vp->flags.has_tag) {
		switch (vp->type) {
			case PW_TYPE_INTEGER:
			case PW_TYPE_BYTE:
			case PW_TYPE_SHORT:
				if (vp->flags.has_value) break;
				
				len = snprintf(buffer, bufsize, "%u", vp->vp_integer);
				return ((unsigned) len >= (bufsize - 1)) ? -1 : len;

			case PW_TYPE_SIGNED:
				len = snprintf(buffer, bufsize, "%d", vp->vp_signed);
				return ((unsigned) len >= (bufsize - 1)) ? -1 : len;

			default:
				break;
		}
	}

	if(bufsize < 3) return -1;
	*p++ = '"';

	switch (vp->type) {
		case PW_TYPE_STRING:
			for (q = vp->vp_strvalue; q < vp->vp_strvalue + vp->length; q++) {
				s = bufsize - (p - buffer);
				if (s < 4) return -1;
				
				if (*q == '"') {
					*p++ = '\\';
					*p++ = '"';
				} else if (*q == '\\') {
					*p++ = '\\';
					*p++ = '\\';
				} else if (*q == '/') {
					*p++ = '\\';
					*p++ = '/';
				} else if (*q >= ' ') {
					*p++ = *q;
				} else {
					*p++ = '\\';
					
					if (*q == '\b') {
						*p++ = 'b';
					} else if (*q == '\f') {
						*p++ = 'f';
					} else if (*q == '\n') {
						*p++ = 'n';
					} else if (*q == '\r') {
						*p++ = 'r';
					} else if (*q == '\t'){ 
						*p++ = 't';
					} else {
						if(s < 8) return -1;
						p += sprintf(p, "u%04X", *q);
					}
				}
			}
			break;

		default:
			/* -1 to account for trailing double quote */
			s = bufsize - ((p - buffer) - 1);
			
			len = vp_prints_value(p, s, vp, 0);
			if (len >= (s - 1)) return -1;
			
			p += len;
			break;
	}

	*p++ = '"';
	*p = '\0';

	return p - buffer;
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
  "++",
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

extern int fr_attr_max_tlv;
extern int fr_attr_shift[];
extern int fr_attr_mask[];

static size_t vp_print_attr_oid(char *buffer, size_t size, unsigned int attr,
				int dv_type)
{
	int nest;
	size_t outlen;
	size_t len;

	switch (dv_type) {
	case 4:
		return snprintf(buffer, size, "%u", attr);

	case 2:
		return snprintf(buffer, size, "%u", attr & 0xffff);

	default:
	case 1:
		len = snprintf(buffer, size, "%u", attr & 0xff);
		break;
	}

	if ((attr >> 8) == 0) return len;

	outlen = len;
	buffer += len;
	size -= len;

	for (nest = 1; nest <= fr_attr_max_tlv; nest++) {
		if (((attr >> fr_attr_shift[nest]) & fr_attr_mask[nest]) == 0) break;

		len = snprintf(buffer, size, ".%u",
			       (attr >> fr_attr_shift[nest]) & fr_attr_mask[nest]);

		outlen = len;
		buffer += len;
		size -= len;
	}

	return outlen;
}

/*
 *	Handle attributes which are not in the dictionaries.
 */
size_t vp_print_name(char *buffer, size_t bufsize,
		     unsigned int attr, unsigned int vendor)
{
	char *p = buffer;
	int dv_type = 1;
	size_t len = 0;

	if (!buffer) return 0;
	
	len = snprintf(p, bufsize, "Attr-");
	p += len;
	bufsize -= len;

	if (vendor > FR_MAX_VENDOR) {
		len = snprintf(p, bufsize, "%u.",
			       vendor / FR_MAX_VENDOR);
		p += len;
		bufsize -= len;
		vendor &= (FR_MAX_VENDOR) - 1;
	}

	if (vendor) {
		DICT_VENDOR *dv;

		dv = dict_vendorbyvalue(vendor);
		if (dv) {
			dv_type = dv->type;
		}
		len = snprintf(p, bufsize, "26.%u.", vendor);
		
		p += len;
		bufsize -= len;
	}

	p += vp_print_attr_oid(p, bufsize , attr, dv_type);

	return p - buffer;
}


/*
 *	Print one attribute and value into a string.
 */
int vp_prints(char *out, size_t outlen, const VALUE_PAIR *vp)
{
	size_t		len;
	const char	*token = NULL;

	out[0] = 0;
	if (!vp) return 0;

	if ((vp->op > T_OP_INVALID) &&
	    (vp->op < T_TOKEN_LAST)) {
		token = vp_tokens[vp->op];
	} else {
		token = "<INVALID-TOKEN>";
	}

	if( vp->flags.has_tag ) {
		snprintf(out, outlen, "%s:%d %s ",
			 vp->name, vp->flags.tag, token);

		len = strlen(out);
		vp_prints_value(out + len, outlen - len, vp, 1);

	} else {
	        snprintf(out, outlen, "%s %s ", vp->name, token);
		len = strlen(out);
		vp_prints_value(out + len, outlen - len, vp, 1);

	}

	return len + strlen(out + len);
}


/*
 *	Print one attribute and value.
 */
void vp_print(FILE *fp, const VALUE_PAIR *vp)
{
	char	buf[1024];

	vp_prints(buf, sizeof(buf), vp);
	fputc('\t', fp);
	fputs(buf, fp);
	fputc('\n', fp);
}


/*
 *	Print a whole list of attributes, indented by a TAB
 *	and with a newline at the end.
 */
void vp_printlist(FILE *fp, const VALUE_PAIR *vp)
{
	for (; vp; vp = vp->next) {
		vp_print(fp, vp);
	}
}

