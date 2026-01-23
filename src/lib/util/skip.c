/*
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
 */

/** Preparse input by skipping known tokens
 *
 * @file src/lib/util/skip.c
 *
 * @copyright 2025 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/skip.h>
#include <freeradius-devel/util/strerror.h>

/**  Skip a quoted string.
 *
 *  @param[in] start	start of the string, pointing to the quotation character
 *  @param[in] end	end of the string (or NULL for zero-terminated strings)
 *  @return
 *	>0 length of the string which was parsed
 *	<=0 on error
 */
ssize_t fr_skip_string(char const *start, char const *end)
{
	char const *p = start;
	char quote;

	quote = *(p++);

	while ((end && (p < end)) || *p) {
		/*
		 *	Stop at the quotation character
		 */
		if (*p == quote) {
			p++;
			return p - start;
		}

		/*
		 *	Not an escape character: it's OK.
		 */
		if (*p != '\\') {
			p++;
			continue;
		}

		if (end && ((p + 2) >= end)) {
		fail:
			fr_strerror_const("Unexpected escape at end of string");
			return -(p - start);
		}

		/*
		 *	Escape at EOL is not allowed.
		 */
		if (p[1] < ' ') goto fail;

		/*
		 *	\r or \n, etc.
		 */
		if (!isdigit((uint8_t) p[1])) {
			p += 2;
			continue;
		}

		/*
		 *	Double-quoted strings use \000
		 *	Regexes use \0
		 */
		if (quote == '/') {
			p++;
			continue;
		}

		if (end && ((p + 4) >= end)) goto fail;

		/*
		 *	Allow for \1f in single quoted strings
		 */
		if ((quote == '\'') && isxdigit((uint8_t) p[1]) && isxdigit((uint8_t) p[2])) {
			p += 3;
			continue;
		}

		if (!isdigit((uint8_t) p[2]) || !isdigit((uint8_t) p[3])) {
			fr_strerror_const("Invalid octal escape");
			return -(p - start);
		}

		p += 4;
	}

	/*
	 *	Unexpected end of string.
	 */
	fr_strerror_const("Unexpected end of string");
	return -(p - start);
}

/** Skip a generic {...} or (...) arguments
 *
 */
ssize_t fr_skip_brackets(char const *start, char const *end, char end_quote)
{
	ssize_t slen;
	char const *p = start;

	while ((end && (p < end)) || *p) {
		if (*p == end_quote) {
			p++;
			return p - start;
		}

		/*
		 *	Expressions.  Arguably we want to
		 *	differentiate conditions and function
		 *	arguments, but it's not clear how to do that
		 *	in a pre-parsing stage.
		 */
		if (*p == '(') {
			p++;
			slen = fr_skip_brackets(p, end, ')');
			if (slen <= 0) return slen - (p - start);

		next:
			fr_assert((size_t) slen <= (size_t) (end - p));
			p += slen;
			continue;
		}

		/*
		 *	A quoted string.
		 */
		if ((*p == '"') || (*p == '\'') || (*p == '`')) {
			slen = fr_skip_string(p, end);
			goto next;
		}

		/*
		 *	Nested expansion.
		 */
		if ((p[0] == '$') || (p[0] == '%')) {
			if (end && (p + 2) >= end) break;

			/*
			 *	%% inside of an xlat
			 */
			if ((p[0] == '%') && (p[1] == '%')) {
				p += 2;
				continue;
			}

			if ((p[1] == '{') || (p[1] == '(')) {
				slen = fr_skip_xlat(p, end);
				goto next;
			}

			/*
			 *	Bare $ or %, just leave it alone.
			 */
			p++;
			continue;
		}

		/*
		 *	Escapes are special.
		 */
		if (*p != '\\') {
			p++;
			continue;
		}

		if (end && ((p + 2) >= end)) break;

		/*
		 *	Escapes here are only one-character escapes.
		 */
		if (p[1] < ' ') break;
		p += 2;
	}

	/*
	 *	Unexpected end of xlat
	 */
	fr_strerror_const("Unexpected end of expansion");
	return -(p - start);
}

/**  Skip an xlat expression.
 *
 *  This is a simple "peek ahead" parser which tries to not be wrong.  It may accept
 *  some things which will later parse as invalid (e.g. unknown attributes, etc.)
 *  But it also rejects all malformed expressions.
 *
 *  It's used as a quick hack because the full parser isn't always available.
 *
 *  @param[in] start	start of the expression, MUST point to the "%{" or "%("
 *  @param[in] end	end of the string (or NULL for zero-terminated strings)
 *  @return
 *	>0 length of the string which was parsed
 *	<=0 on error
 */
ssize_t fr_skip_xlat(char const *start, char const *end)
{
	ssize_t slen;
	char const *p = start;

	/*
	 *	At least %{1} or $(.)
	 */
	if (end && ((end - start) < 4)) {
		fr_strerror_const("Invalid expansion");
		return 0;
	}

	if (!((memcmp(p, "%{", 2) == 0) || /* xlat */
	      (memcmp(p, "${", 2) == 0) || /* config file macro */
	      (memcmp(p, "$(", 2) == 0))) {  /* shell expansion in an back-ticks argument */
		fr_strerror_const("Invalid expansion");
		return 0;
	}
	p++;

	if (*p == '(') {
		p++;		/* skip the '(' */
		slen = fr_skip_brackets(p, end, ')');

	} else if (*p == '{') {
		p++;		/* skip the '{' */
		slen = fr_skip_brackets(p, end, '}');

	} else {
		char const *q = p;

		/*
		 *	New xlat syntax: %foo(...)
		 */
		while (isalnum((int) *q) || (*q == '.') || (*q == '_') || (*q == '-')) {
			q++;
		}

		if (*q != '(') {
			fr_strerror_const("Invalid character after '%'");
			return -(p - start);
		}

		p = q + 1;

		slen = fr_skip_brackets(p, end, ')');
	}

	if (slen <= 0) return slen - (p - start);
	return slen + (p - start);
}

/**  Skip a conditional expression.
 *
 *  This is a simple "peek ahead" parser which tries to not be wrong.  It may accept
 *  some things which will later parse as invalid (e.g. unknown attributes, etc.)
 *  But it also rejects all malformed expressions.
 *
 *  It's used as a quick hack because the full parser isn't always available.
 *
 *  @param[in] start	start of the condition.
 *  @param[in] end	end of the string (or NULL for zero-terminated strings)
 *  @param[in] terminal	terminal character(s)
 *  @param[out] eol	did the parse error happen at eol?
 *  @return
 *	>0 length of the string which was parsed.  *eol is false.
 *	<=0 on error, *eol may be set.
 */
ssize_t fr_skip_condition(char const *start, char const *end, bool const terminal[static SBUFF_CHAR_CLASS], bool *eol)
{
	char const *p = start;
	bool was_regex = false;
	int depth = 0;
	ssize_t slen;

	if (eol) *eol = false;

	/*
	 *	Keep parsing the condition until we hit EOS or EOL.
	 */
	while ((end && (p < end)) || *p) {
		if (isspace((uint8_t) *p)) {
			p++;
			continue;
		}

		/*
		 *	In the configuration files, conditions end with ") {" or just "{"
		 */
		if ((depth == 0) && terminal[(uint8_t) *p]) {
			return p - start;
		}

		/*
		 *	"recurse" to get more conditions.
		 */
		if (*p == '(') {
			p++;
			depth++;
			was_regex = false;
			continue;
		}

		if (*p == ')') {
			if (!depth) {
				fr_strerror_const("Too many ')'");
				return -(p - start);
			}

			p++;
			depth--;
			was_regex = false;
			continue;
		}

		/*
		 *	Parse xlats.  They cannot span EOL.
		 */
		if ((*p == '$') || (*p == '%')) {
			if (end && ((p + 2) >= end)) {
				fr_strerror_const("Expansions cannot extend across end of line");
				return -(p - start);
			}

			if ((p[1] == '{') || ((p[0] == '$') && (p[1] == '('))) {
				slen = fr_skip_xlat(p, end);

			check:
				if (slen <= 0) return -(p - start) + slen;

				p += slen;
				continue;
			}

			/*
			 *	Bare $ or %, just leave it alone.
			 */
			p++;
			was_regex = false;
			continue;
		}

		/*
		 *	Parse quoted strings.  They cannot span EOL.
		 */
		if ((*p == '"') || (*p == '\'') || (*p == '`') || (was_regex && (*p == '/'))) {
			was_regex = false;

			slen = fr_skip_string((char const *) p, end);
			goto check;
		}

		/*
		 *	192.168/16 is a netmask.  So we only
		 *	allow regex after a regex operator.
		 *
		 *	This isn't perfect, but is good enough
		 *	for most purposes.
		 */
		if ((p[0] == '=') || (p[0] == '!')) {
			if (end && ((p + 2) >= end)) {
				fr_strerror_const("Operators cannot extend across end of line");
				return -(p - start);
			}

			if (p[1] == '~') {
				was_regex = true;
				p += 2;
				continue;
			}

			/*
			 *	Some other '==' or '!=', just leave it alone.
			 */
			p++;
			was_regex = false;
			continue;
		}

		/*
		 *	Any control characters (other than \t) cause an error.
		 */
		if (*p < ' ') break;

		was_regex = false;

		/*
		 *	Normal characters just get skipped.
		 */
		if (*p != '\\') {
			p++;
			continue;
		}

		/*
		 *	Backslashes at EOL are ignored.
		 */
		if (end && ((p + 2) >= end)) break;

		/*
		 *	Escapes here are only one-character escapes.
		 */
		if (p[1] < ' ') break;
		p += 2;
	}

	/*
	 *	We've fallen off of the end of a string.  It may be OK?
	 */
	if (eol) *eol = (depth > 0);

	if (terminal[(uint8_t) *p]) return p - start;

	fr_strerror_const("Unexpected end of condition");
	return -(p - start);
}

