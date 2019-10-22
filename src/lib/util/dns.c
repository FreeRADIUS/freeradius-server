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

/** Functions to manipulate DNS labels
 *
 * @file src/lib/util/dns.c
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Network RADIUS SARL <legal@networkradius.com>
 */
RCSID("$Id$")

#include <freeradius-devel/util/cursor.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/dns.h>

/** Compare two labels in a case-insensitive fashion.
 *
 *  This function requires that the input is valid, i.e. all
 *  characters are within [-0-9A-Za-z].  If any other input is given,
 *  it will break.
 */
static bool labelcmp(uint8_t const *a, uint8_t const *b, size_t len)
{
	for (/* nothing */; len > 0; len--) {
		if (*a == *b) {
			a++;
			b++;
			continue;
		}

		/*
		 *	If one or the other isn't a letter, we can't
		 *	do case insensitive comparisons of them, so
		 *	they can't match.
		 */
		if ((*a < 'A') || (*b < 'A')) {
			return false;
		}

		/*
		 *	If they're equal but different case, then the
		 *	only bit that's different is 0x20.
		 */
		if (((*a)^(*b)) != 0x20) {
			return false;
		}

		a++;
		b++;
	}

	return true;
}

/** Compress "label" by looking at it recursively.
 *
 *  For "ftp.example.com", it searches the input buffer for a matching
 *  "com".  It only does string compares if it finds bytes "03 xx xx
 *  xx 00".  This means that the scan is quick, because most bytes are
 *  skipped.
 *
 *  If a matching string is found, the label is updated to replace
 *  "com" with a 2-byte pointer P1.  The process then proceeds
 *  recursively, with "exampleP1".
 *
 *  The input buffer is the scanned again for labels of matching
 *  length (7 here), AND which either end in the value of "P1", or end
 *  *at* P1.  If we find a match, we replace "exampleP1" with "P2".
 *  The process then proceeds recursively with "ftpP2".
 *
 *  Since the algorithm replaces known suffixes with pointers, we
 *  *never* have to compare full names.  Instead, we only ever compare
 *  one label to one other label.  And then only if the labels have
 *  the same lengths AND the same suffixes (00 byte, or a pointer P).
 *
 *  As an extra optimization, we track the start of the label where we
 *  found the compressed pointer.  e.g. "www.example.com" when
 *  compressing "com".  We know that the "com" string CANNOT appear
 *  before this label.  Because if it did, then the "www.example.com"
 *  name would have instead been compressed, as in "www.exampleP1".
 *
 *  This optimization ensures that we scan as little of the buffer as
 *  possible, by moving the search start ahead in the buffer.  This
 *  optimization also means that in many cases, the suffix we're
 *  looking for (e.g. "example.com") is in the first label we search.
 *  Which means that we end up ignoring most of the buffer.
 *
 *  This algorithm is O(N * B), where N is the number of labels in a
 *  name (e.g. 3 for "ftp.example.com"), and "B" is the size of the
 *  buffer.  It also does linear scans of the buffer, which are good
 *  for read-ahead.  Each input label is compared to labels in the
 *  buffer only when very limited situations apply.  And we never
 *  compare the full input name to full names in the buffer.
 *
 *  In the case where we are adding many names from the same zone to
 *  the input buffer, the input buffer will start with the zone name.
 *  So any searches will match that.  The only reason to continue
 *  scanning the buffer is to see if the name prefix already exists.
 *  If we assume that the records do not contain duplicates, then we
 *  can likely skip that scan, too.
 *
 *  Adding that optimization, however, requires tracking the maximum
 *  size of a name across multiple invocations of the function.  For
 *  example, if the maximum length name in the buffer is 3 labels, and
 *  we're adding a 3 label name, then we can stop scanning the buffer
 *  as soon as we compressed the 2 suffix labels.  Since we are
 *  guaranteed that there are no duplicates, we are sure that there is
 *  no existing 3-label name which matches a 3-label name in the
 *  buffer.
 *
 *
 *  A different and more straightforward approach is to loop over all
 *  labels in the name from longest to shortest, and comparing them to
 *  each name in the buffer in turn.  That algorithm ends up being
 *  O(L1 * T * L2), where L1 is the length of the input name, T is the
 *  total number of names in the buffer, and L2 is the average length
 *  of names in the buffer.  This algorithm can result in the buffer
 *  being scanned many, many, times.  The scan is also done forwards
 *  (due to comparing names one after the other), but also backwards
 *  (due to following pointers).  Which makes for poor locality of
 *  reference.
 *
 *  i.e. that approach *has* to scan the entire input buffer, because
 *  that's where all of the names are.  Further, it has to scan it at
 *  least "N" times, because there are N labels in the input name.  So
 *  O(N * B) is the *lower* bound for this algorithm.
 *
 *  It gets worse when the straightforward algorithm does pointer
 *  following instead of pointer comparisons.  It ends up scanning
 *  portions of the input buffer many, many, times.  i.e. it can
 *  compare an input "com" name to "org" once for every "org" name in
 *  the input buffer.  In contrast, because our algorithm does not do
 *  pointer following, it only compares "com" to "org" once.
 *
 * @param[in] start	  input buffer holding one or more labels
 * @param[in] end	  end of the input buffer
 * @param[out] new_search Where the parent call to dns_label_compress()
 *			  should start searching from, instead of from "start".
 * @param[in] label	  label to add to the buffer.
 * @param[out] label_end  updated end of the input label after compression.
 * @return
 *	- false, we didn't compress the input
 *	- true, we did compress the input.
 */
static bool dns_label_compress(uint8_t const *start, uint8_t const *end, uint8_t const **new_search,
			       uint8_t *label, uint8_t **label_end)
{
	uint8_t *next;
	uint8_t const *q, *ptr, *suffix, *search;
	uint16_t offset;

	/*
	 *	Don't compress "end of label" byte or pointers.
	 */
	if (!*label || (*label > 63)) {
		return false;
	}

	/*
	 *	Check the next label.  Note that this is *after*
	 *	"end".  It also MUST be a valid, uncompressed label.
	 */
	next = label + *label + 1;

	/*
	 *	Note that by design, next > end.  We don't care about
	 *	the size of the buffer we put "label" into.  We only
	 *	care that all bytes of "label" are valid, and we don't
	 *	access memroy after "label".
	 */

	/*
	 *	On the first call, begin searching from the start of
	 *	the buffer.
	 *
	 *	For subsequent calls, begin from where we started
	 *	searching before.
	 */
	if (!new_search) {
		search = start;
	} else {
		search = *new_search;
	}

	/*
	 *	We're at the last uncompressed label, scan the input
	 *	buffer to see if there's a match.
	 *
	 *	The scan skips ahead until it find both a label length
	 *	that matches, AND "next" label which is 0x00.  Only
	 *	then does it do the string compare of the label
	 *	values.
	 *
	 *	We speed this up slightly by tracking the previous
	 *	uncompressed pointer.  If we do compress the current
	 *	label, then we should also tell the caller where the
	 *	previous uncompressed label started.  That way the
	 *	caller can start looking there for the next piece to
	 *	compress.  There's no need to search from the
	 *	beginning of the input buffer, as we're sure that
	 *	there is no earlier instance of the suffix we found.
	 *
	 *	i.e. as we compress the current name, we start
	 *	searching not at the beginning of the input buffer/
	 *	Instead, we start searching at the name which contains
	 *	the label that we just compressed.  The previous
	 *	sarching guarantees that no name *before* that one
	 *	will match the suffix we're looking for.  So we can
	 *	skip all of the previous names in subsequent searches,
	 */
	if (*next == 0x00) {
		q = search;
		while (q < end) {
			if (*q == 0x00) {
				q++;

				/*
				 *	None of the previous names
				 *	matched, so we tell the caller
				 *	to start searching from the
				 *	next name in the buffer.
				 */
				search = q;
				continue;
			}

			/*
			 *	Our label is a terminal one.  Which
			 *	can't point to a pointer.
			 */
			if (*q > 63) {
				q += 2;

				/*
				 *	None of the previous
				 *	uncompressed names matched,
				 *	and this pointer refers to a
				 *	compressed name.  So it
				 *	doesn't match, either.
				 */
				search = q;
				continue;
			}

			/*
			 *	We now have a label which MIGHT match.
			 *	We have to walk down it until it does
			 *	match.  But we don't update "search"
			 *	here, because there may be a suffix
			 *	which matches.
			 */
			ptr = q + *q + 1;
			if (ptr > end) return false;

			/*
			 *	Label lengths aren't the same, skip
			 *	it.
			 */
			if (*q != *label) {
				q = ptr;
				continue;
			}

			/*
			 *	Our input label ends with 0x00.  If
			 *	this label doesn't end with 0x00, skip
			 *	it.
			 */
			if (*ptr != 0x00) {
				q = ptr;
				continue;
			}

			/*
			 *	The pointer is too far away.  Don't
			 *	point to it.  This check is mainly for
			 *	static analyzers.
			 */
			if ((q - start) > (1 << 14)) return false;

			/*
			 *	Only now do case-insensitive
			 *	comparisons.
			 */
			if (!labelcmp(q + 1, label + 1, *label)) {
				q = ptr;
				continue;
			}

			/*
			 *	We have a match.  Replace the input
			 *	label with a compressed pointer.  Tell
			 *	the caller the start of the found
			 *	name, so subsequent searches can start
			 *	from there.  Then return to the caller
			 *	that we managed to compress this
			 *	label.
			 */
			offset = (q - start);
			label[0] = (offset >> 8) | 0xc0;
			label[1] = offset & 0xff;
			*label_end = label + 2;
			if (new_search) *new_search = search;
			return true;
		}

		return false;
	}

	/*
	 *	The next label is still uncompressed, so we call
	 *	ourselves recursively in order to compress it.
	 */
	if (*next < 63) {
		if (!dns_label_compress(start, end, &search, next, label_end)) return false;

		/*
		 *	Else it WAS compressed.
		 */
	}

	/*
	 *	The next label wasn't compressed, OR it is invalid,
	 *	skip it.  This check is here only to shut up the
	 *	static analysis tools.
	 */
	if (*next < 0xc0) {
		return false;
	}

	/*
	 *	Remember where our suffix points to.
	 */
	suffix = start + ((next[0] & ~0xc0) << 8) + next[1];

	/*
	 *	Our label now ends with a compressed pointer.  Scan
	 *	the input until we find either an uncompressed label
	 *	which ends with the same compressed pointer, OR we
	 *	find an uncompressed label which ends AT our
	 *	compressed pointer.
	 *
	 *	Note that we start searching from the beginning of the
	 *	label which resulted in us finding the compressed
	 *	pointer!
	 *
	 *	We're guaranteed that any label BEFORE that one
	 *	doesn't end with a matching compressed pointer.
	 */
	q = search;
	while (q < end) {
		if (*q == 0x00) {
			q++;

			/*
			 *	None of the previous stuff matched, so
			 *	we tell the caller to start searching
			 *	from the next name.
			 */
			search = q;
			continue;
		}

		/*
		 *	Skip compressed pointers.  We can't point to
		 *	compressed pointers.
		 */
		if (*q > 63) {
			q += 2;

			/*
			 *	None of the previous uncompressed
			 *	names matched, and this pointer refers
			 *	to a compressed name.  So it doesn't
			 *	match, either.
			 */
			search = q;
			continue;
		}

		/*
		 *	We now have an uncompressed label in the input
		 *	buffer.  Check for a match.
		 */
		ptr = q + *q + 1;
		if (ptr > end) return false;

		/*
		 *	Label lengths aren't the same, skip it.
		 */
		if (*q != *label) {
			q = ptr;
			continue;
		}

		/*
		 *	If the NEXT label is uncompressed, then skip
		 *	it unless it's the suffix we're pointing to.
		 */
		if (*ptr < 63) {
			if (ptr != suffix) {
				q = ptr;
				continue;
			}

			goto check_label;
		}

		/*
		 *	The next label is a compressed pointer.  If
		 *	the compressed pointers are different, then
		 *	skip both this label and the compressed
		 *	pointer after it.
		 */
		if ((ptr[0] != next[0]) ||
		    (ptr[1] != next[1])) {
			q = ptr + 2;

			/*
			 *	None of the previous uncompressed
			 *	names matched, and this pointer refers
			 *	to a compressed name.  So it doesn't
			 *	match, either.
			 */
			search = q;
			continue;
		}

	check_label:
		/*
		 *	Pointer is too far away.  Don't point
		 *	to it.
		 */
		if ((q - start) > (1 << 14)) return false;

		/*
		 *	Only now do case-insensitive
		 *	comparisons.
		 */
		if (!labelcmp(q + 1, label + 1, *label)) {
			q = ptr;
			continue;
		}

		/*
		 *	We have a match.  Replace the input
		 *	label with a compressed pointer.  Tell
		 *	the caller the start of the found
		 *	name, so subsequent searches can start
		 *	from there.  Then return to the caller
		 *	that we managed to compress this
		 *	label.
		 */
		offset = (q - start);
		label[0] = (offset >> 8) | 0xc0;
		label[1] = offset & 0xff;
		*label_end = label + 2;
		if (new_search) *new_search = search;
		return true;
	}

	/*
	 *	Who knows what it is, we couldn't compress it.
	 */
	return false;
}


/** Encode a single value box of type string, serializing its contents to a dns label
 *
 * This functions takes a large buffer and encodes the label in part
 * of the buffer.  This API is necessary in order to allow DNS label
 * compression.
 *
 * @param[out] need	if not NULL, how many bytes are required to serialize
 *			the remainder of the boxed data.
 *			Note: Only variable length types will be partially
 *			encoded. Fixed length types will not be partially encoded.
 * @param[out] buf	Buffer where labels are stored
 * @param[in] buf_len	The length of the output buffer
 * @param[out] where	Where to write this label
 * @param[in] compression Whether or not to do DNS label compression.
 * @param[in] value	to encode.
 * @return
 *	- 0 no bytes were written, see need value to determine
 *	- >0 the number of bytes written to "where", NOT "buf + where + outlen"
 *	- <0 on error.
 */
ssize_t fr_value_box_to_dns_label(size_t *need, uint8_t *buf, size_t buf_len, uint8_t *where, bool compression,
				  fr_value_box_t const *value)
{
	uint8_t *label;
	uint8_t *end = buf + buf_len;
	uint8_t const *q, *strend;
	uint8_t *data;
	int namelen = 0;

	if (!buf || !buf_len || !where || !value) {
		fr_strerror_printf("Invalid input");
		return -1;
	}

	/*
	 *	Don't allow stupidities
	 */
	if (!((where >= buf) && (where < (buf + buf_len)))) {
		fr_strerror_printf("Label is outside of buffer");
		return -1;
	}

	/*
	 *	We can only encode strings.
	 */
	if (value->type != FR_TYPE_STRING) {
		fr_strerror_printf("Asked to encode non-string type");
		return -1;
	}

	if (value->vb_length > 255) {
		fr_strerror_printf("Label is too long");
		return -1;
	}

	/*
	 *	'.' or empty string is special, and is encoded as a
	 *	plain zero byte.
	 *
	 *	Since "where < end", we can always write 1 byte to it.
	 */
	if ((value->vb_length == 0) ||
	    ((value->vb_length == 1) && (value->vb_strvalue[0] == '.'))) {
		*where = 0x00;
		return 1;
	}

	/*
	 *	For now, just encode the value as-is.  We do
	 *	compression as a second step.
	 *
	 *	We need a minimum length of string + beginning length
	 *	+ trailing zero.  Intermediate '.' are converted to
	 *	length bytes.
	 */
	if ((where + value->vb_length + 2) > end) {
	need_more:
		if (need) *need = value->vb_length + 2;
		return 0;
	}

	q = (uint8_t const *) value->vb_strvalue;
	strend = q + value->vb_length;
	label = where;
	*label = 0;
	data = label + 1;

	/*
	 *	@todo - encode into a local buffer, and then try to
	 *	compress that into the output buffer.  This means that
	 *	the output buffer can be a little bit smaller.
	 */
	while (q < strend) {
		/*
		 *	Just for pairanoia
		 */
		if (data >= end) goto need_more;

		/*
		 *	'.' is a label delimiter.
		 *
		 *	'..' is disallowed.  '.' at the start of a
		 *	string is disallowed.
		 */
		if (*q == '.') {
			if (*label == 0) {
				fr_strerror_printf("Empty labels are invalid");
				return -1;
			}

			/*
			 *	'.' at the end of a non-zero label is
			 *	allowed.
			 */
			if ((q + 1) == strend) break;

			/*
			 *	Start a new label.
			 */
			label = data;
			*label = 0;
			data = label + 1;

			q++;
			continue;
		}

		/*
		 *	Label lengths can be 1..63
		 */
		if (*label >= 63) {
			fr_strerror_printf("Label is larger than 63 characters");
			return -1;
		}

		/*
		 *	Name lengths can be 1..255
		 */
		if (namelen >= 255) {
			fr_strerror_printf("Name is larger than 255 characters");
			return -1;
		}

		/*
		 *	Only encode [-0-9a-zA-Z].  Anything else is forbidden.
		 */
		if (!((*q == '-') || ((*q >= '0') && (*q <= '9')) ||
		      ((*q >= 'A') && (*q <= 'Z')) || ((*q >= 'a') && (*q <= 'z')))) {
			fr_strerror_printf("Invalid character %02x in label", *q);
			return -1;
		}

		*(data++) = *(q++);
		(*label)++;
		namelen++;
	}

	*(data++) = 0;		/* end of label */

	/*
	 *	Only one label, don't compress it.  Or, the label is
	 *	already compressed.
	 */
	if (!compression || (buf == where) || ((data - where) <= 2)) goto done;

	/*
	 *	Compress it, AND tell us where the new end buffer is located.
	 */
	(void) dns_label_compress(buf, where, NULL, where, &data);

done:
	if (need) *need = 0;
	return data - where;
}

/** Get the *uncompressed* length of a DNS label in a network buffer.
 *
 *  i.e. how bytes are required to store the uncompressed version of
 *  the label.
 *
 *  Note that a bare 0x00 byte has length 1, to account for '.'
 *
 * @param[in] buf	buffer holding one or more DNS labels
 * @param[in] buf_len	total length of the buffer
 * @param[in,out] next	the DNS label to check, updated to point to the next label
 * @return
 *	- <=0 on error, offset from buf where the invalid label is located.
 *	- > 0 decoded size of this particular DNS label
 */
ssize_t fr_dns_label_length(uint8_t const *buf, size_t buf_len, uint8_t const **next)
{
	uint8_t const *p, *q, *end;
	uint8_t const *current, *start;
	size_t length;
	bool at_first_label;

	if (!buf || (buf_len == 0) || !next) return 0;

	start = *next;

	/*
	 *	Don't allow stupidities
	 */
	if (!((start >= buf) && (start < (buf + buf_len)))) return 0;

	end = buf + buf_len;
	p = current = start;
	length = 0;
	at_first_label = true;

	/*
	 *	We silently accept labels *without* a trailing 0x00,
	 *	so long as they end at the end of the input buffer.
	 */
	while (p < end) {
		/*
		 *	End of label byte.  Skip it.
		 *
		 *	Empty labels are length 1, to account for the
		 *	'.'.  The caller has to take care of this
		 *	manually.
		 */
		if (*p == 0x00) {
			p++;
			if (at_first_label) length++;

			/*
			 *	We're still processing the first
			 *	label, tell the caller where the next
			 *	one is located.
			 */
			if (current == start) {
				*next = p;
			}

			break;
		}
		
		/*
		 *	0b10 and 0b10 are forbidden
		 */
		if ((*p > 63) && (*p < 0xc0)) {
			fr_strerror_printf("Data with invalid high bits");
			return -(p - buf);
		}

		/*
		 *	Maybe it's a compressed pointer.
		 */
		if (*p > 63) {
			uint16_t offset;

			if ((p + 2) > end) {
			overflow:
				fr_strerror_printf("Label overflows buffer");
				return -(p - buf);
			}

			offset = p[1];
			offset += ((*p & ~0xc0) << 8);

			/*
			 *	Forward references are forbidden,
			 *	including self-references.
			 */
			if (offset >= (p - buf)) {
				fr_strerror_printf("Pointer %04x is an invalid forward reference", offset);
				return -(p - buf);
			}

			q = buf + offset;

			/*
			 *	As an additional sanity check, the
			 *	pointer MUST NOT point to something
			 *	within the label we're parsing.  If
			 *	that happens, we have a loop.
			 *
			 *	i.e. the pointer must be backwards to
			 *	*before* our current label.  When that
			 *	limitation is enforced, pointer loops
			 *	are impossible.
			 */
			if (q >= current) {
				fr_strerror_printf("Pointer %04x creates a loop within a label", offset);
				return -(p - buf);
			}


			/*
			 *	The pointer MUST point to a valid
			 *	label length, and not to another
			 *	pointer.
			 */
			if (*q > 63) {
				fr_strerror_printf("Pointer %04x does not point to the start of a label", offset);
				return -(p - buf);
			}

			/*
			 *	If we're jumping away from the label
			 *	we started with, tell the caller where
			 *	the next label is in the network
			 *	buffer.
			 */
			if (current == start) *next = p + 2;

			p = current = q;
			continue;
		}

		/*
		 *	Else it's an uncompressed label
		 */
		if ((p + *p + 1) > end) goto overflow;

		/*
		 *	Account for the '.' on every label after the
		 *	first one.
		 */
		if (!at_first_label) length++;
		at_first_label = false;
		length += *p;

		/*
		 *	DNS names can be no more than 255 octets.
		 */
		if (length > 255) {
			fr_strerror_printf("Total length of labels is > 255");
			return -(p - buf);
		}

		/*
		 *	Verify that the contents of the label are OK.
		 */
		for (q = p + 1; q < p + *p + 1; q++) {
			if (!((*q == '-') || ((*q >= '0') && (*q <= '9')) ||
			      ((*q >= 'A') && (*q <= 'Z')) || ((*q >= 'a') && (*q <= 'z')))) {
				fr_strerror_printf("Invalid character %02x in label", *q);
				return -(q - buf);
			}
		}

		p += *p + 1;
	}

	/*
	 *	Return the length of this label.
	 */
	return length;
}

/** Verify that a network buffer contains valid DNS labels.
 *
 * @param[in] buf	buffer holding one or more DNS labels
 * @param[in] buf_len	total length of the buffer
 * @return
 *	- <=0 on error, where in the buffer the invalid label is located.
 *	- > 0 total size of the labels.  SHOULD be buf_len
 */
ssize_t fr_dns_labels_network_verify(uint8_t const *buf, size_t buf_len)
{
	ssize_t slen;
	uint8_t const *label;
	uint8_t const *end = buf + buf_len;

	for (label = buf; label < end; /* nothing */) {
		slen = fr_dns_label_length(buf, buf_len, &label);
		if (slen < 0) return slen; /* already is offset from 'buf' and not 'label' */
	}

	return buf_len;
}

static ssize_t dns_label_decode(uint8_t const *buf, uint8_t const **start, uint8_t const **next)
{
	uint8_t const *p;

	p = *start;

	if (*p == 0x00) {
		*next = p + 1;
		return 0;
	}

	/*
	 *	Pointer, which MUST point to a valid label, but we don't
	 *	check.
	 */
	if (*p > 63) {
		uint16_t offset;

		offset = p[1];
		offset += ((*p & ~0xc0) << 8);

		p = buf + offset;
	}

	/*
	 *	Tell the caller where the actual label is located.
	 */
	*start = p;
	*next = p + *p + 1;
	return *p;
}


/** Decode a #fr_value_box_t from one DNS label
 *
 * The output type is always FR_TYPE_STRING
 *
 * Note that the caller MUST call fr_dns_labels_network_verify(src, len)
 * before calling this function.  Otherwise bad things will happen.
 *
 * @param[in] ctx	Where to allocate any talloc buffers required.
 * @param[out] dst	value_box to write the result to.
 * @param[in] src	Start of the buffer containing DNS labels
 * @param[in] len	Length of the buffer to decode
 * @param[in] label	This particular label
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- >= 0 The number of network bytes consumed.
 *	- <0 on error.
 */
ssize_t fr_value_box_from_dns_label(TALLOC_CTX *ctx, fr_value_box_t *dst,
				    uint8_t const *src, size_t len, uint8_t const *label,
				    bool tainted)
{
	ssize_t slen;
	uint8_t const *after = label;
	uint8_t const *current, *next;
	uint8_t *p;
	char *q;

	/*
	 *	Get the uncompressed length of the label, and the
	 *	label after this one.
	 */
	slen = fr_dns_label_length(src, len, &after);
	if (slen <= 0) return slen;

	dst->type = FR_TYPE_STRING;
	dst->tainted = tainted;
	dst->enumv = NULL;
	dst->next = NULL;

	/*
	 *	An empty label is a 0x00 byte.  Just create an empty
	 *	string.
	 */
	if (slen == 1) {
		dst->vb_strvalue = q = talloc_array(ctx, char, 2);
		q[0] = '.';
		q[1] = '\0';
		dst->datum.length = 1;
		return after - label;
	}

	/*
	 *	Allocate the string and set up the value_box
	 */
	dst->vb_strvalue = q = talloc_array(ctx, char, slen + 1);
	dst->datum.length = slen;

	current = label;
	p = (uint8_t *) q;
	q += slen;

	while (*current != 0x00) {
		/*
		 *	Get how many bytes this label has, and where
		 *	we will go to obtain the next label.
		 */
		slen = dns_label_decode(src, &current, &next);
		if (slen < 0) {
		fail:
			fr_value_box_clear(dst);
			return -1;
		}

		/*
		 *	As a sanity check, ensure we don't have a
		 *	buffer overflow.
		 */
		if ((p + slen) > (uint8_t *) q) {
			goto fail;
		}

		/*
		 *	Add '.' before the label, but only for the
		 *	second and subsequent labels.
		 */
		if (p != (uint8_t const *) dst->vb_strvalue) {
			*(p++) = '.';
		}

		/*
		 *	Copy the raw bytes from the network.
		 */
		memcpy(p, current + 1, slen);

		/*
		 *	Go ahead in the output string, and go to the
		 *	next label for decoding.
		 */
		p += slen;
		current = next;
	}

	/*
	 *	As a last sanity check, ensure that we've filled the
	 *	buffer exactly.
	 */
	if (p != (uint8_t *) q) {
		goto fail;
	}

	*p = '\0';

	/*
	 *	Return the number of network bytes used to parse this
	 *	part of the label.
	 */
	return after - label;
}
