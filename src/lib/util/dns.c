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
 * @copyright 2019 Network RADIUS SARL (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/dns.h>
#include <freeradius-devel/util/proto.h>

#define MAX_OFFSET (1 << 14)

static int dns_label_add(fr_dns_labels_t *lb, uint8_t const *start, uint8_t const *end)
{
	size_t offset, size = end - start;
	fr_dns_block_t *block;

	/*
	 *	If we don't care about tracking the blocks, then don't
	 *	do anything.
	 */
	if (!lb) return 0;

	fr_assert(start >= lb->start);
	fr_assert(end >= start);

	offset = start - lb->start;

	/*
	 *	DNS packets can be up to 64K in size, but the
	 *	compressed pointers can only be up to 2^14 in size.
	 *	So we just ignore offsets which are greater than 2^14.
	 */
	if ((offset + size) >= MAX_OFFSET) return 0;

	/*
	 *	We're not tracking labels, so don't do anything.
	 */
	if (lb->max == 1) return 0;

	FR_PROTO_TRACE("adding label at offset %zu", offset);

	/*
	 *	We add blocks append-only.  No adding new blocks in
	 *	the middle of a packet.
	 */
	block = &lb->blocks[lb->num - 1];
	fr_assert(block->start <= offset);
	fr_assert(offset);

	FR_PROTO_TRACE("Last block (%d) is %u..%u", lb->num - 1, block->start, block->end);

	/*
	 *	Fits within an existing block.
	 */
	if (block->end == offset) {
		block->end += size;
		FR_PROTO_TRACE("Expanding last block (%d) to %u..%u", lb->num - 1, block->start, block->end);
		return 0;
	}

	/*
	 *	It's full, die.
	 */
	if (lb->num == lb->max) return -1;

	lb->num++;
	block++;

	block->start = offset;
	block->end = offset + size;
	FR_PROTO_TRACE("Appending block (%d) to %u..%u", lb->num - 1, block->start, block->end);

	return 0;
}

static void dns_label_mark(fr_dns_labels_t *lb, uint8_t const *p)
{
	if (!lb || !lb->mark) return;

	fr_assert(p >= (lb->start + 12)); /* can't point to the packet header */
	fr_assert(!lb->end || (p < lb->end));

	lb->mark[p - lb->start] = 1;
}


static bool dns_pointer_valid(fr_dns_labels_t *lb, uint16_t offset)
{
	int i;

	if (!lb) return true;	/* we have no idea, so allow it */

	if (lb->mark) return (lb->mark[offset] != 0);

	/*
	 *	Brute-force searching.
	 *
	 *	@todo - manually walk through the pointers for the block?
	 */
	for (i = 0; i < lb->num; i++) {
		FR_PROTO_TRACE("Checking block %d %u..%u against %u",
			       i, lb->blocks[i].start, lb->blocks[i].end, offset);

		if (offset < lb->blocks[i].start) return false;

		if (offset < lb->blocks[i].end) return true;
	}

	return false;
}

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
		if (!(((*a >= 'a') && (*a <= 'z')) || ((*a >= 'A') && (*a <= 'Z')))) return false;
		if (!(((*b >= 'a') && (*b <= 'z')) || ((*b >= 'A') && (*b <= 'Z')))) return false;

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

/** Compress "label" by looking at the label recursively.
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
 *  Note that this function does NOT follow pointers in the input
 *  buffer!
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
 * @param[in] packet	  where the packet starts
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
static bool dns_label_compress(uint8_t const *packet, uint8_t const *start, uint8_t const *end, uint8_t const **new_search,
			       uint8_t *label, uint8_t **label_end)
{
	uint8_t *next;
	uint8_t const *q, *ptr, *suffix, *search;
	uint16_t offset;
	bool compressed = false;

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
			if ((q - packet) > (1 << 14)) return false;

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
			offset = (q - packet);
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
		if (!dns_label_compress(packet, start, end, &search, next, label_end)) return false;

		/*
		 *	Else it WAS compressed.
		 */
		compressed = true;
	}

	/*
	 *	The next label wasn't compressed, OR it is invalid,
	 *	skip it.  This check is here only to shut up the
	 *	static analysis tools.
	 */
	if (*next < 0xc0) {
		return compressed;
	}

	/*
	 *	Remember where our suffix points to.
	 */
	suffix = packet + ((next[0] & ~0xc0) << 8) + next[1];

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
		if (ptr > end) return compressed;

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
		if ((q - packet) > (1 << 14)) return compressed;

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
		offset = (q - packet);
		label[0] = (offset >> 8) | 0xc0;
		label[1] = offset & 0xff;
		*label_end = label + 2;
		if (new_search) *new_search = search;
		return true;
	}

	/*
	 *	Who knows what it is, we couldn't compress it.
	 */
	return compressed;
}


/** Encode a single value box of type string, serializing its contents to a dns label
 *  in a dbuff
 *
 * @param[in] dbuff	Buffer where labels are written
 * @param[in] compression Whether or not to do DNS label compression.
 * @param[in] value	to encode.
 * @return
 *	- >0 the number of bytes written to the dbuff
 *	- 0 could not encode anything, an error has occurred.
 *	- <0 the number of bytes the dbuff should have had, instead of "remaining".
 */
ssize_t fr_dns_label_from_value_box_dbuff(fr_dbuff_t *dbuff, bool compression, fr_value_box_t const *value, fr_dns_labels_t *lb)
{
	ssize_t			slen;
	size_t			need = 0;

	slen = fr_dns_label_from_value_box(&need, dbuff->p, fr_dbuff_remaining(dbuff), dbuff->p, compression, value, lb);
	if (slen < 0) return 0;

	if (slen == 0) return -need;

	fr_dbuff_advance(dbuff, (size_t)slen);
	return slen;
}

/** Encode a single value box of type string, serializing its contents to a dns label
 *
 * This functions takes a large buffer and encodes the label in part
 * of the buffer.  This API is necessary in order to allow DNS label
 * compression.
 *
 * @param[out] need	if not NULL, how long "buf_len" should be to
 *			serialize the rest of the data.
 *			Note: Only variable length types will be partially
 *			encoded. Fixed length types will not be partially encoded.
 * @param[out] buf	Buffer where labels are stored
 * @param[in] buf_len	The length of the output buffer
 * @param[out] where	Where to write this label
 * @param[in] compression Whether or not to do DNS label compression.
 * @param[in] value	to encode.
 * @param[in] lb	label tracking data structure
 * @return
 *	- 0 no bytes were written, see need value to determine
 *	- >0 the number of bytes written to "where", NOT "buf + where + outlen"
 *	- <0 on error.
 */
ssize_t fr_dns_label_from_value_box(size_t *need, uint8_t *buf, size_t buf_len, uint8_t *where, bool compression,
				    fr_value_box_t const *value, fr_dns_labels_t *lb)
{
	uint8_t *label;
	uint8_t const *end = buf + buf_len;
	uint8_t const *q, *strend, *last;
	uint8_t *data;
	bool underscore = true;

	if (!buf || !buf_len || !where || !value) {
		fr_strerror_const("Invalid input");
		return -1;
	}

	/*
	 *	Don't allow stupidities
	 */
	if (!((where >= buf) && (where < (buf + buf_len)))) {
		fr_strerror_const("Label to write is outside of buffer");
		return -1;
	}

	/*
	 *	We can only encode strings.
	 */
	if (value->type != FR_TYPE_STRING) {
		fr_strerror_const("Asked to encode non-string type");
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
	 *	Sanity check the name before writing anything to the
	 *	buffer.
	 *
	 *	Only encode [-0-9a-zA-Z].  Anything else is forbidden.
	 *	Dots at the start are forbidden.  Double dots are
	 *	forbidden.
	 */
	q = (uint8_t const *) value->vb_strvalue;
	strend = q + value->vb_length;
	last = q;

	if (*q == '.') {
		fr_strerror_const("Empty labels are invalid");
		return -1;
	}

	/*
	 *	Convert it piece by piece.
	 */
	while (q < strend) {
		/*
		 *	Allow underscore at the start of a label.
		 */
		if (underscore) {
			underscore = false;

			if (*q == '_') goto next;
		}

		if (*q == '.') {
			/*
			 *	Don't count final dot as an
			 *	intermediate dot, and don't bother
			 *	encoding it.
			 */
			if ((q + 1) == strend) {
				strend--;
				break;
			}

			if (q[1] == '.') {
				fr_strerror_const("Double dots '..' are forbidden");
				return -1;
			}
			last = q;

			/*
			 *	We had a dot, allow underscore as the
			 *	first character of the next label.
			 */
			underscore = true;

		} else if (!((*q == '-') || ((*q >= '0') && (*q <= '9')) ||
			     ((*q >= 'A') && (*q <= 'Z')) || ((*q >= 'a') && (*q <= 'z')))) {
			fr_strerror_printf("Invalid character 0x%02x in label", *q);
			return -1;
		}

	next:
		q++;

		if ((q - last) > 63) {
			fr_strerror_const("Label is larger than 63 characters");
			return -1;
		}
	}

	q = (uint8_t const *) value->vb_strvalue;

	/*
	 *	For now, just encode the value as-is.  We do
	 *	compression as a second step.
	 *
	 *	We need a minimum length of string + beginning length
	 *	+ trailing zero.  Intermediate '.' are converted to
	 *	length bytes.
	 */
	if ((where + (strend - q) + 2) > end) {
		if (need) *need = (where + (strend - q) + 2) - buf;
		return 0;
	}

	label = where;
	*label = 0;
	data = label + 1;

	/*
	 *	@todo - encode into a local buffer, and then try to
	 *	compress that into the output buffer.  This means that
	 *	the output buffer can be a little bit smaller.
	 */
	while (q < strend) {
		fr_assert(data < end);
		fr_assert((data - where) < 255);

		/*
		 *	'.' is a label delimiter.
		 *
		 *	We've already checked above for '.' at the
		 *	start, for double dots, and have already
		 *	suppressed '.' at the end of the string.
		 *
		 *	Start a new label.
		 */
		if (*q == '.') {
			label = data;
			*label = 0;
			data = label + 1;

			q++;
			continue;
		}

		*(data++) = *(q++);
		(*label)++;
		fr_assert(*label <= 63);
	}

	*(data++) = 0;		/* end of label */

	/*
	 *	If we're compressing it, and we have data to compress,
	 *	then do it.
	 */
	if (compression && ((data - where) > 2)) {
		if (lb) {
			int i;

			/*
			 *	Loop over the parts of the packet which have DNS labels.
			 *
			 *	Note that the dns_label_compress() function does NOT follow pointers in the
			 *	start/end block which it's searching!  It just tries to compress the *input*,
			 *	and assumes that the input is compressed last label to first label.
			 *
			 *	In addition, dns_label_compress() tracks where in the block it started
			 *	searching.  So it only scans the block once, even if we pass a NULL search
			 *	parameter to it.
			 *
			 *	We could start compression from the *last* block.  When we add
			 *	"www.example.com" and then "ftp.example.com", we could point "ftp" to the
			 *	"example.com" portion. which is already in the packet.  However, doing that
			 *	would require that dns_label_compress() follows pointers in the block it's
			 *	searching. Which would greatly increase the complexity of the algorithm.
			 *
			 *
			 *	We could still optimize this algorithm a bit, by tracking which parts of the
			 *	buffer have DNS names of label length 1, 2, etc.  Doing that would mean more
			 *	complex data structures, but fewer passes over the packet.
			 */
			for (i = 0; i < lb->num; i++) {
				bool compressed;

				FR_PROTO_TRACE("Trying to compress %s in block %d of %u..%u",
					       value->vb_strvalue, i,
					       lb->blocks[i].start, lb->blocks[i].end);

				compressed = dns_label_compress(lb->start, lb->start + lb->blocks[i].start,
								lb->start + lb->blocks[i].end,
								NULL, where, &data);
				if (compressed) {
					FR_PROTO_TRACE("Compressed label in block %d", i);
					if (*(where + *where + 1) >= 0xc0) {
						FR_PROTO_TRACE("Next label is compressed, stopping");
					}
				}
			}

			dns_label_add(lb, where, data);

		} else if (buf != where) {
			if (dns_label_compress(buf, buf, where, NULL, where, &data)) {
				FR_PROTO_TRACE("Compressed single label %s to %zu bytes",
					       value->vb_strvalue, data - where);
			} else {
				FR_PROTO_TRACE("Did not compress single label");
			}
		}
	} else {
		FR_PROTO_TRACE("Not compressing label");
	}

	fr_assert(data > where);
	return data - where;
}

/** Get the *uncompressed* length of a DNS label in a network buffer.
 *
 *  i.e. how bytes are required to store the uncompressed version of
 *  the label.
 *
 *  Note that a bare 0x00 byte has length 1, to account for '.'
 *
 * @param[in] packet	  where the packet starts
 * @param[in] buf	buffer holding one or more DNS labels
 * @param[in] buf_len	total length of the buffer
 * @param[in,out] next	the DNS label to check, updated to point to the next label
 * @param[in] lb	label tracking data structure
 * @return
 *	- <=0 on error, offset from buf where the invalid label is located.
 *	- > 0 decoded size of this particular DNS label
 */
ssize_t fr_dns_label_uncompressed_length(uint8_t const *packet, uint8_t const *buf, size_t buf_len, uint8_t const **next, fr_dns_labels_t *lb)
{
	uint8_t const *p, *q, *end, *label_end;
	uint8_t const *current, *start;
	size_t length;
	bool at_first_label, already_set_next;

	if (!packet || !buf || (buf_len == 0) || !next) {
		fr_strerror_printf("Invalid argument");
		return 0;
	}

	start = *next;

	/*
	 *	Don't allow stupidities
	 */
	if (!((start >= packet) && (start < (buf + buf_len)))) {
		fr_strerror_printf("Label is not within the buffer");
		return 0;
	}

	end = buf + buf_len;
	p = current = start;
	length = 0;
	at_first_label = true;
	already_set_next = false;

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
				already_set_next = true;
			}

			break;
		}

		/*
		 *	If there's only one byte in the packet, then
		 *	it MUST be 0x00.  If it's not, then the label
		 *	overflows the buffer.
		 */
		if ((p + 1) >= end) goto overflow;

		/*
		 *	0b10 and 0b10 are forbidden
		 */
		if ((*p > 63) && (*p < 0xc0)) {
			fr_strerror_const("Data with invalid high bits");
			return -(p - packet);
		}

		/*
		 *	Maybe it's a compressed pointer.
		 */
		if (*p > 63) {
			uint16_t offset;

			if ((p + 2) > end) {
			overflow:
				fr_strerror_const("Label overflows buffer");
				return -(p - packet);
			}

			offset = p[1];
			offset += ((*p & ~0xc0) << 8);

			/*
			 *	Forward references are forbidden,
			 *	including self-references.
			 *
			 *	This requirement follows RFC 1035
			 *	Section 4.1.4, which says:
			 *
			 *	... an entire domain name or a list of
			 *	labels at the end of a domain name is
			 *	replaced with a pointer to a prior
			 *	occurance of the same name.
			 *	...
			 *
			 *	Note the key word PRIOR.  If we
			 *	enforce that the pointer is backwards,
			 *	and do various other enforcements,
			 *	then it is very difficult for
			 *	attackers to create malicious DNS
			 *	packets which will cause the decoder
			 *	to do bad things.
			 */
			if (offset >= (p - packet)) {
				fr_strerror_printf("Pointer %04x at offset %04x is an invalid forward reference",
						   offset, (int) (p - packet));
				return -(p - packet);
			}

			q = packet + offset;

			/*
			 *	As an additional sanity check, the
			 *	pointer MUST NOT point to something
			 *	within the label we're parsing.  If
			 *	that happens, we have a loop.
			 *
			 *	i.e. the pointer must point backwards
			 *	to *before* our current label.  When
			 *	that limitation is enforced, pointer
			 *	loops are impossible.
			 */
			if (q >= current) {
				fr_strerror_printf("Pointer %04x at offset %04x creates a loop within a label",
						   offset, (int) (p - packet));
				return -(p - packet);
			}

			/*
			 *	If we're tracking which labels are
			 *	valid, then check the pointer, too.
			 */
			if (!dns_pointer_valid(lb, offset)) {
				fr_strerror_printf("Pointer %04x at offset %04x does not point to a DNS label",
						   offset, (int) (p - packet));
				return -(p - packet);
			}

			/*
			 *	The pointer MUST point to a valid
			 *	length field, and not to another
			 *	pointer.
			 */
			if (*q > 63) {
				fr_strerror_printf("Pointer %04x at offset %04x does not point to the start of a label",
						   offset, (int) (p - packet));
				return -(p - packet);
			}

			/*
			 *	The pointer MUST NOT point to an end of label field.
			 */
			if (!*q) {
				fr_strerror_printf("Pointer %04x at offset %04x refers to an invalid field", offset,
						   (int) (p - packet));
				return -(p - packet);
			}

			/*
			 *	If we're jumping away from the label
			 *	we started with, tell the caller where
			 *	the next label is in the network
			 *	buffer.
			 */
			if (current == start) {
				*next = p + 2;
				already_set_next = true;
			}

			p = current = q;
			continue;
		}

		/*
		 *	Else it's an uncompressed label
		 */
		if ((p + *p + 1) > end) goto overflow;

		/*
		 *	It's a valid label.  Mark it as such.
		 */
		dns_label_mark(lb, p);

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
			fr_strerror_const("Total length of labels is > 255");
			return -(p - packet);
		}

		q = p + 1;
		label_end = q + *p;

		/*
		 *	Allow for underscore at the beginning of a
		 *	label.
		 */
		if (*q == '_') q++;

		/*
		 *	Verify that the contents of the label are OK.
		 */
		while (q < label_end) {
			if (!((*q == '-') || ((*q >= '0') && (*q <= '9')) ||
			      ((*q >= 'A') && (*q <= 'Z')) || ((*q >= 'a') && (*q <= 'z')))) {
				fr_strerror_printf("Invalid character 0x%02x in label", *q);
				return -(q - packet);
			}

			q++;
		}

		p += *p + 1;
	}

	/*
	 *	Return the length of this label.
	 */
	if (!already_set_next) *next = p; /* should be <='end' */

	/*
	 *	Add the label, only if we're not using the markup field.
	 */
	if (lb && !lb->mark) (void) dns_label_add(lb, start, *next);

	return length;
}

/** Verify that a network buffer contains valid DNS labels.
 *
 * @param[in] packet	  where the packet starts
 * @param[in] buf	buffer holding one or more DNS labels
 * @param[in] buf_len	total length of the buffer
 * @param[in] start	where to start looking
 * @param[in] lb	label tracking data structure
 * @return
 *	- <=0 on error, where in the buffer the invalid label is located.
 *	- > 0 total size of the encoded label(s).  Will be <= buf_len
 */
ssize_t fr_dns_labels_network_verify(uint8_t const *packet, uint8_t const *buf, size_t buf_len, uint8_t const *start, fr_dns_labels_t *lb)
{
	ssize_t slen;
	uint8_t const *label = start;
	uint8_t const *end = buf + buf_len;

	while (label < end) {
		if (*label == 0x00) {
			label++;
			break;
		}

		slen = fr_dns_label_uncompressed_length(packet, buf, buf_len, &label, lb);
		if (slen <= 0) return slen; /* already is offset from 'buf' and not 'label' */
	}

	return label - buf;
}

static ssize_t dns_label_decode(uint8_t const *packet, uint8_t const *end, uint8_t const **start, uint8_t const **next)
{
	uint8_t const *p, *q;

	p = *start;

	if (end == packet) return -1;

	if (*p == 0x00) {
		*next = p + 1;
		return 0;
	}

	/*
	 *	Pointer, which points somewhere in the packet.
	 */
	if (*p >= 0xc0) {
		uint16_t offset;

		if ((end - packet) < 2) {
			return -(p - packet);
		}

		offset = p[1];
		offset += ((*p & ~0xc0) << 8);

		q = packet + offset;
		if (q >= p) {
			return -(p - packet);
		}
		p = q;
	}

	/*
	 *	0b10 and 0b10 are forbidden, and pointers can't point to other pointers.
	 */
	if (*p > 63) return -(p - packet);

	if ((p + *p + 1) > end) {
		return -(p - packet);
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
 * Note that the caller MUST call fr_dns_labels_network_verify(src, len, start)
 * before calling this function.  Otherwise bad things will happen.
 *
 * @param[in] ctx	Where to allocate any talloc buffers required.
 * @param[out] dst	value_box to write the result to.
 * @param[in] src	Start of the buffer containing DNS labels
 * @param[in] len	Length of the buffer to decode
 * @param[in] label	This particular label
 * @param[in] tainted	Whether the value came from a trusted source.
 * @param[in] lb	label tracking data structure
 * @return
 *	- >= 0 The number of network bytes consumed.
 *	- <0 on error.
 */
ssize_t fr_dns_label_to_value_box(TALLOC_CTX *ctx, fr_value_box_t *dst,
				  uint8_t const *src, size_t len, uint8_t const *label,
				  bool tainted, fr_dns_labels_t *lb)
{
	ssize_t slen;
	uint8_t const *after = label;
	uint8_t const *current, *next = NULL;
	uint8_t const *packet = src;
	uint8_t const *end = packet + len;
	uint8_t *p;
	char *q;

	if (!len) return -1;

	/*
	 *	The label must be within the current buffer we're
	 *	passed.
	 */
	if ((label < src) || (label >= end)) return -1;

	/*
	 *	The actual packet might start earlier than the buffer,
	 *	so reset it if necessary.
	 */
	if (lb) packet = lb->start;

	/*
	 *	Get the uncompressed length of the label, and the
	 *	label after this one.
	 */
	slen = fr_dns_label_uncompressed_length(packet, src, len, &after, lb);
	if (slen <= 0) {
		FR_PROTO_TRACE("dns_label_to_value_box - Failed getting length");
		return slen;
	}

	fr_value_box_init_null(dst);

	/*
	 *	An empty label is a 0x00 byte.  Just create an empty
	 *	string.
	 */
	if (slen == 1) {
		if (fr_value_box_bstr_alloc(ctx, &q, dst, NULL, 1, tainted) < 0) return -1;
		q[0] = '.';
		return after - label;
	}

	/*
	 *	Allocate the string and set up the value_box
	 */
	if (fr_value_box_bstr_alloc(ctx, &q, dst, NULL, slen, tainted) < 0) return -1;

	current = label;
	p = (uint8_t *) q;
	q += slen;

	while (current && (current < after) && (*current != 0x00)) {
		/*
		 *	Get how many bytes this label has, and where
		 *	we will go to obtain the next label.
		 */
		slen = dns_label_decode(packet, end, &current, &next);
		if (slen < 0) return slen;

		/*
		 *	As a sanity check, ensure we don't have a
		 *	buffer overflow.
		 */
		if ((p + slen) > (uint8_t *) q) {
			FR_PROTO_TRACE("dns_label_to_value_box - length %zd Failed at %d", slen, __LINE__);

		fail:
			fr_value_box_clear(dst);
			return -1;
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
		FR_PROTO_TRACE("dns_label_to_value_box - Failed at %d", __LINE__);
		goto fail;
	}

	*p = '\0';

	/*
	 *	Return the number of network bytes used to parse this
	 *	part of the label.
	 */
	return after - label;
}
