#include <freeradius-devel/util/cbor.h>
#include <freeradius-devel/io/test_point.h>

static ssize_t decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
			   uint8_t const *data, size_t data_len, UNUSED void *decode_ctx)
{
	fr_dbuff_t dbuff;
	uint8_t field = 0;
	ssize_t slen;

	fr_dbuff_init(&dbuff, data, data_len);

	FR_DBUFF_OUT_RETURN(&field, &dbuff);
	if (field != 0x9f) {
		fr_strerror_printf("Invalid cbor header - expected indefinite array 9f, got %02x",
				   field);
		return -1;
	}

	do {
		if (fr_dbuff_extend_lowat(NULL, &dbuff, 1) == 0) {
			fr_strerror_printf("Invalid cbor header - unexpected end of data");
			return -fr_dbuff_used(&dbuff);
		}

		field = *fr_dbuff_current(&dbuff);
		if (field == 0xff) {
			fr_dbuff_advance(&dbuff, 1);
			break;
		}

		slen = fr_cbor_decode_pair(ctx, out, &dbuff, parent, false);
		if (slen <= 0) return FR_DBUFF_ERROR_OFFSET(slen, fr_dbuff_used(&dbuff));
	} while (true);

	return fr_dbuff_used(&dbuff);
}

static ssize_t encode_pair(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED void *encode_ctx)
{
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);
	fr_pair_t *vp;

	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) 0x9f); /* indefinite array */

	for (vp = fr_dcursor_current(cursor);
	       vp != NULL;
	       vp = fr_dcursor_next(cursor)) {
		ssize_t slen;

		slen = fr_cbor_encode_pair(&work_dbuff, vp);
		if (slen <= 0) return FR_DBUFF_ERROR_OFFSET(slen, fr_dbuff_used(&work_dbuff));
	}

	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) 0xff); /* end of indefinite array */

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/*
 *	Test points
 */
extern fr_test_point_pair_encode_t cbor_tp_encode_pair;
fr_test_point_pair_encode_t cbor_tp_encode_pair = {
	.func		= encode_pair,
};

extern fr_test_point_pair_decode_t cbor_tp_decode_pair;
fr_test_point_pair_decode_t cbor_tp_decode_pair = {
	.func		= decode_pair
};

static int decode_test_ctx(void **out, UNUSED TALLOC_CTX *ctx, fr_dict_t const *dict,
			   UNUSED fr_dict_attr_t const *root_da)
{
	*out = UNCONST(fr_dict_t *, dict);

	return 0;
}

static ssize_t encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_list_t *vps, uint8_t *data, size_t data_len, UNUSED void *proto_ctx)
{
	fr_dbuff_t dbuff;
	fr_dcursor_t cursor;

	FR_DBUFF_INIT(&dbuff, data, data_len);

	fr_pair_dcursor_init(&cursor, vps);
	return encode_pair(&dbuff, &cursor, NULL);
}

static ssize_t decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *out, uint8_t const *data, size_t data_len, void *proto_ctx)
{
	fr_dict_t *dict = proto_ctx;

	return decode_pair(ctx, out, fr_dict_root(dict), data, data_len, proto_ctx);
}

extern fr_test_point_proto_encode_t cbor_tp_encode_proto;
fr_test_point_proto_encode_t cbor_tp_encode_proto = {
	.func		= encode_proto
};

extern fr_test_point_proto_decode_t cbor_tp_decode_proto;
fr_test_point_proto_decode_t cbor_tp_decode_proto = {
	.test_ctx	= decode_test_ctx,
	.func		= decode_proto
};
