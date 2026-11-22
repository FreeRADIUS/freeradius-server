/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

/**
 * @file src/fuzzer/fuzzer_rlm_eap_tls.c
 * @brief Drive fixture-backed EAP-TLS, PEAP and TTLS handshakes with a reply-aware client.
 *
 * Input layout:
 *	byte 0		profile (0 = EAP-TLS, 1 = PEAP, 2 = TTLS)
 *	byte 1		client step at which fuzzed data replaces the normal client response
 *	bytes 2..	"FUZZ"-delimited packets
 *
 * The harness behaves as a conforming client (in-process OpenSSL client over memory BIOs,
 * EAP-TLS fragmentation and ACKs, State replay) until the selected step.  From there on,
 * each packet is sent as a raw EAP frame while the handshake is in progress, or written as
 * plaintext into the client TLS session once a PEAP/TTLS tunnel is established.
 */
#define LLVMFuzzerInitialize rlm_eap_fuzzer_initialize
#define LLVMFuzzerTestOneInput rlm_eap_fuzzer_test_one_input
#undef RCSID
#define RCSID(_id)
#include "fuzzer_rlm_eap.c"
#undef RCSID
#undef LLVMFuzzerInitialize
#undef LLVMFuzzerTestOneInput

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../lib/eap/types.h"

#define EAP_BUF_MAX	8192
#define CHUNK_SIZE	1000
#define MAX_ROUNDS	48

static char const fixture_user[] = "fuzz-user";

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(uint8_t const *buf, size_t len);

typedef struct {
	uint8_t		data[EAP_BUF_MAX];
	size_t		len;
	bool		valid;
} eap_buf_t;

typedef struct {
	TALLOC_CTX	*ctx;
	CONF_SECTION	*server;
	fr_pair_t	*state;
	SSL		*ssl;
	unsigned int	profile;
	unsigned int	step;
	uint8_t		type;
	uint8_t		id;
	bool		tunnel_sent;
} tls_client_t;

static SSL_CTX *client_ctx;

static void exchange(tls_client_t *c, eap_frame_t const *frame, eap_buf_t *out)
{
	request_t *request;
	fr_pair_t *vp;

	out->len = 0;
	out->valid = false;

	request = request_alloc(c->ctx, c->server, frame, c->state);
	talloc_free(c->state);
	c->state = NULL;
	if (!request) return;

	if (fr_timer_in(request, el->tl, &request->timeout, fr_time_delta_from_msec(10),
			false, cancel_request, request) >= 0) {
		unlang_interpret_synchronous(el, request);

		vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_state);
		if (vp) c->state = fr_pair_copy(c->ctx, vp);

		for (vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_eap_message);
		     vp;
		     vp = fr_pair_find_by_da(&request->reply_pairs, vp, attr_eap_message)) {
			if (vp->vp_length > (EAP_BUF_MAX - out->len)) break;
			memcpy(out->data + out->len, vp->vp_octets, vp->vp_length);
			out->len += vp->vp_length;
			out->valid = true;
		}
	}

	FR_TIMER_DISARM(request->timeout);
	talloc_free(request);
}

static void send_raw(tls_client_t *c, uint8_t const *packet, size_t len, eap_buf_t *out)
{
	eap_frame_t frame;

	eap_frame_parse(&frame, packet, len);
	exchange(c, &frame, out);
}

static void send_tls(tls_client_t *c, uint8_t flags, uint8_t const *data, size_t len, size_t total, eap_buf_t *out)
{
	uint8_t packet[EAP_BUF_MAX];
	size_t hdr = 6, eap_len;

	packet[0] = FR_EAP_CODE_RESPONSE;
	packet[1] = c->id;
	packet[4] = c->type;
	packet[5] = flags;
	if (flags & 0x80) {
		packet[6] = (total >> 24) & 0xff;
		packet[7] = (total >> 16) & 0xff;
		packet[8] = (total >> 8) & 0xff;
		packet[9] = total & 0xff;
		hdr = 10;
	}
	if (len) memcpy(packet + hdr, data, len);
	eap_len = hdr + len;
	packet[2] = (eap_len >> 8) & 0xff;
	packet[3] = eap_len & 0xff;

	c->step++;
	send_raw(c, packet, eap_len, out);
}

static size_t drain_client(tls_client_t *c, uint8_t *out, size_t max)
{
	BIO *wbio = SSL_get_wbio(c->ssl);
	size_t len = 0;
	int n;

	while ((len < max) && (BIO_ctrl_pending(wbio) > 0)) {
		n = BIO_read(wbio, out + len, (int)(max - len));
		if (n <= 0) break;
		len += (size_t)n;
	}
	return len;
}

/*
 *	Parse the server request into c->id/c->type, and return TLS payload.
 */
static bool parse_request(tls_client_t *c, eap_buf_t const *in, uint8_t *flags, uint8_t const **payload, size_t *plen)
{
	size_t hdr, eap_len;

	if (!in->valid || (in->len < 6) || (in->data[0] != FR_EAP_CODE_REQUEST)) return false;

	eap_len = ((size_t)in->data[2] << 8) | in->data[3];
	if (eap_len > in->len) return false;

	c->id = in->data[1];
	c->type = in->data[4];
	*flags = in->data[5];
	hdr = (*flags & 0x80) ? 10 : 6;
	if (eap_len < hdr) return false;

	*payload = in->data + hdr;
	*plen = eap_len - hdr;
	return true;
}

/*
 *	Send an outbound TLS buffer as EAP-TLS fragments, following server ACKs.
 */
static void send_fragments(tls_client_t *c, uint8_t const *data, size_t len, eap_buf_t *reply)
{
	size_t off = 0;
	uint8_t flags;
	uint8_t const *payload;
	size_t plen;

	do {
		size_t chunk = len - off;
		bool more;

		if (chunk > CHUNK_SIZE) chunk = CHUNK_SIZE;
		more = (off + chunk) < len;
		flags = (more ? 0x40 : 0) | (off == 0 ? 0x80 : 0);
		if ((off == 0) && !more) flags = 0;

		send_tls(c, flags, data + off, chunk, len, reply);
		off += chunk;

		if (more && (!parse_request(c, reply, &flags, &payload, &plen) || plen != 0)) return;
	} while (off < len);
}

static void inject(tls_client_t *c, uint8_t const *buf, size_t len)
{
	uint8_t const *frame, *next, *end = buf + len;
	uint8_t tls_out[EAP_BUF_MAX];
	eap_buf_t reply;

	frame = buf;
	while (frame < end) {
		size_t flen;

		next = memmem(frame, end - frame, frame_delimiter, sizeof(frame_delimiter) - 1);
		flen = next ? (size_t)(next - frame) : (size_t)(end - frame);

		if ((c->profile != 0) && c->ssl && SSL_is_init_finished(c->ssl)) {
			size_t out_len;

			if (flen > 0) (void)SSL_write(c->ssl, frame, (int)flen);
			out_len = drain_client(c, tls_out, sizeof(tls_out));
			if (out_len > 0) send_fragments(c, tls_out, out_len, &reply);
		} else {
			send_raw(c, frame, flen, &reply);
		}

		if (!next) break;
		frame = next + sizeof(frame_delimiter) - 1;
	}
}

static size_t inner_response(tls_client_t *c, uint8_t *out)
{
	size_t user_len = sizeof(fixture_user) - 1;

	if (c->profile == 1) {
		size_t len = 5 + user_len;

		out[0] = FR_EAP_CODE_RESPONSE;
		out[1] = 0;
		out[2] = 0;
		out[3] = len;
		out[4] = FR_EAP_METHOD_IDENTITY;
		memcpy(out + 5, fixture_user, user_len);
		return len;
	}

	/* TTLS: User-Name AVP, padded to four octets */
	out[0] = 0;
	out[1] = 0;
	out[2] = 0;
	out[3] = 1;
	out[4] = 0x40;
	out[5] = 0;
	out[6] = 0;
	out[7] = 8 + user_len;
	memcpy(out + 8, fixture_user, user_len);
	memset(out + 8 + user_len, 0, 3);
	return 8 + ((user_len + 3) & ~(size_t)3);
}

static void drive(tls_client_t *c, unsigned int fuzz_step, uint8_t const *fuzz, size_t fuzz_len)
{
	uint8_t identity[5 + sizeof(fixture_user)];
	uint8_t nak[6] = { FR_EAP_CODE_RESPONSE, 1, 0, 6, FR_EAP_METHOD_NAK, FR_EAP_METHOD_TTLS };
	uint8_t tls_in[EAP_BUF_MAX], tls_out[EAP_BUF_MAX], scratch[512];
	size_t in_len = 0, out_len, plen;
	uint8_t flags;
	uint8_t const *payload;
	eap_buf_t reply;
	unsigned int round;

	identity[0] = FR_EAP_CODE_RESPONSE;
	identity[1] = 0;
	identity[2] = 0;
	identity[3] = 4 + 1 + sizeof(fixture_user) - 1;
	identity[4] = FR_EAP_METHOD_IDENTITY;
	memcpy(identity + 5, fixture_user, sizeof(fixture_user) - 1);
	send_raw(c, identity, identity[3], &reply);

	if ((c->profile == 2) && reply.valid && (reply.len > 1)) {
		nak[1] = reply.data[1];
		send_raw(c, nak, sizeof(nak), &reply);
	}

	for (round = 0; round < MAX_ROUNDS; round++) {
		if (!parse_request(c, &reply, &flags, &payload, &plen)) return;

		if (c->step >= fuzz_step) {
			inject(c, fuzz, fuzz_len);
			return;
		}

		if (flags & 0x20) {
			if (SSL_connect(c->ssl) > 0) {}
			in_len = 0;
		} else {
			if ((plen > sizeof(tls_in) - in_len)) return;
			memcpy(tls_in + in_len, payload, plen);
			in_len += plen;

			if (flags & 0x40) {
				send_tls(c, 0, NULL, 0, 0, &reply);
				continue;
			}

			if (in_len > 0) {
				BIO_write(SSL_get_rbio(c->ssl), tls_in, (int)in_len);
				in_len = 0;
			}
			if (!SSL_is_init_finished(c->ssl)) {
				(void)SSL_do_handshake(c->ssl);
			} else {
				while (SSL_read(c->ssl, scratch, sizeof(scratch)) > 0) {}
				if (!c->tunnel_sent && (c->profile != 0)) {
					size_t n = inner_response(c, tls_out);

					c->tunnel_sent = true;
					(void)SSL_write(c->ssl, tls_out, (int)n);
				}
			}
		}

		out_len = drain_client(c, tls_out, sizeof(tls_out));
		if (out_len == 0) {
			send_tls(c, 0, NULL, 0, 0, &reply);
		} else {
			send_fragments(c, tls_out, out_len, &reply);
		}
	}
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	int ret = rlm_eap_fuzzer_initialize(argc, argv);

	if (ret < 0) return ret;

	client_ctx = SSL_CTX_new(TLS_client_method());
	if (!client_ctx) return -1;
	SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_max_proto_version(client_ctx, TLS1_2_VERSION);
	SSL_CTX_set_security_level(client_ctx, 0);
	return 0;
}

int LLVMFuzzerTestOneInput(uint8_t const *buf, size_t len)
{
	static size_t const servers[] = { 4, 5, 5 };
	tls_client_t c = {};
	BIO *rbio, *wbio;

	if (len < 2) return 0;
	if (!client_ctx) LLVMFuzzerInitialize(NULL, NULL);
	if (!client_ctx) return 0;

	c.profile = buf[0] % NUM_ELEMENTS(servers);
	c.server = server_cs[servers[c.profile]];
	c.ctx = talloc_init_const("fuzzer_rlm_eap_tls");
	if (!c.ctx) return 0;

	c.ssl = SSL_new(client_ctx);
	rbio = BIO_new(BIO_s_mem());
	wbio = BIO_new(BIO_s_mem());
	if (!c.ssl || !rbio || !wbio) {
		BIO_free(rbio);
		BIO_free(wbio);
		goto finish;
	}
	SSL_set_bio(c.ssl, rbio, wbio);
	SSL_set_connect_state(c.ssl);

	drive(&c, buf[1], buf + 2, len - 2);

finish:
	if (c.ssl) SSL_free(c.ssl);
	ERR_clear_error();
	talloc_free(c.state);
	talloc_free(c.ctx);
	fr_strerror_clear();
	return 0;
}
