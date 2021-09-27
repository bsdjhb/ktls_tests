/*
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Chelsio Communications, Inc.
 * All rights reserved.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * A special BIO that delays writes on a socket.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>

#include "local.h"

static BIO_METHOD *BIO_delay_method;

struct delay_ctx {
	uint8_t header[5];
	int hlen;
	int resid;	/* remaining payload data for current record */
	int delay_type;
	int delay_us;
};

BIO *
BIO_new_delay(int fd, int close_flag, int delay_type, int delay_us)
{
	struct delay_ctx *ctx;
	BIO *bio, *sock;

	sock = BIO_new_socket(fd, close_flag);
	if (sock == NULL)
		return (NULL);
	(void)BIO_set_tcp_ndelay(fd, 1);

	bio = BIO_new(BIO_delay_method);
	if (bio == NULL) {
		BIO_free(sock);
		return (NULL);
	}
	BIO_push(bio, sock);

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		BIO_free_all(bio);
		return (NULL);
	}
	ctx->delay_type = delay_type;
	ctx->delay_us = delay_us;
	BIO_set_data(bio, ctx);

	return (bio);
}

static int
delay_destroy(BIO *bio)
{
	struct delay_ctx *ctx = BIO_get_data(bio);

	free(ctx);
	return (1);
}

static int
delay_write(BIO *bio, const char *in, int inl)
{
	struct delay_ctx *ctx = BIO_get_data(bio);
	BIO *sock = BIO_next(bio);
	bool sending_header;
	int ret, sent, todo;

	if (in == NULL || inl <= 0)
		return (0);
	if (sock == NULL)
		return (0);

	sent = 0;

again:
	/*
	 * Populate header if needed.
	 */
	sending_header = (ctx->hlen == 0);
	if (ctx->hlen < sizeof(ctx->header)) {
		todo = sizeof(ctx->header) - ctx->hlen;
		if (todo > inl)
			todo = inl;
		memcpy(ctx->header + ctx->hlen, in, todo);
		ctx->hlen += todo;

		ctx->resid = (ctx->header[3] << 8) | ctx->header[4] + todo;
	}

	/*
	 * Sending part of a header, just send it.
	 */
	if (ctx->hlen < sizeof(ctx->header)) {
		assert(ctx->resid == 0);
		assert(inl < sizeof(ctx->header));
		ret = BIO_write(sock, in, inl);
		if (ret > 0)
			sent += ret;
		goto out;
	}

	/*
	 * If splitting headers, send part of the header and delay.
	 */
	if (sending_header && inl >= sizeof(ctx->header) &&
	    (ctx->delay_type == DELAY_SPLIT_HEADER ||
	     ctx->delay_type == DELAY_SPLIT_BOTH)) {
		ret = BIO_write(sock, in, sizeof(ctx->header) - 1);
		if (ret <= 0)
			goto out;
		sent += ret;
		in += ret;
		inl -= ret;
		ctx->resid -= ret;
		assert(ctx->resid != 0);
		usleep(ctx->delay_us);
		if (inl == 0)
			goto out;
	}

	assert(ctx->resid > 0);

	/*
	 * If splitting payloads, send half of the remaining record (or
	 * whatever is left) and delay.
	 */
	if (ctx->resid > 1 && (ctx->delay_type == DELAY_SPLIT_BODY ||
	    ctx->delay_type == DELAY_SPLIT_BOTH)) {
		todo = ctx->resid / 2;
		if (todo > inl)
			todo = inl;
		ret = BIO_write(sock, in, todo);
		if (ret <= 0)
			goto out;
		sent += ret;
		in += ret;
		inl -= ret;
		ctx->resid -= ret;
		assert(ctx->resid != 0);
		usleep(ctx->delay_us);
		if (inl == 0)
			goto out;
	}

	/*
	 * Send the rest of the record body.
	 */
	todo = ctx->resid;
	if (todo > inl)
		todo = inl;
	ret = BIO_write(sock, in, todo);
	if (ret <= 0)
		goto out;
	sent += ret;
	in += ret;
	inl -= ret;
	ctx->resid -= ret;
	if (ctx->resid == 0)
		ctx->hlen = 0;
	if (inl == 0)
		goto out;
	goto again;

out:
	BIO_clear_retry_flags(bio);
	BIO_copy_next_retry(bio);
	if (sent != 0)
		return (sent);
	return (ret);
}

static int
delay_puts(BIO *bio, const char *str)
{
	return (delay_write(bio, str, strlen(str)));
}

static long
delay_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
	BIO *sock = BIO_next(bio);

	return (BIO_ctrl(sock, cmd, num, ptr));
}

bool
init_bio_delay(void)
{
	BIO_delay_method = BIO_meth_new(BIO_get_new_index() |
	    BIO_TYPE_FILTER, "delayed socket");
	if (BIO_delay_method == NULL)
		return (false);
	BIO_meth_set_destroy(BIO_delay_method, delay_destroy);
	BIO_meth_set_write(BIO_delay_method, delay_write);
	BIO_meth_set_puts(BIO_delay_method, delay_puts);
	BIO_meth_set_ctrl(BIO_delay_method, delay_ctrl);
	return (true);
}
