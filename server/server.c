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

#include <sys/event.h>
#include <sys/socket.h>
#include <err.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

static void
usage(void)
{
	fprintf(stderr, "Usage: server -c certfile -k keyfile [-p port]\n");
	exit(1);
}

static void
warnssl(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vwarnx(fmt, ap);
	va_end(ap);
	ERR_print_errors_fp(stderr);
}

static void
errssl(int code, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vwarnx(fmt, ap);
	va_end(ap);
	ERR_print_errors_fp(stderr);
	exit(code);
}

static SSL_CTX *
create_server_context(const char *cert, const char *key, bool read_ahead)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL)
		errssl(1, "SSL_CTX_new");

	SSL_CTX_set_options(ctx, SSL_OP_NO_ENCRYPT_THEN_MAC |
	    SSL_OP_ENABLE_KTLS);

	if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1)
		errssl(1, "SSL_CTX_use_certificate_file");
	if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1)
		errssl(1, "SSL_CTX_use_PrivateKey_file");
	if (SSL_CTX_check_private_key(ctx) != 1)
		errssl(1, "SSL_CTX_check_private_key");

	if (read_ahead)
		SSL_CTX_set_read_ahead(ctx, 1);

	return (ctx);
}

static bool
create_server(int kq, struct addrinfo *ai)
{
	struct kevent ev;
	int s;

	s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (s < 0) {
		warn("socket");
		return (false);
	}

	if (bind(s, ai->ai_addr, ai->ai_addrlen) == -1) {
		warn("bind");
		close(s);
		return (false);
	}

	if (listen(s, 1) == -1) {
		warn("listen");
		close(s);
		return (false);
	}

	EV_SET(&ev, s, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
		warn("kevent");
		close(s);
		return (false);
	}

	return (true);
}

static void
create_server_sockets(int kq, const char *port)
{
	struct addrinfo hints, *ai, *tofree;
	int error;
	bool created;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_ADDRCONFIG | AI_PASSIVE;

	error = getaddrinfo(NULL, port, &hints, &tofree);
	if (error != 0)
		errx(1, "getaddrinfo(%s): %s", port, gai_strerror(error));

	created = false;
	for (ai = tofree; ai != NULL; ai = ai->ai_next) {
		if (create_server(kq, ai))
			created = true;
	}

	freeaddrinfo(tofree);

	if (!created)
		errx(1, "Failed to create any server sockets");
}

static void
handle_connection(SSL_CTX *ctx, int s)
{
	char buf[4096];
	SSL *ssl;
	size_t total;
	int error, ret;

	printf("Accepting new connection\n");

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		warnssl("SSL_new");
		return;
	}

	if (SSL_set_fd(ssl, s) != 1) {
		warnssl("SSL_set_fd");
		SSL_free(ssl);
		return;
	}

	ret = SSL_accept(ssl);
	if (ret != 1) {
		warnssl("SSL_accept");
		SSL_free(ssl);
		return;
	}

	if (BIO_get_ktls_recv(SSL_get_rbio(ssl)))
		printf("Using KTLS for receive\n");

	total = 0;
	for (;;) {
		ret = SSL_read(ssl, buf, sizeof(buf));
		if (ret <= 0)
			break;
		total += ret;
	}

	printf("Received %zu bytes\n", total);

	error = SSL_get_error(ssl, ret);
	if (error == SSL_ERROR_ZERO_RETURN) {
		ret = SSL_shutdown(ssl);
		if (ret < 0)
			warnssl("SSL_shutdown");
	} else {
		warnssl("SSL_read");
	}
	SSL_free(ssl);
}

static void
run(int kq, SSL_CTX *ctx)
{
	struct kevent ev;
	int s;

	for (;;) {
		if (kevent(kq, NULL, 0, &ev, 1, NULL) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "kevent");
		}

		s = accept(ev.ident, NULL, NULL);
		if (s == -1) {
			warn("accept");
			continue;
		}

		handle_connection(ctx, s);
		close(s);
	}
}

int
main(int ac, char **av)
{
	SSL_CTX *ctx;
	const char *cert, *key, *port;
	bool read_ahead;
	int ch, kq;

	read_ahead = false;
	cert = key = NULL;
	port = "45678";
	while ((ch = getopt(ac, av, "Ac:k:p:")) != -1)
		switch (ch) {
		case 'A':
			read_ahead = true;
			break;
		case 'c':
			cert = optarg;
			break;
		case 'k':
			key = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		default:
			usage();
		}

	if (cert == NULL || key == NULL)
		errx(1, "cert and key are required");

	kq = kqueue();
	if (kq < 0)
		err(1, "kqueue");

	ctx = create_server_context(cert, key, read_ahead);

	create_server_sockets(kq, port);

	run(kq, ctx);

	SSL_CTX_free(ctx);

	return (0);
}
