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

#include <sys/socket.h>
#include <err.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

static volatile sig_atomic_t quit;

static void
usage(void)
{
	fprintf(stderr, "Usage: client host [port]\n");
	exit(1);
}

static void
handler(int sig __unused)
{
	quit = 1;
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
create_client_context(void)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL)
		errssl(1, "SSL_CTX_new");

	SSL_CTX_set_options(ctx, SSL_OP_NO_ENCRYPT_THEN_MAC |
	    SSL_OP_ENABLE_KTLS);

	return (ctx);
}

static int
create_client_socket(struct addrinfo *ai)
{
	int s;

	s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (s < 0) {
		warn("socket");
		return (-1);
	}

	if (connect(s, ai->ai_addr, ai->ai_addrlen) == -1) {
		warn("connect");
		close(s);
		return (-1);
	}

	return (s);
}

static int
open_client(const char *host, const char *port)
{
	struct addrinfo hints, *ai, *tofree;
	int error, s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_ADDRCONFIG;

	error = getaddrinfo(host, port, &hints, &tofree);
	if (error != 0)
		errx(1, "getaddrinfo(%s): %s", port, gai_strerror(error));

	s = -1;
	for (ai = tofree; ai != NULL; ai = ai->ai_next) {
		s = create_client_socket(ai);
		if (s != -1)
			break;
	}

	freeaddrinfo(tofree);

	return (s);
}

static char buf[] = "!\"#$%&'()*+,-./01234567890:;<=>?@"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

static void
handle_connection(SSL_CTX *ctx, int s)
{
	SSL *ssl;
	size_t total;
	int error, ret;

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		warnssl("SSL_new");
		close(s);
		return;
	}

	if (SSL_set_fd(ssl, s) != 1) {
		warnssl("SSL_set_fd");
		SSL_free(ssl);
		close(s);
		return;
	}

	ret = SSL_connect(ssl);
	if (ret != 1) {
		warnssl("SSL_connect");
		SSL_free(ssl);
		close(s);
		return;
	}

	if (BIO_get_ktls_send(SSL_get_wbio(ssl)))
		printf("Using KTLS for send\n");

	(void)signal(SIGTERM, handler);
	(void)signal(SIGINT, handler);
	(void)signal(SIGQUIT, handler);

	total = 0;
	while (!quit) {
		ret = SSL_write(ssl, buf, sizeof(buf));
		if (ret <= 0)
			break;
		total += ret;
	}

	printf("Wrote %zu bytes\n", total);

	error = SSL_get_error(ssl, ret);
	if (error == SSL_ERROR_ZERO_RETURN) {
		ret = SSL_shutdown(ssl);
		if (ret < 0)
			warnssl("SSL_shutdown");
	} else {
		warnssl("SSL_write");
	}
	SSL_free(ssl);
	close(s);
}

int
main(int ac, char **av)
{
	SSL_CTX *ctx;
	const char *host, *port;
	int ch, s;

	port = "45678";
	while ((ch = getopt(ac, av, "")) != -1)
		switch (ch) {
		default:
			usage();
		}

	av += optind;
	ac -= optind;
	if (ac < 1)
		errx(1, "host required");
	if (ac > 2)
		usage();

	host = av[0];
	if (ac == 2)
		port = av[1];

	ctx = create_client_context();

	s = open_client(host, port);
	if (s == -1)
		return (1);

	handle_connection(ctx, s);

	close(s);

	SSL_CTX_free(ctx);

	return (0);
}
