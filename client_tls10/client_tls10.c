/*
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Netflix, Inc.
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
 * This client seeks to expose a bug with out of order processing for
 * TLS 1.0 transmit.  To do this, read a file to ensure it is cached
 * in memory, then use posix_fadvise to try to force some of the
 * backing store out of cache before invoking sendfile.
 */

#include <sys/socket.h>
#include <sys/stat.h>
#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
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
	fprintf(stderr,
	    "Usage: client -f file host [port]\n");
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
create_client_context(void)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL)
		errssl(1, "SSL_CTX_new");

	SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);

	if (SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION) != 1)
		errssl(1, "SSL_CTX_set_min_proto_version");
	if (SSL_CTX_set_max_proto_version(ctx, TLS1_VERSION) != 1)
		errssl(1, "SSL_CTX_set_max_proto_version");

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

static bool
prep_file(int fd, const struct stat *sb)
{
	char buf[1024 * 1024];
	off_t offset, len;
	ssize_t nread;
	int state;

	if (sb->st_size < sizeof(buf) * 4) {
		warn("file too small");
		return (false);
	}

	state = 0;
	offset = 0;
	for (;;) {
		if (state == 0) {
			nread = pread(fd, buf, sizeof(buf), offset);
			if (nread == -1) {
				warn("pread");
				return (false);
			}
			if (nread < sizeof(buf))
				return (true);
			offset += nread;
		} else {
			/*
			 * This depends on POSIX_FADV_DONTNEED
			 * revoking pages so that sendfile() will have
			 * to use disk I/O to complete the request.
			 */
			len = sizeof(buf);
			if (len > sb->st_size - offset)
				len = 0;
			nread = posix_fadvise(fd, offset, sizeof(buf),
			    POSIX_FADV_DONTNEED);
			if (nread != 0) {
				warnc(nread, "posix_fadvise");
				return (false);
			}
			if (len == 0)
				return (true);
			offset += len;
		}
		state ^= 1;
	}
}

static void
handle_connection(SSL_CTX *ctx, int s, int fd)
{
	struct stat sb;
	SSL *ssl;
	ssize_t ret;

	if (fstat(fd, &sb) != 0) {
		warn("fstat");
		return;
	}
	if (!prep_file(fd, &sb))
		return;

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		warnssl("SSL_new");
		return;
	}

	ret = SSL_set_fd(ssl, s);
	if (ret == 0) {
		warnssl("SSL_set_fd");
		SSL_free(ssl);
		return;
	}

	ret = SSL_connect(ssl);
	if (ret != 1) {
		warnssl("SSL_connect");
		SSL_free(ssl);
		return;
	}

	if (BIO_get_ktls_send(SSL_get_wbio(ssl)))
		printf("Using KTLS for send\n");
	else {
		warnx("KTLS not enabled");
		SSL_free(ssl);
		return;
	}

	ret = SSL_sendfile(ssl, fd, 0, sb.st_size, 0);
	if (ret < 0) {
		warnssl("SSL_sendfile");
		SSL_free(ssl);
		return;
	}

	printf("Wrote %zd bytes\n", ret);

	ret = SSL_shutdown(ssl);
	if (ret < 0)
		warnssl("SSL_shutdown");
	SSL_free(ssl);
}

int
main(int ac, char **av)
{
	SSL_CTX *ctx;
	const char *file, *host, *port;
	int ch, fd, s;

	file = NULL;
	port = "45678";
	while ((ch = getopt(ac, av, "f:")) != -1)
		switch (ch) {
		case 'f':
			file = optarg;
			break;
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

	if (file == NULL)
		errx(1, "Missing file");
	fd = open(file, O_RDONLY);
	if (fd == -1)
		err(1, "open(%s)", file);

	ctx = create_client_context();

	s = open_client(host, port);
	if (s == -1)
		return (1);

	handle_connection(ctx, s, fd);

	close(s);

	SSL_CTX_free(ctx);

	return (0);
}
