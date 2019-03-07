/*
 * Copyright (c) 2019 Christian S.J. Peron
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef PRIVSEP_DOT_H_
#define PRIVSEP_DOT_H_

struct priv_getaddrinfo_args {
    char    hostname[256];
    char    servname[256];
    struct addrinfo hints;
};

struct priv_getaddrinfo_results {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    socklen_t ai_addrlen;
    struct sockaddr_storage sas;
    char ai_canonname[256];
};

/*
 * List of the privileges that will be used by h2o workers.
 */
enum {
    PRIV_NOOP,
    PRIV_NEVERBLEED_SOCK,
    PRIV_GETADDRINFO,
    PRIV_CONNECT_SOCK
};

int             priv_init(void);
int             priv_may_read(int, void *, size_t);
void            priv_must_read(int, void *, size_t);
void            priv_must_write(int, void *, size_t);
void            priv_send_fd(int, int);
int             priv_receive_fd(int);
int             privsep_get_neverbleed_sock(struct sockaddr_un *);
int             priv_getaddrinfo(const char *, const char *, const struct addrinfo *,
                  struct addrinfo **res);
int             priv_connect_sock_noblock(struct sockaddr_storage *);

#endif  /* PRIVSEP_DOT_H_ */
