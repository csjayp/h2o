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
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <linux/un.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <stdarg.h>

#include "privsep.h"

volatile pid_t child_pid = -1;
int priv_fd = -1;

volatile sig_atomic_t gotsig_chld = 0;

/* Proto-types */
static void sig_pass_to_chld(int);
static void sig_chld(int);

static void sig_chld(int sig)
{

    gotsig_chld = 1;
}

/* If priv parent gets a TERM or HUP, pass it through to child instead */
static void sig_pass_to_chld(int sig)
{
    int oerrno;

    oerrno = errno;
    if (child_pid != -1)
        (void) kill(child_pid, sig);
    errno = oerrno;
}

static size_t bsd_strlcpy(char *dst, const char *src, size_t siz)
{
    size_t n = siz;
    char *d = dst;
    const char *s;

    s = src;
    if (n != 0 && --n != 0) {
        do {
            if ((*d++ = *s++) == 0)
                break;
        } while (--n != 0);
    }
    if (n == 0) {
        if (siz != 0)
            *d = '\0';      /* NUL-terminate dst */
        while (*s++)
            ;
    }
    return (s - src - 1);   /* count does not include NUL */
}

static void priv_deliver_getaddrinfo(int sock)
{
            struct priv_getaddrinfo_results *ent, *vec;
            struct priv_getaddrinfo_args ga_args;
            struct addrinfo *res, *res0;
            size_t vec_used, vec_alloc;
            size_t curlen;
            int error;

            priv_must_read(sock, &ga_args, sizeof(ga_args));
            error = getaddrinfo(ga_args.hostname, ga_args.servname, &ga_args.hints,
                &res0);
            if (error != 0) {
                fprintf(stderr, "[privsep]: getaddr failed: %s\n", gai_strerror(error));
            }
            /* report success/failure */
            priv_must_write(sock, &error, sizeof(error));
            if (error != 0) {
                return;
            }
            vec_used = 0;
            vec_alloc = 0;
            vec = NULL;
            for (res = res0; res; res = res->ai_next) {
                if (vec == NULL) {
                    vec_alloc = sizeof(*ent);
                    vec = calloc(1, vec_alloc);
                } else {
                    vec_alloc = vec_alloc + sizeof(*ent);
                    vec = realloc(vec,vec_alloc);
                }
                ent = &vec[vec_used++];
                ent->ai_flags = res->ai_flags;
                ent->ai_family = res->ai_family;
                ent->ai_socktype = res->ai_socktype;
                ent->ai_protocol = res->ai_protocol;
                ent->ai_addrlen = res->ai_addrlen;
                memcpy(&ent->sas, res->ai_addr, res->ai_addrlen);
                if (res->ai_canonname != NULL) {
                    bsd_strlcpy(ent->ai_canonname, res->ai_canonname,
                        sizeof(ent->ai_canonname));
                } else {
                    ent->ai_canonname[0] = '\0';
                }
            }
            curlen = vec_used * sizeof(*ent);
            if (curlen == 0) {
                curlen = -1;
                priv_must_write(sock, &curlen, sizeof(curlen));
                return;
            }
            priv_must_write(sock, &curlen, sizeof(curlen));
            priv_must_write(sock, vec, curlen);
}

static void priv_deliver_neverbleed_sock(int sock)
{
    struct sockaddr_un sun;
    int error, nb_sock;

    fprintf(stderr, "calling neverbleed get sock\n");
    priv_must_read(sock, &sun, sizeof(struct sockaddr_un));
    nb_sock = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock == -1) {
        error = errno;
        priv_must_write(nb_sock, &error, sizeof(int));
        return;
    }
    while (connect(nb_sock, (void *)&sun, sizeof(sun)) != 0) {
        if (errno != EINTR) {
            error = errno;
            priv_must_write(sock, &error, sizeof(int));
            return;
        }
    }
    error = 0;
    priv_must_write(sock, &error, sizeof(int));
    priv_send_fd(sock, nb_sock);
}

static void priv_deliver_connected_sock(int sock, int block)
{
    struct sockaddr_storage saddr;
    int error, nb_sock;
    socklen_t s;

    /*
     * NB: ACL check from whatever was specified in the configuration.
     * This could probably a generic interface used by neverbleed too.
     */
    priv_must_read(sock, &saddr, sizeof(struct sockaddr_storage));
    switch (saddr.ss_family) {
    case PF_UNIX:
        s = sizeof(struct sockaddr_un);
        break;
    case PF_INET:
        s = sizeof(struct sockaddr_in);
        break;
    case PF_INET6:
        s = sizeof(struct sockaddr_in6);
        break;
    default:
        abort();
    }
    /*
     * We need to write multiple error codes back .One for socket and
     * the other for connect so we can replicate the same error
     * conditions exactly.
     */
    nb_sock = socket(saddr.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock == -1) {
        error = errno;
        priv_must_write(nb_sock, &error, sizeof(int));
        return;
    }
    (void) fcntl(nb_sock, F_SETFL, O_NONBLOCK);
    if (!(connect(nb_sock, (struct sockaddr *)&saddr, s) == 0 || errno == EINPROGRESS)) {
        error = errno;
        close(nb_sock);
        priv_must_write(nb_sock, &error, sizeof(int));
        return;
    }
    error = 0;
    priv_must_write(sock, &error, sizeof(int));
    priv_send_fd(sock, nb_sock);
}

int priv_init(void)
{
    int i, socks[2], cmd;

    fprintf(stderr, "[sandbox] creating privileged process\n");
    for (i = 1; i < NSIG; i++)
        signal(i, SIG_DFL);
    if (socketpair(AF_LOCAL, SOCK_STREAM, PF_UNSPEC, socks) == -1) {
        err(1, "socketpair failed");
    }
    child_pid = fork();
    if (child_pid == -1) {
        err(1, "fork failed");
    }
    if (child_pid == 0) {
        (void) close(socks[0]);
        priv_fd = socks[1];
        return (0);
    }
    close(socks[1]);
    while (!gotsig_chld) {
        if (priv_may_read(socks[0], &cmd, sizeof(int))) {
            break;
        }
        switch (cmd) {
        case PRIV_NEVERBLEED_SOCK:
            priv_deliver_neverbleed_sock(socks[0]);
            break;
        case PRIV_GETADDRINFO:
            priv_deliver_getaddrinfo(socks[0]);
            break;
        case PRIV_CONNECT_SOCK:
            priv_deliver_connected_sock(socks[0], 0);
            break;
        default:
            (void) fprintf(stderr, "got request for unknown priv\n");
        }
    }
    _exit(1);
}

/*
 * priv_may_read():
 *
 * Read all data or return 1 for error.
 */
int priv_may_read(int fd, void *buf, size_t n)
{
    ssize_t res, pos = 0;
    char *s = buf;

    while (n > pos) {
        res = read(fd, s + pos, n - pos);
        switch (res) {
        case -1:
            if (errno == EINTR || errno == EAGAIN)
                continue;
        case 0:
            return (1);
        default:
            pos += res;
        }
    }
    return (0);
}

/*
 * priv_must_read():
 *
 * Read data with the assertion that it all must come through, or
 * else abort the process.  Based on atomicio() from openssh.
 */
void priv_must_read(int fd, void *buf, size_t n)
{
    char *s = buf;
    ssize_t res, pos = 0;

    while (n > pos) {
        res = read(fd, s + pos, n - pos);
        switch (res) {
        case -1:
            if (errno == EINTR || errno == EAGAIN)
                continue;
        case 0:
            _exit(0);
        default:
            pos += res;
        }
    }
}

/*
 * priv_must_write():
 *
 * Write data with the assertion that it all has to be written, or
 * else abort the process.  Based on atomicio() from openssh.
 */
void priv_must_write(int fd, void *buf, size_t n)
{
    ssize_t res, pos = 0;
    char *s = buf;

    while (n > pos) {
        res = write(fd, s + pos, n - pos);
        switch (res) {
        case -1:
            if (errno == EINTR || errno == EAGAIN)
                continue;
        case 0:
            _exit(0);
        default:
            pos += res;
        }
    }
}

/*
 * Send a file descriptor to non-privileged process
 */
void priv_send_fd(int sock, int fd)
{
    int *fdp, result = 0;
    struct msghdr msg;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
    struct iovec vec;
    ssize_t n;

    printf("sending this mutha phucan fd\n");
    memset(&msg, 0, sizeof(msg));
    if (fd < 0) {
        return;
    }
    msg.msg_control = (caddr_t)&cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    fdp = (int *)CMSG_DATA(cmsg);
    *fdp = fd;
    vec.iov_base = &result;
    vec.iov_len = sizeof(int);
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    if ((n = sendmsg(sock, &msg, 0)) == -1)  {
        fprintf(stderr, "sendmsg: %s\n", strerror(errno));
        //abort();
    }
    if (n != sizeof(int)) {
        fprintf(stderr, "sendmsg: %s\n", strerror(errno));
        //abort();
    }
}

/*
 * Recieve a file descriptor from the privileged process.
 */
int priv_receive_fd(int sock)
{
    struct msghdr msg;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;
    struct iovec vec;
    ssize_t n;
    int result;
    int fd;

    memset(&msg, 0, sizeof(msg));
    vec.iov_base = &result;
    vec.iov_len = sizeof(int);
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsgbuf.buf;
    msg.msg_controllen = sizeof(cmsgbuf.buf);
    if ((n = recvmsg(sock, &msg, 0)) == -1) {
        fprintf(stderr, "recvmsg: %s\n", strerror(errno));
    }
    if (n != sizeof(int)) {
        fprintf(stderr, "recvmsg: %s\n", strerror(errno));
    }
    if (result == 0) {
        cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg == NULL) {
            fprintf(stderr, "%s: no message header", __func__);
            return -1;
        }
        if (cmsg->cmsg_type != SCM_RIGHTS)
            (void) fprintf(stderr, "%s: expected type %d got %d", __func__,
                SCM_RIGHTS, cmsg->cmsg_type);
        fd = (int)(*CMSG_DATA(cmsg));
        return (fd);
    } else {
        errno = result;
        return (-1);
    }
}

/**
 * Operations for the sandboxed process.
 **/

/*
 * privsep_get_neverbleed_sock()
 *
 * Receive a connected socket (connected to the neverbleed process) so
 * we do not have to allow socket(2) and connect(2).
 */
int privsep_get_neverbleed_sock(struct sockaddr_un *sun)
{
    int priv, sock, error;

    priv = PRIV_NEVERBLEED_SOCK;
    priv_must_write(priv_fd, &priv, sizeof(int));
    priv_must_write(priv_fd, sun, sizeof(struct sockaddr_un));
    priv_must_read(priv_fd, &error, sizeof(int));
    if (error != 0) {
        errno = error;
        return (-1);
    }
    sock = priv_receive_fd(priv_fd);
    return (sock);
}


int priv_connect_sock_noblock(struct sockaddr_storage *sas)
{
    int priv, sock, error;

    priv = PRIV_CONNECT_SOCK;
    priv_must_write(priv_fd, &priv, sizeof(int));
    priv_must_write(priv_fd, sas, sizeof(struct sockaddr_storage));
    priv_must_read(priv_fd, &error, sizeof(int));
    if (error != 0) {
        errno = error;
        return (-1);
    }
    sock = priv_receive_fd(priv_fd);
    return (sock);
}

static struct addrinfo *
addrinfo_copy(struct priv_getaddrinfo_results *ent)
{
    struct addrinfo *cres;

    cres = malloc(sizeof(*cres));
    if (cres == NULL)
        return (NULL);
    cres->ai_flags = ent->ai_flags;
    cres->ai_family = ent->ai_family;
    cres->ai_socktype = ent->ai_socktype;
    cres->ai_protocol = ent->ai_protocol;
    cres->ai_addrlen = ent->ai_addrlen;
    cres->ai_addr = malloc(cres->ai_addrlen);
    memcpy(cres->ai_addr, &ent->sas, cres->ai_addrlen);
    cres->ai_canonname = strdup(ent->ai_canonname);
    if (cres->ai_canonname == NULL) {
        free(cres);
        return (NULL);
    }
    return (cres);
}

static int
process_getaddr_data(struct priv_getaddrinfo_results *vec, size_t blen,
    struct addrinfo **res)
{
    struct priv_getaddrinfo_results *ent;
    struct addrinfo *cres, *head;
    int nitems;

    if (blen % sizeof(*ent) != 0)
        return (-1);
    head = NULL;
    nitems = blen / sizeof(*ent);
    for (ent = &vec[0]; ent < &vec[nitems]; ent++) {
        cres = addrinfo_copy(ent);
        if (cres == NULL)
            return (-1);
        cres->ai_next = head;
        head = cres;
    }
    *res = head;
    return (0);
}

int priv_getaddrinfo(const char *hostname, const char *servname, const struct addrinfo *hints,
    struct addrinfo **res)
{
    struct priv_getaddrinfo_args ga_args;
    struct priv_getaddrinfo_results *vec;
    size_t blen;
    int cmd, ret;

    memset(&ga_args, 0, sizeof(ga_args));
    bsd_strlcpy(ga_args.hostname, hostname, sizeof(ga_args.hostname));
    bsd_strlcpy(ga_args.servname, servname, sizeof(ga_args.servname));
    memcpy(&ga_args.hints, hints, sizeof(ga_args.hints));
    cmd = PRIV_GETADDRINFO;
    priv_must_write(priv_fd, &cmd, sizeof(cmd));
    priv_must_write(priv_fd, &ga_args, sizeof(ga_args));
    priv_must_read(priv_fd, &ret, sizeof(cmd));
    if (ret != 0) {
        return (ret);
    }
    priv_must_read(priv_fd, &blen, sizeof(blen));
    if (blen == -1) {
        return (EAI_MEMORY);
    }
    vec = malloc(blen);
    if (vec == NULL) {
        return (EAI_MEMORY);
    }
    priv_must_read(priv_fd, vec, blen);
    ret = process_getaddr_data(vec, blen, res);
    free(vec);
    if (ret == -1) {
        return (EAI_MEMORY);
    }
    return (0);
}
