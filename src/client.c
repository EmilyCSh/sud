// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/client.c
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sud/sud.h>
#include <sud/utils.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

static int tty;
static struct termios term_old;

void reset_term() {
    tcsetattr(tty, TCSANOW, &term_old); // Reset terminal to old settings
}

void sig_int_term(int sig) {
    signal(sig, SIG_IGN);
    reset_term();
    exit(1);
}

int unix_socket_connect(const char *socket_path, size_t socket_path_len, int timeout) {
    int sock_fd;
    int rc;
    struct sockaddr_un sock_addr;

    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sun_family = AF_UNIX;
    memcpy(sock_addr.sun_path, socket_path, socket_path_len);

    sock_fd = socket(sock_addr.sun_family, SOCK_SEQPACKET, 0);
    if (sock_fd < 0) {
        SUD_DEBUG_ERRNO_CLIENT();
        return -1;
    }

    rc = -1;
    while (timeout-- >= 0) {
        rc = connect(sock_fd, (struct sockaddr *)&sock_addr, offsetof(struct sockaddr_un, sun_path) + socket_path_len);
        if (rc == 0) {
            break;
        } else {
            sleep(1);
        }
    }

    if (rc < 0) {
        SUD_DEBUG_ERRNO_CLIENT();
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

int main_client() {
    int fd;
    struct sud_response_msg msg;

    tty = open("/dev/tty", O_RDWR);
    if (tty < 0) {
        SUD_DEBUG_ERRNO_CLIENT();
        return 1;
    }

    if (tcgetattr(tty, &term_old) < 0) {
        SUD_DEBUG_ERRNO_CLIENT();
        return 1;
    }

    signal(SIGINT, sig_int_term);
    signal(SIGTERM, sig_int_term);

    fd = unix_socket_connect(SUD_SOCKET_PATH, sizeof(SUD_SOCKET_PATH) - 1, 1);

    if (recv(fd, &msg, sizeof(struct sud_response_msg), 0) != sizeof(struct sud_response_msg)) {
        SUD_DEBUG_ERRNO_CLIENT();
        msg.error = SUD_MSG_ERROR_RESPONSE_FAIL;
    }

    if (msg.error != 0) {
        reset_term();
        fprintf(stderr, "error %d\n", msg.error);
    }

    return msg.exit_code;
}
