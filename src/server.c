// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/server.c
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sud/sud.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <systemd/sd-daemon.h>
#include <unistd.h>

static pid_t exec_pid = -1;

void *conn_guard_thread(void *p) {
    int rc;
    int conn_fd = *((int *)p);
    struct pollfd pollfd;

    pollfd.fd = conn_fd;
    pollfd.events = POLLHUP | POLLERR | POLLNVAL;

    while (true) {
        rc = poll(&pollfd, 1, -1);
        if ((rc < 0 && errno == EINTR) || rc == 0) {
            continue;
        }

        // rc < 0: something bad is happening, kill them all!
        if ((pollfd.revents & (POLLHUP | POLLERR | POLLNVAL)) || rc < 0) {
            if (exec_pid > 1) {
                SUD_FNOTICE("Connection closed by client, SIGTERM sent to exec process %d\n", exec_pid);
                kill(exec_pid, SIGTERM);

                sleep(10);

                if (!(kill(exec_pid, 0) < 0 && errno == ESRCH)) {
                    SUD_FERR("Process %d does not respond to SIGTERM, sending SIGKILL\n", exec_pid);
                    kill(exec_pid, SIGKILL);
                }
            }

            exit(0);
        }
    }
}

int main_server() {
    int rc;
    int error = SUD_MSG_ERROR_GENERIC;
    int exit_code = -1;
    int conn_fd = -1;
    int num_fds;
    int status;
    pthread_t guard_thread;
    char **names = nullptr;

    num_fds = sd_listen_fds_with_names(0, &names);
    if (num_fds < 0) {
        SUD_DEBUG_ERRNO();
        return 1;
    }

    if (num_fds == 0 || names == nullptr) {
        SUD_ERR("Unable to find any file descriptors\n");
        return 1;
    }

    for (int i = 0; i < num_fds; i++) {
        if (strcmp(names[i], "connection") == 0) {
            conn_fd = i + SD_LISTEN_FDS_START;
            break;
        }
    }

    free(names);

    if (conn_fd < 0) {
        SUD_ERR("Unable to find accepted socket connection\n");
        return 1;
    }

    if (!sd_is_socket(conn_fd, AF_UNIX, SOCK_SEQPACKET, 0)) {
        SUD_ERR("Wrong socket type\n");
        return 1;
    }

    if (pthread_create(&guard_thread, nullptr, *conn_guard_thread, &conn_fd) != 0) {
        SUD_DEBUG_ERRNO();
        return 1;
    }

    if (pthread_detach(guard_thread) != 0) {
        SUD_DEBUG_ERRNO();
        return 1;
    }

    exec_pid = sud_handle(conn_fd, &error);
    if (exec_pid < 0) {
        goto exit;
    }

    rc = waitpid(exec_pid, &status, 0);
    if (rc < 0) {
        SUD_DEBUG_ERRNO();
        goto exit;
    }

    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
        error = 0;
    }

    SUD_FNOTICE("Process %d exited with exit code %d\n", exec_pid, exit_code);

exit:
    send(conn_fd, &(struct sud_response_msg){SUD_MAGIC, exit_code, error, {}}, sizeof(struct sud_response_msg), 0);
    return 0;
}
