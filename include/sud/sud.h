// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/include/sud/sud.h
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

#ifndef SUD_SUD_H_
#define SUD_SUD_H_

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <systemd/sd-daemon.h>

/* System costants */
/* 2MiB */
#define SUD_MIN_ARG                 0x200000

#define SUD_PRIVILEGED_GROUP        "wheel"

#define SUD_SOCKET_PATH             "\0sud_privilege_manager_socket"

#define SUD_MAGIC                   "____sud_privilege_manager____"
#define SUD_MAGIC_SIZE              sizeof(SUD_MAGIC)

#define SUD_MSG_ERROR_GENERIC       0x01
#define SUD_MSG_ERROR_AUTH          0x02
#define SUD_MSG_ERROR_TOO_MANY_CONN 0x03
#define SUD_MSG_ERROR_RESPONSE_FAIL 0x04

struct sud_response_msg {
    char magic[SUD_MAGIC_SIZE];
    int exit_code;
    int error;
    char nothing[1024];
};

int main_client();
int main_server();
pid_t sud_handle(int conn_fd, int *error);

#define write_str(out, str)                                                                                            \
    if (write(out, str, strlen(str))) {                                                                                \
    }

#define SUD_OUTPUT(format, args...) fprintf(stderr, format, args)
#define SUD_DEBUG_OUTPUT(preformat, postformat, args...)                                                               \
    SUD_OUTPUT(preformat "%s:%s():%d: " postformat, __FILE__, __func__, __LINE__, args)

#define SUD_FERR(format, args...)    SUD_OUTPUT(SD_ERR format, args)
#define SUD_ERR(format)              SUD_FERR(format, 0)

#define SUD_FNOTICE(format, args...) SUD_OUTPUT(SD_NOTICE format, args)
#define SUD_NOTICE(format)           SUD_FNOTICE(format, 0)

#define SUD_FDEBUG(format, args...)  SUD_DEBUG_OUTPUT(SD_DEBUG, format, args)
#define SUD_DEBUG(format)            SUD_FDEBUG(format, 0)
#define SUD_DEBUG_ERRNO()                                                                                              \
    if (errno != 0)                                                                                                    \
    SUD_FDEBUG("errno: %s\n", strerror(errno))

#define SUD_FDEBUG_CLIENT(format, args...) SUD_DEBUG_OUTPUT("", format, args)
#define SUD_DEBUG_CLIENT(format)           SUD_FDEBUG_CLIENT(format, 0)
#define SUD_DEBUG_ERRNO_CLIENT()                                                                                       \
    if (errno != 0)                                                                                                    \
    SUD_FDEBUG_CLIENT("errno: %s\n", strerror(errno))

#endif // SUD_SUD_H_
