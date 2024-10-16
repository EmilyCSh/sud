// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/include/sud/utils.h
 *
 *  Copyright (C) Emily <info@emy.sh>
 *  Copyright (C) Kat <kat@castellotti.net>
 */

#ifndef SUD_PROCFS_H_
#define SUD_PROCFS_H_

#include <limits.h>

typedef struct process_info {
    pid_t pid;
    uid_t uid;
    gid_t gid;
    int stdin;
    int stdout;
    int stderr;
    int tty;
    char cwd[PATH_MAX];
    char exe[PATH_MAX];
    int argc;
    char **argv;
    int envp_len;
    char **envp;
    size_t internal_arg_buf_len;
    char *internal_arg_buf;
} process_info_t;

ssize_t get_arg_max();
int get_process_info_conn(int unix_conn, process_info_t *obj);
void free_process_info(process_info_t *obj);
char *getenv_envp_str(const char *name, char **envp);
char *getenv_envp(const char *name, char **envp);

#endif // SUD_PROCFS_H_
