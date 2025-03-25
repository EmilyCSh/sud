// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/exec.c
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

#include <stdarg.h>
#include <stdlib.h>
#include <sud/exec.h>
#include <sud/sud.h>
#include <unistd.h>

int set_stdio_process(int _stdin, int _stdout, int _stderr) {
    int rc;

    if (_stdin != STDIN_FILENO) {
        rc = dup2(_stdin, STDIN_FILENO);
        if (rc < 0) {
            SUD_DEBUG_ERRNO();
            return -1;
        }

        close(_stdin);
    }

    if (_stdout != STDOUT_FILENO) {
        rc = dup2(_stdout, STDOUT_FILENO);
        if (rc < 0) {
            SUD_DEBUG_ERRNO();
            return -1;
        }

        close(_stdout);
    }

    if (_stderr != STDERR_FILENO) {
        rc = dup2(_stderr, STDERR_FILENO);
        if (rc < 0) {
            SUD_DEBUG_ERRNO();
            return -1;
        }

        close(_stderr);
    }

    return 0;
}

#define add_args(p, s)             (p = (p + strlen(strcpy(p, s)) + 1))
#define add_args_check(o, p, n, s) ((p - o + strlen(s) < (size_t)n) ? add_args(p, s) : nullptr)

int add_env_arg(char **p, char *name, char *value) {
    size_t name_len;
    size_t value_len;
    char *arg;

    name_len = strlen(name);
    value_len = strlen(value);
    arg = malloc(name_len + value_len + 2);
    if (!arg) {
        SUD_DEBUG_ERRNO();
        return -1;
    }

    strcpy(arg, name);
    arg[name_len] = '=';
    strcpy(arg + name_len + 1, value);

    add_args(*p, "-E");
    add_args(*p, arg);
    free(arg);
    return 0;
}

bool multi_flag_check(int value, int wflag, ...) {
    int oflag;
    va_list arglist;

    if (!(value & wflag)) {
        return false;
    }

    va_start(arglist, wflag);

    while ((oflag = va_arg(arglist, int)) != 0) {
        if (value & oflag) {
            return false;
        }
    }

    va_end(arglist);
    return true;
}

pid_t sud_exec(process_info_t *pinfo, user_info_t *o_user, user_info_t *t_user, sud_cmdline_args_t *args) {
    int rc;
    pid_t result = -1;
    int i_argv = 0;
    ssize_t arg_max;
    char *envtemp;
    char *shell;
    char *argv_buf = nullptr;
    char *next_arg;
    int argc = 0;
    char **exec_argv = nullptr;
    char *exec_envp[2];

    arg_max = get_arg_max();
    if (arg_max < 0) {
        goto exit;
    }

    argv_buf = malloc(arg_max * sizeof(char));
    if (!argv_buf) {
        SUD_DEBUG_ERRNO();
        goto exit;
    }

    next_arg = argv_buf;

    add_args(next_arg, "/usr/bin/systemd-run");
    add_args(next_arg, "--quiet");
    add_args(next_arg, "--collect");
    add_args(next_arg, "--send-sighup");
    add_args(next_arg, "--expand-environment=false");

    if (isatty(pinfo->stdin) && isatty(pinfo->stdout) && isatty(pinfo->stderr)) {
        add_args(next_arg, "--pty");
    } else {
        add_args(next_arg, "--pipe");
    }

    add_args(next_arg, "--service-type=exec");
    add_args(next_arg, "--wait");

    add_args(next_arg, "--working-directory");
    add_args(next_arg, args->workdir);
    add_args(next_arg, "--uid");
    add_args(next_arg, t_user->name);
    add_args(next_arg, "--background");
    add_args(next_arg, args->background_color);

    add_env_arg(&next_arg, "SUD_USER", o_user->name);
    add_env_arg(&next_arg, "HOME", t_user->home_dir);
    add_env_arg(&next_arg, "LOGNAME", t_user->name);
    add_env_arg(&next_arg, "USER", t_user->name);

    envtemp = getenv_envp("DISPLAY", pinfo->envp);
    if (envtemp) {
        add_env_arg(&next_arg, "DISPLAY", envtemp);
    }

    envtemp = getenv_envp("TERM", pinfo->envp);
    if (!envtemp) {
        envtemp = "linux";
    }

    exec_envp[0] = next_arg + 3;
    exec_envp[1] = nullptr;
    add_env_arg(&next_arg, "TERM", envtemp);

    envtemp = getenv_envp("SHELL", pinfo->envp);
    if (envtemp && args->flags & SUD_F_SHELL) {
        shell = envtemp;
    } else {
        shell = t_user->shell;
    }

    add_env_arg(&next_arg, "SHELL", shell);

    if (multi_flag_check(
            args->isolate, SUD_I_SYSTEM,
            /* more restrictive */
            SUD_I_SYSTEM_FULL, SUD_I_SYSTEM_STRICT, 0
        )) {
        add_args(next_arg, "-pProtectSystem=true");
    }

    if (multi_flag_check(args->isolate, SUD_I_SYSTEM_FULL, /* more restrictive */ SUD_I_SYSTEM_STRICT, 0)) {
        add_args(next_arg, "-pProtectSystem=full");
    }

    if (multi_flag_check(args->isolate, SUD_I_SYSTEM_STRICT, /* more restrictive */ 0)) {
        add_args(next_arg, "-pProtectSystem=strict");
    }

    if (multi_flag_check(args->isolate, SUD_I_HOME_RO, /* more restrictive */ SUD_I_TMP, SUD_I_HOME, 0)) {
        add_args(next_arg, "-pProtectHome=read-only");
    }

    if (multi_flag_check(args->isolate, SUD_I_TMP, /* more restrictive */ SUD_I_HOME, 0)) {
        add_args(next_arg, "-pProtectHome=tmpfs");
    }

    if (multi_flag_check(args->isolate, SUD_I_HOME, /* more restrictive */ 0)) {
        add_args(next_arg, "-pProtectHome=true");
    }

    if (args->isolate & SUD_I_DEVICES) {
        add_args(next_arg, "-pPrivateDeviced=true");
    }

    if (args->isolate & SUD_I_NET) {
        add_args(next_arg, "-pPrivateNetwork=true");
    }

    if (args->isolate & SUD_I_USER) {
        add_args(next_arg, "-pPrivateUsers=true");
    }

    if (args->isolate & SUD_I_KTUNABLES) {
        add_args(next_arg, "-pProtectKernelLogs=true");
    }

    if (args->isolate & SUD_I_KLOGS) {
        add_args(next_arg, "-pProtectKernelLogs=true");
    }

    if (args->isolate & SUD_I_HOME_RO) {
        add_args(next_arg, "-pProtectHome=read-only");
    }

    if (args->isolate & SUD_I_HOME_TMPFS) {
        add_args(next_arg, "-pProtectHome=tmpfs");
    }

    if (args->flags & SUD_F_SHELL) {
        add_args(next_arg, shell);
    } else {
        add_args(next_arg, "--"); // Our cmd after this
        add_args(next_arg, args->cmd);

        for (int i = 0; i < args->argc; i++) {
            if (!add_args_check(argv_buf, next_arg, arg_max, args->argv[i])) {
                goto exit;
            }
        }
    }

    for (char *ptr = argv_buf; *ptr != '\0'; ptr += (strlen(ptr) + 1)) {
        argc++;
    }

    exec_argv = malloc((argc + 1) * sizeof(char *));
    if (!exec_argv) {
        SUD_DEBUG_ERRNO();
        goto exit;
    }

    for (char *ptr = argv_buf; *ptr != '\0'; ptr += (strlen(ptr) + 1)) {
        exec_argv[i_argv++] = ptr;
    }

    exec_argv[i_argv] = nullptr;

    rc = fork();
    if (rc == 0) {
        rc = set_stdio_process(pinfo->stdin, pinfo->stdout, pinfo->stderr);
        if (rc < 0) {
            exit(1);
        }

        rc = close_range(3, ~0U, CLOSE_RANGE_UNSHARE);
        if (rc < 0) {
            SUD_DEBUG_ERRNO();
            exit(1);
        }

        execve(exec_argv[0], exec_argv, exec_envp);

        // You shouldn't reach this!
        SUD_DEBUG_ERRNO();
        exit(1);
    } else if (rc < 0) {
        SUD_DEBUG_ERRNO();
        goto exit;
    }

    result = rc;
exit:
    if (argv_buf) {
        free(argv_buf);
    }

    if (exec_argv) {
        free(exec_argv);
    }

    return result;
}
