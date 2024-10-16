// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/args.c
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

#include <argp.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sud/args.h>
#include <sud/sud.h>
#include <sys/types.h>

#define DAEMON_OPTION     0x80
#define ISOLATE_OPTION    0x81
#define COLOR_OPTION      0x82

#define SUD_I_SYSTEM_MASK SUD_I_SYSTEM | SUD_I_SYSTEM_FULL | SUD_I_SYSTEM_STRICT
#define SUD_I_SYSTEM_ERR                                                                                               \
    "options '--isolate=system', '--isolate=system-full' and '--isolate=system-strict' "                               \
    "cannot be used together"

#define SUD_I_HOME_MASK SUD_I_HOME | SUD_I_HOME_RO | SUD_I_HOME_TMPFS
#define SUD_I_HOME_ERR                                                                                                 \
    "options '--isolate=home', '--isolate=home-ro' and '--isolate=home-tmpfs' "                                        \
    "cannot be used together"

#define SET_MULTI_FLAG(value, mask, dst) (((dst) & (mask)) ? false : (((dst) |= (value)), true))

const char *argp_program_version = "0.1";
const char *argp_program_bug_address = "<erny@castellotti.net>";

int get_uid_from_str(const char *str) {
    struct passwd *passwd = getpwnam(str);
    long num;

    for (size_t i = 0; i < strlen(str); i++) {
        if (!isdigit(str[i])) {
            return -1;
        }
    }

    num = strtol(str, nullptr, 10);

    if (num >= INT_MAX || num < 0) {
        return -1;
    }

    // Check if valid
    errno = 0;
    passwd = getpwuid(num);
    if (!passwd) {
        SUD_DEBUG_ERRNO();
        return -1;
    }

    return passwd->pw_uid;
}

int get_uid_from_name(const char *str) {
    struct passwd *passwd;

    errno = 0;
    passwd = getpwnam(str);
    if (!passwd) {
        SUD_DEBUG_ERRNO();
        return -1;
    }

    return passwd->pw_uid;
}

int get_uid_from_arg(const char *str) {
    int uid;

    uid = get_uid_from_str(str);
    if (uid >= 0) {
        return uid;
    }

    return get_uid_from_name(str);
}

static struct argp_option options[] = {
    {"color", COLOR_OPTION, "color", 0, "Set background color (default = \"41\")", 0},

    {"daemon", DAEMON_OPTION, 0, 0, "Start SUD as server (must be root)", 0},

    {"shell", 's', 0, 0, "Run shell as the target user", 0},

    {"user", 'u', "user", 0, "Run command as specified user name or ID", 0},

    {"non-interactive", 'n', 0, 0, "Non-interactive mode", 0},

    {"stdin", 'S', 0, 0, "Read password from standard input", 0},

    {"isolate", ISOLATE_OPTION, "policy", 0, "Apply sandboxing policies to the process", 0},

    {"version", 'V', 0, 0, "Display version information and exit", 0},

    {"help", 'h', 0, 0, "Display help message and exit", 0},

    {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    int uid;
    sud_cmdline_args_t *arguments = state->input;

    switch (key) {
        case COLOR_OPTION: {
            arguments->background_color = arg;
            break;
        }

        case DAEMON_OPTION: {
            if (state->argc > 2) {
                argp_error(state, "option '--daemon' cannot be used with other options");
                return ARGP_KEY_ERROR;
            }

            arguments->flags |= SUD_F_DAEMON;
            break;
        }

        case 's': {
            arguments->flags |= SUD_F_SHELL;
            break;
        }

        case 'u': {
            uid = get_uid_from_arg(arg);
            if (uid < 0) {
                argp_error(state, "invalid uid");
                return ARGP_KEY_ERROR;
            }

            arguments->user = uid;

            break;
        }

        case 'n': {
            arguments->flags |= SUD_F_NOINT;
            break;
        }

        case 'S': {
            arguments->flags |= SUD_F_STDIN;
            break;
        }

        case ISOLATE_OPTION: {
            if (strcmp(arg, "system") == 0) {
                if (!SET_MULTI_FLAG(SUD_I_SYSTEM, SUD_I_SYSTEM_MASK, arguments->isolate)) {
                    argp_error(state, SUD_I_SYSTEM_ERR);
                    return ARGP_KEY_ERROR;
                }
            } else if (strcmp(arg, "system-full") == 0) {
                if (!SET_MULTI_FLAG(SUD_I_SYSTEM_FULL, SUD_I_SYSTEM_MASK, arguments->isolate)) {
                    argp_error(state, SUD_I_SYSTEM_ERR);
                    return ARGP_KEY_ERROR;
                }
            } else if (strcmp(arg, "system-strict") == 0) {
                if (!SET_MULTI_FLAG(SUD_I_SYSTEM_STRICT, SUD_I_SYSTEM_MASK, arguments->isolate)) {
                    argp_error(state, SUD_I_SYSTEM_ERR);
                    return ARGP_KEY_ERROR;
                }
            } else if (strcmp(arg, "home") == 0) {
                if (!SET_MULTI_FLAG(SUD_I_HOME, SUD_I_HOME_MASK, arguments->isolate)) {
                    argp_error(state, SUD_I_HOME_ERR);
                    return ARGP_KEY_ERROR;
                }
            } else if (strcmp(arg, "home-ro") == 0) {
                if (!SET_MULTI_FLAG(SUD_I_HOME_RO, SUD_I_HOME_MASK, arguments->isolate)) {
                    argp_error(state, SUD_I_HOME_ERR);
                    return ARGP_KEY_ERROR;
                }
            } else if (strcmp(arg, "home-tmpfs") == 0) {
                if (!SET_MULTI_FLAG(SUD_I_HOME_TMPFS, SUD_I_HOME_MASK, arguments->isolate)) {
                    argp_error(state, SUD_I_HOME_ERR);
                    return ARGP_KEY_ERROR;
                }
            } else if (strcmp(arg, "tmp") == 0) {
                arguments->isolate |= SUD_I_TMP;
            } else if (strcmp(arg, "devices") == 0) {
                arguments->isolate |= SUD_I_DEVICES;
            } else if (strcmp(arg, "net") == 0) {
                arguments->isolate |= SUD_I_NET;
            } else if (strcmp(arg, "user") == 0) {
                arguments->isolate |= SUD_I_USER;
            } else if (strcmp(arg, "kernel-tunables") == 0) {
                arguments->isolate |= SUD_I_KTUNABLES;
            } else if (strcmp(arg, "kernel-logs") == 0) {
                arguments->isolate |= SUD_I_KLOGS;
            }

            break;
        }

        case ARGP_KEY_ARGS: {
            arguments->argc = state->argc - state->next;
            arguments->argv = state->argv + state->next;
            break;
        }

        case 'h': {
            printf("Super User Daemon - privilege manager for systemd/Linux\n");
            argp_state_help(state, state->out_stream, ARGP_HELP_STD_HELP);
            break;
        }

        case ARGP_KEY_FINI: {
            if ((arguments->flags & SUD_F_SHELL) && arguments->argc != 0) {
                argp_error(state, "option '--shell' expects no command arguments");
                return ARGP_KEY_ERROR;
            }

            break;
        }

        default: {
            return ARGP_ERR_UNKNOWN;
        }
    }

    return 0;
}

static struct argp argp = {options, parse_opt, "[command [arg ...]]", 0, 0, 0, 0};

int __parse_cmdline(int argc, char *argv[], sud_cmdline_args_t *args, int options) {
    memset(args, 0, sizeof(sud_cmdline_args_t));

    args->background_color = "41";

    return argp_parse(&argp, argc, argv, options, 0, args);
}

int parse_cmdline(int argc, char *argv[], sud_cmdline_args_t *args) {
    return __parse_cmdline(argc, argv, args, ARGP_IN_ORDER | ARGP_NO_HELP);
}

int parse_cmdline_silence(int argc, char *argv[], sud_cmdline_args_t *args) {
    return __parse_cmdline(argc, argv, args, ARGP_IN_ORDER | ARGP_SILENT);
}
