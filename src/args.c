// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/args.c
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

#include <argp.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sud/args.h>
#include <sud/sud.h>
#include <sud/utils.h>
#include <sys/types.h>

#define DAEMON_OPTION  0x80
#define ISOLATE_OPTION 0x81
#define COLOR_OPTION   0x82

const char *argp_program_version = "0.1";
const char *argp_program_bug_address = "<erny@castellotti.net>";

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
    int isolate;
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
            uid = get_uid_from_str(arg);
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
            isolate = parse_isolate_str(arg);
            if (isolate < 0) {
                argp_error(state, "isolate option parse fail!");
                return ARGP_KEY_ERROR;
            }

            arguments->isolate |= isolate;
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
