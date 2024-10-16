// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/include/sud/args.h
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

#ifndef SUD_ARGS_H_
#define SUD_ARGS_H_

#include <argp.h>
#include <unistd.h>

typedef struct sud_cmdline_args {
    int flags;
    int isolate;
    uid_t user;
    char *workdir;
    char *background_color;
    int argc;
    char **argv;
} sud_cmdline_args_t;

#define SUD_F_DAEMON        0x01
#define SUD_F_SHELL         0x02
#define SUD_F_NOINT         0x04
#define SUD_F_STDIN         0x08

#define SUD_I_SYSTEM        0x01
#define SUD_I_SYSTEM_FULL   0x02
#define SUD_I_SYSTEM_STRICT 0x04
#define SUD_I_HOME          0x08
#define SUD_I_HOME_RO       0x10
#define SUD_I_HOME_TMPFS    0x20
#define SUD_I_TMP           0x40
#define SUD_I_DEVICES       0x80
#define SUD_I_NET           0x100
#define SUD_I_USER          0x200
#define SUD_I_KTUNABLES     0x400
#define SUD_I_KLOGS         0x800

int parse_cmdline(int argc, char *argv[], sud_cmdline_args_t *args);
int parse_cmdline_silence(int argc, char *argv[], sud_cmdline_args_t *args);

#endif // SUD_ARGS_H_
