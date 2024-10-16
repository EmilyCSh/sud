// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/main.c
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

#include <stdio.h>
#include <sud/args.h>
#include <sud/sud.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    int rc;
    sud_cmdline_args_t arguments = {0};

    rc = parse_cmdline(argc, argv, &arguments);
    if (rc != 0) {
        return -1;
    }

    if (arguments.flags & SUD_F_DAEMON) {
        if (getppid() != 1) {
            fprintf(stderr, "SUD daemon should only be started by systemd init!\n");
            return -1;
        }

        if (getuid() != 0) {
            fprintf(stderr, "SUD daemon should be started as root!\n");
            return -1;
        }

        return main_server();
    } else {
        return main_client();
    }
}
