// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/include/sud/config.h
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

#ifndef SUD_CONFIG_H_
#define SUD_CONFIG_H_

#include <limits.h>

#define SUD_C_CONF_PATH   "/etc/sud.conf"
#define SUD_C_AUTH_SHADOW 0x01

typedef struct sud_global_config {
    int auth_mode;
    char background_color[256];
} sud_global_config_t;

int load_global_config(sud_global_config_t *conf);

#endif // SUD_CONFIG_H_
