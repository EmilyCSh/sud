// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/config.c
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

#include <stdio.h>
#include <stdlib.h>
#include <sud/config.h>
#include <sud/sud.h>

#define STRINGIFY(x) #x
#define TOSTRING(x)  STRINGIFY(x)

int load_global_config(sud_global_config_t *conf) {
    FILE *file;
    char *line = nullptr;
    size_t len;
    char key[256];
    char subkey[256];
    char *value;

    file = fopen(SUD_C_CONF_PATH, "r");
    if (!file) {
        SUD_FERR("Unable to open config file %s\n", SUD_C_CONF_PATH);
        return -1;
    }

    while (getline(&line, &len, file) != -1) {
        if (sscanf(line, "%255s %255s", key, subkey) != 2) {
            continue;
        }

        if (strcmp(key, "global") != 0) {
            continue;
        }

        value = strchr(line, ' ') + 1;
        value = strchr(value, ' ') + 1;
        value[strcspn(value, "\n")] = '\0';

        if (strcmp(subkey, "auth_mode") == 0) {
            if (strcmp(value, "shadow") == 0) {
                conf->auth_mode = SUD_C_AUTH_SHADOW;
            } else {
                SUD_FERR("Unsupported value \"%s\" for option auth_mode\n", value);
                return -1;
            }
        } else if (strcmp(subkey, "background_color") == 0) {
            strncpy(conf->background_color, value, sizeof(conf->background_color) - 1);
            conf->background_color[sizeof(conf->background_color) - 1] = '\0';
        } else {
            SUD_FERR("Unsupported key \"%s\" for global options\n", subkey);
            return -1;
        }

        free(line);
        line = nullptr;
    }

    return 0;
}
