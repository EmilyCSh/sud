// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/include/sud/auth.h
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

#ifndef SUD_AUTH_H_
#define SUD_AUTH_H_

#include <sud/args.h>
#include <sud/config.h>
#include <sud/utils.h>

typedef struct user_info {
    char *name;
    char *shadow;
    long psw_last_change;
    long psw_min_day;
    long psw_max_day;
    long psw_expire_day;
    uid_t uid;
    gid_t gid;
    char *home_dir;
    char *shell;
} user_info_t;

bool sud_auth(
    process_info_t *pinfo, user_info_t *o_user, user_info_t *t_user, sud_cmdline_args_t *args,
    sud_global_config_t *global_conf
);
bool auth_shadow(process_info_t *pinfo, user_info_t *o_user, sud_cmdline_args_t *args);
size_t read_password(int stdin, int tty, const char *username, char *out, size_t len);
int compare_password(const char *user_password, const char *password);
bool user_in_grp(const char *user_name, const char *group_name);
bool user_valid(user_info_t *user);
int get_userinfo_from_pid(uid_t uid, user_info_t *obj);
void free_userinfo(user_info_t *obj);

#endif // SUD_AUTH_H_
