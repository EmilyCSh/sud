// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/auth.c
 *
 *  Copyright (C) Emily <info@emy.sh>
 *  Copyright (C) Kat <kat@castellotti.net>
 */

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sud/auth.h>
#include <sud/sud.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

bool sud_auth(process_info_t *pinfo, user_info_t *o_user, user_info_t *t_user, sud_cmdline_args_t *args) {
    int rc;
    char password[PAM_MAX_RESP_SIZE + 1] = {};
    char *hash;

    if (!user_valid(o_user) || !user_valid(t_user)) {
        return false;
    }

    if (o_user->uid == 0 || o_user->uid == t_user->uid) {
        return true;
    }

    if ((args->flags & SUD_F_NOINT) && !(args->flags & SUD_F_STDIN)) {
        return false;
    }

    if (!user_in_grp(o_user->name, SUD_PRIVILEGED_GROUP)) {
        return false;
    }

    rc = read_password(
        pinfo->stdin, args->flags & SUD_F_STDIN ? -1 : pinfo->tty, o_user->name, password, PAM_MAX_RESP_SIZE
    );

    if (rc < 0) {
        explicit_bzero(password, PAM_MAX_RESP_SIZE);
        return false;
    }

    errno = 0;
    hash = crypt(password, o_user->shadow);
    explicit_bzero(password, PAM_MAX_RESP_SIZE);

    if (!hash) {
        SUD_DEBUG_ERRNO();
        return false;
    }

    return compare_password(hash, o_user->shadow) == 0;
}

size_t read_password(int stdin, int tty, const char *username, char *out, size_t len) {
    int rc = -1;
    size_t i = 0;
    char ch;
    int flags_fcntl = 0;
    struct termios term_old;
    struct termios term_new;

    if (tty >= 0) {
        stdin = tty;

        tcgetattr(tty, &term_old);
        term_new = term_old;
        term_new.c_lflag &= ~(ICANON | ECHO);

        if (tcsetattr(tty, TCSANOW, &term_new) < 0) {
            SUD_DEBUG_ERRNO();
            i = -1;
            goto exit;
        }

        write_str(tty, "[sud] password for ");
        write_str(tty, username);
        write_str(tty, ": ");
    } else {
        flags_fcntl = fcntl(stdin, F_GETFL, 0);
        if (flags_fcntl < 0) {
            SUD_DEBUG_ERRNO();
            i = -1;
            goto exit;
        }

        if (fcntl(stdin, F_SETFL, flags_fcntl | O_NONBLOCK) < 0) {
            SUD_DEBUG_ERRNO();
            i = -1;
            goto exit;
        }
    }

    while ((rc = read(stdin, &ch, 1)) == 1 && ch != '\r' && ch != '\n' && i < len - 1) {
        if ((ch == 127 || ch == 8) && tty >= 0) {
            if (i > 0) {
                i--;
                write_str(tty, "\b \b");
            }
        } else {
            out[i++] = ch;

            if (tty >= 0) {
                write_str(tty, "*");
            }
        }
    }

    out[i] = '\0';
    ch = '\0';

exit:
    if (tty >= 0) {
        write_str(tty, "\n");
        tcsetattr(tty, TCSANOW, &term_old);
    } else {
        if (fcntl(stdin, F_SETFL, flags_fcntl) < 0) {
            SUD_DEBUG_ERRNO();
            return -1;
        }

        if (rc == -1 && errno != EAGAIN) {
            return -1;
        }
    }

    return i;
}

int compare_password(const char *user_password, const char *password) {
    int user_password_len = strlen(user_password);
    int password_len = strlen(password);
    int result = user_password_len ^ password_len;
    char user_password_inv[CRYPT_OUTPUT_SIZE + 1];

    if (CRYPT_OUTPUT_SIZE < user_password_len) {
        return -1;
    }

    user_password_inv[user_password_len] = '\0';

    for (int i = 0; i < user_password_len; i++) {
        user_password_inv[i] = (~user_password[i]);
    }

    for (int i = 0; i < user_password_len; i++) {
        result |= i >= password_len ? (user_password[i] ^ user_password_inv[i]) : (user_password[i] ^ password[i]);
    }

    return result;
}

bool user_in_grp(const char *user_name, const char *group_name) {
    struct group *grp;

    errno = 0;
    grp = getgrnam(group_name);
    if (!grp) {
        SUD_DEBUG_ERRNO();
        return false;
    }

    for (int i = 0; grp->gr_mem[i] != nullptr; i++) {
        if (strcmp(grp->gr_mem[i], user_name) == 0) {
            return true;
        }
    }

    return false;
}

bool user_valid(user_info_t *user) {
    time_t time_sec;
    time_t time_day;

    time_sec = time(nullptr);
    if (time_sec < 0) {
        SUD_DEBUG_ERRNO();
        return false;
    }

    time_day = time_sec / (60 * 60 * 24);

    if (user->psw_last_change == -1) {
        return true;
    }

    if (user->psw_last_change == 0) {
        return false;
    }

    if (user->psw_max_day != -1 && user->psw_last_change + user->psw_max_day - time_day < 0) {
        return false;
    }

    if (user->psw_expire_day != -1 && user->psw_expire_day - time_day < 0) {
        return false;
    }

    return true;
}

int get_userinfo_from_pid(uid_t uid, user_info_t *obj) {
    struct passwd *passwd;
    struct spwd *spwd;

    /* init */
    memset(obj, 0, sizeof(user_info_t));

    errno = 0;
    passwd = getpwuid(uid);
    if (!passwd) {
        SUD_DEBUG_ERRNO();
        goto exit;
    }

    errno = 0;
    spwd = getspnam(passwd->pw_name);
    if (!spwd) {
        SUD_DEBUG_ERRNO();
        goto exit;
    }

    if (!(strlen(passwd->pw_passwd) == 1 && passwd->pw_passwd[0] == 'x')) {
        goto exit;
    }

    obj->psw_last_change = spwd->sp_lstchg;
    obj->psw_min_day = spwd->sp_min;
    obj->psw_max_day = spwd->sp_max;
    obj->psw_expire_day = spwd->sp_expire;
    obj->uid = passwd->pw_uid;
    obj->gid = passwd->pw_gid;

    if (!(obj->name = strdup(passwd->pw_name))) {
        SUD_DEBUG_ERRNO();
        goto exit;
    }

    if (!(obj->shadow = strdup(spwd->sp_pwdp))) {
        SUD_DEBUG_ERRNO();
        goto exit;
    }

    if (!(obj->home_dir = strdup(passwd->pw_dir))) {
        SUD_DEBUG_ERRNO();
        goto exit;
    }

    if (!(obj->shell = strdup(passwd->pw_shell))) {
        SUD_DEBUG_ERRNO();
        goto exit;
    }

    return 0;

exit:
    free_userinfo(obj);
    return -1;
}

void free_userinfo(user_info_t *obj) {
    if (obj->name) {
        free(obj->name);
    }

    if (obj->shadow) {
        free(obj->shadow);
    }

    if (obj->home_dir) {
        free(obj->home_dir);
    }

    if (obj->shell) {
        free(obj->shell);
    }
}
