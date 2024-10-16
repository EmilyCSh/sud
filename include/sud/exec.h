// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/include/sud/exec.h
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

#ifndef SUD_EXEC_H_
#define SUD_EXEC_H_

#include <sud/args.h>
#include <sud/auth.h>
#include <sud/utils.h>

int set_stdio_process(int _stdin, int _stdout, int _stderr);
pid_t sud_exec(process_info_t *pinfo, user_info_t *o_user, user_info_t *t_user, sud_cmdline_args_t *args);

#endif // SUD_EXEC_H_
