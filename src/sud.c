// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/server.c
 *
 *  Copyright (C) Emily <info@emy.sh>
 *  Copyright (C) Kat <kat@castellotti.net>
 */

#include <stdio.h>
#include <sud/args.h>
#include <sud/auth.h>
#include <sud/exec.h>
#include <sud/sud.h>

pid_t sud_handle(int conn_fd, int *error) {
    int rc;
    pid_t exec_pid = -1;
    process_info_t pinfo;
    user_info_t original_user_info;
    user_info_t target_user_info;
    sud_cmdline_args_t args;
    char *process_path;
    char cmd[PATH_MAX];

    rc = get_process_info_conn(conn_fd, &pinfo);
    if (rc < 0) {
        SUD_ERR("Failed to get process info from procfs\n");
        goto exit;
    }

    rc = get_userinfo_from_pid(pinfo.uid, &original_user_info);
    if (rc < 0) {
        SUD_ERR("Failed to get original user info\n");
        return -1;
    }

    rc = get_userinfo_from_pid(args.user, &target_user_info);
    if (rc < 0) {
        SUD_ERR("Failed to get original user info\n");
        return -1;
    }

    rc = parse_cmdline_silence(pinfo.argc, pinfo.argv, &args);
    if (rc != 0) {
        SUD_ERR("Cmdline parser error\n");
        goto exit;
    }

    process_path = getenv_envp("PATH", pinfo.envp);
    if (!process_path) {
        SUD_ERR("Missing env PATH in caller process\n");
        goto exit;
    }

    if (!args.workdir) {
        args.workdir = pinfo.cwd;
    }

    rc = find_executable(args.argv[0], process_path, args.workdir, cmd);
    if (rc < 0) {
        SUD_ERR("Can't find cmd to be execute'\n");
        goto exit;
    }

    args.cmd = cmd;
    args.argc = args.argc - 1;
    args.argv = &(args.argv[1]);

    SUD_FNOTICE("Authentication for user %d from process %d started\n", pinfo.uid, pinfo.pid);

    if (!sud_auth(&pinfo, &original_user_info, &target_user_info, &args)) {
        SUD_FERR("Authentication for user %d from process %d failed\n", pinfo.uid, pinfo.pid);
        *error = SUD_MSG_ERROR_AUTH;
        goto exit;
    }

    SUD_FNOTICE("Authentication for user %d from process %d completed successfully\n", pinfo.uid, pinfo.pid);

    exec_pid = sud_exec(&pinfo, &original_user_info, &target_user_info, &args);
    if (exec_pid < 0) {
        SUD_ERR("Failed to start exec process\n");
        goto exit;
    }

    SUD_FNOTICE("Executed process %d authenticated as user %d\n", exec_pid, pinfo.uid);

exit:
    free_process_info(&pinfo);
    free_userinfo(&original_user_info);
    free_userinfo(&target_user_info);
    return exec_pid;
}
