// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/exec.rs
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

use crate::args::{SudCmdlineArgs, SudIsolateFlags};
use crate::auth::UserInfo;
use crate::config::SudGlobalConfig;
use crate::sud;
use crate::utils::ProcessInfo;
use crate::utils::find_executable;
use nix::unistd::isatty;
use std::os::fd::AsRawFd;
use std::process::{Child, Command};

fn check_if_tty(pinfo: &ProcessInfo) -> Result<bool, sud::SudError> {
    let stdin_is_tty = isatty(pinfo.stdin.as_raw_fd())?;
    let stdout_is_tty = isatty(pinfo.stdout.as_raw_fd())?;
    let stderr_is_tty = isatty(pinfo.stderr.as_raw_fd())?;

    Ok(stdin_is_tty && stdout_is_tty && stderr_is_tty)
}

pub fn sud_exec(
    pinfo: &ProcessInfo,
    o_user: UserInfo,
    t_user: UserInfo,
    args: SudCmdlineArgs,
    global_conf: SudGlobalConfig,
) -> Result<Child, sud::SudError> {
    let mut command = Command::new("/usr/bin/systemd-run");

    command.arg("--quiet");
    command.arg("--collect");
    command.arg("--send-sighup");
    command.arg("--expand-environment=false");

    if check_if_tty(&pinfo)? {
        command.arg("--pty");
    } else {
        command.arg("--pipe");
    }

    command.arg("--service-type=exec");
    command.arg("--wait");

    command.arg("--working-directory");
    let workdir = match args.workdir {
        Some(ref workdir) => workdir,
        None => &pinfo.cwd.to_string_lossy().to_string(),
    };
    command.arg(&workdir);

    command.arg("--uid");
    command.arg(&t_user.user.name);

    command.arg("--background");
    match args.color {
        Some(ref color) => command.arg(color),
        None => command.arg(global_conf.background_color),
    };

    command.arg("-E");
    command.arg(String::from("SUD_USER") + "=" + &o_user.user.name);

    command.arg("-E");
    command.arg(String::from("HOME") + "=" + &t_user.user.homedir);

    command.arg("-E");
    command.arg(String::from("LOGNAME") + "=" + &t_user.user.name);

    command.arg("-E");
    command.arg(String::from("USER") + "=" + &t_user.user.name);

    match pinfo.get_env("DISPLAY") {
        Some(env) => {
            command.arg("-E");
            command.arg(String::from("DISPLAY") + "=" + &env);
        }
        None => {}
    };

    command.arg("-E");
    match pinfo.get_env("TERM") {
        Some(env) => {
            command.arg(String::from("TERM") + "=" + &env);
            command.env("TERM", &env);
        }
        None => {
            command.arg(String::from("TERM") + "=" + "linux");
            command.env("TERM", "linux");
        }
    };

    let shell = match pinfo.get_env("SHELL") {
        Some(env) => env,
        None => t_user.user.shell,
    };

    command.arg("-E");
    command.arg(String::from("SHELL") + "=" + &shell);

    let process_path = pinfo.get_env("PATH").ok_or(sud::SudError::NotFound(
        "Missing env PATH in caller process".into(),
    ))?;
    command.arg("-E");
    command.arg(String::from("PATH") + "=" + &process_path);

    match args.get_isolate_system() {
        Some(SudIsolateFlags::SystemStrict) => {
            command.arg("-pProtectSystem=strict");
        }
        Some(SudIsolateFlags::SystemFull) => {
            command.arg("-pProtectSystem=full");
        }
        Some(SudIsolateFlags::System) => {
            command.arg("-pProtectSystem=true");
        }
        _ => {}
    };

    match args.get_isolate_home() {
        Some(SudIsolateFlags::Home) => {
            command.arg("-pProtectHome=true");
        }
        Some(SudIsolateFlags::HomeTmpfs) => {
            command.arg("-pProtectHome=tmpfs");
        }
        Some(SudIsolateFlags::HomeRo) => {
            command.arg("-pProtectSystem=read-only");
        }
        _ => {}
    };

    if args.get_isolate(SudIsolateFlags::Devices) {
        command.arg("-pPrivateDeviced=true");
    }

    if args.get_isolate(SudIsolateFlags::Net) {
        command.arg("-pPrivateNetwork=true");
    }

    if args.get_isolate(SudIsolateFlags::User) {
        command.arg("-pPrivateUsers=true");
    }

    if args.get_isolate(SudIsolateFlags::Ktuneables) {
        command.arg("-pProtectKernelTunables=true");
    }

    if args.get_isolate(SudIsolateFlags::Klogs) {
        command.arg("-pProtectKernelLogs=true");
    }

    if args.shell {
        command.arg(shell);
    } else {
        let cmd = args
            .command
            .ok_or(sud::SudError::NotFound("Command not found in args".into()))?;
        let exe = find_executable(&cmd, &process_path, &workdir)
            .ok_or(sud::SudError::NotFound("Command not found in PATH".into()))?;

        command.arg("--");
        command.arg(exe);
        command.args(args.args);
    }

    command.stdin(pinfo.stdin.try_clone().unwrap());
    command.stdout(pinfo.stdout.try_clone().unwrap());
    command.stderr(pinfo.stderr.try_clone().unwrap());

    Ok(command.spawn()?)
}
