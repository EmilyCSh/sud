// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/args.rs
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

use crate::auth::UserInfo;
use crate::sud;
use crate::utils::{ProcessInfo, find_executable};
use clap::Parser;

#[derive(Debug, PartialEq, Clone)]
pub enum SudIsolateFlags {
    System,
    SystemFull,
    SystemStrict,
    Home,
    HomeRo,
    HomeTmpfs,
    Tmp,
    Devices,
    Net,
    User,
    Ktuneables,
    Klogs,
}

impl SudIsolateFlags {
    pub fn as_str(&self) -> &'static str {
        match self {
            SudIsolateFlags::System => "system",
            SudIsolateFlags::SystemFull => "system-full",
            SudIsolateFlags::SystemStrict => "system-strict",
            SudIsolateFlags::Home => "home",
            SudIsolateFlags::HomeRo => "home-ro",
            SudIsolateFlags::HomeTmpfs => "home-tmpfs",
            SudIsolateFlags::Tmp => "tmp",
            SudIsolateFlags::Devices => "devices",
            SudIsolateFlags::Net => "net",
            SudIsolateFlags::User => "user",
            SudIsolateFlags::Ktuneables => "kernel-tunables",
            SudIsolateFlags::Klogs => "kernel-logs",
        }
    }
}

#[derive(Parser, Debug, Default)]
#[command(about, version, before_help = "SUD - Super User Daemon")]
pub struct SudCmdlineArgs {
    #[arg(long, help = "Set background color")]
    pub color: Option<String>,

    #[arg(
        long,
        default_value = "false",
        exclusive = true,
        help = "Start SUD as server (must be root)"
    )]
    pub daemon: bool,

    #[arg(
        long,
        short,
        default_value = "false",
        conflicts_with = "command",
        help = "Run shell as the target user"
    )]
    pub shell: bool,

    #[arg(
        long,
        short,
        default_value = "0",
        help = "Run command as specified user name or ID"
    )]
    user: String,

    #[arg(
        long = "non-interactive",
        short = 'n',
        default_value = "false",
        help = "Non-interactive mode"
    )]
    pub non_interactive: bool,

    #[arg(
        long,
        short = 'S',
        default_value = "false",
        help = "Read password from standard input"
    )]
    pub stdin: bool,

    #[arg(long, help = "Run command in a specified working directory")]
    pub workdir: Option<String>,

    #[arg(long, num_args=1.., help="Apply sandboxing policies to the process")]
    isolate: Vec<String>,

    #[arg(
        long,
        default_value = "false",
        exclusive = true,
        help = "Clear persistent authentications of the current user"
    )]
    pub clear_persist: bool,

    #[arg(
        long,
        default_value = "false",
        exclusive = true,
        help = "Clear persistent authentications for all users (alias of --clear-persist if the user is not root)"
    )]
    pub clear_persist_all: bool,

    #[arg(num_args=1, trailing_var_arg=true, allow_hyphen_values=true, required_unless_present_any(["daemon", "shell", "clear_persist", "clear_persist_all"]))]
    pub command: Option<String>,

    #[arg(num_args=1..)]
    pub args: Vec<String>,
}

impl SudCmdlineArgs {
    pub fn parse(pinfo: &ProcessInfo) -> Result<Self, sud::SudError> {
        let mut args = SudCmdlineArgs::try_parse_from(&pinfo.argv)?;

        args.workdir = match args.workdir {
            Some(workdir) => Some(workdir),
            None => Some(pinfo.cwd.to_string_lossy().to_string()),
        };

        if args.shell {
            args.command = match pinfo.get_env("SHELL") {
                Some(env) => Some(env),
                None => Some(args.get_user()?.user.shell),
            };
        }

        if args.command.is_some() {
            let process_path = pinfo.get_env("PATH").ok_or(sud::SudError::NotFound(
                "Missing env PATH in caller process".into(),
            ))?;

            args.command = Some(
                find_executable(
                    &args.command.unwrap(),
                    &process_path,
                    &args.workdir.clone().unwrap(),
                )
                .ok_or(sud::SudError::NotFound("Command not found in PATH".into()))?,
            );
        }

        Ok(args)
    }

    pub fn get_isolate(&self, flag_check: SudIsolateFlags) -> bool {
        self.isolate.iter().any(|s| s == flag_check.as_str())
    }

    fn get_multi_isolate<const N: usize>(
        &self,
        flags: [SudIsolateFlags; N],
    ) -> Option<SudIsolateFlags> {
        for flag in flags {
            if self.get_isolate(flag.clone()) {
                return Some(flag);
            }
        }
        None
    }

    pub fn get_isolate_system(&self) -> Option<SudIsolateFlags> {
        self.get_multi_isolate([
            SudIsolateFlags::SystemStrict,
            SudIsolateFlags::SystemFull,
            SudIsolateFlags::System,
        ])
    }

    pub fn get_isolate_home(&self) -> Option<SudIsolateFlags> {
        self.get_multi_isolate([
            SudIsolateFlags::Home,
            SudIsolateFlags::HomeTmpfs,
            SudIsolateFlags::HomeRo,
        ])
    }

    pub fn get_user(&self) -> Result<UserInfo, sud::SudError> {
        UserInfo::from_str(&self.user)
    }
}
