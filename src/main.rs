// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/main.rs
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

pub mod args;
pub mod auth;
pub mod client;
pub mod config;
pub mod exec;
pub mod server;
pub mod sud;
pub mod utils;

pub mod c_ffi;

use crate::args::SudCmdlineArgs;
use crate::client::main_client;
use crate::server::main_server;
use clap::Parser;
use nix::unistd;
use once_cell::sync::Lazy;
use std::env;
use std::process::ExitCode;

static SUD_CONFIG_PATH: Lazy<String> = Lazy::new(|| {
    env::var("SUD_CONFIG_PATH").unwrap_or_else(|_| {
        eprintln!("Error: SUD_CONFIG_PATH environment variable not found!");
        std::process::exit(1);
    })
});

fn main() -> ExitCode {
    let args = SudCmdlineArgs::parse_from(env::args());

    if args.daemon {
        if unistd::getppid().as_raw() != 1 {
            eprintln!("SUD daemon should only be started by systemd init!");
            return ExitCode::from(1);
        }

        if unistd::getuid().as_raw() != 0 {
            eprintln!("SUD daemon should be started as root!");
            return ExitCode::from(1);
        }

        if main_server().error == sud::SudMsgError::Success {
            return ExitCode::from(0);
        } else {
            return ExitCode::from(1);
        }
    } else {
        let msg = main_client();

        if msg.error == sud::SudMsgError::Success {
            return ExitCode::from(msg.exit_code as u8);
        } else {
            return ExitCode::from(1);
        }
    }
}
