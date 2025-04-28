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
pub mod persist;
pub mod server;
pub mod sud;
pub mod utils;

pub mod c_ffi;

use crate::args::SudCmdlineArgs;
use crate::client::main_client;
use crate::persist::main_server_persist;
use crate::server::main_server;
use crate::sud::SUD_MAGIC;
use crate::sud::SUD_SOCKET_PERSIST_PATH;
use crate::sud::SudAuthPersistMsg;
use crate::sud::SudAuthPersistMsgAction;
use crate::utils::unix_socket_connect;
use clap::Parser;
use nix::unistd;
use once_cell::sync::Lazy;
use std::env;
use std::io::Error;
use std::io::Write;
use std::process::ExitCode;

static SUD_CONFIG_PATH: Lazy<String> = Lazy::new(|| {
    env::var("SUD_CONFIG_PATH").unwrap_or_else(|_| {
        eprintln!("Error: SUD_CONFIG_PATH environment variable not found!");
        std::process::exit(1);
    })
});

pub fn clear_persist(all: bool) -> Result<(), Error> {
    let mut stream = unix_socket_connect(SUD_SOCKET_PERSIST_PATH, 1)?;

    let action = if all {
        SudAuthPersistMsgAction::RemoveAll
    } else {
        SudAuthPersistMsgAction::Remove
    };

    let msg = SudAuthPersistMsg {
        magic: SUD_MAGIC.as_bytes().try_into().unwrap(),
        action: action,
        uid: unistd::Uid::current(),
    };

    stream.write_all(msg.as_bytes())?;
    Ok(())
}

fn main() -> ExitCode {
    let args = SudCmdlineArgs::parse_from(env::args());

    if args.daemon || args.daemon_persist {
        if unistd::getppid().as_raw() != 1 {
            eprintln!("SUD daemon should only be started by systemd init!");
            return ExitCode::from(1);
        }

        if unistd::getuid().as_raw() != 0 {
            eprintln!("SUD daemon should be started as root!");
            return ExitCode::from(1);
        }

        let result = if args.daemon {
            main_server()
        } else {
            main_server_persist()
        };

        match result {
            Ok(()) => {
                return ExitCode::from(0);
            }
            Err(e) => {
                eprintln!("{}", e);
                return ExitCode::from(1);
            }
        }
    } else if args.clear_persist || args.clear_persist_all {
        if args.clear_persist_all && unistd::getuid().as_raw() != 0 {
            eprintln!("You must be root to clear persistent authentications for all users!");
            return ExitCode::from(1);
        }

        match clear_persist(args.clear_persist_all) {
            Ok(()) => ExitCode::from(0),
            Err(e) => {
                eprintln!("{}", e);
                ExitCode::from(1)
            }
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
