// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/persist.rs
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

use crate::config::SudGlobalConfig;
use crate::sud::{self, SudAuthPersistMsg, SudAuthPersistMsgAction, SudMsgError, SudResponseMsg};
use nix::sys::socket;
use nix::sys::socket::UnixCredentials;
use nix::unistd::Uid;
use std::io::{Read, Write};
use std::mem;
use std::os::fd::AsFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

struct SudAuthPersist {
    uid: Uid,
    valid_time: u64,
}

fn handle_msg(
    msg: SudAuthPersistMsg,
    peercred: UnixCredentials,
    global_config: Arc<SudGlobalConfig>,
    auth_persists: Arc<Mutex<Vec<SudAuthPersist>>>,
) -> SudMsgError {
    if !(peercred.uid() == 0
        || (msg.action == SudAuthPersistMsgAction::Remove && peercred.uid() == msg.uid.into()))
    {
        return SudMsgError::Auth;
    }

    let mut auth_persists = match auth_persists.lock() {
        Ok(auth_persists) => auth_persists,
        Err(_) => {
            return SudMsgError::Generic;
        }
    };

    let current_time =
        match std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => return SudMsgError::Generic,
        };

    match msg.action {
        SudAuthPersistMsgAction::Check => {
            for auth_persist in &*auth_persists {
                if auth_persist.uid == msg.uid && current_time < auth_persist.valid_time {
                    return SudMsgError::Success;
                }
            }

            return SudMsgError::Auth;
        }
        SudAuthPersistMsgAction::Add => {
            auth_persists.retain(|auth_persist| auth_persist.uid != msg.uid);
            auth_persists.push(SudAuthPersist {
                uid: msg.uid,
                valid_time: current_time + global_config.persist_timeout,
            });
        }
        SudAuthPersistMsgAction::Remove => {
            auth_persists.retain(|auth_persist| auth_persist.uid != msg.uid);
        }
        SudAuthPersistMsgAction::RemoveAll => {
            auth_persists.clear();
        }
    }

    return SudMsgError::Success;
}

fn handle_fd(
    mut stream: UnixStream,
    global_config: Arc<SudGlobalConfig>,
    auth_persists: Arc<Mutex<Vec<SudAuthPersist>>>,
) {
    let mut buffer = [0u8; mem::size_of::<SudAuthPersistMsg>()];
    let mut response = SudResponseMsg::default();
    response.error = SudMsgError::Generic;

    let peercred = match socket::getsockopt(&stream.as_fd(), socket::sockopt::PeerCredentials) {
        Ok(peercred) => peercred,
        Err(_) => {
            let _ = stream.write_all(response.as_bytes());
            return;
        }
    };

    if let Ok(()) = stream.read_exact(&mut buffer) {
        if let Some(msg) = SudAuthPersistMsg::from_bytes(&buffer) {
            response.error = handle_msg(msg, peercred, global_config, auth_persists);
        }
    }

    let _ = stream.write_all(response.as_bytes());
}

pub fn main_server_persist() -> Result<(), sud::SudError> {
    let listener = unsafe { UnixListener::from_raw_fd(0) };
    let auth_persists: Arc<Mutex<Vec<SudAuthPersist>>> = Arc::new(Mutex::new(Vec::new()));
    let global_config = Arc::new(SudGlobalConfig::load()?);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let global_config = Arc::clone(&global_config);
                let auth_persists_clone = Arc::clone(&auth_persists);

                thread::spawn(move || {
                    handle_fd(stream, global_config, auth_persists_clone);
                });
            }
            Err(e) => {
                return Err(sud::SudError::IoError(e));
            }
        }
    }

    Ok(())
}
