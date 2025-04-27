// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/client.rs
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

use crate::sud::{SUD_SOCKET_PATH, SudMsgError, SudResponseMsg};
use crate::utils::unix_socket_connect;
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use termios::{TCSANOW, Termios, tcsetattr};

pub fn main_client() -> SudResponseMsg {
    let mut msg: SudResponseMsg = SudResponseMsg::default();
    msg.error = SudMsgError::ClientError;

    let tty_fd = match File::open("/dev/tty") {
        Ok(tty) => Some(tty.as_raw_fd()),
        Err(_) => None,
    };

    let term_attrs = match tty_fd {
        Some(tty_fd) => match Termios::from_fd(tty_fd) {
            Ok(term) => Some(term),
            Err(_) => None,
        },
        None => None,
    };

    if let (Some(tty_fd), Some(term_attrs)) = (tty_fd, term_attrs) {
        ctrlc::set_handler(move || {
            let _ = tcsetattr(tty_fd, TCSANOW, &term_attrs);
            std::process::exit(0);
        })
        .expect("Error setting Ctrl-C handler")
    }

    match unix_socket_connect(SUD_SOCKET_PATH, 1) {
        Ok(mut stream) => {
            let mut buf = [0u8; std::mem::size_of::<SudResponseMsg>()];

            if let Err(e) = stream.read_exact(&mut buf) {
                eprintln!("Error receiving message: {}", e);
            } else {
                if let Some(msg_r) = SudResponseMsg::from_bytes(&buf) {
                    msg = msg_r;
                } else {
                    eprintln!("Error deserialize message");
                }
            }
        }
        Err(e) => {
            eprintln!("Connection failed: {}", e);
        }
    }

    if msg.error != SudMsgError::Success {
        if let (Some(tty_fd), Some(term_attrs)) = (tty_fd, term_attrs) {
            let _ = tcsetattr(tty_fd, TCSANOW, &term_attrs);
        }

        if msg.error == SudMsgError::Generic {
            eprintln!("sud: generic error in sud daemon");
        }

        if msg.error == SudMsgError::Auth {
            eprintln!("sud: authentication failed");
        }

        if msg.error == SudMsgError::ClientError {
            eprintln!("sud: client failed to connect to daemon/failed to receive response");
        }
    }

    msg
}
