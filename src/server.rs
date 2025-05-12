// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/server.rs
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

use crate::sud::{self, SudMsgError, SudResponseMsg, sud_handle};
use libsystemd::activation::{IsType, receive_descriptors_with_names};
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::sys::socket;
use nix::unistd::Pid;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::IntoRawFd;
use std::thread;
use std::time::Duration;

fn kill_pid(pid: i32) {
    println!("SIGTERM sent to process {}", pid);
    let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);

    thread::sleep(Duration::new(10, 0));

    match kill(Pid::from_raw(pid), None) {
        Err(Errno::ESRCH) => {}
        _ => {
            println!(
                "Process {} does not respond to SIGTERM, sending SIGKILL",
                pid
            );
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        }
    }
}

fn check_conn_closed(conn_fd: BorrowedFd) -> Result<bool, Errno> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    let pollfd = PollFd::new(
        conn_fd.as_fd(),
        PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL,
    );

    let nfds = match poll(&mut [pollfd], PollTimeout::ZERO) {
        Err(Errno::EINTR) => return Ok(false),
        nfds => nfds?,
    };

    if nfds <= 0 {
        return Ok(false);
    }

    Ok(true)
}

fn get_conn_fd<'a>() -> Result<BorrowedFd<'a>, sud::SudError> {
    let mut conn_fd = None;

    let fds = receive_descriptors_with_names(true)?;

    for (fd, name) in fds {
        if name != "connection" {
            continue;
        }

        if !fd.is_unix() {
            continue;
        }

        let raw_fd = fd.into_raw_fd();

        if raw_fd < 0 {
            continue;
        }

        conn_fd = Some(unsafe { BorrowedFd::borrow_raw(raw_fd) });
        break;
    }

    conn_fd.ok_or(sud::SudError::NotFound(
        "Unable to find socket connection".into(),
    ))
}

pub fn main_server() -> Result<(), sud::SudError> {
    let mut response = SudResponseMsg::default();
    response.error = SudMsgError::Generic;

    fn send(conn_fd: BorrowedFd, msg: SudResponseMsg) -> SudResponseMsg {
        let _ = socket::send(
            conn_fd.as_raw_fd(),
            msg.as_bytes(),
            socket::MsgFlags::from_bits_truncate(0),
        );
        msg
    }

    let conn_fd = get_conn_fd()?;

    // Handle the connection
    let mut child = match sud_handle(conn_fd) {
        Ok(child) => child,
        Err(sud::SudError::AuthFail(e)) => {
            response.error = SudMsgError::Auth;
            send(conn_fd, response);
            return Err(sud::SudError::AuthFail(e));
        }
        Err(e) => {
            send(conn_fd, response);
            return Err(e);
        }
    };

    let child_pid = child.id() as i32;

    let exit_status = loop {
        let wait_res = match child.try_wait() {
            Ok(res) => res,
            Err(e) => {
                kill_pid(child_pid);
                send(conn_fd, response);
                return Err(sud::SudError::IoError(e));
            }
        };

        if let Some(exit_status) = wait_res {
            break exit_status;
        }

        let is_conn_inactive = match check_conn_closed(conn_fd) {
            Ok(is_conn_inactive) => is_conn_inactive,
            Err(e) => {
                kill_pid(child_pid);
                send(conn_fd, response);
                return Err(sud::SudError::NixError(e));
            }
        };

        if is_conn_inactive {
            kill_pid(child_pid);
            return Ok(());
        }
    };

    response.exit_code = match exit_status.code() {
        Some(code) => code,
        None => {
            send(conn_fd, response);
            return Err(sud::SudError::NotFound("Error with waitpid".into()));
        }
    };

    response.error = SudMsgError::Success;
    println!(
        "Process {} exited with exit code {}",
        child.id(),
        response.exit_code
    );

    send(conn_fd, response);
    Ok(())
}
