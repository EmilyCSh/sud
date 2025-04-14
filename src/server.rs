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

fn conn_guard_thread(conn_fd: BorrowedFd, exec_pid: i32) {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use std::time::Duration;

    let pollfd = PollFd::new(
        conn_fd.as_fd(),
        PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL,
    );

    loop {
        match poll(&mut [pollfd], PollTimeout::NONE) {
            Err(Errno::EINTR) => continue,
            _ => {
                println!(
                    "Connection closed by client, SIGTERM sent to exec process {}",
                    exec_pid
                );
                let _ = kill(Pid::from_raw(exec_pid), Signal::SIGTERM);

                thread::sleep(Duration::new(10, 0));

                match kill(Pid::from_raw(exec_pid), None) {
                    Err(Errno::ESRCH) => {}
                    _ => {
                        println!(
                            "Process {} does not respond to SIGTERM, sending SIGKILL",
                            exec_pid
                        );
                        let _ = kill(Pid::from_raw(exec_pid), Signal::SIGKILL);
                    }
                }

                std::process::exit(0);
            }
        }
    }
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

pub fn main_server() -> SudResponseMsg {
    let mut response = SudResponseMsg::default();
    response.error = SudMsgError::Generic;

    fn send_return(conn_fd: BorrowedFd, msg: SudResponseMsg) -> SudResponseMsg {
        let _ = socket::send(
            conn_fd.as_raw_fd(),
            msg.as_bytes(),
            socket::MsgFlags::from_bits_truncate(0),
        );
        msg
    }

    let conn_fd = match get_conn_fd() {
        Ok(conn_fd) => conn_fd,
        Err(e) => {
            eprintln!("{}", e);
            return response;
        }
    };

    // Handle the connection
    let mut child = match sud_handle(conn_fd) {
        Ok(child) => child,
        Err(sud::SudError::AuthFail(e)) => {
            eprintln!("{}", e);
            response.error = SudMsgError::Auth;
            return send_return(conn_fd, response);
        }
        Err(e) => {
            eprintln!("{}", e);
            return send_return(conn_fd, response);
        }
    };

    // Start the connection guard thread
    let child_pid = child.id();
    thread::spawn(move || conn_guard_thread(conn_fd, child_pid.try_into().unwrap()));

    let exit_status = match child.wait() {
        Ok(exit_status) => exit_status,
        Err(e) => {
            eprintln!("Fail wait pid: {}", e);
            return send_return(conn_fd, response);
        }
    };

    response.exit_code = match exit_status.code() {
        Some(code) => code,
        None => {
            eprintln!("Error with waitpid");
            return send_return(conn_fd, response);
        }
    };

    response.error = SudMsgError::Success;
    println!(
        "Process {} exited with exit code {}",
        child.id(),
        response.exit_code
    );

    send_return(conn_fd, response)
}
