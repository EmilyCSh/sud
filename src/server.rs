// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/server.rs
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

use crate::auth::SudAuthPersist;
use crate::config::SudGlobalConfig;
use crate::sud::{self, SudMsgError, SudResponseMsg, sud_handle};
use nix::errno::Errno;
use nix::poll::PollFd;
use nix::poll::PollFlags;
use nix::poll::PollTimeout;
use nix::poll::poll;
use nix::sys::signal::{Signal, kill};
use nix::sys::signalfd::SigSet;
use nix::sys::signalfd::SignalFd;
use nix::sys::socket;
use nix::unistd::Pid;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::Mutex;
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

fn handle_conn(
    stream: UnixStream,
    global_config: Arc<SudGlobalConfig>,
    auth_persists: Arc<Mutex<Vec<SudAuthPersist>>>,
) {
    let conn_fd = stream.as_fd();
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

    let mut sigset = SigSet::empty();
    sigset.add(Signal::SIGCHLD);
    match sigset.thread_block() {
        Err(e) => {
            send(conn_fd, response);
            eprintln!("{}", e);
            return;
        }
        _ => {}
    }

    let signalfd = match SignalFd::new(&sigset) {
        Ok(signalfd) => signalfd,
        Err(e) => {
            send(conn_fd, response);
            eprintln!("{}", e);
            return;
        }
    };

    // Handle the connection
    let mut child = match sud_handle(conn_fd, &*global_config, auth_persists) {
        Ok(child) => match child {
            Some(child) => child,
            None => {
                response.exit_code = 0;
                response.error = SudMsgError::Success;
                send(conn_fd, response);
                return;
            }
        },
        Err(sud::SudError::AuthFail(e)) => {
            response.error = SudMsgError::Auth;
            send(conn_fd, response);
            eprintln!("{}", e);
            return;
        }
        Err(e) => {
            send(conn_fd, response);
            eprintln!("{}", e);
            return;
        }
    };

    let child_pid = child.id() as i32;

    let mut pollfds = [
        PollFd::new(signalfd.as_fd(), PollFlags::POLLIN),
        PollFd::new(
            conn_fd.as_fd(),
            PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL,
        ),
    ];

    let exit_status = loop {
        match poll(&mut pollfds, PollTimeout::NONE) {
            Err(Errno::EINTR) => continue,
            Err(e) => {
                kill_pid(child_pid);
                send(conn_fd, response);
                eprintln!("{}", e);
                return;
            }
            Ok(_) => {
                if pollfds[0].any().unwrap_or_default() {
                    let wait_res = match child.try_wait() {
                        Ok(res) => res,
                        Err(e) => {
                            kill_pid(child_pid);
                            send(conn_fd, response);
                            eprintln!("{}", e);
                            return;
                        }
                    };

                    if let Some(exit_status) = wait_res {
                        break exit_status;
                    }
                }

                if pollfds[1].any().unwrap_or_default() {
                    kill_pid(child_pid);
                    return;
                }
            }
        }
    };

    response.exit_code = match exit_status.code() {
        Some(code) => code,
        None => {
            send(conn_fd, response);
            eprintln!("Error with waitpid");
            return;
        }
    };

    response.error = SudMsgError::Success;
    println!(
        "Process {} exited with exit code {}",
        child.id(),
        response.exit_code
    );

    send(conn_fd, response);
}

pub fn main_server() -> Result<(), sud::SudError> {
    let listener = unsafe { UnixListener::from_raw_fd(0) };
    let global_config = Arc::new(SudGlobalConfig::load()?);
    let auth_persists: Arc<Mutex<Vec<SudAuthPersist>>> = Arc::new(Mutex::new(Vec::new()));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let global_config = Arc::clone(&global_config);
                let auth_persists = Arc::clone(&auth_persists);

                thread::spawn(move || {
                    handle_conn(stream, global_config, auth_persists);
                });
            }
            Err(e) => {
                return Err(sud::SudError::IoError(e));
            }
        }
    }
    Ok(())
}
