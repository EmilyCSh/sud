// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/utils.rs
 *
 *  Copyright (C) Emily <info@emy.sh>
 *  Copyright (C) Kat <kat@castellotti.net>
 */

use crate::sud;
use nix::fcntl::OFlag;
use nix::sys::socket;
use nix::unistd;
use nix::unistd::isatty;
use std::env;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::io::{self, ErrorKind};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{SocketAddr, UnixStream};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct ProcessInfo {
    pub pid: unistd::Pid,
    pub uid: unistd::Uid,
    pub gid: unistd::Gid,
    pub ppid: unistd::Pid,
    pub ppid_starttime: u64,
    pub session: unistd::Pid,
    pub session_starttime: u64,
    pub stdin: File,
    pub stdout: File,
    pub stderr: File,
    pub tty: Option<File>,
    pub ttydev: Option<i32>,
    pub cwd: PathBuf,
    pub exe: PathBuf,
    pub argv: Vec<String>,
    pub envp: Vec<String>,
}

impl ProcessInfo {
    pub fn from_conn(fd: BorrowedFd) -> Result<Self, sud::SudError> {
        let peercred = socket::getsockopt(&fd, socket::sockopt::PeerCredentials)?;

        let stdin = OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .custom_flags(OFlag::O_CLOEXEC.bits())
            .open(format!("/proc/{}/fd/0", peercred.pid()))?;

        let stdout = OpenOptions::new()
            .read(false)
            .write(true)
            .create(false)
            .custom_flags(OFlag::O_CLOEXEC.bits())
            .open(format!("/proc/{}/fd/1", peercred.pid()))?;

        let stderr = OpenOptions::new()
            .read(false)
            .write(true)
            .create(false)
            .custom_flags(OFlag::O_CLOEXEC.bits())
            .open(format!("/proc/{}/fd/2", peercred.pid()))?;

        let tty_fd =
            [&stdin, &stdout, &stderr]
                .iter()
                .enumerate()
                .find_map(|(fd_index, stream)| {
                    if isatty(stream.as_raw_fd()).unwrap_or(false) {
                        Some(fd_index as i32)
                    } else {
                        None
                    }
                });

        let tty = match tty_fd {
            Some(tty_fd) => Some(
                OpenOptions::new()
                    .read(false)
                    .write(true)
                    .create(false)
                    .custom_flags(OFlag::O_CLOEXEC.bits())
                    .open(format!("/proc/{}/fd/{}", peercred.pid(), tty_fd))?,
            ),
            None => None,
        };

        let cwd = fs::read_link(format!("/proc/{}/cwd", peercred.pid()))?;
        let exe = fs::read_link(format!("/proc/{}/exe", peercred.pid()))?;
        let cmdline_buf = fs::read(format!("/proc/{}/cmdline", peercred.pid()))?;
        let envp_buf = fs::read(format!("/proc/{}/environ", peercred.pid()))?;

        let pid_stat_infos = get_stat_pid(peercred.pid())?;

        let ppid = pid_stat_infos[3].parse::<i32>().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("invalid PPID: {}", e))
        })?;

        let session = pid_stat_infos[5].parse::<i32>().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid session: {}", e),
            )
        })?;

        let tty_nr = pid_stat_infos[6]
            .parse::<i32>()
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid tty_nr: {}", e))
            })
            .ok()
            .filter(|&n| n > 0);

        let ppid_stat_infos = get_stat_pid(ppid)?;

        let ppid_starttime = ppid_stat_infos[21].parse::<u64>().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid starttime: {}", e),
            )
        })?;

        let session_stat_infos = get_stat_pid(session)?;

        let session_starttime = session_stat_infos[21].parse::<u64>().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid starttime: {}", e),
            )
        })?;

        let argv: Vec<String> = cmdline_buf
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();

        let envp: Vec<String> = envp_buf
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();

        Ok(Self {
            pid: unistd::Pid::from_raw(peercred.pid()),
            uid: unistd::Uid::from_raw(peercred.uid()),
            gid: unistd::Gid::from_raw(peercred.gid()),
            ppid: unistd::Pid::from_raw(ppid),
            ppid_starttime: ppid_starttime,
            session: unistd::Pid::from_raw(session),
            session_starttime: session_starttime,
            stdin: stdin,
            stdout: stdout,
            stderr: stderr,
            tty: tty,
            ttydev: tty_nr,
            cwd: cwd,
            exe: exe,
            argv: argv,
            envp: envp,
        })
    }

    pub fn get_env(&self, name: &str) -> Option<String> {
        for env in &self.envp {
            if let Some((key, value)) = env.split_once('=') {
                if key == name {
                    return Some(value.to_string());
                }
            }
        }

        None
    }
}

fn is_executable(path: &str) -> bool {
    let path = Path::new(path);

    if let Ok(metadata) = fs::metadata(path) {
        if metadata.is_file() && metadata.permissions().mode() & 0o100 != 0 {
            return true;
        }
    }

    false
}

pub fn find_executable(relative_path: &str, path_env: &str, workdir: &str) -> Option<String> {
    let full_path;

    let path_dup = path_env.to_string();
    let tokens: Vec<&str> = path_dup.split(':').collect();

    let prev_workdir = env::current_dir().unwrap_or_else(|_| PathBuf::new());

    if env::set_current_dir(workdir).is_err() {
        return None;
    }

    if relative_path.contains('/') {
        if let Some(abs_path) = fs::canonicalize(relative_path).ok() {
            let abs_path_str = abs_path.to_str().unwrap_or("");
            if is_executable(abs_path_str) {
                full_path = abs_path_str.to_string();
                env::set_current_dir(prev_workdir).unwrap_or_else(|_| ());
                return Some(full_path);
            }
        }
    } else {
        for token in tokens {
            let candidate_path = format!("{}/{}", token, relative_path);
            if is_executable(&candidate_path) {
                full_path = candidate_path;
                env::set_current_dir(prev_workdir).unwrap_or_else(|_| ());
                return Some(full_path);
            }
        }
    }

    env::set_current_dir(prev_workdir).unwrap_or_else(|_| ());
    None
}

pub fn unix_socket_connect(socket_path: &str, timeout: usize) -> io::Result<UnixStream> {
    let addr = SocketAddr::from_abstract_name(socket_path)?;

    let start_time = Instant::now();
    loop {
        match UnixStream::connect_addr(&addr) {
            Ok(stream) => return Ok(stream),
            Err(ref e)
                if e.kind() == ErrorKind::NotFound || e.kind() == ErrorKind::ConnectionRefused => {}
            Err(e) => return Err(e),
        }

        if start_time.elapsed() > Duration::from_secs(timeout as u64) {
            return Err(io::Error::new(ErrorKind::TimedOut, "Connection timeout"));
        }

        sleep(Duration::from_secs(1));
    }
}

fn get_stat_pid(pid: i32) -> io::Result<Vec<String>> {
    let path = format!("/proc/{}/stat", pid);
    let mut file = File::open(&path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let _open_paren = contents
        .find('(')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing opening parenthesis"))?;
    let _close_paren = contents
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing closing parenthesis"))?;

    let fields: Vec<String> = contents.split_whitespace().map(str::to_string).collect();

    if fields.len() < 52 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not enough fields",
        ));
    }

    Ok(fields)
}
