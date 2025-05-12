// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/server.rs
 *
 *  Copyright (C) Emily <info@emy.sh>
 *  Copyright (C) Kat <kat@castellotti.net>
 */

use crate::args::SudCmdlineArgs;
use crate::auth::SudAuthPersist;
use crate::auth::{UserInfo, sud_auth};
use crate::config::SudGlobalConfig;
use crate::exec::sud_exec;
use crate::utils::ProcessInfo;
use clap;
use nix;
use std::fmt;
use std::io;
use std::mem;
use std::num;
use std::os::fd::BorrowedFd;
use std::process::Child;
use std::sync::Arc;
use std::sync::Mutex;

pub const SUD_SOCKET_PATH: &str = "sud_privilege_manager_socket";
pub const SUD_MAGIC: &str = "____sud_privilege_manager____";

#[derive(Debug)]
pub enum SudError {
    GenericFuncError(String, String),
    GenericUnsafeCall(String, i32, String),
    InvalidConfig(String),
    NotFound(String),
    AuthFail(String),
    IoError(io::Error),
    ParseIntError(num::ParseIntError),
    NixError(nix::errno::Errno),
    ClapError(clap::error::Error),
}

impl fmt::Display for SudError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SudError::GenericFuncError(fn_name, msg) => {
                write!(f, "Error in fn {}(): {}", fn_name, msg)
            }
            SudError::GenericUnsafeCall(fn_name, code, msg) => write!(
                f,
                "Unsafe call to fn {}() failed with code {}: {}",
                fn_name, code, msg
            ),
            SudError::InvalidConfig(msg) => write!(f, "Invalid config: {}", msg),
            SudError::NotFound(msg) => write!(f, "Not found: {}", msg),
            SudError::AuthFail(msg) => write!(f, "Auth failed: {}", msg),
            SudError::IoError(e) => write!(f, "IO error ({}): {}", e.kind(), e.to_string()),
            SudError::ParseIntError(e) => write!(f, "Parse int error: {}", e.to_string()),
            SudError::NixError(e) => write!(f, "Error in nix function: {}", e.to_string()),
            SudError::ClapError(e) => write!(f, "Error in args parsing: {}", e.to_string()),
        }
    }
}

impl From<io::Error> for SudError {
    fn from(err: io::Error) -> SudError {
        SudError::IoError(err)
    }
}

impl From<num::ParseIntError> for SudError {
    fn from(err: num::ParseIntError) -> SudError {
        SudError::ParseIntError(err)
    }
}

impl From<nix::errno::Errno> for SudError {
    fn from(err: nix::errno::Errno) -> SudError {
        SudError::NixError(err)
    }
}

impl From<clap::error::Error> for SudError {
    fn from(err: clap::error::Error) -> SudError {
        SudError::ClapError(err)
    }
}

#[repr(u32)]
#[derive(PartialEq, Clone, Debug)]
pub enum SudMsgError {
    Success = 0x00,
    Generic = 0x01,
    Auth = 0x02,
    ClientError = 0x03,
}

#[repr(C)]
pub struct SudResponseMsg {
    pub magic: [u8; SUD_MAGIC.len()],
    pub exit_code: i32,
    pub error: SudMsgError,
}

impl Default for SudResponseMsg {
    fn default() -> Self {
        Self {
            magic: SUD_MAGIC.as_bytes().try_into().unwrap(),
            exit_code: 0,
            error: SudMsgError::Generic,
        }
    }
}

impl SudResponseMsg {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, mem::size_of::<Self>()) }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < mem::size_of::<Self>() {
            return None;
        }

        let msg = unsafe { std::ptr::read(bytes.as_ptr() as *const SudResponseMsg) };

        if msg.magic != SUD_MAGIC.as_bytes() {
            return None;
        }

        Some(msg)
    }
}

pub fn sud_handle(
    conn_fd: BorrowedFd,
    global_config: &SudGlobalConfig,
    auth_persists: Arc<Mutex<Vec<SudAuthPersist>>>,
) -> Result<Child, SudError> {
    let mut pinfo = ProcessInfo::from_conn(conn_fd)?;

    let original_userinfo = UserInfo::from_uid(pinfo.uid)?;

    let args = SudCmdlineArgs::parse(&pinfo)?;

    let target_userinfo = args.get_user()?;

    println!(
        "Authentication for user {} ({}) as target user {} ({}) from process {} trying to execute {} {} started",
        original_userinfo.user.name,
        original_userinfo.user.uid,
        target_userinfo.user.name,
        target_userinfo.user.uid,
        pinfo.pid,
        args.command.as_ref().unwrap(),
        args.args
            .is_empty()
            .then(|| String::new())
            .unwrap_or_else(|| args.args.join(" ")),
    );

    if !sud_auth(
        &mut pinfo,
        &original_userinfo,
        &target_userinfo,
        &args,
        &global_config,
        auth_persists,
    )? {
        return Err(SudError::AuthFail(format!(
            "Authentication for user {} from process {} failed",
            pinfo.uid, pinfo.pid
        )));
    }

    println!(
        "Authentication for user {} from process {} completed successfully",
        pinfo.uid, pinfo.pid
    );

    let child = sud_exec(
        &pinfo,
        &original_userinfo,
        &target_userinfo,
        &args,
        global_config,
    )?;

    println!(
        "Executed process {} ({} {}) as user {} ({}) authenticated as user {} ({})",
        child.id(),
        args.command.unwrap(),
        args.args
            .is_empty()
            .then(|| String::new())
            .unwrap_or_else(|| args.args.join(" ")),
        target_userinfo.user.name,
        target_userinfo.user.uid,
        original_userinfo.user.name,
        original_userinfo.user.uid,
    );

    Ok(child)
}
