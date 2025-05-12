// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/auth.rs
 *
 *  Copyright (C) Emily <info@emy.sh>
 *  Copyright (C) Kat <kat@castellotti.net>
 */

use crate::args::SudCmdlineArgs;
use crate::c_ffi;
use crate::config::{ConfigAuthMode, SudGlobalConfig, SudPolicy, policy_get_match};
use crate::sud;
use crate::utils::ProcessInfo;
use nix::fcntl;
use nix::unistd;
use nix::unistd::Uid;
use passwd_rs::AccountStatus;
use passwd_rs::group::Group;
use passwd_rs::shadow::Shadow;
use passwd_rs::user::User;
use secure_string::SecureVec;
use std::ffi::CString;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::raw::c_int;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use termios::{ECHO, ICANON, TCSANOW, Termios};

pub struct UserInfo {
    pub user: User,
    pub shadow: Shadow,
    pub groups: Vec<Group>,
}

impl UserInfo {
    pub fn from_user(user: User) -> Result<Self, sud::SudError> {
        let shadow = Shadow::new_from_username(&user.name)?;

        let mut groups = Vec::<Group>::new();
        let gids = unistd::getgrouplist(
            CString::new(user.name.as_str()).unwrap().as_c_str(),
            user.gid.into(),
        )?;

        for gid in gids.into_iter() {
            groups.push(Group::new_from_gid(gid.into())?);
        }

        Ok(Self {
            user: user,
            shadow: shadow,
            groups: groups,
        })
    }

    pub fn from_uid(uid: unistd::Uid) -> Result<Self, sud::SudError> {
        let user = User::new_from_uid(uid.as_raw())?;
        Self::from_user(user)
    }

    pub fn from_username(username: &str) -> Result<Self, sud::SudError> {
        let user = User::new_from_name(username)?;
        Self::from_user(user)
    }

    pub fn from_str(str: &str) -> Result<Self, sud::SudError> {
        if str.chars().all(|c| c.is_digit(10)) {
            let num: i64 = str.parse()?;

            if num >= std::u32::MAX as i64 || num < 0 {
                return Self::from_username(str);
            }

            match Self::from_uid(unistd::Uid::from_raw(num.try_into().unwrap())) {
                Ok(user) => return Ok(user),
                Err(_) => {}
            };
        }

        return Self::from_username(str);
    }

    pub fn is_in_group(&self, group_name: &str) -> bool {
        for group in self.groups.iter() {
            if group.name == group_name {
                return true;
            }
        }

        return false;
    }

    fn is_user_valid(&self) -> bool {
        let time_sec = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs() as i64,
            Err(_) => {
                return false;
            }
        };

        let time_day = time_sec / (60 * 60 * 24);

        if !matches!(self.shadow.passwd, AccountStatus::Active(_)) {
            return false;
        }

        if self.shadow.last_chage == -1 {
            return true;
        }

        if self.shadow.last_chage == 0 {
            return false;
        }

        if self.shadow.max != -1 && (self.shadow.last_chage + self.shadow.max - time_day) < 0 {
            return false;
        }

        if self.shadow.expires != -1 && (self.shadow.expires - time_day) < 0 {
            return false;
        }

        true
    }
}

pub struct SudAuthPersist {
    uid: Uid,
    valid_time: u64,
}

pub fn sud_auth(
    pinfo: &mut ProcessInfo,
    o_user: &UserInfo,
    t_user: &UserInfo,
    args: &SudCmdlineArgs,
    global_conf: &SudGlobalConfig,
    auth_persists: Arc<Mutex<Vec<SudAuthPersist>>>,
) -> Result<bool, sud::SudError> {
    if !o_user.is_user_valid() || !t_user.is_user_valid() {
        return Ok(false);
    }

    if o_user.user.uid == 0 || o_user.user.uid == t_user.user.uid {
        return Ok(true);
    }

    if args.non_interactive && !args.stdin {
        return Ok(false);
    }

    let cmd = args
        .command
        .clone()
        .ok_or(sud::SudError::NotFound("Missing command in args".into()))?;

    let policies = SudPolicy::load()?;
    let policy = policy_get_match(&policies, o_user, t_user, cmd)
        .ok_or(sud::SudError::NotFound("Missing sud policy".into()))?;

    if !policy.permit {
        return Ok(false);
    }

    if check_persist(auth_persists.clone(), o_user) {
        return Ok(true);
    }

    let is_auth = if global_conf.auth_mode == ConfigAuthMode::Shadow {
        auth_shadow(pinfo, &o_user, &args, &global_conf)?
    } else if global_conf.auth_mode == ConfigAuthMode::Pam {
        auth_pam(pinfo, &o_user, &args, &global_conf)
    } else {
        false
    };

    if is_auth && policy.persist {
        add_persist(auth_persists.clone(), global_conf, o_user);
    }

    Ok(is_auth)
}

fn add_persist(
    auth_persists: Arc<Mutex<Vec<SudAuthPersist>>>,
    global_conf: &SudGlobalConfig,
    o_user: &UserInfo,
) {
    let mut auth_persists = auth_persists.lock().unwrap();
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    auth_persists.retain(|auth_persist| auth_persist.uid != o_user.user.uid.into());
    auth_persists.push(SudAuthPersist {
        uid: o_user.user.uid.into(),
        valid_time: current_time + global_conf.persist_timeout,
    });
}

fn check_persist(auth_persists: Arc<Mutex<Vec<SudAuthPersist>>>, o_user: &UserInfo) -> bool {
    let auth_persists = auth_persists.lock().unwrap();
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    for auth_persist in &*auth_persists {
        if auth_persist.uid == o_user.user.uid.into() && current_time < auth_persist.valid_time {
            return true;
        }
    }

    return false;
}

pub fn clear_persist(auth_persists: Arc<Mutex<Vec<SudAuthPersist>>>, o_user: &UserInfo) {
    let mut auth_persists = auth_persists.lock().unwrap();
    auth_persists.retain(|auth_persist| auth_persist.uid != o_user.user.uid.into());
}

pub fn clear_persist_all(auth_persists: Arc<Mutex<Vec<SudAuthPersist>>>) {
    let mut auth_persists = auth_persists.lock().unwrap();
    auth_persists.clear();
}

fn auth_shadow(
    pinfo: &mut ProcessInfo,
    o_user: &UserInfo,
    args: &SudCmdlineArgs,
    global_conf: &SudGlobalConfig,
) -> Result<bool, sud::SudError> {
    let o_shadow = match &o_user.shadow.passwd {
        AccountStatus::Active(shadow) => shadow,
        _ => return Ok(false),
    };

    let mut password = read_password(pinfo, o_user, args, global_conf)?;
    let hash = c_ffi::crypt::crypt(&password, o_shadow.to_string())?;
    password.zero_out();

    Ok(time_compare(&hash, o_shadow))
}

fn auth_pam(
    pinfo: &mut ProcessInfo,
    o_user: &UserInfo,
    args: &SudCmdlineArgs,
    global_conf: &SudGlobalConfig,
) -> bool {
    struct Conversation<'a> {
        pinfo: &'a mut ProcessInfo,
        o_user: &'a UserInfo,
        args: &'a SudCmdlineArgs,
        global_conf: &'a SudGlobalConfig,
    }

    impl c_ffi::pam::PamConversation for Conversation<'_> {
        fn prompt_echo(&mut self, _msg: String) -> Result<SecureVec<u8>, ()> {
            match read_password(self.pinfo, self.o_user, self.args, self.global_conf) {
                Ok(password) => Ok(password),
                Err(_) => return Err(()),
            }
        }

        fn prompt_noecho(&mut self, msg: String) -> Result<SecureVec<u8>, ()> {
            self.prompt_echo(msg)
        }

        fn info(&mut self, msg: String) {
            let mut tty_o = match &self.pinfo.tty {
                Some(tty) => {
                    if !self.args.stdin {
                        tty.try_clone().ok()
                    } else {
                        None
                    }
                }
                None => None,
            };

            if let Some(ref mut tty) = tty_o {
                let _ = writeln!(tty, "PAM: {}", msg);
            }
        }

        fn error(&mut self, msg: String) {
            self.info(msg)
        }
    }

    let mut conv = Conversation {
        pinfo: pinfo,
        o_user: o_user,
        args: args,
        global_conf: global_conf,
    };

    let mut handle = match c_ffi::pam::pam_start("sud", &o_user.user.name, &mut conv) {
        Ok(handle) => handle,
        Err(_) => return false,
    };

    let mut result = match c_ffi::pam::pam_authenticate(&mut handle, 0) {
        Ok(_) => 0 as i32,
        Err(code) => code,
    };

    if result == c_ffi::pam::PAM_SUCCESS {
        result = match c_ffi::pam::pam_acct_mgmt(&mut handle, 0) {
            Ok(_) => 0 as i32,
            Err(code) => code,
        };
    }

    c_ffi::pam::pam_end(&mut handle, result).ok();

    if result == c_ffi::pam::PAM_SUCCESS {
        return true;
    }

    false
}

fn read_password(
    pinfo: &mut ProcessInfo,
    o_user: &UserInfo,
    args: &SudCmdlineArgs,
    global_conf: &SudGlobalConfig,
) -> Result<SecureVec<u8>, sud::SudError> {
    let mut buffer = Vec::<u8>::new();
    let mut i: usize = 0;
    let mut ch = [0];
    let mut flags_fcntl: Option<c_int> = None;
    let mut term_old: Option<Termios> = None;

    let mut tty_o = match &pinfo.tty {
        Some(tty) => {
            if !args.stdin {
                Some(tty.try_clone()?)
            } else {
                None
            }
        }
        None => None,
    };

    if let Some(ref mut tty) = tty_o {
        // Save terminal settings
        let mut term = Termios::from_fd(tty.as_raw_fd())?;
        term_old = Some(term.clone());

        // Set terminal settings
        term.c_lflag &= !(ICANON | ECHO);
        termios::tcsetattr(tty.as_raw_fd(), TCSANOW, &term)?;

        write!(tty, "[sud] password for {}: ", o_user.user.name)?;
    } else {
        flags_fcntl = Some(fcntl::fcntl(
            pinfo.stdin.as_raw_fd(),
            fcntl::FcntlArg::F_GETFL,
        )?);
        fcntl::fcntl(
            pinfo.stdin.as_raw_fd(),
            fcntl::FcntlArg::F_SETFL(
                fcntl::OFlag::from_bits_truncate(flags_fcntl.unwrap()) | fcntl::OFlag::O_NONBLOCK,
            ),
        )?;
    }

    while let Ok(rc) = unistd::read(pinfo.stdin.as_raw_fd(), &mut ch) {
        if rc == 1 && ch[0] != b'\r' && ch[0] != b'\n' {
            if let Some(ref mut tty) = tty_o {
                if ch[0] == 127 || ch[0] == 8 {
                    // Backspace
                    if i != 0 {
                        i -= 1;
                        buffer.pop();
                        write!(tty, "\x08 \x08")?;
                    }

                    continue;
                }
            }

            buffer.insert(i, ch[0]);
            i += 1;

            if let Some(ref mut tty) = tty_o {
                if global_conf.password_echo_enable {
                    write!(tty, "{}", global_conf.password_echo)?;
                }
            }
        } else {
            break;
        }
    }

    buffer.push(0);

    if let Some(ref mut tty) = tty_o {
        write!(tty, "\n")?;
        termios::tcsetattr(tty.as_raw_fd(), TCSANOW, &term_old.unwrap())?;
    } else {
        fcntl::fcntl(
            pinfo.stdin.as_raw_fd(),
            fcntl::FcntlArg::F_SETFL(fcntl::OFlag::from_bits_truncate(flags_fcntl.unwrap())),
        )?;
    }

    Ok(SecureVec::new(buffer))
}

fn time_compare(str1: &str, str2: &str) -> bool {
    let buf1 = str1.as_bytes();
    let buf2 = str2.as_bytes();
    let buf1_len = buf1.len();
    let buf2_len = buf2.len();

    let mut result = buf1_len ^ buf2_len;
    let mut buf_inv = Vec::with_capacity(buf1_len);

    for &b in buf1 {
        buf_inv.push(!b);
    }

    for i in 0..buf1_len {
        let cmp = if i >= buf2_len {
            buf1[i] ^ buf_inv[i]
        } else {
            buf1[i] ^ buf2[i]
        };

        result |= cmp as usize;
    }

    result == 0
}
