// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/config.rs
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

use crate::SUD_CONFIG_PATH;
use crate::auth::UserInfo;
use crate::sud;
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[repr(u32)]
#[derive(Debug, Default, PartialEq)]
pub enum ConfigAuthMode {
    #[default]
    Shadow = 0x00,
    Pam = 0x01,
}

#[derive(Debug, Default)]
pub struct SudGlobalConfig {
    pub auth_mode: ConfigAuthMode,
    pub background_color: String,
    pub password_echo_enable: bool,
    pub password_echo: String,
}

impl SudGlobalConfig {
    pub fn load() -> Result<Self, sud::SudError> {
        let mut conf: SudGlobalConfig = SudGlobalConfig::default();

        let path = Path::new(SUD_CONFIG_PATH.as_str());
        let file = File::open(&path)?;
        let reader = BufReader::new(file);

        for line_res in reader.lines() {
            let line = match line_res {
                Ok(l) => l,
                Err(_) => continue,
            };

            let mut parts = line.split_whitespace();
            let key = parts.next();
            let subkey = parts.next();
            let value = parts.collect::<Vec<_>>().join(" ");

            let (key, subkey) = match (key, subkey) {
                (Some(k), Some(sk)) => (k, sk),
                _ => continue,
            };

            if key != "global" {
                continue;
            }

            match subkey {
                "auth_mode" => match value.as_str() {
                    "shadow" => conf.auth_mode = ConfigAuthMode::Shadow,
                    "pam" => conf.auth_mode = ConfigAuthMode::Pam,
                    _ => {
                        return Err(sud::SudError::InvalidConfig(format!(
                            "Unsupported value \"{}\" for option \"{}\"",
                            value, subkey
                        )));
                    }
                },

                "background_color" => {
                    conf.background_color = value;
                }

                "password_echo_enable" => match value.as_str() {
                    "true" => conf.password_echo_enable = true,
                    "false" => conf.password_echo_enable = false,
                    _ => {
                        return Err(sud::SudError::InvalidConfig(format!(
                            "Unsupported value \"{}\" for option \"{}\"",
                            value, subkey
                        )));
                    }
                },

                "password_echo" => {
                    conf.password_echo = value;
                }

                _ => {
                    return Err(sud::SudError::InvalidConfig(format!(
                        "Unsupported key \"{}\" for global options",
                        subkey
                    )));
                }
            }
        }

        Ok(conf)
    }
}

pub enum SudPolicyUserGroup {
    User(UserInfo),
    Group(String),
}

pub struct SudPolicy {
    pub weight: i32,
    pub index: i32,
    pub permit: bool,
    pub original_user_group: SudPolicyUserGroup,
    pub target_user: Option<UserInfo>,
    pub cmd: Option<String>,
}

impl SudPolicy {
    pub fn load() -> Result<Vec<SudPolicy>, sud::SudError> {
        let path = Path::new(SUD_CONFIG_PATH.as_str());
        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let regex =
            Regex::new(r"^(permit|deny)\s+(\S+)(?:\s+(?:as\s+(\S+)|cmd\s+(\S+))){0,2}$").unwrap();
        let mut policies: Vec<SudPolicy> = Vec::new();
        let mut index = 0;

        for line_res in reader.lines() {
            let line = match line_res {
                Ok(l) => l,
                Err(_) => continue,
            };

            if !(line.starts_with("deny") || line.starts_with("permit")) {
                continue;
            }

            let caps = match regex.captures(line.trim()) {
                Some(caps) => caps,
                None => {
                    return Err(sud::SudError::InvalidConfig(format!(
                        "Invalid policy format ({})",
                        line
                    )));
                }
            };

            let permit = match &caps[1] {
                "permit" => true,
                "deny" => false,
                _ => {
                    return Err(sud::SudError::InvalidConfig(format!(
                        "Invalid policy format ({})",
                        line
                    )));
                }
            };

            let mut weight = 0;
            let original_user_group_str = caps[2].to_string();

            let original_user_group = if original_user_group_str.starts_with(':') {
                SudPolicyUserGroup::Group((&original_user_group_str[1..]).to_string())
            } else {
                SudPolicyUserGroup::User(UserInfo::from_str(&original_user_group_str)?)
            };

            let target_user = match caps.get(3).map(|m| m.as_str().to_string()) {
                Some(target_user) => {
                    weight += 1;
                    Some(UserInfo::from_str(&target_user)?)
                }
                None => None,
            };

            let cmd = match caps.get(4).map(|m| m.as_str().to_string()) {
                Some(cmd) => {
                    weight += 1;
                    Some(cmd)
                }
                None => None,
            };

            policies.push(SudPolicy {
                weight: weight,
                index: index,
                permit: permit,
                original_user_group: original_user_group,
                target_user: target_user,
                cmd: cmd,
            });

            index += 1;
        }

        Ok(policies)
    }
}

pub fn policy_is_permit(
    policies: &Vec<SudPolicy>,
    original_user: &UserInfo,
    target_user: &UserInfo,
    cmd: String,
) -> bool {
    let mut matches: Vec<&SudPolicy> = Vec::new();

    for policy in policies {
        match &policy.original_user_group {
            SudPolicyUserGroup::User(user) => {
                if user.user.name != original_user.user.name {
                    continue;
                }
            }
            SudPolicyUserGroup::Group(group) => {
                if !original_user.is_in_group(&group) {
                    continue;
                }
            }
        }

        if let Some(policy_target_user) = &policy.target_user {
            if policy_target_user.user.name != target_user.user.name {
                continue;
            }
        }

        if let Some(policy_cmd) = &policy.cmd {
            if *policy_cmd != cmd {
                continue;
            }
        }

        matches.push(policy);
    }

    if matches.len() < 1 {
        return false;
    }

    matches.sort_by(|a, b| {
        b.weight
            .cmp(&a.weight)
            .then_with(|| {
                let a_is_user = matches!(a.original_user_group, SudPolicyUserGroup::User(_));
                let b_is_user = matches!(b.original_user_group, SudPolicyUserGroup::User(_));
                b_is_user.cmp(&a_is_user)
            })
            .then_with(|| b.index.cmp(&a.index))
    });

    matches[0].permit
}
