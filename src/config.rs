// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/config.rs
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

use crate::sud;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

const SUD_C_CONF_PATH: &str = "/etc/sud.conf";

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

        let path = Path::new(SUD_C_CONF_PATH);
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
