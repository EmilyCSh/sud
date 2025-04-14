// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/c_ffi/crypt.rs
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

use crate::sud;
use secure_string::SecureVec;
use std::ffi::{CStr, CString};

mod c_crypt {
    use std::os::raw::c_char;

    unsafe extern "C" {
        pub fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
    }
}

pub fn crypt(passwd: &SecureVec<u8>, salt: String) -> Result<String, sud::SudError> {
    unsafe {
        let hash = c_crypt::crypt(
            passwd.unsecure().as_ptr() as *const i8,
            CString::new(salt).unwrap().as_ptr(),
        );

        if hash.is_null() {
            return Err(sud::SudError::GenericUnsafeCall(
                "crypt".into(),
                -1,
                "Failed to generate password hash".into(),
            ));
        }

        return Ok(CStr::from_ptr(hash).to_string_lossy().into_owned());
    }
}
