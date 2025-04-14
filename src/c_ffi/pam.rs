// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/src/c_ffi/pam.rs
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

use libc::{calloc, free, size_t, strdup};
use secure_string::SecureVec;
use std::ffi::{CStr, CString};
use std::mem;
use std::os::raw::{c_int, c_void};

pub mod c_pam {
    use std::os::raw::{c_char, c_int, c_void};

    pub const PAM_PROMPT_ECHO_OFF: i32 = 1;
    pub const PAM_PROMPT_ECHO_ON: i32 = 2;
    pub const PAM_ERROR_MSG: i32 = 3;
    pub const PAM_TEXT_INFO: i32 = 4;

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct pam_message {
        pub msg_style: c_int,
        pub msg: *const c_char,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct pam_response {
        pub resp: *mut c_char,
        pub resp_retcode: c_int,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct pam_conv {
        pub conv: unsafe extern "C" fn(
            num_msg: c_int,
            msg: *const *const pam_message,
            resp: *mut *mut pam_response,
            appdata_ptr: *mut c_void,
        ) -> c_int,
        pub appdata_ptr: *mut c_void,
    }

    unsafe extern "C" {
        pub fn pam_start(
            service_name: *const c_char,
            user: *const c_char,
            pam_conversation: *const pam_conv,
            pamh: *mut *mut super::PamHandle,
        ) -> c_int;

        pub fn pam_authenticate(pamh: *mut super::PamHandle, flags: c_int) -> c_int;
        pub fn pam_acct_mgmt(pamh: *mut super::PamHandle, flags: c_int) -> c_int;
        pub fn pam_end(pamh: *mut super::PamHandle, pam_status: c_int) -> c_int;
    }
}

pub type PamHandle = u8;
pub const PAM_SUCCESS: i32 = 0;
pub const PAM_SYSTEM_ERR: i32 = 4;
pub const PAM_BUF_ERR: i32 = 5;
pub const PAM_PERM_DENIED: i32 = 6;
pub const PAM_AUTH_ERR: i32 = 7;
pub const PAM_CRED_INSUFFICIENT: i32 = 8;
pub const PAM_AUTHINFO_UNAVAIL: i32 = 9;
pub const PAM_USER_UNKNOWN: i32 = 10;
pub const PAM_MAXTRIES: i32 = 11;
pub const PAM_NEW_AUTHTOK_REQD: i32 = 12;
pub const PAM_ACCT_EXPIRED: i32 = 13;
pub const PAM_CONV_ERR: i32 = 19;
pub const PAM_ABORT: i32 = 26;
pub const PAM_MAX_RESP_SIZE: usize = 512;

pub trait PamConversation {
    fn prompt_echo(&mut self, msg: String) -> Result<SecureVec<u8>, ()>;
    fn prompt_noecho(&mut self, msg: String) -> Result<SecureVec<u8>, ()>;
    fn info(&mut self, msg: String);
    fn error(&mut self, msg: String);
}

extern "C" fn pam_conv<T: PamConversation>(
    num_msg: c_int,
    msg: *const *const c_pam::pam_message,
    resp: *mut *mut c_pam::pam_response,
    appdata_ptr: *mut c_void,
) -> c_int {
    let reply = unsafe {
        calloc(
            num_msg as size_t,
            mem::size_of::<c_pam::pam_response>() as size_t,
        ) as *mut c_pam::pam_response
    };
    let mut result = PAM_SUCCESS;

    if reply.is_null() {
        return PAM_BUF_ERR as c_int;
    }

    let conv = unsafe { &mut *(appdata_ptr as *mut T) };

    for i in 0..num_msg {
        let m: &mut c_pam::pam_message =
            unsafe { &mut *(*(msg.offset(i as isize)) as *mut c_pam::pam_message) };
        let r: &mut c_pam::pam_response = unsafe { &mut *(reply.offset(i as isize)) };

        let msg_str = unsafe { CStr::from_ptr(m.msg) }
            .to_str()
            .unwrap()
            .to_string();

        match m.msg_style {
            c_pam::PAM_PROMPT_ECHO_ON => {
                if let Ok(mut handler_response) = conv.prompt_echo(msg_str) {
                    if handler_response.unsecure().len() < PAM_MAX_RESP_SIZE {
                        r.resp =
                            unsafe { strdup(handler_response.unsecure().as_ptr() as *const i8) };
                        handler_response.zero_out();

                        r.resp_retcode = 0;
                    } else {
                        result = PAM_CONV_ERR;
                    }
                } else {
                    result = PAM_CONV_ERR;
                }
            }
            c_pam::PAM_PROMPT_ECHO_OFF => {
                if let Ok(mut handler_response) = conv.prompt_noecho(msg_str) {
                    if handler_response.unsecure().len() < PAM_MAX_RESP_SIZE {
                        r.resp =
                            unsafe { strdup(handler_response.unsecure().as_ptr() as *const i8) };
                        handler_response.zero_out();

                        r.resp_retcode = 0;
                    } else {
                        result = PAM_CONV_ERR;
                    }
                } else {
                    result = PAM_CONV_ERR;
                }
            }
            c_pam::PAM_ERROR_MSG => conv.error(msg_str),
            c_pam::PAM_TEXT_INFO => conv.info(msg_str),
            _ => result = PAM_CONV_ERR,
        }

        if result != PAM_SUCCESS {
            break;
        }
    }

    if result != PAM_SUCCESS {
        unsafe { free(reply as *mut c_void) };
    } else {
        unsafe { *resp = reply };
    }

    result as c_int
}

pub fn pam_start<'a, T: PamConversation>(
    service: &str,
    username: &str,
    conversation: &mut T,
) -> Result<&'a mut PamHandle, i32> where {
    let result: i32;
    let c_service = CString::new(service).unwrap();
    let c_username = CString::new(username).unwrap();
    let mut handle: *mut PamHandle = std::ptr::null_mut();
    let mut conv = c_pam::pam_conv {
        conv: pam_conv::<T>,
        appdata_ptr: conversation as *mut T as *mut c_void,
    };

    unsafe {
        result = c_pam::pam_start(
            c_service.as_ptr(),
            c_username.as_ptr(),
            &mut conv,
            &mut handle,
        ) as i32;
    }

    if result == PAM_SUCCESS && !handle.is_null() {
        return Ok(unsafe { &mut *handle });
    }

    Err(result)
}

pub fn pam_authenticate(handle: &mut PamHandle, flags: u32) -> Result<(), i32> {
    let result: i32;

    unsafe {
        result = c_pam::pam_authenticate(handle, flags as c_int) as i32;
    }

    if result == PAM_SUCCESS {
        return Ok(());
    }

    Err(result)
}

pub fn pam_acct_mgmt(handle: &mut PamHandle, flags: u32) -> Result<(), i32> {
    let result: i32;

    unsafe {
        result = c_pam::pam_acct_mgmt(handle, flags as c_int) as i32;
    }

    if result == PAM_SUCCESS {
        return Ok(());
    }

    Err(result)
}

pub fn pam_end(handle: &mut PamHandle, status: i32) -> Result<(), i32> {
    let result: i32;

    unsafe {
        result = c_pam::pam_end(handle, status as c_int) as i32;
    }

    if result == PAM_SUCCESS {
        return Ok(());
    }

    Err(result)
}
