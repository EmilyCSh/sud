// SPDX-License-Identifier: GPL-3.0-only
/*
 *  sud/build.rs
 *
 *  Copyright (C) Emily <info@emy.sh>
 */

fn main() {
    println!("cargo:rustc-link-lib=dylib=crypt");
    println!("cargo:rustc-link-lib=dylib=pam");
}
