//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use crate::error::EcliResult;

use super::{get_auth_save_file, AuthInfo};

pub fn logout(u: String) -> EcliResult<()> {
    let mut auth_info = AuthInfo::get()?;
    auth_info.remove_login_info(u.as_str())?;
    auth_info.write_to_file(&mut get_auth_save_file()?)?;
    println!("Logout success");
    Ok(())
}
