use anyhow::{anyhow, Result};
use bpf_loader_lib::serde::Deserialize;
use std::{
    any::type_name,
    ffi::{c_char, CStr},
};
pub unsafe fn convert_args(args: &[*const c_char]) -> Result<Vec<&str>> {
    let mut ret = vec![];
    for arg in args.iter() {
        let arg = unsafe { CStr::from_ptr(*arg) }.to_str()?;
        ret.push(arg);
    }
    Ok(ret)
}

pub fn load_object<T: for<'a> Deserialize<'a>>(raw_str: *const c_char) -> Result<T> {
    let str = unsafe { CStr::from_ptr(raw_str) }
        .to_str()
        .map_err(|e| anyhow!("Input string contains illegal utf8 bytes: {}", e))?;
    let parsed = serde_json::from_str::<T>(str).map_err(|e| {
        anyhow!(
            "Failed to deserialize input string to {}: {}",
            type_name::<T>(),
            e
        )
    })?;
    Ok(parsed)
}

pub fn load_null_ptr_to_option_string(s: *const c_char) -> Result<Option<&'static str>> {
    Ok(if s.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(s) }
                .to_str()
                .map_err(|e| anyhow!("Input string contains illegal utf-8 chars: {}", e))?,
        )
    })
}
