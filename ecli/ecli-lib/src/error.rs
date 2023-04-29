//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to perform IO operation")]
    IOErr(io::Error),
    #[error("Invalid param: {0}")]
    InvalidParam(String),
    #[error("Unknown suffix: {0}")]
    UnknownSuffix(String),
    #[error("Unknown filetype: {0}")]
    UnknownFileType(String),
    #[error("Error occurred when performing http operations: {0}")]
    Http(String),
    #[error("Bpf error: {0}")]
    Bpf(String),
    #[error("Wasm error: {0}")]
    Wasm(String),
    #[error("Failed to push oci image: {0}")]
    OciPush(String),
    #[error("Failed to pull oci image: {0}")]
    OciPull(String),
    #[error("Failed to serialize: {0}")]
    Serialize(String),
    #[error("Failed to login: {0}")]
    Login(String),
    #[error("Login info not found: {0}")]
    LoginInfoNotFound(String),
    #[error("Failed to join: {0}")]
    ThreadJoin(String),
    #[error("{0}")]
    Tar(String),
    #[error("Errors when logging: {0}")]
    Log(String),
    #[error("Failed to read: {0}")]
    IORead(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
