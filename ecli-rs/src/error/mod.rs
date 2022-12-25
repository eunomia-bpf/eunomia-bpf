use std::io;

#[derive(Debug)]
pub enum EcliError {
    IOErr(io::Error),
    UnknownSuffix(String),
    UnknownFileType(String),
    HttpError(String),
    BpfError(String),
    WasmError(String),
    Other(String),
}

pub type EcliResult<T> = Result<T, EcliError>;
