use std::io;

#[derive(Debug)]
pub enum EcliError {
    IOErr(io::Error),
    ParamErr(String),
    UnknownSuffix(String),
    UnknownFileType(String),
    HttpError(String),
    BpfError(String),
    WasmError(String),
    JsonError(String),
    Other(String),
}

pub type EcliResult<T> = Result<T, EcliError>;
