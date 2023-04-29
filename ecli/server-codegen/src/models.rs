#![allow(unused_qualifications)]

#[cfg(any(feature = "client", feature = "server"))]
use crate::header;
use crate::models;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct GeneralError {
    /// description of the unexpected situation
    #[serde(rename = "message")]
    pub message: String,
}

impl GeneralError {
    #[allow(clippy::new_without_default)]
    pub fn new(message: String) -> GeneralError {
        GeneralError { message }
    }
}

/// Converts the GeneralError value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::string::ToString for GeneralError {
    fn to_string(&self) -> String {
        let params: Vec<Option<String>> =
            vec![Some("message".to_string()), Some(self.message.to_string())];

        params.into_iter().flatten().collect::<Vec<_>>().join(",")
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a GeneralError value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for GeneralError {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub message: Vec<String>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => {
                    return std::result::Result::Err(
                        "Missing value while parsing GeneralError".to_string(),
                    )
                }
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "message" => intermediate_rep.message.push(
                        <String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?,
                    ),
                    _ => {
                        return std::result::Result::Err(
                            "Unexpected key while parsing GeneralError".to_string(),
                        )
                    }
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(GeneralError {
            message: intermediate_rep
                .message
                .into_iter()
                .next()
                .ok_or_else(|| "message missing in GeneralError".to_string())?,
        })
    }
}

// Methods for converting between header::IntoHeaderValue<GeneralError> and hyper::header::HeaderValue

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<header::IntoHeaderValue<GeneralError>> for hyper::header::HeaderValue {
    type Error = String;

    fn try_from(
        hdr_value: header::IntoHeaderValue<GeneralError>,
    ) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match hyper::header::HeaderValue::from_str(&hdr_value) {
            std::result::Result::Ok(value) => std::result::Result::Ok(value),
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Invalid header value for GeneralError - value: {} is invalid {}",
                hdr_value, e
            )),
        }
    }
}

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<hyper::header::HeaderValue> for header::IntoHeaderValue<GeneralError> {
    type Error = String;

    fn try_from(hdr_value: hyper::header::HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
            std::result::Result::Ok(value) => {
                match <GeneralError as std::str::FromStr>::from_str(value) {
                    std::result::Result::Ok(value) => {
                        std::result::Result::Ok(header::IntoHeaderValue(value))
                    }
                    std::result::Result::Err(err) => std::result::Result::Err(format!(
                        "Unable to convert header value '{}' into GeneralError - {}",
                        value, err
                    )),
                }
            }
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Unable to convert header: {:?} to string: {}",
                hdr_value, e
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct GetTaskLogRequest {
    /// The program ID
    #[serde(rename = "id")]
    pub id: u64,

    /// Only fetch logs after this cursor (included). If not provided, return logs stored with minimum cursor
    #[serde(rename = "log_cursor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_cursor: Option<u64>,

    /// Fetch at most such number of logs. If not provided, use a default value that server specified
    #[serde(rename = "maximum_count")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_count: Option<u64>,
}

impl GetTaskLogRequest {
    #[allow(clippy::new_without_default)]
    pub fn new(id: u64) -> GetTaskLogRequest {
        GetTaskLogRequest {
            id,
            log_cursor: None,
            maximum_count: None,
        }
    }
}

/// Converts the GetTaskLogRequest value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::string::ToString for GetTaskLogRequest {
    fn to_string(&self) -> String {
        let params: Vec<Option<String>> = vec![
            Some("id".to_string()),
            Some(self.id.to_string()),
            self.log_cursor
                .as_ref()
                .map(|log_cursor| vec!["log_cursor".to_string(), log_cursor.to_string()].join(",")),
            self.maximum_count.as_ref().map(|maximum_count| {
                vec!["maximum_count".to_string(), maximum_count.to_string()].join(",")
            }),
        ];

        params.into_iter().flatten().collect::<Vec<_>>().join(",")
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a GetTaskLogRequest value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for GetTaskLogRequest {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub id: Vec<u64>,
            pub log_cursor: Vec<u64>,
            pub maximum_count: Vec<u64>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => {
                    return std::result::Result::Err(
                        "Missing value while parsing GetTaskLogRequest".to_string(),
                    )
                }
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "id" => intermediate_rep.id.push(
                        <u64 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?,
                    ),
                    #[allow(clippy::redundant_clone)]
                    "log_cursor" => intermediate_rep.log_cursor.push(
                        <u64 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?,
                    ),
                    #[allow(clippy::redundant_clone)]
                    "maximum_count" => intermediate_rep.maximum_count.push(
                        <u64 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?,
                    ),
                    _ => {
                        return std::result::Result::Err(
                            "Unexpected key while parsing GetTaskLogRequest".to_string(),
                        )
                    }
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(GetTaskLogRequest {
            id: intermediate_rep
                .id
                .into_iter()
                .next()
                .ok_or_else(|| "id missing in GetTaskLogRequest".to_string())?,
            log_cursor: intermediate_rep.log_cursor.into_iter().next(),
            maximum_count: intermediate_rep.maximum_count.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<GetTaskLogRequest> and hyper::header::HeaderValue

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<header::IntoHeaderValue<GetTaskLogRequest>>
    for hyper::header::HeaderValue
{
    type Error = String;

    fn try_from(
        hdr_value: header::IntoHeaderValue<GetTaskLogRequest>,
    ) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match hyper::header::HeaderValue::from_str(&hdr_value) {
            std::result::Result::Ok(value) => std::result::Result::Ok(value),
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Invalid header value for GetTaskLogRequest - value: {} is invalid {}",
                hdr_value, e
            )),
        }
    }
}

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<hyper::header::HeaderValue>
    for header::IntoHeaderValue<GetTaskLogRequest>
{
    type Error = String;

    fn try_from(hdr_value: hyper::header::HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
            std::result::Result::Ok(value) => {
                match <GetTaskLogRequest as std::str::FromStr>::from_str(value) {
                    std::result::Result::Ok(value) => {
                        std::result::Result::Ok(header::IntoHeaderValue(value))
                    }
                    std::result::Result::Err(err) => std::result::Result::Err(format!(
                        "Unable to convert header value '{}' into GetTaskLogRequest - {}",
                        value, err
                    )),
                }
            }
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Unable to convert header: {:?} to string: {}",
                hdr_value, e
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct GetTaskLogResponseInner {
    #[serde(rename = "cursor")]
    pub cursor: u64,

    #[serde(rename = "log")]
    pub log: models::GetTaskLogResponseInnerLog,
}

impl GetTaskLogResponseInner {
    #[allow(clippy::new_without_default)]
    pub fn new(cursor: u64, log: models::GetTaskLogResponseInnerLog) -> GetTaskLogResponseInner {
        GetTaskLogResponseInner { cursor, log }
    }
}

/// Converts the GetTaskLogResponseInner value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::string::ToString for GetTaskLogResponseInner {
    fn to_string(&self) -> String {
        let params: Vec<Option<String>> = vec![
            Some("cursor".to_string()),
            Some(self.cursor.to_string()),
            // Skipping log in query parameter serialization
        ];

        params.into_iter().flatten().collect::<Vec<_>>().join(",")
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a GetTaskLogResponseInner value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for GetTaskLogResponseInner {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub cursor: Vec<u64>,
            pub log: Vec<models::GetTaskLogResponseInnerLog>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => {
                    return std::result::Result::Err(
                        "Missing value while parsing GetTaskLogResponseInner".to_string(),
                    )
                }
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "cursor" => intermediate_rep.cursor.push(
                        <u64 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?,
                    ),
                    #[allow(clippy::redundant_clone)]
                    "log" => intermediate_rep.log.push(
                        <models::GetTaskLogResponseInnerLog as std::str::FromStr>::from_str(val)
                            .map_err(|x| x.to_string())?,
                    ),
                    _ => {
                        return std::result::Result::Err(
                            "Unexpected key while parsing GetTaskLogResponseInner".to_string(),
                        )
                    }
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(GetTaskLogResponseInner {
            cursor: intermediate_rep
                .cursor
                .into_iter()
                .next()
                .ok_or_else(|| "cursor missing in GetTaskLogResponseInner".to_string())?,
            log: intermediate_rep
                .log
                .into_iter()
                .next()
                .ok_or_else(|| "log missing in GetTaskLogResponseInner".to_string())?,
        })
    }
}

// Methods for converting between header::IntoHeaderValue<GetTaskLogResponseInner> and hyper::header::HeaderValue

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<header::IntoHeaderValue<GetTaskLogResponseInner>>
    for hyper::header::HeaderValue
{
    type Error = String;

    fn try_from(
        hdr_value: header::IntoHeaderValue<GetTaskLogResponseInner>,
    ) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match hyper::header::HeaderValue::from_str(&hdr_value) {
            std::result::Result::Ok(value) => std::result::Result::Ok(value),
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Invalid header value for GetTaskLogResponseInner - value: {} is invalid {}",
                hdr_value, e
            )),
        }
    }
}

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<hyper::header::HeaderValue>
    for header::IntoHeaderValue<GetTaskLogResponseInner>
{
    type Error = String;

    fn try_from(hdr_value: hyper::header::HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
            std::result::Result::Ok(value) => {
                match <GetTaskLogResponseInner as std::str::FromStr>::from_str(value) {
                    std::result::Result::Ok(value) => {
                        std::result::Result::Ok(header::IntoHeaderValue(value))
                    }
                    std::result::Result::Err(err) => std::result::Result::Err(format!(
                        "Unable to convert header value '{}' into GetTaskLogResponseInner - {}",
                        value, err
                    )),
                }
            }
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Unable to convert header: {:?} to string: {}",
                hdr_value, e
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct GetTaskLogResponseInnerLog {
    #[serde(rename = "log")]
    pub log: String,

    #[serde(rename = "timestamp")]
    pub timestamp: u64,

    #[serde(rename = "log_type")]
    pub log_type: models::LogType,
}

impl GetTaskLogResponseInnerLog {
    #[allow(clippy::new_without_default)]
    pub fn new(
        log: String,
        timestamp: u64,
        log_type: models::LogType,
    ) -> GetTaskLogResponseInnerLog {
        GetTaskLogResponseInnerLog {
            log,
            timestamp,
            log_type,
        }
    }
}

/// Converts the GetTaskLogResponseInnerLog value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::string::ToString for GetTaskLogResponseInnerLog {
    fn to_string(&self) -> String {
        let params: Vec<Option<String>> = vec![
            Some("log".to_string()),
            Some(self.log.to_string()),
            Some("timestamp".to_string()),
            Some(self.timestamp.to_string()),
            // Skipping log_type in query parameter serialization
        ];

        params.into_iter().flatten().collect::<Vec<_>>().join(",")
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a GetTaskLogResponseInnerLog value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for GetTaskLogResponseInnerLog {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub log: Vec<String>,
            pub timestamp: Vec<u64>,
            pub log_type: Vec<models::LogType>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => {
                    return std::result::Result::Err(
                        "Missing value while parsing GetTaskLogResponseInnerLog".to_string(),
                    )
                }
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "log" => intermediate_rep.log.push(
                        <String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?,
                    ),
                    #[allow(clippy::redundant_clone)]
                    "timestamp" => intermediate_rep.timestamp.push(
                        <u64 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?,
                    ),
                    #[allow(clippy::redundant_clone)]
                    "log_type" => intermediate_rep.log_type.push(
                        <models::LogType as std::str::FromStr>::from_str(val)
                            .map_err(|x| x.to_string())?,
                    ),
                    _ => {
                        return std::result::Result::Err(
                            "Unexpected key while parsing GetTaskLogResponseInnerLog".to_string(),
                        )
                    }
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(GetTaskLogResponseInnerLog {
            log: intermediate_rep
                .log
                .into_iter()
                .next()
                .ok_or_else(|| "log missing in GetTaskLogResponseInnerLog".to_string())?,
            timestamp: intermediate_rep
                .timestamp
                .into_iter()
                .next()
                .ok_or_else(|| "timestamp missing in GetTaskLogResponseInnerLog".to_string())?,
            log_type: intermediate_rep
                .log_type
                .into_iter()
                .next()
                .ok_or_else(|| "log_type missing in GetTaskLogResponseInnerLog".to_string())?,
        })
    }
}

// Methods for converting between header::IntoHeaderValue<GetTaskLogResponseInnerLog> and hyper::header::HeaderValue

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<header::IntoHeaderValue<GetTaskLogResponseInnerLog>>
    for hyper::header::HeaderValue
{
    type Error = String;

    fn try_from(
        hdr_value: header::IntoHeaderValue<GetTaskLogResponseInnerLog>,
    ) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match hyper::header::HeaderValue::from_str(&hdr_value) {
            std::result::Result::Ok(value) => std::result::Result::Ok(value),
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Invalid header value for GetTaskLogResponseInnerLog - value: {} is invalid {}",
                hdr_value, e
            )),
        }
    }
}

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<hyper::header::HeaderValue>
    for header::IntoHeaderValue<GetTaskLogResponseInnerLog>
{
    type Error = String;

    fn try_from(hdr_value: hyper::header::HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
            std::result::Result::Ok(value) => {
                match <GetTaskLogResponseInnerLog as std::str::FromStr>::from_str(value) {
                    std::result::Result::Ok(value) => {
                        std::result::Result::Ok(header::IntoHeaderValue(value))
                    }
                    std::result::Result::Err(err) => std::result::Result::Err(format!(
                        "Unable to convert header value '{}' into GetTaskLogResponseInnerLog - {}",
                        value, err
                    )),
                }
            }
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Unable to convert header: {:?} to string: {}",
                hdr_value, e
            )),
        }
    }
}

/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them as `#[repr(C)]`
/// which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[cfg_attr(feature = "conversion", derive(frunk_enum_derive::LabelledGenericEnum))]
pub enum LogType {
    #[serde(rename = "stderr")]
    Stderr,
    #[serde(rename = "stdout")]
    Stdout,
    #[serde(rename = "plain")]
    Plain,
}

impl std::fmt::Display for LogType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            LogType::Stderr => write!(f, "stderr"),
            LogType::Stdout => write!(f, "stdout"),
            LogType::Plain => write!(f, "plain"),
        }
    }
}

impl std::str::FromStr for LogType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "stderr" => std::result::Result::Ok(LogType::Stderr),
            "stdout" => std::result::Result::Ok(LogType::Stdout),
            "plain" => std::result::Result::Ok(LogType::Plain),
            _ => std::result::Result::Err(format!("Value not valid: {}", s)),
        }
    }
}

/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them as `#[repr(C)]`
/// which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[cfg_attr(feature = "conversion", derive(frunk_enum_derive::LabelledGenericEnum))]
pub enum ProgramType {
    #[serde(rename = "wasm")]
    Wasm,
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "tar")]
    Tar,
}

impl std::fmt::Display for ProgramType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            ProgramType::Wasm => write!(f, "wasm"),
            ProgramType::Json => write!(f, "json"),
            ProgramType::Tar => write!(f, "tar"),
        }
    }
}

impl std::str::FromStr for ProgramType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "wasm" => std::result::Result::Ok(ProgramType::Wasm),
            "json" => std::result::Result::Ok(ProgramType::Json),
            "tar" => std::result::Result::Ok(ProgramType::Tar),
            _ => std::result::Result::Err(format!("Value not valid: {}", s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct SimpleIdRequest {
    #[serde(rename = "id")]
    pub id: u64,
}

impl SimpleIdRequest {
    #[allow(clippy::new_without_default)]
    pub fn new(id: u64) -> SimpleIdRequest {
        SimpleIdRequest { id }
    }
}

/// Converts the SimpleIdRequest value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::string::ToString for SimpleIdRequest {
    fn to_string(&self) -> String {
        let params: Vec<Option<String>> = vec![Some("id".to_string()), Some(self.id.to_string())];

        params.into_iter().flatten().collect::<Vec<_>>().join(",")
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a SimpleIdRequest value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for SimpleIdRequest {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub id: Vec<u64>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => {
                    return std::result::Result::Err(
                        "Missing value while parsing SimpleIdRequest".to_string(),
                    )
                }
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "id" => intermediate_rep.id.push(
                        <u64 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?,
                    ),
                    _ => {
                        return std::result::Result::Err(
                            "Unexpected key while parsing SimpleIdRequest".to_string(),
                        )
                    }
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(SimpleIdRequest {
            id: intermediate_rep
                .id
                .into_iter()
                .next()
                .ok_or_else(|| "id missing in SimpleIdRequest".to_string())?,
        })
    }
}

// Methods for converting between header::IntoHeaderValue<SimpleIdRequest> and hyper::header::HeaderValue

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<header::IntoHeaderValue<SimpleIdRequest>>
    for hyper::header::HeaderValue
{
    type Error = String;

    fn try_from(
        hdr_value: header::IntoHeaderValue<SimpleIdRequest>,
    ) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match hyper::header::HeaderValue::from_str(&hdr_value) {
            std::result::Result::Ok(value) => std::result::Result::Ok(value),
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Invalid header value for SimpleIdRequest - value: {} is invalid {}",
                hdr_value, e
            )),
        }
    }
}

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<hyper::header::HeaderValue>
    for header::IntoHeaderValue<SimpleIdRequest>
{
    type Error = String;

    fn try_from(hdr_value: hyper::header::HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
            std::result::Result::Ok(value) => {
                match <SimpleIdRequest as std::str::FromStr>::from_str(value) {
                    std::result::Result::Ok(value) => {
                        std::result::Result::Ok(header::IntoHeaderValue(value))
                    }
                    std::result::Result::Err(err) => std::result::Result::Err(format!(
                        "Unable to convert header value '{}' into SimpleIdRequest - {}",
                        value, err
                    )),
                }
            }
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Unable to convert header: {:?} to string: {}",
                hdr_value, e
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct StartTask200Response {
    #[serde(rename = "id")]
    pub id: u64,

    #[serde(rename = "task_list")]
    pub task_list: models::TaskListResponse,
}

impl StartTask200Response {
    #[allow(clippy::new_without_default)]
    pub fn new(id: u64, task_list: models::TaskListResponse) -> StartTask200Response {
        StartTask200Response { id, task_list }
    }
}

/// Converts the StartTask200Response value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::string::ToString for StartTask200Response {
    fn to_string(&self) -> String {
        let params: Vec<Option<String>> = vec![
            Some("id".to_string()),
            Some(self.id.to_string()),
            // Skipping task_list in query parameter serialization
        ];

        params.into_iter().flatten().collect::<Vec<_>>().join(",")
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a StartTask200Response value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for StartTask200Response {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub id: Vec<u64>,
            pub task_list: Vec<models::TaskListResponse>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => {
                    return std::result::Result::Err(
                        "Missing value while parsing StartTask200Response".to_string(),
                    )
                }
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "id" => intermediate_rep.id.push(
                        <u64 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?,
                    ),
                    #[allow(clippy::redundant_clone)]
                    "task_list" => intermediate_rep.task_list.push(
                        <models::TaskListResponse as std::str::FromStr>::from_str(val)
                            .map_err(|x| x.to_string())?,
                    ),
                    _ => {
                        return std::result::Result::Err(
                            "Unexpected key while parsing StartTask200Response".to_string(),
                        )
                    }
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(StartTask200Response {
            id: intermediate_rep
                .id
                .into_iter()
                .next()
                .ok_or_else(|| "id missing in StartTask200Response".to_string())?,
            task_list: intermediate_rep
                .task_list
                .into_iter()
                .next()
                .ok_or_else(|| "task_list missing in StartTask200Response".to_string())?,
        })
    }
}

// Methods for converting between header::IntoHeaderValue<StartTask200Response> and hyper::header::HeaderValue

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<header::IntoHeaderValue<StartTask200Response>>
    for hyper::header::HeaderValue
{
    type Error = String;

    fn try_from(
        hdr_value: header::IntoHeaderValue<StartTask200Response>,
    ) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match hyper::header::HeaderValue::from_str(&hdr_value) {
            std::result::Result::Ok(value) => std::result::Result::Ok(value),
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Invalid header value for StartTask200Response - value: {} is invalid {}",
                hdr_value, e
            )),
        }
    }
}

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<hyper::header::HeaderValue>
    for header::IntoHeaderValue<StartTask200Response>
{
    type Error = String;

    fn try_from(hdr_value: hyper::header::HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
            std::result::Result::Ok(value) => {
                match <StartTask200Response as std::str::FromStr>::from_str(value) {
                    std::result::Result::Ok(value) => {
                        std::result::Result::Ok(header::IntoHeaderValue(value))
                    }
                    std::result::Result::Err(err) => std::result::Result::Err(format!(
                        "Unable to convert header value '{}' into StartTask200Response - {}",
                        value, err
                    )),
                }
            }
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Unable to convert header: {:?} to string: {}",
                hdr_value, e
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct StartTaskRequest {
    /// Base64-encoded program data
    #[serde(rename = "program_data_buf")]
    pub program_data_buf: String,

    #[serde(rename = "program_type")]
    pub program_type: models::ProgramType,

    /// The name of the program. If not provided, will generate a random one
    #[serde(rename = "program_name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_name: Option<String>,

    /// Btf archive path in the server.
    #[serde(rename = "btf_archive_path")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub btf_archive_path: Option<String>,

    /// Command line arguments to the eBPF program
    #[serde(rename = "extra_args")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_args: Option<Vec<String>>,

    /// Whether to let the bpf-loader program dumps json. Only works for json & tar program
    #[serde(rename = "export_json")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_json: Option<bool>,
}

impl StartTaskRequest {
    #[allow(clippy::new_without_default)]
    pub fn new(program_data_buf: String, program_type: models::ProgramType) -> StartTaskRequest {
        StartTaskRequest {
            program_data_buf,
            program_type,
            program_name: None,
            btf_archive_path: None,
            extra_args: None,
            export_json: None,
        }
    }
}

/// Converts the StartTaskRequest value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::string::ToString for StartTaskRequest {
    fn to_string(&self) -> String {
        let params: Vec<Option<String>> = vec![
            Some("program_data_buf".to_string()),
            Some(self.program_data_buf.to_string()),
            // Skipping program_type in query parameter serialization
            self.program_name.as_ref().map(|program_name| {
                vec!["program_name".to_string(), program_name.to_string()].join(",")
            }),
            self.btf_archive_path.as_ref().map(|btf_archive_path| {
                vec!["btf_archive_path".to_string(), btf_archive_path.to_string()].join(",")
            }),
            self.extra_args.as_ref().map(|extra_args| {
                vec![
                    "extra_args".to_string(),
                    extra_args
                        .iter()
                        .map(|x| x.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ]
                .join(",")
            }),
            self.export_json.as_ref().map(|export_json| {
                vec!["export_json".to_string(), export_json.to_string()].join(",")
            }),
        ];

        params.into_iter().flatten().collect::<Vec<_>>().join(",")
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a StartTaskRequest value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for StartTaskRequest {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub program_data_buf: Vec<String>,
            pub program_type: Vec<models::ProgramType>,
            pub program_name: Vec<String>,
            pub btf_archive_path: Vec<String>,
            pub extra_args: Vec<Vec<String>>,
            pub export_json: Vec<bool>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => {
                    return std::result::Result::Err(
                        "Missing value while parsing StartTaskRequest".to_string(),
                    )
                }
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "program_data_buf" => intermediate_rep.program_data_buf.push(
                        <String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?,
                    ),
                    #[allow(clippy::redundant_clone)]
                    "program_type" => intermediate_rep.program_type.push(
                        <models::ProgramType as std::str::FromStr>::from_str(val)
                            .map_err(|x| x.to_string())?,
                    ),
                    #[allow(clippy::redundant_clone)]
                    "program_name" => intermediate_rep.program_name.push(
                        <String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?,
                    ),
                    #[allow(clippy::redundant_clone)]
                    "btf_archive_path" => intermediate_rep.btf_archive_path.push(
                        <String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?,
                    ),
                    "extra_args" => return std::result::Result::Err(
                        "Parsing a container in this style is not supported in StartTaskRequest"
                            .to_string(),
                    ),
                    #[allow(clippy::redundant_clone)]
                    "export_json" => intermediate_rep.export_json.push(
                        <bool as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?,
                    ),
                    _ => {
                        return std::result::Result::Err(
                            "Unexpected key while parsing StartTaskRequest".to_string(),
                        )
                    }
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(StartTaskRequest {
            program_data_buf: intermediate_rep
                .program_data_buf
                .into_iter()
                .next()
                .ok_or_else(|| "program_data_buf missing in StartTaskRequest".to_string())?,
            program_type: intermediate_rep
                .program_type
                .into_iter()
                .next()
                .ok_or_else(|| "program_type missing in StartTaskRequest".to_string())?,
            program_name: intermediate_rep.program_name.into_iter().next(),
            btf_archive_path: intermediate_rep.btf_archive_path.into_iter().next(),
            extra_args: intermediate_rep.extra_args.into_iter().next(),
            export_json: intermediate_rep.export_json.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<StartTaskRequest> and hyper::header::HeaderValue

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<header::IntoHeaderValue<StartTaskRequest>>
    for hyper::header::HeaderValue
{
    type Error = String;

    fn try_from(
        hdr_value: header::IntoHeaderValue<StartTaskRequest>,
    ) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match hyper::header::HeaderValue::from_str(&hdr_value) {
            std::result::Result::Ok(value) => std::result::Result::Ok(value),
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Invalid header value for StartTaskRequest - value: {} is invalid {}",
                hdr_value, e
            )),
        }
    }
}

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<hyper::header::HeaderValue>
    for header::IntoHeaderValue<StartTaskRequest>
{
    type Error = String;

    fn try_from(hdr_value: hyper::header::HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
            std::result::Result::Ok(value) => {
                match <StartTaskRequest as std::str::FromStr>::from_str(value) {
                    std::result::Result::Ok(value) => {
                        std::result::Result::Ok(header::IntoHeaderValue(value))
                    }
                    std::result::Result::Err(err) => std::result::Result::Err(format!(
                        "Unable to convert header value '{}' into StartTaskRequest - {}",
                        value, err
                    )),
                }
            }
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Unable to convert header: {:?} to string: {}",
                hdr_value, e
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct TaskListResponse {
    #[serde(rename = "tasks")]
    pub tasks: Vec<models::TaskListResponseTasksInner>,
}

impl TaskListResponse {
    #[allow(clippy::new_without_default)]
    pub fn new(tasks: Vec<models::TaskListResponseTasksInner>) -> TaskListResponse {
        TaskListResponse { tasks }
    }
}

/// Converts the TaskListResponse value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::string::ToString for TaskListResponse {
    fn to_string(&self) -> String {
        let params: Vec<Option<String>> = vec![
            // Skipping tasks in query parameter serialization

        ];

        params.into_iter().flatten().collect::<Vec<_>>().join(",")
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a TaskListResponse value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for TaskListResponse {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub tasks: Vec<Vec<models::TaskListResponseTasksInner>>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => {
                    return std::result::Result::Err(
                        "Missing value while parsing TaskListResponse".to_string(),
                    )
                }
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    "tasks" => return std::result::Result::Err(
                        "Parsing a container in this style is not supported in TaskListResponse"
                            .to_string(),
                    ),
                    _ => {
                        return std::result::Result::Err(
                            "Unexpected key while parsing TaskListResponse".to_string(),
                        )
                    }
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(TaskListResponse {
            tasks: intermediate_rep
                .tasks
                .into_iter()
                .next()
                .ok_or_else(|| "tasks missing in TaskListResponse".to_string())?,
        })
    }
}

// Methods for converting between header::IntoHeaderValue<TaskListResponse> and hyper::header::HeaderValue

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<header::IntoHeaderValue<TaskListResponse>>
    for hyper::header::HeaderValue
{
    type Error = String;

    fn try_from(
        hdr_value: header::IntoHeaderValue<TaskListResponse>,
    ) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match hyper::header::HeaderValue::from_str(&hdr_value) {
            std::result::Result::Ok(value) => std::result::Result::Ok(value),
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Invalid header value for TaskListResponse - value: {} is invalid {}",
                hdr_value, e
            )),
        }
    }
}

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<hyper::header::HeaderValue>
    for header::IntoHeaderValue<TaskListResponse>
{
    type Error = String;

    fn try_from(hdr_value: hyper::header::HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
            std::result::Result::Ok(value) => {
                match <TaskListResponse as std::str::FromStr>::from_str(value) {
                    std::result::Result::Ok(value) => {
                        std::result::Result::Ok(header::IntoHeaderValue(value))
                    }
                    std::result::Result::Err(err) => std::result::Result::Err(format!(
                        "Unable to convert header value '{}' into TaskListResponse - {}",
                        value, err
                    )),
                }
            }
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Unable to convert header: {:?} to string: {}",
                hdr_value, e
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct TaskListResponseTasksInner {
    #[serde(rename = "status")]
    pub status: models::TaskStatus,

    /// The ID of the task
    #[serde(rename = "id")]
    pub id: u64,

    /// The name of the task
    #[serde(rename = "name")]
    pub name: String,
}

impl TaskListResponseTasksInner {
    #[allow(clippy::new_without_default)]
    pub fn new(status: models::TaskStatus, id: u64, name: String) -> TaskListResponseTasksInner {
        TaskListResponseTasksInner { status, id, name }
    }
}

/// Converts the TaskListResponseTasksInner value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::string::ToString for TaskListResponseTasksInner {
    fn to_string(&self) -> String {
        let params: Vec<Option<String>> = vec![
            // Skipping status in query parameter serialization
            Some("id".to_string()),
            Some(self.id.to_string()),
            Some("name".to_string()),
            Some(self.name.to_string()),
        ];

        params.into_iter().flatten().collect::<Vec<_>>().join(",")
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a TaskListResponseTasksInner value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for TaskListResponseTasksInner {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub status: Vec<models::TaskStatus>,
            pub id: Vec<u64>,
            pub name: Vec<String>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => {
                    return std::result::Result::Err(
                        "Missing value while parsing TaskListResponseTasksInner".to_string(),
                    )
                }
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "status" => intermediate_rep.status.push(
                        <models::TaskStatus as std::str::FromStr>::from_str(val)
                            .map_err(|x| x.to_string())?,
                    ),
                    #[allow(clippy::redundant_clone)]
                    "id" => intermediate_rep.id.push(
                        <u64 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?,
                    ),
                    #[allow(clippy::redundant_clone)]
                    "name" => intermediate_rep.name.push(
                        <String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?,
                    ),
                    _ => {
                        return std::result::Result::Err(
                            "Unexpected key while parsing TaskListResponseTasksInner".to_string(),
                        )
                    }
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(TaskListResponseTasksInner {
            status: intermediate_rep
                .status
                .into_iter()
                .next()
                .ok_or_else(|| "status missing in TaskListResponseTasksInner".to_string())?,
            id: intermediate_rep
                .id
                .into_iter()
                .next()
                .ok_or_else(|| "id missing in TaskListResponseTasksInner".to_string())?,
            name: intermediate_rep
                .name
                .into_iter()
                .next()
                .ok_or_else(|| "name missing in TaskListResponseTasksInner".to_string())?,
        })
    }
}

// Methods for converting between header::IntoHeaderValue<TaskListResponseTasksInner> and hyper::header::HeaderValue

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<header::IntoHeaderValue<TaskListResponseTasksInner>>
    for hyper::header::HeaderValue
{
    type Error = String;

    fn try_from(
        hdr_value: header::IntoHeaderValue<TaskListResponseTasksInner>,
    ) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match hyper::header::HeaderValue::from_str(&hdr_value) {
            std::result::Result::Ok(value) => std::result::Result::Ok(value),
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Invalid header value for TaskListResponseTasksInner - value: {} is invalid {}",
                hdr_value, e
            )),
        }
    }
}

#[cfg(any(feature = "client", feature = "server"))]
impl std::convert::TryFrom<hyper::header::HeaderValue>
    for header::IntoHeaderValue<TaskListResponseTasksInner>
{
    type Error = String;

    fn try_from(hdr_value: hyper::header::HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
            std::result::Result::Ok(value) => {
                match <TaskListResponseTasksInner as std::str::FromStr>::from_str(value) {
                    std::result::Result::Ok(value) => {
                        std::result::Result::Ok(header::IntoHeaderValue(value))
                    }
                    std::result::Result::Err(err) => std::result::Result::Err(format!(
                        "Unable to convert header value '{}' into TaskListResponseTasksInner - {}",
                        value, err
                    )),
                }
            }
            std::result::Result::Err(e) => std::result::Result::Err(format!(
                "Unable to convert header: {:?} to string: {}",
                hdr_value, e
            )),
        }
    }
}

/// The status of the task
/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them as `#[repr(C)]`
/// which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[cfg_attr(feature = "conversion", derive(frunk_enum_derive::LabelledGenericEnum))]
pub enum TaskStatus {
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "paused")]
    Paused,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            TaskStatus::Running => write!(f, "running"),
            TaskStatus::Paused => write!(f, "paused"),
        }
    }
}

impl std::str::FromStr for TaskStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "running" => std::result::Result::Ok(TaskStatus::Running),
            "paused" => std::result::Result::Ok(TaskStatus::Paused),
            _ => std::result::Result::Err(format!("Value not valid: {}", s)),
        }
    }
}
