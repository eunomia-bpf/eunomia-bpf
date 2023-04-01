use async_trait::async_trait;
use futures::{
    future, future::BoxFuture, future::FutureExt, future::TryFutureExt, stream, stream::StreamExt,
    Stream,
};
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use hyper::{service::Service, Body, Request, Response, Uri};
use percent_encoding::{utf8_percent_encode, AsciiSet};
use std::borrow::Cow;
use std::convert::TryInto;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io::{ErrorKind, Read};
use std::marker::PhantomData;
use std::path::Path;
use std::str;
use std::str::FromStr;
use std::string::ToString;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use swagger::{ApiError, AuthData, BodyExt, Connector, DropContextService, Has, XSpanIdString};
use url::form_urlencoded;

use mime::Mime;
use multipart::client::lazy::Multipart;
use std::io::Cursor;

use crate::header;
use crate::models;

/// https://url.spec.whatwg.org/#fragment-percent-encode-set
#[allow(dead_code)]
const FRAGMENT_ENCODE_SET: &AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`');

/// This encode set is used for object IDs
///
/// Aside from the special characters defined in the `PATH_SEGMENT_ENCODE_SET`,
/// the vertical bar (|) is encoded.
#[allow(dead_code)]
const ID_ENCODE_SET: &AsciiSet = &FRAGMENT_ENCODE_SET.add(b'|');

use crate::{Api, ListGetResponse, LogPostResponse, StartPostResponse, StopPostResponse};

/// Convert input into a base path, e.g. "http://example:123". Also checks the scheme as it goes.
fn into_base_path(
    input: impl TryInto<Uri, Error = hyper::http::uri::InvalidUri>,
    correct_scheme: Option<&'static str>,
) -> Result<String, ClientInitError> {
    // First convert to Uri, since a base path is a subset of Uri.
    let uri = input.try_into()?;

    let scheme = uri.scheme_str().ok_or(ClientInitError::InvalidScheme)?;

    // Check the scheme if necessary
    if let Some(correct_scheme) = correct_scheme {
        if scheme != correct_scheme {
            return Err(ClientInitError::InvalidScheme);
        }
    }

    let host = uri.host().ok_or(ClientInitError::MissingHost)?;
    let port = uri
        .port_u16()
        .map(|x| format!(":{}", x))
        .unwrap_or_default();
    Ok(format!(
        "{}://{}{}{}",
        scheme,
        host,
        port,
        uri.path().trim_end_matches('/')
    ))
}

/// A client that implements the API by making HTTP calls out to a server.
pub struct Client<S, C>
where
    S: Service<(Request<Body>, C), Response = Response<Body>> + Clone + Sync + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<crate::ServiceError> + fmt::Display,
    C: Clone + Send + Sync + 'static,
{
    /// Inner service
    client_service: S,

    /// Base path of the API
    base_path: String,

    /// Marker
    marker: PhantomData<fn(C)>,
}

impl<S, C> fmt::Debug for Client<S, C>
where
    S: Service<(Request<Body>, C), Response = Response<Body>> + Clone + Sync + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<crate::ServiceError> + fmt::Display,
    C: Clone + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Client {{ base_path: {} }}", self.base_path)
    }
}

impl<S, C> Clone for Client<S, C>
where
    S: Service<(Request<Body>, C), Response = Response<Body>> + Clone + Sync + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<crate::ServiceError> + fmt::Display,
    C: Clone + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            client_service: self.client_service.clone(),
            base_path: self.base_path.clone(),
            marker: PhantomData,
        }
    }
}

impl<Connector, C> Client<DropContextService<hyper::client::Client<Connector, Body>, C>, C>
where
    Connector: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    C: Clone + Send + Sync + 'static,
{
    /// Create a client with a custom implementation of hyper::client::Connect.
    ///
    /// Intended for use with custom implementations of connect for e.g. protocol logging
    /// or similar functionality which requires wrapping the transport layer. When wrapping a TCP connection,
    /// this function should be used in conjunction with `swagger::Connector::builder()`.
    ///
    /// For ordinary tcp connections, prefer the use of `try_new_http`, `try_new_https`
    /// and `try_new_https_mutual`, to avoid introducing a dependency on the underlying transport layer.
    ///
    /// # Arguments
    ///
    /// * `base_path` - base path of the client API, i.e. "http://www.my-api-implementation.com"
    /// * `protocol` - Which protocol to use when constructing the request url, e.g. `Some("http")`
    /// * `connector` - Implementation of `hyper::client::Connect` to use for the client
    pub fn try_new_with_connector(
        base_path: &str,
        protocol: Option<&'static str>,
        connector: Connector,
    ) -> Result<Self, ClientInitError> {
        let client_service = hyper::client::Client::builder().build(connector);
        let client_service = DropContextService::new(client_service);

        Ok(Self {
            client_service,
            base_path: into_base_path(base_path, protocol)?,
            marker: PhantomData,
        })
    }
}

#[derive(Debug, Clone)]
pub enum HyperClient {
    Http(hyper::client::Client<hyper::client::HttpConnector, Body>),
    Https(hyper::client::Client<HttpsConnector, Body>),
}

impl Service<Request<Body>> for HyperClient {
    type Response = Response<Body>;
    type Error = hyper::Error;
    type Future = hyper::client::ResponseFuture;

    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        match self {
            HyperClient::Http(client) => client.poll_ready(cx),
            HyperClient::Https(client) => client.poll_ready(cx),
        }
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        match self {
            HyperClient::Http(client) => client.call(req),
            HyperClient::Https(client) => client.call(req),
        }
    }
}

impl<C> Client<DropContextService<HyperClient, C>, C>
where
    C: Clone + Send + Sync + 'static,
{
    /// Create an HTTP client.
    ///
    /// # Arguments
    /// * `base_path` - base path of the client API, i.e. "http://www.my-api-implementation.com"
    pub fn try_new(base_path: &str) -> Result<Self, ClientInitError> {
        let uri = Uri::from_str(base_path)?;

        let scheme = uri.scheme_str().ok_or(ClientInitError::InvalidScheme)?;
        let scheme = scheme.to_ascii_lowercase();

        let connector = Connector::builder();

        let client_service = match scheme.as_str() {
            "http" => HyperClient::Http(hyper::client::Client::builder().build(connector.build())),
            "https" => {
                let connector = connector
                    .https()
                    .build()
                    .map_err(ClientInitError::SslError)?;
                HyperClient::Https(hyper::client::Client::builder().build(connector))
            }
            _ => {
                return Err(ClientInitError::InvalidScheme);
            }
        };

        let client_service = DropContextService::new(client_service);

        Ok(Self {
            client_service,
            base_path: into_base_path(base_path, None)?,
            marker: PhantomData,
        })
    }
}

impl<C> Client<DropContextService<hyper::client::Client<hyper::client::HttpConnector, Body>, C>, C>
where
    C: Clone + Send + Sync + 'static,
{
    /// Create an HTTP client.
    ///
    /// # Arguments
    /// * `base_path` - base path of the client API, i.e. "http://www.my-api-implementation.com"
    pub fn try_new_http(base_path: &str) -> Result<Self, ClientInitError> {
        let http_connector = Connector::builder().build();

        Self::try_new_with_connector(base_path, Some("http"), http_connector)
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "ios"))]
type HttpsConnector = hyper_tls::HttpsConnector<hyper::client::HttpConnector>;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
type HttpsConnector = hyper_openssl::HttpsConnector<hyper::client::HttpConnector>;

impl<C> Client<DropContextService<hyper::client::Client<HttpsConnector, Body>, C>, C>
where
    C: Clone + Send + Sync + 'static,
{
    /// Create a client with a TLS connection to the server
    ///
    /// # Arguments
    /// * `base_path` - base path of the client API, i.e. "https://www.my-api-implementation.com"
    pub fn try_new_https(base_path: &str) -> Result<Self, ClientInitError> {
        let https_connector = Connector::builder()
            .https()
            .build()
            .map_err(ClientInitError::SslError)?;
        Self::try_new_with_connector(base_path, Some("https"), https_connector)
    }

    /// Create a client with a TLS connection to the server using a pinned certificate
    ///
    /// # Arguments
    /// * `base_path` - base path of the client API, i.e. "https://www.my-api-implementation.com"
    /// * `ca_certificate` - Path to CA certificate used to authenticate the server
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
    pub fn try_new_https_pinned<CA>(
        base_path: &str,
        ca_certificate: CA,
    ) -> Result<Self, ClientInitError>
    where
        CA: AsRef<Path>,
    {
        let https_connector = Connector::builder()
            .https()
            .pin_server_certificate(ca_certificate)
            .build()
            .map_err(ClientInitError::SslError)?;
        Self::try_new_with_connector(base_path, Some("https"), https_connector)
    }

    /// Create a client with a mutually authenticated TLS connection to the server.
    ///
    /// # Arguments
    /// * `base_path` - base path of the client API, i.e. "https://www.my-api-implementation.com"
    /// * `ca_certificate` - Path to CA certificate used to authenticate the server
    /// * `client_key` - Path to the client private key
    /// * `client_certificate` - Path to the client's public certificate associated with the private key
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
    pub fn try_new_https_mutual<CA, K, D>(
        base_path: &str,
        ca_certificate: CA,
        client_key: K,
        client_certificate: D,
    ) -> Result<Self, ClientInitError>
    where
        CA: AsRef<Path>,
        K: AsRef<Path>,
        D: AsRef<Path>,
    {
        let https_connector = Connector::builder()
            .https()
            .pin_server_certificate(ca_certificate)
            .client_authentication(client_key, client_certificate)
            .build()
            .map_err(ClientInitError::SslError)?;
        Self::try_new_with_connector(base_path, Some("https"), https_connector)
    }
}

impl<S, C> Client<S, C>
where
    S: Service<(Request<Body>, C), Response = Response<Body>> + Clone + Sync + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<crate::ServiceError> + fmt::Display,
    C: Clone + Send + Sync + 'static,
{
    /// Constructor for creating a `Client` by passing in a pre-made `hyper::service::Service` /
    /// `tower::Service`
    ///
    /// This allows adding custom wrappers around the underlying transport, for example for logging.
    pub fn try_new_with_client_service(
        client_service: S,
        base_path: &str,
    ) -> Result<Self, ClientInitError> {
        Ok(Self {
            client_service,
            base_path: into_base_path(base_path, None)?,
            marker: PhantomData,
        })
    }
}

/// Error type failing to create a Client
#[derive(Debug)]
pub enum ClientInitError {
    /// Invalid URL Scheme
    InvalidScheme,

    /// Invalid URI
    InvalidUri(hyper::http::uri::InvalidUri),

    /// Missing Hostname
    MissingHost,

    /// SSL Connection Error
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "ios"))]
    SslError(native_tls::Error),

    /// SSL Connection Error
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
    SslError(openssl::error::ErrorStack),
}

impl From<hyper::http::uri::InvalidUri> for ClientInitError {
    fn from(err: hyper::http::uri::InvalidUri) -> ClientInitError {
        ClientInitError::InvalidUri(err)
    }
}

impl fmt::Display for ClientInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &dyn fmt::Debug = self;
        s.fmt(f)
    }
}

impl Error for ClientInitError {
    fn description(&self) -> &str {
        "Failed to produce a hyper client."
    }
}

#[async_trait]
impl<S, C> Api<C> for Client<S, C>
where
    S: Service<(Request<Body>, C), Response = Response<Body>> + Clone + Sync + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<crate::ServiceError> + fmt::Display,
    C: Has<XSpanIdString> + Clone + Send + Sync + 'static,
{
    fn poll_ready(&self, cx: &mut Context) -> Poll<Result<(), crate::ServiceError>> {
        match self.client_service.clone().poll_ready(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(o)) => Poll::Ready(Ok(o)),
            Poll::Pending => Poll::Pending,
        }
    }

    async fn list_get(&self, context: &C) -> Result<ListGetResponse, ApiError> {
        let mut client_service = self.client_service.clone();
        let mut uri = format!("{}/list", self.base_path);

        // Query parameters
        let query_string = {
            let mut query_string = form_urlencoded::Serializer::new("".to_owned());
            query_string.finish()
        };
        if !query_string.is_empty() {
            uri += "?";
            uri += &query_string;
        }

        let uri = match Uri::from_str(&uri) {
            Ok(uri) => uri,
            Err(err) => return Err(ApiError(format!("Unable to build URI: {}", err))),
        };

        let mut request = match Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
        {
            Ok(req) => req,
            Err(e) => return Err(ApiError(format!("Unable to create request: {}", e))),
        };

        let header = HeaderValue::from_str(Has::<XSpanIdString>::get(context).0.as_str());
        request.headers_mut().insert(
            HeaderName::from_static("x-span-id"),
            match header {
                Ok(h) => h,
                Err(e) => {
                    return Err(ApiError(format!(
                        "Unable to create X-Span ID header value: {}",
                        e
                    )))
                }
            },
        );

        let response = client_service
            .call((request, context.clone()))
            .map_err(|e| ApiError(format!("No response received: {}", e)))
            .await?;

        match response.status().as_u16() {
            200 => {
                let body = response.into_body();
                let body = body
                    .into_raw()
                    .map_err(|e| ApiError(format!("Failed to read response: {}", e)))
                    .await?;
                let body = str::from_utf8(&body)
                    .map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                let body =
                    serde_json::from_str::<models::ListGet200Response>(body).map_err(|e| {
                        ApiError(format!("Response body did not match the schema: {}", e))
                    })?;
                Ok(ListGetResponse::ListOfRunningTasks(body))
            }
            code => {
                let headers = response.headers().clone();
                let body = response.into_body().take(100).into_raw().await;
                Err(ApiError(format!(
                    "Unexpected response code {}:\n{:?}\n\n{}",
                    code,
                    headers,
                    match body {
                        Ok(body) => match String::from_utf8(body) {
                            Ok(body) => body,
                            Err(e) => format!("<Body was not UTF8: {:?}>", e),
                        },
                        Err(e) => format!("<Failed to read body: {}>", e),
                    }
                )))
            }
        }
    }

    async fn log_post(
        &self,
        param_log_post_request: models::LogPostRequest,
        context: &C,
    ) -> Result<LogPostResponse, ApiError> {
        let mut client_service = self.client_service.clone();
        let mut uri = format!("{}/log", self.base_path);

        // Query parameters
        let query_string = {
            let mut query_string = form_urlencoded::Serializer::new("".to_owned());
            query_string.finish()
        };
        if !query_string.is_empty() {
            uri += "?";
            uri += &query_string;
        }

        let uri = match Uri::from_str(&uri) {
            Ok(uri) => uri,
            Err(err) => return Err(ApiError(format!("Unable to build URI: {}", err))),
        };

        let mut request = match Request::builder()
            .method("POST")
            .uri(uri)
            .body(Body::empty())
        {
            Ok(req) => req,
            Err(e) => return Err(ApiError(format!("Unable to create request: {}", e))),
        };

        let body = serde_json::to_string(&param_log_post_request)
            .expect("impossible to fail to serialize");
        *request.body_mut() = Body::from(body);

        let header = "application/json";
        request.headers_mut().insert(
            CONTENT_TYPE,
            match HeaderValue::from_str(header) {
                Ok(h) => h,
                Err(e) => {
                    return Err(ApiError(format!(
                        "Unable to create header: {} - {}",
                        header, e
                    )))
                }
            },
        );
        let header = HeaderValue::from_str(Has::<XSpanIdString>::get(context).0.as_str());
        request.headers_mut().insert(
            HeaderName::from_static("x-span-id"),
            match header {
                Ok(h) => h,
                Err(e) => {
                    return Err(ApiError(format!(
                        "Unable to create X-Span ID header value: {}",
                        e
                    )))
                }
            },
        );

        let response = client_service
            .call((request, context.clone()))
            .map_err(|e| ApiError(format!("No response received: {}", e)))
            .await?;

        match response.status().as_u16() {
            200 => {
                let body = response.into_body();
                let body = body
                    .into_raw()
                    .map_err(|e| ApiError(format!("Failed to read response: {}", e)))
                    .await?;
                let body = str::from_utf8(&body)
                    .map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                let body =
                    serde_json::from_str::<models::LogPost200Response>(body).map_err(|e| {
                        ApiError(format!("Response body did not match the schema: {}", e))
                    })?;
                Ok(LogPostResponse::SendLog(body))
            }
            code => {
                let headers = response.headers().clone();
                let body = response.into_body().take(100).into_raw().await;
                Err(ApiError(format!(
                    "Unexpected response code {}:\n{:?}\n\n{}",
                    code,
                    headers,
                    match body {
                        Ok(body) => match String::from_utf8(body) {
                            Ok(body) => body,
                            Err(e) => format!("<Body was not UTF8: {:?}>", e),
                        },
                        Err(e) => format!("<Failed to read body: {}>", e),
                    }
                )))
            }
        }
    }

    async fn start_post(
        &self,
        param_program_data_buf: Option<swagger::ByteArray>,
        param_program_type: Option<String>,
        param_program_name: Option<String>,
        param_btf_data: Option<swagger::ByteArray>,
        param_extra_params: Option<&Vec<String>>,
        context: &C,
    ) -> Result<StartPostResponse, ApiError> {
        let mut client_service = self.client_service.clone();
        let mut uri = format!("{}/start", self.base_path);

        // Query parameters
        let query_string = {
            let mut query_string = form_urlencoded::Serializer::new("".to_owned());
            query_string.finish()
        };
        if !query_string.is_empty() {
            uri += "?";
            uri += &query_string;
        }

        let uri = match Uri::from_str(&uri) {
            Ok(uri) => uri,
            Err(err) => return Err(ApiError(format!("Unable to build URI: {}", err))),
        };

        let mut request = match Request::builder()
            .method("POST")
            .uri(uri)
            .body(Body::empty())
        {
            Ok(req) => req,
            Err(e) => return Err(ApiError(format!("Unable to create request: {}", e))),
        };

        let (body_string, multipart_header) = {
            let mut multipart = Multipart::new();

            // For each parameter, encode as appropriate and add to the multipart body as a stream.

            let program_data_buf_str = match serde_json::to_string(&param_program_data_buf) {
                Ok(str) => str,
                Err(e) => {
                    return Err(ApiError(format!(
                        "Unable to serialize program_data_buf to string: {}",
                        e
                    )))
                }
            };

            let program_data_buf_vec = program_data_buf_str.as_bytes().to_vec();
            let program_data_buf_mime =
                mime_0_2::Mime::from_str("application/json").expect("impossible to fail to parse");
            let program_data_buf_cursor = Cursor::new(program_data_buf_vec);

            multipart.add_stream(
                "program_data_buf",
                program_data_buf_cursor,
                None::<&str>,
                Some(program_data_buf_mime),
            );

            let program_type_str = match serde_json::to_string(&param_program_type) {
                Ok(str) => str,
                Err(e) => {
                    return Err(ApiError(format!(
                        "Unable to serialize program_type to string: {}",
                        e
                    )))
                }
            };

            let program_type_vec = program_type_str.as_bytes().to_vec();
            let program_type_mime =
                mime_0_2::Mime::from_str("application/json").expect("impossible to fail to parse");
            let program_type_cursor = Cursor::new(program_type_vec);

            multipart.add_stream(
                "program_type",
                program_type_cursor,
                None::<&str>,
                Some(program_type_mime),
            );

            let program_name_str = match serde_json::to_string(&param_program_name) {
                Ok(str) => str,
                Err(e) => {
                    return Err(ApiError(format!(
                        "Unable to serialize program_name to string: {}",
                        e
                    )))
                }
            };

            let program_name_vec = program_name_str.as_bytes().to_vec();
            let program_name_mime =
                mime_0_2::Mime::from_str("application/json").expect("impossible to fail to parse");
            let program_name_cursor = Cursor::new(program_name_vec);

            multipart.add_stream(
                "program_name",
                program_name_cursor,
                None::<&str>,
                Some(program_name_mime),
            );

            let btf_data_str = match serde_json::to_string(&param_btf_data) {
                Ok(str) => str,
                Err(e) => {
                    return Err(ApiError(format!(
                        "Unable to serialize btf_data to string: {}",
                        e
                    )))
                }
            };

            let btf_data_vec = btf_data_str.as_bytes().to_vec();
            let btf_data_mime =
                mime_0_2::Mime::from_str("application/json").expect("impossible to fail to parse");
            let btf_data_cursor = Cursor::new(btf_data_vec);

            multipart.add_stream(
                "btf_data",
                btf_data_cursor,
                None::<&str>,
                Some(btf_data_mime),
            );

            let extra_params_str = match serde_json::to_string(&param_extra_params) {
                Ok(str) => str,
                Err(e) => {
                    return Err(ApiError(format!(
                        "Unable to serialize extra_params to string: {}",
                        e
                    )))
                }
            };

            let extra_params_vec = extra_params_str.as_bytes().to_vec();
            let extra_params_mime =
                mime_0_2::Mime::from_str("application/json").expect("impossible to fail to parse");
            let extra_params_cursor = Cursor::new(extra_params_vec);

            multipart.add_stream(
                "extra_params",
                extra_params_cursor,
                None::<&str>,
                Some(extra_params_mime),
            );

            let mut fields = match multipart.prepare() {
                Ok(fields) => fields,
                Err(err) => return Err(ApiError(format!("Unable to build request: {}", err))),
            };

            let mut body_string = String::new();

            match fields.read_to_string(&mut body_string) {
                Ok(_) => (),
                Err(err) => return Err(ApiError(format!("Unable to build body: {}", err))),
            }

            let boundary = fields.boundary();

            let multipart_header = format!("multipart/form-data;boundary={}", boundary);

            (body_string, multipart_header)
        };

        *request.body_mut() = Body::from(body_string);

        request.headers_mut().insert(
            CONTENT_TYPE,
            match HeaderValue::from_str(&multipart_header) {
                Ok(h) => h,
                Err(e) => {
                    return Err(ApiError(format!(
                        "Unable to create header: {} - {}",
                        multipart_header, e
                    )))
                }
            },
        );

        let header = HeaderValue::from_str(Has::<XSpanIdString>::get(context).0.as_str());
        request.headers_mut().insert(
            HeaderName::from_static("x-span-id"),
            match header {
                Ok(h) => h,
                Err(e) => {
                    return Err(ApiError(format!(
                        "Unable to create X-Span ID header value: {}",
                        e
                    )))
                }
            },
        );

        let response = client_service
            .call((request, context.clone()))
            .map_err(|e| ApiError(format!("No response received: {}", e)))
            .await?;

        match response.status().as_u16() {
            200 => {
                let body = response.into_body();
                let body = body
                    .into_raw()
                    .map_err(|e| ApiError(format!("Failed to read response: {}", e)))
                    .await?;
                let body = str::from_utf8(&body)
                    .map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                let body =
                    serde_json::from_str::<models::ListGet200Response>(body).map_err(|e| {
                        ApiError(format!("Response body did not match the schema: {}", e))
                    })?;
                Ok(StartPostResponse::ListOfRunningTasks(body))
            }
            code => {
                let headers = response.headers().clone();
                let body = response.into_body().take(100).into_raw().await;
                Err(ApiError(format!(
                    "Unexpected response code {}:\n{:?}\n\n{}",
                    code,
                    headers,
                    match body {
                        Ok(body) => match String::from_utf8(body) {
                            Ok(body) => body,
                            Err(e) => format!("<Body was not UTF8: {:?}>", e),
                        },
                        Err(e) => format!("<Failed to read body: {}>", e),
                    }
                )))
            }
        }
    }

    async fn stop_post(
        &self,
        param_list_get200_response_tasks_inner: models::ListGet200ResponseTasksInner,
        context: &C,
    ) -> Result<StopPostResponse, ApiError> {
        let mut client_service = self.client_service.clone();
        let mut uri = format!("{}/stop", self.base_path);

        // Query parameters
        let query_string = {
            let mut query_string = form_urlencoded::Serializer::new("".to_owned());
            query_string.finish()
        };
        if !query_string.is_empty() {
            uri += "?";
            uri += &query_string;
        }

        let uri = match Uri::from_str(&uri) {
            Ok(uri) => uri,
            Err(err) => return Err(ApiError(format!("Unable to build URI: {}", err))),
        };

        let mut request = match Request::builder()
            .method("POST")
            .uri(uri)
            .body(Body::empty())
        {
            Ok(req) => req,
            Err(e) => return Err(ApiError(format!("Unable to create request: {}", e))),
        };

        let body = serde_json::to_string(&param_list_get200_response_tasks_inner)
            .expect("impossible to fail to serialize");

        *request.body_mut() = Body::from(body);

        let header = "application/json";
        request.headers_mut().insert(
            CONTENT_TYPE,
            match HeaderValue::from_str(header) {
                Ok(h) => h,
                Err(e) => {
                    return Err(ApiError(format!(
                        "Unable to create header: {} - {}",
                        header, e
                    )))
                }
            },
        );

        let header = HeaderValue::from_str(Has::<XSpanIdString>::get(context).0.as_str());
        request.headers_mut().insert(
            HeaderName::from_static("x-span-id"),
            match header {
                Ok(h) => h,
                Err(e) => {
                    return Err(ApiError(format!(
                        "Unable to create X-Span ID header value: {}",
                        e
                    )))
                }
            },
        );

        let response = client_service
            .call((request, context.clone()))
            .map_err(|e| ApiError(format!("No response received: {}", e)))
            .await?;

        match response.status().as_u16() {
            200 => {
                let body = response.into_body();
                let body = body
                    .into_raw()
                    .map_err(|e| ApiError(format!("Failed to read response: {}", e)))
                    .await?;
                let body = str::from_utf8(&body)
                    .map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
                let body =
                    serde_json::from_str::<models::StopPost200Response>(body).map_err(|e| {
                        ApiError(format!("Response body did not match the schema: {}", e))
                    })?;
                Ok(StopPostResponse::StatusOfStoppingTheTask(body))
            }
            code => {
                let headers = response.headers().clone();
                let body = response.into_body().take(100).into_raw().await;
                Err(ApiError(format!(
                    "Unexpected response code {}:\n{:?}\n\n{}",
                    code,
                    headers,
                    match body {
                        Ok(body) => match String::from_utf8(body) {
                            Ok(body) => body,
                            Err(e) => format!("<Body was not UTF8: {:?}>", e),
                        },
                        Err(e) => format!("<Failed to read body: {}>", e),
                    }
                )))
            }
        }
    }
}
