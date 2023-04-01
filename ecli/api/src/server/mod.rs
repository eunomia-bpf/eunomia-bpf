use futures::{future, future::BoxFuture, future::FutureExt, stream, stream::TryStreamExt, Stream};
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use hyper::{Body, HeaderMap, Request, Response, StatusCode};
use log::warn;
use multipart::server::save::SaveResult;
use multipart::server::Multipart;
#[allow(unused_imports)]
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::future::Future;
use std::marker::PhantomData;
use std::task::{Context, Poll};
pub use swagger::auth::Authorization;
use swagger::auth::Scopes;
use swagger::{ApiError, BodyExt, Has, RequestParser, XSpanIdString};
use url::form_urlencoded;

use crate::header;
#[allow(unused_imports)]
use crate::models;

pub use crate::context;

type ServiceFuture = BoxFuture<'static, Result<Response<Body>, crate::ServiceError>>;

use crate::{Api, ListGetResponse, LogPostResponse, StartPostResponse, StopPostResponse};

mod paths {
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref GLOBAL_REGEX_SET: regex::RegexSet =
            regex::RegexSet::new(vec![r"^/list$", r"^/log$", r"^/start$", r"^/stop$"])
                .expect("Unable to create global regex set");
    }
    pub(crate) static ID_LIST: usize = 0;
    pub(crate) static ID_LOG: usize = 1;
    pub(crate) static ID_START: usize = 2;
    pub(crate) static ID_STOP: usize = 3;
}

pub struct MakeService<T, C>
where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString> + Send + Sync + 'static,
{
    api_impl: T,
    marker: PhantomData<C>,
}

impl<T, C> MakeService<T, C>
where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString> + Send + Sync + 'static,
{
    pub fn new(api_impl: T) -> Self {
        MakeService {
            api_impl,
            marker: PhantomData,
        }
    }
}

impl<T, C, Target> hyper::service::Service<Target> for MakeService<T, C>
where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString> + Send + Sync + 'static,
{
    type Response = Service<T, C>;
    type Error = crate::ServiceError;
    type Future = future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: Target) -> Self::Future {
        futures::future::ok(Service::new(self.api_impl.clone()))
    }
}

fn method_not_allowed() -> Result<Response<Body>, crate::ServiceError> {
    Ok(Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .body(Body::empty())
        .expect("Unable to create Method Not Allowed response"))
}

pub struct Service<T, C>
where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString> + Send + Sync + 'static,
{
    api_impl: T,
    marker: PhantomData<C>,
}

impl<T, C> Service<T, C>
where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString> + Send + Sync + 'static,
{
    pub fn new(api_impl: T) -> Self {
        Service {
            api_impl,
            marker: PhantomData,
        }
    }
}

impl<T, C> Clone for Service<T, C>
where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString> + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Service {
            api_impl: self.api_impl.clone(),
            marker: self.marker,
        }
    }
}

impl<T, C> hyper::service::Service<(Request<Body>, C)> for Service<T, C>
where
    T: Api<C> + Clone + Send + Sync + 'static,
    C: Has<XSpanIdString> + Send + Sync + 'static,
{
    type Response = Response<Body>;
    type Error = crate::ServiceError;
    type Future = ServiceFuture;

    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.api_impl.poll_ready(cx)
    }

    fn call(&mut self, req: (Request<Body>, C)) -> Self::Future {
        async fn run<T, C>(
            mut api_impl: T,
            req: (Request<Body>, C),
        ) -> Result<Response<Body>, crate::ServiceError>
        where
            T: Api<C> + Clone + Send + 'static,
            C: Has<XSpanIdString> + Send + Sync + 'static,
        {
            let (request, context) = req;
            let (parts, body) = request.into_parts();
            let (method, uri, headers) = (parts.method, parts.uri, parts.headers);
            let path = paths::GLOBAL_REGEX_SET.matches(uri.path());

            match method {
                // ListGet - GET /list
                hyper::Method::GET if path.matched(paths::ID_LIST) => {
                    let result = api_impl.list_get(&context).await;
                    let mut response = Response::new(Body::empty());
                    response.headers_mut().insert(
                        HeaderName::from_static("x-span-id"),
                        HeaderValue::from_str(
                            (&context as &dyn Has<XSpanIdString>)
                                .get()
                                .0
                                .clone()
                                .as_str(),
                        )
                        .expect("Unable to create X-Span-ID header value"),
                    );

                    match result {
                        Ok(rsp) => match rsp {
                            ListGetResponse::ListOfRunningTasks(body) => {
                                *response.status_mut() = StatusCode::from_u16(200)
                                    .expect("Unable to turn 200 into a StatusCode");
                                response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/json")
                                                            .expect("Unable to create Content-Type header for LIST_GET_LIST_OF_RUNNING_TASKS"));
                                let body = serde_json::to_string(&body)
                                    .expect("impossible to fail to serialize");
                                *response.body_mut() = Body::from(body);
                            }
                        },
                        Err(_) => {
                            // Application code returned an error. This should not happen, as the implementation should
                            // return a valid response.
                            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                            *response.body_mut() = Body::from("An internal error occurred");
                        }
                    }

                    Ok(response)
                }

                // LogPost - POST /log
                hyper::Method::POST if path.matched(paths::ID_LOG) => {
                    // Body parameters (note that non-required body parameters will ignore garbage
                    // values, rather than causing a 400 response). Produce warning header and logs for
                    // any unused fields.
                    let result = body.into_raw().await;
                    match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_log_post_request: Option<models::LogPostRequest> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_log_post_request) => param_log_post_request,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter LogPostRequest - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter LogPostRequest due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_log_post_request = match param_log_post_request {
                                    Some(param_log_post_request) => param_log_post_request,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter LogPostRequest"))
                                                        .expect("Unable to create Bad Request response for missing body parameter LogPostRequest")),
                                };

                                let result = api_impl.log_post(
                                            param_log_post_request,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                LogPostResponse::SendLog
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/json")
                                                            .expect("Unable to create Content-Type header for LOG_POST_SEND_LOG"));
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = Body::from(body);
                                                },
                                            },
                                            Err(_) => {
                                                // Application code returned an error. This should not happen, as the implementation should
                                                // return a valid response.
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from("An internal error occurred");
                                            },
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter LogPostRequest: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter LogPostRequest")),
                        }
                }

                // StartPost - POST /start
                hyper::Method::POST if path.matched(paths::ID_START) => {
                    let boundary =
                        match swagger::multipart::form::boundary(&headers) {
                            Some(boundary) => boundary.to_string(),
                            None => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from("Couldn't find valid multipart body".to_string()))
                                .expect(
                                    "Unable to create Bad Request response for incorrect boundary",
                                )),
                        };

                    // Form Body parameters (note that non-required body parameters will ignore garbage
                    // values, rather than causing a 400 response). Produce warning header and logs for
                    // any unused fields.
                    let result = body.into_raw();
                    match result.await {
                            Ok(body) => {
                                use std::io::Read;

                                // Read Form Parameters from body
                                let mut entries = match Multipart::with_body(&body.to_vec()[..], boundary).save().temp() {
                                    SaveResult::Full(entries) => {
                                        entries
                                    },
                                    _ => {
                                        return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Unable to process all message parts".to_string()))
                                                        .expect("Unable to create Bad Request response due to failure to process all message"))
                                    },
                                };
                                let field_program_data_buf = entries.fields.remove("program_data_buf");
                                let param_program_data_buf = match field_program_data_buf {
                                    Some(field) => {
                                        let mut reader = field[0].data.readable().expect("Unable to read field for program_data_buf");
                                    Some({
                                        let mut data = String::new();
                                        reader.read_to_string(&mut data).expect("Reading saved String should never fail");
                                        let program_data_buf_model: swagger::ByteArray = match serde_json::from_str(&data) {
                                            Ok(model) => model,
                                            Err(e) => {
                                                return Ok(
                                                    Response::builder()
                                                    .status(StatusCode::BAD_REQUEST)
                                                    .body(Body::from(format!("program_data_buf data does not match API definition : {}", e)))
                                                    .expect("Unable to create Bad Request due to missing required form parameter program_data_buf"))
                                            }
                                        };
                                        program_data_buf_model
                                    })
                                    },
                                    None => {
                                            None
                                    }
                                };
                                let field_program_type = entries.fields.remove("program_type");
                                let param_program_type = match field_program_type {
                                    Some(field) => {
                                        let mut reader = field[0].data.readable().expect("Unable to read field for program_type");
                                    Some({
                                        let mut data = String::new();
                                        reader.read_to_string(&mut data).expect("Reading saved String should never fail");
                                        let program_type_model: String = match serde_json::from_str(&data) {
                                            Ok(model) => model,
                                            Err(e) => {
                                                return Ok(
                                                    Response::builder()
                                                    .status(StatusCode::BAD_REQUEST)
                                                    .body(Body::from(format!("program_type data does not match API definition : {}", e)))
                                                    .expect("Unable to create Bad Request due to missing required form parameter program_type"))
                                            }
                                        };
                                        program_type_model
                                    })
                                    },
                                    None => {
                                            None
                                    }
                                };
                                let field_program_name = entries.fields.remove("program_name");
                                let param_program_name = match field_program_name {
                                    Some(field) => {
                                        let mut reader = field[0].data.readable().expect("Unable to read field for program_name");
                                    Some({
                                        let mut data = String::default();
                                        reader.read_to_string(&mut data).expect("Reading saved String should never fail");
                                        let program_name_model: String = match serde_json::from_str(&data) {
                                            Ok(model) => model,
                                            Err(e) => {
                                                return Ok(
                                                    Response::builder()
                                                    .status(StatusCode::BAD_REQUEST)
                                                    .body(Body::from(format!("program_name data does not match API definition : {}", e)))
                                                    .expect("Unable to create Bad Request due to missing required form parameter program_name"))
                                            }
                                        };
                                        program_name_model
                                    })
                                    },
                                    None => {
                                            None
                                    }
                                };

                                let field_btf_data = entries.fields.remove("btf_data");
                                let param_btf_data = match field_btf_data {
                                    Some(field) => {
                                        let mut reader = field[0].data.readable().expect("Unable to read field for btf_data");
                                    Some({
                                        let mut data = String::new();
                                        reader.read_to_string(&mut data).expect("Reading saved String should never fail");
                                        let btf_data_model: swagger::ByteArray = match serde_json::from_str(&data) {
                                            Ok(model) => model,
                                            Err(e) => {
                                                return Ok(
                                                    Response::builder()
                                                    .status(StatusCode::BAD_REQUEST)
                                                    .body(Body::from(format!("btf_data data does not match API definition : {}", e)))
                                                    .expect("Unable to create Bad Request due to missing required form parameter btf_data"))
                                            }
                                        };
                                        btf_data_model
                                    })
                                    },
                                    None => {
                                            None
                                    }
                                };
                                let field_extra_params = entries.fields.remove("extra_params");
                                let param_extra_params = match field_extra_params {
                                    Some(field) => {
                                        let mut reader = field[0].data.readable().expect("Unable to read field for extra_params");
                                    Some({
                                        let mut data = String::new();
                                        reader.read_to_string(&mut data).expect("Reading saved String should never fail");
                                        let extra_params_model: Vec<String> = match serde_json::from_str(&data) {
                                            Ok(model) => model,
                                            Err(e) => {
                                                return Ok(
                                                    Response::builder()
                                                    .status(StatusCode::BAD_REQUEST)
                                                    .body(Body::from(format!("extra_params data does not match API definition : {}", e)))
                                                    .expect("Unable to create Bad Request due to missing required form parameter extra_params"))
                                            }
                                        };
                                        extra_params_model
                                    })
                                    },
                                    None => {
                                            None
                                    }
                                };
                                let result = api_impl.start_post(
                                            param_program_data_buf,
                                            param_program_type,
                                            param_program_name,
                                            param_btf_data,
                                            param_extra_params.as_ref(),
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                StartPostResponse::ListOfRunningTasks
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/json")
                                                            .expect("Unable to create Content-Type header for START_POST_LIST_OF_RUNNING_TASKS"));
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = Body::from(body);
                                                },
                                            },
                                            Err(_) => {
                                                // Application code returned an error. This should not happen, as the implementation should
                                                // return a valid response.
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from("An internal error occurred");
                                            },
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from("Couldn't read multipart body".to_string()))
                                                .expect("Unable to create Bad Request response due to unable read multipart body")),
                        }
                }

                // StopPost - POST /stop
                hyper::Method::POST if path.matched(paths::ID_STOP) => {
                    // Body parameters (note that non-required body parameters will ignore garbage
                    // values, rather than causing a 400 response). Produce warning header and logs for
                    // any unused fields.
                    let result = body.into_raw().await;
                    match result {
                            Ok(body) => {
                                let mut unused_elements = Vec::new();
                                let param_list_get200_response_tasks_inner: Option<models::ListGet200ResponseTasksInner> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {}", path);
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_list_get200_response_tasks_inner) => param_list_get200_response_tasks_inner,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from(format!("Couldn't parse body parameter ListGet200ResponseTasksInner - doesn't match schema: {}", e)))
                                                        .expect("Unable to create Bad Request response for invalid body parameter ListGet200ResponseTasksInner due to schema")),
                                    }
                                } else {
                                    None
                                };
                                let param_list_get200_response_tasks_inner = match param_list_get200_response_tasks_inner {
                                    Some(param_list_get200_response_tasks_inner) => param_list_get200_response_tasks_inner,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(Body::from("Missing required body parameter ListGet200ResponseTasksInner"))
                                                        .expect("Unable to create Bad Request response for missing body parameter ListGet200ResponseTasksInner")),
                                };

                                let result = api_impl.stop_post(
                                            param_list_get200_response_tasks_inner,
                                        &context
                                    ).await;
                                let mut response = Response::new(Body::empty());
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }

                                        match result {
                                            Ok(rsp) => match rsp {
                                                StopPostResponse::StatusOfStoppingTheTask
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_str("application/json")
                                                            .expect("Unable to create Content-Type header for STOP_POST_STATUS_OF_STOPPING_THE_TASK"));
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = Body::from(body);
                                                },
                                            },
                                            Err(_) => {
                                                // Application code returned an error. This should not happen, as the implementation should
                                                // return a valid response.
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = Body::from("An internal error occurred");
                                            },
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(Body::from(format!("Couldn't read body parameter ListGet200ResponseTasksInner: {}", e)))
                                                .expect("Unable to create Bad Request response due to unable to read body parameter ListGet200ResponseTasksInner")),
                        }
                }

                _ if path.matched(paths::ID_LIST) => method_not_allowed(),
                _ if path.matched(paths::ID_LOG) => method_not_allowed(),
                _ if path.matched(paths::ID_START) => method_not_allowed(),
                _ if path.matched(paths::ID_STOP) => method_not_allowed(),
                _ => Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .expect("Unable to create Not Found response")),
            }
        }
        Box::pin(run(self.api_impl.clone(), req))
    }
}

/// Request parser for `Api`.
pub struct ApiRequestParser;
impl<T> RequestParser<T> for ApiRequestParser {
    fn parse_operation_id(request: &Request<T>) -> Option<&'static str> {
        let path = paths::GLOBAL_REGEX_SET.matches(request.uri().path());
        match *request.method() {
            // ListGet - GET /list
            hyper::Method::GET if path.matched(paths::ID_LIST) => Some("ListGet"),
            // LogPost - POST /log
            hyper::Method::POST if path.matched(paths::ID_LOG) => Some("LogPost"),
            // StartPost - POST /start
            hyper::Method::POST if path.matched(paths::ID_START) => Some("StartPost"),
            // StopPost - POST /stop
            hyper::Method::POST if path.matched(paths::ID_STOP) => Some("StopPost"),
            _ => None,
        }
    }
}
