use ::MatchResult;

use pact_matching::Mismatch;
use pact_matching::models::{Pact, Interaction, Request, OptionalBody, PactSpecification};
use pact_matching::models::matchingrules::*;
use pact_matching::models::generators::*;
use pact_matching::models::parse_query_string;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use log::{log, error, warn, info, debug};
use hyper::{Body, Response, Server, Error};
use hyper::http::response::{Builder as ResponseBuilder};
use hyper::http::header::{HeaderMap, HeaderName, HeaderValue, InvalidHeaderName, InvalidHeaderValue};
use hyper::service::service_fn;
use futures::future;
use futures::future::Future;
use futures::stream::Stream;
use itertools::Itertools;

enum MockRequestError {
    InvalidHeaderEncoding,
    RequestBodyError,
    ResponseHeaderEncodingError,
    ResponseBodyError
}

fn extract_path(uri: &hyper::Uri) -> String {
    uri.path_and_query()
        .map(|path_and_query| path_and_query.path())
        .unwrap_or("/")
        .into()
}

fn extract_query_string(uri: &hyper::Uri) -> Option<HashMap<String, Vec<String>>> {
    uri.path_and_query()
        .and_then(|path_and_query| path_and_query.query())
        .and_then(|query| parse_query_string(&query.into()))
}

fn extract_headers(headers: &hyper::HeaderMap) -> Result<Option<HashMap<String, String>>, MockRequestError> {
    if headers.len() > 0 {
        let result: Result<HashMap<String, String>, MockRequestError> = headers.keys()
            .map(|name| -> Result<(String, String), MockRequestError> {
                let values = headers.get_all(name);
                let mut iter = values.iter();

                let first_value = iter.next().unwrap();

                if iter.next().is_some() {
                    warn!("Multiple headers associated with '{}', but only the first is used", name);
                }

                Ok((
                    name.as_str().into(),
                    first_value.to_str()
                        .map_err(|err| MockRequestError::InvalidHeaderEncoding)?
                        .into()
                    )
                )
            })
            .collect();

        result.map(|map| Some(map))
    } else {
        Ok(None)
    }
}

pub fn extract_body(chunk: hyper::Chunk) -> OptionalBody {
    let bytes = chunk.into_bytes();
    if bytes.len() > 0 {
        OptionalBody::Present(bytes.to_vec())
    } else {
        OptionalBody::Empty
    }
}

fn hyper_request_to_pact_request(req: hyper::Request<Body>) -> impl Future<Item = Request, Error = MockRequestError> {
    let method = req.method().to_string();
    let path = extract_path(req.uri());
    let query = extract_query_string(req.uri());
    let headers = extract_headers(req.headers());

    future::done(headers)
        .and_then(move |headers| {
            req.into_body()
                .concat2()
                .map_err(|_| MockRequestError::RequestBodyError)
                .map(|body_chunk| (headers, body_chunk))
        })
        .and_then(|(headers, body_chunk)|
            Ok(Request {
                method: method,
                path: path,
                query: query,
                headers: headers,
                body: extract_body(body_chunk),
                matching_rules: MatchingRules::default(),
                generators: Generators::default()
            })
        )
}

fn method_or_path_mismatch(mismatches: &Vec<Mismatch>) -> bool {
    mismatches.iter()
        .map(|mismatch| mismatch.mismatch_type())
        .any(|mismatch_type| mismatch_type == "MethodMismatch" || mismatch_type == "PathMismatch")
}

fn match_request(req: &Request, interactions: &Vec<Interaction>) -> MatchResult {
    let match_results = interactions
        .into_iter()
        .map(|i| (i.clone(), pact_matching::match_request(i.request.clone(), req.clone())))
        .sorted_by(|i1, i2| {
            let list1 = i1.1.clone().into_iter().map(|m| m.mismatch_type()).unique().count();
            let list2 = i2.1.clone().into_iter().map(|m| m.mismatch_type()).unique().count();
            Ord::cmp(&list1, &list2)
        });
    match match_results.first() {
        Some(res) => {
            if res.1.is_empty() {
                MatchResult::RequestMatch(res.0.clone())
            } else if method_or_path_mismatch(&res.1) {
                MatchResult::RequestNotFound(req.clone())
            } else {
                MatchResult::RequestMismatch(res.0.clone(), res.1.clone())
            }
        },
        None => MatchResult::RequestNotFound(req.clone())
    }
}

fn set_hyper_headers(builder: &mut ResponseBuilder, headers: &Option<HashMap<String, String>>) -> Result<(), MockRequestError> {
    let hyper_headers = builder.headers_mut().unwrap();
    match headers {
        Some(header_map) => {
            for (k, v) in header_map {
                // FIXME?: Headers are not sent in "raw" mode.
                // Names are converted to lower case and values are parsed.
                hyper_headers.insert(
                    HeaderName::from_bytes(k.as_bytes())
                        .map_err(|err| {
                            error!("Invalid header name '{}' ({})", k, err);
                            MockRequestError::ResponseHeaderEncodingError
                        })?,
                    v.parse::<HeaderValue>()
                        .map_err(|err| {
                            error!("Invalid header value '{}': '{}' ({})", k, v, err);
                            MockRequestError::ResponseHeaderEncodingError
                        })?
                );
            }
        },
        _ => {}
    }
    Ok(())
}

fn match_result_to_hyper_response(match_result: MatchResult) -> Result<Response<Body>, MockRequestError> {
    match match_result {
        MatchResult::RequestMatch(ref interaction) => {
            let response = pact_matching::generate_response(&interaction.response);
            info!("Request matched, sending response {:?}", response);
            info!("     body: '{}'\n\n", interaction.response.body.str_value());
            info!("     body: '{}'\n\n", interaction.response.body.str_value());

            let mut builder = Response::builder();
            builder.status(response.status);

            builder.header(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");
            set_hyper_headers(&mut builder, &response.headers)?;

            builder.body(match response.body {
                OptionalBody::Present(ref s) => Body::from(s.clone()),
                _ => Body::empty()
            })
                .map_err(|_| MockRequestError::ResponseBodyError)
        },
        _ => {
            Ok(Response::new(Body::from("Hello")))
        }
    }
}

fn handle_request(
    req: hyper::Request<Body>,
    pact: Arc<Pact>,
) -> impl Future<Item = Response<Body>, Error = MockRequestError> {
    debug!("Creating pact request from hyper request");

    hyper_request_to_pact_request(req)
        .and_then(move |req| {
            info!("Received request {:?}", req);
            let match_result = match_request(&req, &pact.interactions);

            // TODO:
            // record_result(&mock_server_id, &match_result);

            match_result_to_hyper_response(match_result)
        })
}

// TODO: Should instead use some form of X-Pact headers
fn handle_mock_request_error(result: Result<Response<Body>, MockRequestError>) -> Result<Response<Body>, Error> {
    match result {
        Ok(response) => Ok(response),
        Err(error) => {
            let response = match error {
                MockRequestError::InvalidHeaderEncoding => Response::builder()
                    .status(400)
                    .body(Body::from("Found an invalid header encoding")),
                MockRequestError::RequestBodyError => Response::builder()
                    .status(500)
                    .body(Body::from("Could not process request body")),
                MockRequestError::ResponseBodyError => Response::builder()
                    .status(500)
                    .body(Body::from("Could not process response body")),
                MockRequestError::ResponseHeaderEncodingError => Response::builder()
                    .status(500)
                    .body(Body::from("Could not set response header"))
            };
            Ok(response.unwrap())
        }
    }
}

pub fn start(
    id: String,
    pact: Pact,
    port: u16,
    shutdown: impl Future<Item = (), Error = ()>,
) -> (impl Future<Item = (), Error = Error>, u16) {
    let pact = Arc::new(pact);
    let addr = ([0, 0, 0, 0], port).into();

    let server = Server::bind(&addr)
        .serve(move || {
            let pact = pact.clone();
            service_fn(move |req| {
                handle_request(req, pact.clone())
                    .then(handle_mock_request_error)
            })
        });

    let port = server.local_addr().port();

    (server.with_graceful_shutdown(shutdown), port)
}