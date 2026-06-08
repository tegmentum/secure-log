//! `secure-log:log/transport` provider backed by `wasi:http`.
//!
//! The `secure-log-store-remote` provider turns each store operation
//! into one `transport.rpc(method, params-json)` call. This component
//! fulfills that import by issuing an HTTP POST per call:
//!
//! - **target** — the URL in the `SECURE_LOG_RPC_URL` environment
//!   variable (e.g. `http://127.0.0.1:8787`).
//! - **body** — `{"method": <method>, "params": <params-json>}`.
//! - **result** — the response body verbatim; a 2xx status maps to
//!   `ok(body)`, any other status to `err(body)`.
//!
//! The peer that terminates this protocol is `secure-log-rpc-server`
//! (or any server speaking the same wire format).

#[allow(warnings)]
mod bindings;

use bindings::wasi::cli::environment::get_environment;
use bindings::wasi::http::outgoing_handler;
use bindings::wasi::http::types::{Method, OutgoingBody, OutgoingRequest, RequestOptions, Scheme};
use bindings::wasi::io::streams::StreamError;

use bindings::exports::secure_log::log::transport::Guest;

struct Component;

/// Environment variable holding the RPC endpoint URL.
const URL_ENV: &str = "SECURE_LOG_RPC_URL";

/// Largest chunk wasi:io's `blocking-write-and-flush` accepts per call.
const WRITE_CHUNK: usize = 4096;

impl Guest for Component {
    fn rpc(method: String, params_json: String) -> Result<String, String> {
        let url = endpoint_url()?;
        let target = Target::parse(&url)?;
        let body = envelope(&method, &params_json);
        post(&target, body.as_bytes())
    }
}

/// Read the endpoint URL from the environment.
fn endpoint_url() -> Result<String, String> {
    get_environment()
        .into_iter()
        .find(|(k, _)| k == URL_ENV)
        .map(|(_, v)| v)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("transport-http: {URL_ENV} is not set"))
}

/// Build the JSON-RPC envelope. `params_json` is already valid JSON
/// (a serialized argument array), so it is embedded verbatim.
fn envelope(method: &str, params_json: &str) -> String {
    format!(
        "{{\"method\":{},\"params\":{}}}",
        json_string(method),
        params_json
    )
}

/// Minimal JSON string encoder for the method name.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A parsed endpoint: scheme + authority + path-with-query.
struct Target {
    scheme: Scheme,
    authority: String,
    path: String,
}

impl Target {
    fn parse(url: &str) -> Result<Target, String> {
        let (scheme, rest) = match url.split_once("://") {
            Some(("http", rest)) => (Scheme::Http, rest),
            Some(("https", rest)) => (Scheme::Https, rest),
            Some((other, rest)) => (Scheme::Other(other.to_string()), rest),
            None => return Err(format!("transport-http: malformed URL {url:?} (no scheme)")),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
            None => (rest.to_string(), "/".to_string()),
        };
        if authority.is_empty() {
            return Err(format!("transport-http: URL {url:?} has no authority"));
        }
        Ok(Target {
            scheme,
            authority,
            path,
        })
    }
}

/// Issue one POST and return the response body (2xx) or an error.
fn post(target: &Target, body: &[u8]) -> Result<String, String> {
    use bindings::wasi::http::types::Fields;

    let req = OutgoingRequest::new(Fields::new());
    req.set_method(&Method::Post)
        .map_err(|_| "transport-http: set_method failed".to_string())?;
    req.set_scheme(Some(&target.scheme))
        .map_err(|_| "transport-http: set_scheme failed".to_string())?;
    req.set_authority(Some(&target.authority))
        .map_err(|_| "transport-http: set_authority failed".to_string())?;
    req.set_path_with_query(Some(&target.path))
        .map_err(|_| "transport-http: set_path_with_query failed".to_string())?;

    // Write the request body, then finish it. The output-stream is a
    // child of the outgoing-body and must be dropped before finish.
    let out_body = req
        .body()
        .map_err(|_| "transport-http: request body unavailable".to_string())?;
    {
        let stream = out_body
            .write()
            .map_err(|_| "transport-http: body stream unavailable".to_string())?;
        for chunk in body.chunks(WRITE_CHUNK) {
            stream
                .blocking_write_and_flush(chunk)
                .map_err(|e| format!("transport-http: write body: {e:?}"))?;
        }
    }
    OutgoingBody::finish(out_body, None)
        .map_err(|e| format!("transport-http: finish body: {e:?}"))?;

    // Send and block for the response.
    let opts: Option<RequestOptions> = None;
    let future = outgoing_handler::handle(req, opts)
        .map_err(|e| format!("transport-http: handle: {e:?}"))?;
    let pollable = future.subscribe();
    let response = loop {
        match future.get() {
            Some(r) => break r,
            None => pollable.block(),
        }
    };
    let response = response
        .map_err(|_| "transport-http: response future already consumed".to_string())?
        .map_err(|e| format!("transport-http: request failed: {e:?}"))?;

    let status = response.status();

    // Read the full response body.
    let incoming = response
        .consume()
        .map_err(|_| "transport-http: consume response body failed".to_string())?;
    let body_bytes = {
        let stream = incoming
            .stream()
            .map_err(|_| "transport-http: response body stream failed".to_string())?;
        let mut buf = Vec::new();
        loop {
            match stream.blocking_read(WRITE_CHUNK as u64) {
                Ok(chunk) => buf.extend_from_slice(&chunk),
                Err(StreamError::Closed) => break,
                Err(e) => return Err(format!("transport-http: read response: {e:?}")),
            }
        }
        buf
    };
    let text = String::from_utf8_lossy(&body_bytes).into_owned();

    if (200..=299).contains(&status) {
        Ok(text)
    } else {
        Err(format!("transport-http: server returned {status}: {text}"))
    }
}

bindings::export!(Component with_types_in bindings);
