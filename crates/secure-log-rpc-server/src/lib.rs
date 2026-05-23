//! Reference JSON-RPC server for the secure-log remote store.
//!
//! Terminates the wire protocol defined in [`secure_log_rpc`] and runs
//! each call against a native [`secure_log::store::SecureLogStore`]
//! (SQLite-backed). This is the host-side peer of the
//! `secure-log-store-remote` provider: that component forwards every
//! store op here over `wasi:http`, and this server executes it.
//!
//! Deliberately dependency-light — a small std-only HTTP/1.1 loop, one
//! thread per connection, `Connection: close`. Swap in any production
//! HTTP stack without touching [`dispatch`].

pub mod dispatch;

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::JoinHandle;

pub use dispatch::Server;
use secure_log_rpc::Request;

/// Default bind address.
pub const DEFAULT_ADDR: &str = "127.0.0.1:8787";

/// Bind address resolution for the binary: `--addr` argument, else
/// `SECURE_LOG_RPC_ADDR`, else [`DEFAULT_ADDR`].
pub fn resolve_addr() -> String {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--addr" {
            if let Some(v) = args.next() {
                return v;
            }
        } else if let Some(v) = arg.strip_prefix("--addr=") {
            return v.to_string();
        }
    }
    std::env::var("SECURE_LOG_RPC_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.to_string())
}

/// Bind `addr` and serve forever on the calling thread.
pub fn run(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    println!("secure-log-rpc-server listening on http://{local}");
    serve(listener, Arc::new(Server::new()));
    Ok(())
}

/// Bind `addr` (use port 0 for an ephemeral port) and serve on a
/// background thread. Returns the actual bound address so callers can
/// build the `SECURE_LOG_RPC_URL` for it. Intended for tests/harnesses.
pub fn spawn(addr: &str) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    let server = Arc::new(Server::new());
    let handle = std::thread::spawn(move || serve(listener, server));
    Ok((local, handle))
}

/// Accept connections forever, one handler thread each.
fn serve(listener: TcpListener, server: Arc<Server>) {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let server = Arc::clone(&server);
                std::thread::spawn(move || {
                    if let Err(e) = handle_conn(stream, &server) {
                        eprintln!("connection error: {e}");
                    }
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}

/// Handle one request/response round trip then close the connection.
fn handle_conn(stream: TcpStream, server: &Server) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);

    // Request line (ignored) + headers, until a blank line. The body is
    // framed by either Content-Length or chunked transfer-encoding (the
    // wasi:http client sends chunked).
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(()); // client hung up
    }
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            break;
        }
        let trimmed = header.trim_end();
        if trimmed.is_empty() {
            break; // end of headers
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().ok();
            } else if k.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }

    let body = read_body(&mut reader, content_length, chunked)?;

    let (status, payload) = match serde_json::from_slice::<Request>(&body) {
        Ok(req) => match server.dispatch(&req.method, req.params) {
            Ok(result) => ("200 OK", result),
            Err(e) => ("500 Internal Server Error", e),
        },
        Err(e) => ("400 Bad Request", format!("malformed request envelope: {e}")),
    };

    let mut stream = reader.into_inner();
    write_response(&mut stream, status, &payload)
}

/// Read the request body, framed by either chunked transfer-encoding
/// (preferred when present) or Content-Length.
fn read_body<R: BufRead>(
    reader: &mut R,
    content_length: Option<usize>,
    chunked: bool,
) -> std::io::Result<Vec<u8>> {
    if chunked {
        let mut body = Vec::new();
        loop {
            // Chunk size line: hex length, optional ";extension".
            let mut size_line = String::new();
            if reader.read_line(&mut size_line)? == 0 {
                break;
            }
            let hex = size_line.trim().split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(hex, 16).unwrap_or(0);
            if size == 0 {
                // Consume the trailing CRLF after the last chunk.
                let mut trailer = String::new();
                let _ = reader.read_line(&mut trailer);
                break;
            }
            let mut chunk = vec![0u8; size];
            reader.read_exact(&mut chunk)?;
            body.extend_from_slice(&chunk);
            // Each chunk is followed by CRLF.
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf)?;
        }
        Ok(body)
    } else {
        let mut body = vec![0u8; content_length.unwrap_or(0)];
        reader.read_exact(&mut body)?;
        Ok(body)
    }
}

fn write_response(stream: &mut TcpStream, status: &str, body: &str) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    )?;
    stream.flush()
}
