//! Reference JSON-RPC server for the secure-log remote store.
//!
//! Usage:
//!   secure-log-rpc-server [--addr HOST:PORT]
//!
//! Default address: 127.0.0.1:8787 (override with --addr or the
//! SECURE_LOG_RPC_ADDR environment variable). All logic lives in the
//! library crate so harnesses can embed the server directly.

fn main() -> std::io::Result<()> {
    secure_log_rpc_server::run(&secure_log_rpc_server::resolve_addr())
}
