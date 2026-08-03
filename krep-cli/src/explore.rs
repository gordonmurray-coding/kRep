//! `krep serve` — the reputation explorer.
//!
//! # Why this runs on your machine
//!
//! A hosted explorer would be a server of record: you would be trusting its
//! operator's word about whether a chain is anchored, which is precisely the
//! trust kRep exists to remove. So this binds to loopback, verifies with the
//! same code path as `krep verify`, and talks to *your* node. The page is a
//! rendering of a verdict you reached yourself, not a claim someone made to
//! you.
//!
//! The server is deliberately tiny and read-only: two routes, no filesystem
//! access, no state. It is a viewer, not a service.

use anyhow::{Context, Result};
use krep_core::chain::Chain;
use krep_core::kaspad::{KaspadAnchorVerifier, ScanConfig};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

pub struct Explorer {
    pub client: Arc<dyn kaspa_rpc_core::api::rpc::RpcApi>,
    pub handle: tokio::runtime::Handle,
    pub cfg: ScanConfig,
    pub rpc_url: String,
}

impl Explorer {
    /// Verify a pasted chain and render the verdict as JSON.
    fn verdict(&self, body: &str) -> serde_json::Value {
        let chain: Chain = match serde_json::from_str(body) {
            Ok(c) => c,
            Err(e) => return serde_json::json!({ "ok": false, "stage": "parse", "error": e.to_string() }),
        };

        // Structure and signatures first: a chain that fails here is malformed
        // regardless of what any node says.
        if let Err(e) = chain.verify() {
            return serde_json::json!({ "ok": false, "stage": "structure", "error": e.to_string() });
        }

        let verifier =
            KaspadAnchorVerifier::new(self.client.clone(), self.handle.clone(), self.cfg.clone());
        if let Err(e) = verifier.prefetch(chain.attestations.iter().map(|a| &a.body.anchor)) {
            return serde_json::json!({ "ok": false, "stage": "anchor", "error": e.to_string() });
        }
        if let Err(e) = chain.verify_anchored(&verifier) {
            return serde_json::json!({ "ok": false, "stage": "anchor", "error": e.to_string() });
        }

        let score = chain.score();
        let entries: Vec<serde_json::Value> = chain
            .attestations
            .iter()
            .map(|a| {
                serde_json::json!({
                    "index": a.body.index,
                    "role": a.body.role,
                    "outcome": a.body.outcome,
                    "bucket": a.body.amount_bucket,
                    "ts": a.body.ts,
                    "counterparty": hex::encode(a.body.counterparty.serialize()),
                    "anchor": format!("{}:{}", hex::encode(a.body.anchor.txid), a.body.anchor.index),
                    "id": hex::encode(a.id()),
                    // Which entries nobody signed — a default the subject could
                    // not refuse is worth showing as such.
                    "covenant_witnessed": a.covenant_witness().is_some(),
                })
            })
            .collect();

        serde_json::json!({
            "ok": true,
            "rpc": self.rpc_url,
            "owner": hex::encode(chain.owner.serialize()),
            "head": chain.head().map(hex::encode),
            "score": score,
            "entries": entries,
        })
    }

    pub fn serve(self, listen: &str) -> Result<()> {
        let listener = TcpListener::bind(listen).with_context(|| format!("binding {listen}"))?;
        eprintln!("rep explorer on http://{listen}  (verifying against {})", self.rpc_url);
        eprintln!("loopback only — this verifies with your node, so nobody has to be trusted");
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    if let Err(e) = self.handle_one(s) {
                        eprintln!("request failed: {e}");
                    }
                }
                Err(e) => eprintln!("accept failed: {e}"),
            }
        }
        Ok(())
    }

    fn handle_one(&self, mut stream: TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let path = parts.next().unwrap_or_default().to_string();

        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
                break;
            }
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }

        // A pasted chain is bounded; refusing anything larger keeps a stray
        // request from exhausting memory.
        const MAX_BODY: usize = 4 * 1024 * 1024;
        let (status, content_type, body) = match (method.as_str(), path.as_str()) {
            ("GET", "/") => ("200 OK", "text/html; charset=utf-8", PAGE.to_string()),
            ("GET", "/api/info") => (
                "200 OK",
                "application/json",
                serde_json::json!({ "rpc": self.rpc_url }).to_string(),
            ),
            ("POST", "/api/verify") if content_length <= MAX_BODY => {
                let mut buf = vec![0u8; content_length];
                reader.read_exact(&mut buf)?;
                let body = String::from_utf8_lossy(&buf).to_string();
                ("200 OK", "application/json", self.verdict(&body).to_string())
            }
            ("POST", "/api/verify") => (
                "413 Payload Too Large",
                "application/json",
                serde_json::json!({ "ok": false, "stage": "parse", "error": "chain too large" }).to_string(),
            ),
            _ => ("404 Not Found", "text/plain; charset=utf-8", "not found".into()),
        };

        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        stream.flush()?;
        Ok(())
    }
}

const PAGE: &str = include_str!("explore.html");
