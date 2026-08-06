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
//! The server is deliberately tiny and read-only: a handful of routes, no
//! filesystem access, no state. It is a viewer, not a service.
//!
//! The marketplace follows the same rule. Listings come from relays you choose,
//! every record is checked against an accumulator you built, and nothing is
//! ranked by anything that did not come out of the chain. There is no promotion
//! to sell because there is nobody here to sell it.

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
    /// A saved scan, for checking marketplace listings without a node round
    /// trip per seller. Absent means the market route says so rather than
    /// showing scores it has not checked.
    pub roots: Option<Arc<crate::market::RootsVerifier>>,
    pub relays: Vec<String>,
    /// Whether this instance is serving strangers.
    ///
    /// Both pages tell the reader that verification happened on their own
    /// machine against their own node. On a hosted deployment that sentence is
    /// simply false, and it is the exact claim this project exists to make
    /// true — so the copy has to change rather than quietly mislead. A hosted
    /// explorer is a server of record; it can still be useful, but only if it
    /// says which one it is.
    pub public: bool,
}

impl Explorer {
    /// Fetch listings and check each seller's record against the accumulator.
    fn market(&self) -> serde_json::Value {
        let Some(roots) = &self.roots else {
            return serde_json::json!({
                "ok": false,
                "error": "no accumulator. Build one with `krep roots --out roots.json`, then \
                          start the server with --roots roots.json. Without it every score on \
                          this page would be a number nobody checked."
            });
        };
        if self.relays.is_empty() {
            return serde_json::json!({ "ok": false, "error": "no relays configured; pass --relay" });
        }
        let offers = match self
            .handle
            .block_on(crate::board::list_offers(&self.relays, None, None))
        {
            Ok(o) => o,
            Err(e) => return serde_json::json!({ "ok": false, "error": e.to_string() }),
        };
        let mut listings: Vec<crate::market::Listing> = offers
            .into_iter()
            .map(|(id, offer, e)| crate::market::assess(id, e.pubkey, offer, roots))
            .collect();
        crate::market::rank(&mut listings);
        serde_json::json!({
            "ok": true,
            "complete": roots.complete,
            "relays": self.relays,
            "listings": listings,
        })
    }
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
            return serde_json::json!({ "ok": false, "stage": "unknown", "error": e.to_string() });
        }
        // "We cannot tell" and "it never happened" are different answers, and
        // only one of them is an accusation. An anchor that has fallen behind
        // this node's pruning point is the ordinary fate of an old chain, not
        // evidence against its owner.
        if let Err(e) = chain.verify_anchored(&verifier) {
            let stage = match e {
                krep_core::KrepError::AnchorUnknown { .. } => "unknown",
                _ => "anchor",
            };
            return serde_json::json!({ "ok": false, "stage": stage, "error": e.to_string() });
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
        let loopback = listen.starts_with("127.") || listen.starts_with("localhost") || listen.starts_with("[::1]");
        if loopback {
            eprintln!("loopback only — verification happens here, against your node");
        } else {
            // Reachable from the network. Nothing here writes, holds keys or
            // touches the filesystem, so the exposure is bounded — but a single
            // request can cost a full chain scan, and that is worth knowing
            // before this ends up somewhere it can be reached from outside.
            eprintln!(
                "reachable from the network. No keys, no writes, read-only — but unauthenticated,\n\
                 and one request can cost a multi-minute scan of your node. Fine on a LAN you\n\
                 control; do not expose it to the internet."
            );
        }
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
            ("GET", "/market") => ("200 OK", "text/html; charset=utf-8", MARKET.to_string()),
            ("GET", "/api/market") => ("200 OK", "application/json", self.market().to_string()),
            ("GET", "/api/info") => (
                "200 OK",
                "application/json",
                serde_json::json!({
                    "rpc": self.rpc_url,
                    "market": self.roots.is_some() && !self.relays.is_empty(),
                    "public": self.public,
                })
                .to_string(),
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
const MARKET: &str = include_str!("market.html");
