//! Talking to Nostr relays.
//!
//! Deliberately thin, and deliberately distrustful. A relay is an untrusted
//! cache: it can drop events, reorder them, replay old ones or invent new ones.
//! So every event this module returns has had its id recomputed and its
//! signature checked, and anything that fails is discarded rather than
//! surfaced. Censorship is handled by talking to several relays and taking the
//! union — which is why publishing reports per-relay results instead of a
//! single success.

use crate::event::Event;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("connecting to {url}: {reason}")]
    Connect { url: String, reason: String },
    #[error("{0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, RelayError>;

/// What a relay asked for. Only the subset the board needs.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    #[serde(rename = "#a", skip_serializing_if = "Option::is_none")]
    pub a_tags: Option<Vec<String>>,
    #[serde(rename = "#d", skip_serializing_if = "Option::is_none")]
    pub d_tags: Option<Vec<String>>,
    #[serde(rename = "#p", skip_serializing_if = "Option::is_none")]
    pub p_tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Connect, but never hang.
///
/// A relay that accepts the TCP connection and then goes quiet — or a TLS
/// handshake that stalls — would otherwise block forever, since the read
/// timeout only covers the message loop. An unreachable relay must cost a
/// bounded wait, not the whole command.
async fn connect(
    url: &str,
    timeout: Duration,
) -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>> {
    match tokio::time::timeout(timeout, tokio_tungstenite::connect_async(url)).await {
        Err(_) => Err(RelayError::Connect { url: url.into(), reason: format!("no response in {timeout:?}") }),
        Ok(Err(e)) => Err(RelayError::Connect { url: url.into(), reason: e.to_string() }),
        Ok(Ok((ws, _))) => Ok(ws),
    }
}

/// Publish one event to one relay, reporting what the relay said.
pub async fn publish(url: &str, event: &Event, timeout: Duration) -> Result<String> {
    let mut ws = connect(url, timeout).await?;
    ws.send(Message::Text(json!(["EVENT", event]).to_string()))
        .await
        .map_err(|e| RelayError::Io(e.to_string()))?;

    // Wait for the relay's OK for *this* event id; anything else is noise.
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return Ok("no response before timeout".into()),
            msg = ws.next() => {
                let Some(Ok(Message::Text(text))) = msg else { return Ok("connection closed".into()) };
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    if v.get(0).and_then(|x| x.as_str()) == Some("OK")
                        && v.get(1).and_then(|x| x.as_str()) == Some(event.id.as_str())
                    {
                        let accepted = v.get(2).and_then(|x| x.as_bool()).unwrap_or(false);
                        let note = v.get(3).and_then(|x| x.as_str()).unwrap_or("");
                        return Ok(if accepted {
                            "accepted".into()
                        } else {
                            format!("rejected: {note}")
                        });
                    }
                }
            }
        }
    }
}

/// Query one relay, returning only events that actually verify.
pub async fn query(url: &str, filter: &Filter, timeout: Duration) -> Result<Vec<Event>> {
    let mut ws = connect(url, timeout).await?;
    let sub = "krep";
    ws.send(Message::Text(json!(["REQ", sub, filter]).to_string()))
        .await
        .map_err(|e| RelayError::Io(e.to_string()))?;

    let mut out = Vec::new();
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            msg = ws.next() => {
                let Some(Ok(Message::Text(text))) = msg else { break };
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
                match v.get(0).and_then(|x| x.as_str()) {
                    // End of stored events: everything after would be live.
                    Some("EOSE") => break,
                    Some("EVENT") => {
                        if let Some(e) = v.get(2).cloned().and_then(|e| serde_json::from_value::<Event>(e).ok()) {
                            // A relay handing us an unverifiable event is
                            // either buggy or hostile; either way it is noise.
                            if e.verify().is_ok() {
                                out.push(e);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let _ = ws.close(None).await;
    Ok(out)
}

/// Publish to several relays. Returns each relay's verdict — no single relay
/// failing should look like the post failing, and no single relay succeeding
/// should be mistaken for the job being widely visible.
pub async fn publish_all(urls: &[String], event: &Event, timeout: Duration) -> Vec<(String, String)> {
    let mut results = Vec::new();
    for url in urls {
        let verdict = match publish(url, event, timeout).await {
            Ok(v) => v,
            Err(e) => format!("failed: {e}"),
        };
        results.push((url.clone(), verdict));
    }
    results
}

/// Query several relays and merge, keeping the newest event per id.
///
/// Taking the union is the whole censorship story: a relay that silently omits
/// a job only censors the people who ask it alone.
pub async fn query_all(urls: &[String], filter: &Filter, timeout: Duration) -> Vec<Event> {
    let mut merged: HashMap<String, Event> = HashMap::new();
    for url in urls {
        if let Ok(events) = query(url, filter, timeout).await {
            for e in events {
                merged.entry(e.id.clone()).or_insert(e);
            }
        }
    }
    let mut out: Vec<Event> = merged.into_values().collect();
    out.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    out
}

/// Keep only the newest revision of each parameterized-replaceable event.
///
/// Relays are supposed to do this themselves, but they are not trusted to, and
/// an old revision resurfacing could show a stale reward or deadline.
pub fn newest_per_address(events: Vec<Event>) -> Vec<Event> {
    let mut best: HashMap<(u32, String, String), Event> = HashMap::new();
    for e in events {
        let d = e.tag("d").unwrap_or_default().to_string();
        let k = (e.kind, e.pubkey.clone(), d);
        match best.get(&k) {
            Some(existing) if existing.created_at >= e.created_at => {}
            _ => {
                best.insert(k, e);
            }
        }
    }
    let mut out: Vec<Event> = best.into_values().collect();
    out.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::KIND_JOB;
    use secp256k1::{Keypair, Secp256k1};

    fn key(b: u8) -> Keypair {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[b; 32]).unwrap()
    }

    #[test]
    fn filters_serialize_the_way_relays_expect() {
        let f = Filter {
            kinds: Some(vec![KIND_JOB]),
            a_tags: Some(vec!["30402:ab:job-1".into()]),
            limit: Some(20),
            ..Default::default()
        };
        let s = serde_json::to_string(&f).unwrap();
        assert!(s.contains(r#""kinds":[30402]"#));
        // Tag filters are spelled with a leading '#', and absent fields must be
        // omitted entirely rather than sent as null.
        assert!(s.contains(r##""#a":["30402:ab:job-1"]"##));
        assert!(!s.contains("authors"), "empty fields must not be sent");
    }

    #[test]
    fn only_the_newest_revision_of_a_job_survives() {
        let buyer = key(1);
        let old = Event::sign(&buyer, KIND_JOB, vec![vec!["d".into(), "j".into()]], "old".into(), 10);
        let new = Event::sign(&buyer, KIND_JOB, vec![vec!["d".into(), "j".into()]], "new".into(), 20);
        // A relay replaying the old revision must not shadow the current one.
        let kept = newest_per_address(vec![new.clone(), old.clone()]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].content, "new");
        assert_eq!(newest_per_address(vec![old, new])[0].content, "new");
    }

    #[test]
    fn different_authors_are_different_jobs_even_with_the_same_d_tag() {
        // Otherwise anyone could shadow someone else's posting by reusing its
        // identifier.
        let a = Event::sign(&key(1), KIND_JOB, vec![vec!["d".into(), "j".into()]], "mine".into(), 10);
        let b = Event::sign(&key(2), KIND_JOB, vec![vec!["d".into(), "j".into()]], "theirs".into(), 20);
        assert_eq!(newest_per_address(vec![a, b]).len(), 2);
    }
}
