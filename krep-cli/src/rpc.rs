//! kaspad client construction.
//!
//! Both the wRPC and gRPC clients implement `kaspa_rpc_core::api::rpc::RpcApi`,
//! so everything downstream of this module is transport-agnostic and takes an
//! `Arc<dyn RpcApi>`. The URL scheme picks the transport:
//!
//! - `ws://host:17110` / `wss://…` — wRPC (borsh), kaspad's `--rpclisten-borsh`
//! - `grpc://host:16110` — gRPC, kaspad's default `--rpclisten`

use anyhow::{Context, Result, anyhow, bail};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::notify::mode::NotificationMode;
use kaspa_wrpc_client::prelude::{ConnectOptions, ConnectStrategy, KaspaRpcClient, WrpcEncoding};
use std::sync::Arc;
use std::time::Duration;

/// Environment fallback for `--rpc`.
pub const RPC_ENV: &str = "KREP_RPC";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn connect(url: &str) -> Result<Arc<dyn RpcApi>> {
    if url.starts_with("grpc://") {
        let client = GrpcClient::connect_with_args(
            NotificationMode::Direct,
            url.to_string(),
            None,  // subscription context — we never subscribe
            false, // no auto-reconnect: a CLI should fail loudly, not hang
            None,
            false,
            Some(CONNECT_TIMEOUT.as_millis() as u64),
            Default::default(),
        )
        .await
        .with_context(|| format!("connecting to {url}"))?;
        Ok(Arc::new(client))
    } else if url.starts_with("ws://") || url.starts_with("wss://") {
        let client = KaspaRpcClient::new(WrpcEncoding::Borsh, Some(url), None, None, None)
            .map_err(|e| anyhow!("building wRPC client for {url}: {e}"))?;
        client
            .connect(Some(ConnectOptions {
                block_async_connect: true,
                // Fallback = one attempt then give up. Retry would spin forever
                // against a node that simply has wRPC disabled.
                strategy: ConnectStrategy::Fallback,
                connect_timeout: Some(CONNECT_TIMEOUT),
                ..Default::default()
            }))
            .await
            .map_err(|e| anyhow!("connecting to {url}: {e}"))?;
        Ok(Arc::new(client))
    } else {
        bail!(
            "unsupported RPC URL {url:?} — use grpc://host:16110 (kaspad --rpclisten) \
             or ws://host:17110 (kaspad --rpclisten-borsh)"
        )
    }
}

/// Resolve the endpoint from the flag, then the environment.
pub fn endpoint(flag: &Option<String>) -> Option<String> {
    flag.clone().or_else(|| std::env::var(RPC_ENV).ok()).filter(|s| !s.is_empty())
}
