use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;
use tracing::warn;
use zeroize::Zeroizing;

use crate::bypass::BypassRules;
use crate::client::constants::MASTER_RESUME_WINDOW_SECS;
use crate::client::handshake::{self, PqSessionTicket};
use crate::shaper::{ResolvedShaperConfig, TrafficConfig};

pub type InitialMasterEntry = (String, Zeroizing<[u8; 32]>, u64);

pub struct ManualResolver {
    pub target_addr: String,
}

impl wreq::dns::Resolve for ManualResolver {
    fn resolve(&self, _name: wreq::dns::Name) -> wreq::dns::Resolving {
        let target = self.target_addr.clone();
        Box::pin(async move {
            let mut lookup_str = String::with_capacity(target.len() + 2);
            lookup_str.push_str(&target);
            lookup_str.push_str(":0");
            let addrs = tokio::net::lookup_host(lookup_str)
                .await?
                .map(|mut s| {
                    s.set_port(0);
                    s
                })
                .collect::<Vec<_>>();
            Ok(Box::new(addrs.into_iter())
                as Box<dyn Iterator<Item = SocketAddr> + Send + 'static>)
        })
    }
}

pub struct SharedState {
    pub remote_str: String,
    pub auth_header: String,
    pub traffic_config: TrafficConfig,
    pub resolved_traffic: Arc<ResolvedShaperConfig>,
    pub bypass: Option<Arc<BypassRules>>,
    pub server_public_key: Option<x25519_dalek::PublicKey>,
    pub proxy_auth: Option<(String, String)>,
    pub initial_master: Mutex<Option<InitialMasterEntry>>,
    pub handshake_lock: Mutex<()>,
    pub max_download_bytes: Option<u64>,
    pub max_connections: usize,
    pub max_in_flight_bytes: usize,
    pub upload_concurrency: usize,
}

pub struct Resuming {
    pub ticket: PqSessionTicket,
    pub target_host: String,
    pub payload: Bytes,
    pub read_half: Option<OwnedReadHalf>,
    pub write_half: Option<OwnedWriteHalf>,
}

pub struct Handshaking {
    pub target_host: String,
    pub payload: Bytes,
    pub read_half: OwnedReadHalf,
    pub write_half: OwnedWriteHalf,
    pub server_pk: x25519_dalek::PublicKey,
}

pub enum ClientPqFsm {
    Resuming(Resuming),
    Handshaking(Handshaking),
}

impl ClientPqFsm {
    pub async fn new(
        target_host: String,
        payload: Bytes,
        read_half: OwnedReadHalf,
        write_half: OwnedWriteHalf,
        server_pk: x25519_dalek::PublicKey,
        state: &Arc<SharedState>,
    ) -> Self {
        match load_and_validate_ticket(state).await {
            Some(ticket) => ClientPqFsm::Resuming(Resuming {
                ticket,
                target_host,
                payload,
                read_half: Some(read_half),
                write_half: Some(write_half),
            }),
            None => ClientPqFsm::Handshaking(Handshaking {
                target_host,
                payload,
                read_half,
                write_half,
                server_pk,
            }),
        }
    }

    pub async fn run(
        mut self,
        http_client: Arc<wreq::Client>,
        state: Arc<SharedState>,
    ) -> anyhow::Result<()> {
        loop {
            self = match self {
                ClientPqFsm::Resuming(r) => match Self::try_resume(r, &http_client, &state).await {
                    Ok(()) => return Ok(()),
                    Err((resuming, e))
                        if e.downcast_ref::<handshake::RehandshakeRequired>().is_some() =>
                    {
                        warn!(error = %e, "session resumption rejected (428), falling back to full handshake");
                        invalidate_stale_master(&state, &resuming.ticket.session_id).await;
                        let rh = resuming
                            .read_half
                            .ok_or_else(|| anyhow::anyhow!("read half consumed"))?;
                        let wh = resuming
                            .write_half
                            .ok_or_else(|| anyhow::anyhow!("write half consumed"))?;
                        ClientPqFsm::Handshaking(Handshaking {
                            target_host: resuming.target_host,
                            payload: resuming.payload,
                            read_half: rh,
                            write_half: wh,
                            server_pk: state.server_public_key.ok_or_else(|| {
                                anyhow::anyhow!("server public key not configured")
                            })?,
                        })
                    }
                    Err((_, e)) => {
                        warn!(error = %e, "session resumption failed with transient error, aborting");
                        return Err(e);
                    }
                },
                ClientPqFsm::Handshaking(h) => {
                    let ticket = {
                        let _guard = state.handshake_lock.lock().await;
                        if let Some(ticket) = load_and_validate_ticket(&state).await {
                            ticket
                        } else {
                            handshake::perform_pq_handshake(
                                &http_client,
                                state.as_ref(),
                                &h.server_pk,
                            )
                            .await?
                        }
                    };

                    let mut rh = Some(h.read_half);
                    let mut wh = Some(h.write_half);
                    handshake::try_pq_connect(
                        &http_client,
                        &state,
                        &ticket,
                        &h.target_host,
                        h.payload.clone(),
                        &mut rh,
                        &mut wh,
                    )
                    .await?;
                    return Ok(());
                }
            };
        }
    }

    async fn try_resume(
        resuming: Resuming,
        http_client: &Arc<wreq::Client>,
        state: &Arc<SharedState>,
    ) -> std::result::Result<(), (Resuming, anyhow::Error)> {
        let mut read_half = resuming.read_half;
        let mut write_half = resuming.write_half;
        match handshake::try_pq_connect(
            http_client,
            state,
            &resuming.ticket,
            &resuming.target_host,
            resuming.payload.clone(),
            &mut read_half,
            &mut write_half,
        )
        .await
        {
            Ok(()) => Ok(()),
            Err(e) => Err((
                Resuming {
                    read_half,
                    write_half,
                    ..resuming
                },
                e,
            )),
        }
    }
}

fn ticket_is_valid(created: u64, now: u64) -> bool {
    now.saturating_sub(created) < MASTER_RESUME_WINDOW_SECS
}

async fn load_and_validate_ticket(state: &Arc<SharedState>) -> Option<PqSessionTicket> {
    let mut guard = state.initial_master.lock().await;
    let (session_id, master, created) = guard.as_ref()?;
    if !ticket_is_valid(*created, crate::now_secs()) {
        *guard = None;
        return None;
    }
    Some(PqSessionTicket {
        master: Zeroizing::new(**master),
        session_id: session_id.clone(),
    })
}

pub(super) async fn invalidate_stale_master(state: &Arc<SharedState>, rejected_sid: &str) {
    let mut guard = state.initial_master.lock().await;
    if let Some((ref sid, _, _)) = *guard
        && sid == rejected_sid
    {
        warn!(session_id = %sid, "invalidating stale master key after 428");
        *guard = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shaper::{EncodingType, PaddingConfig, TrafficConfig};

    fn shared_state() -> Arc<SharedState> {
        let traffic = TrafficConfig {
            global: PaddingConfig {
                padding_threshold: 0,
                padding_range: [0, 0],
            },
            stages: vec![],
            encoding_type: EncodingType::Binary,
            max_download_bytes: None,
        };
        Arc::new(SharedState {
            remote_str: "http://x/".to_string(),
            auth_header: "Bearer x".to_string(),
            traffic_config: traffic.clone(),
            resolved_traffic: Arc::new(ResolvedShaperConfig::resolve(&traffic)),
            bypass: None,
            server_public_key: None,
            proxy_auth: None,
            initial_master: Mutex::new(None),
            handshake_lock: Mutex::new(()),
            max_download_bytes: None,
            max_connections: 10,
            max_in_flight_bytes: 1024 * 1024,
            upload_concurrency: 4,
        })
    }

    #[tokio::test]
    async fn load_ticket_returns_none_when_empty() {
        let state = shared_state();
        assert!(load_and_validate_ticket(&state).await.is_none());
    }

    #[tokio::test]
    async fn load_ticket_returns_some_when_fresh() {
        let state = shared_state();
        let master = zeroize::Zeroizing::new([7u8; 32]);
        *state.initial_master.lock().await = Some(("sid-1".to_string(), master, crate::now_secs()));
        let ticket = load_and_validate_ticket(&state)
            .await
            .expect("fresh ticket");
        assert_eq!(ticket.session_id, "sid-1");
        assert_eq!(*ticket.master, [7u8; 32]);
    }

    #[test]
    fn ticket_is_valid_boundary() {
        let now = 10_000u64;
        assert!(ticket_is_valid(now, now));
        assert!(ticket_is_valid(now - 1, now));
        assert!(ticket_is_valid(now - MASTER_RESUME_WINDOW_SECS + 1, now));
        assert!(!ticket_is_valid(now - MASTER_RESUME_WINDOW_SECS, now));
        assert!(!ticket_is_valid(0, now));
        assert!(ticket_is_valid(now + 100, now));
    }

    #[tokio::test]
    async fn invalidate_matching_session_clears() {
        let state = shared_state();
        let master = zeroize::Zeroizing::new([7u8; 32]);
        *state.initial_master.lock().await = Some(("sid-2".to_string(), master, crate::now_secs()));
        invalidate_stale_master(&state, "sid-2").await;
        assert!(state.initial_master.lock().await.is_none());
    }

    #[tokio::test]
    async fn invalidate_non_matching_session_keeps() {
        let state = shared_state();
        let master = zeroize::Zeroizing::new([7u8; 32]);
        *state.initial_master.lock().await = Some(("sid-3".to_string(), master, crate::now_secs()));
        invalidate_stale_master(&state, "other-sid").await;
        assert!(state.initial_master.lock().await.is_some());
    }
}
