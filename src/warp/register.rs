use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const API_URL: &str = "https://api.cloudflareclient.com";
const API_VERSION: &str = "v0a4471";
const CLIENT_VERSION: &str = "a-6.35-4471";
const USER_AGENT: &str = "WARP for Android";

pub(crate) const DEFAULT_MODEL: &str = "PC";
pub(crate) const DEFAULT_LOCALE: &str = "en_US";

const API_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WarpCredentials {
    pub id: String,
    pub access_token: String,
    pub private_key: String,
    pub endpoint_pub_key: String,
    #[serde(default)]
    pub ipv4: String,
    #[serde(default)]
    pub ipv6: String,
    #[serde(default)]
    pub endpoint_v4: String,
    #[serde(default)]
    pub endpoint_v6: String,
}

impl WarpCredentials {
    pub(crate) fn signing_key(&self) -> Result<SigningKey> {
        let der = B64
            .decode(self.private_key.as_bytes())
            .context("warp: private_key is not valid base64")?;
        SigningKey::from_pkcs8_der(&der).context("warp: private_key is not a PKCS#8 EC key")
    }

    pub(crate) fn endpoint_spki(&self) -> Result<Vec<u8>> {
        let raw = self.endpoint_pub_key.trim();
        if raw.starts_with("-----BEGIN") {
            let body: String = raw
                .lines()
                .filter(|line| !line.trim_start().starts_with("-----"))
                .collect();
            return B64
                .decode(body.as_bytes())
                .context("warp: endpoint_pub_key is not valid PEM");
        }
        B64.decode(raw.as_bytes())
            .context("warp: endpoint_pub_key is not valid base64")
    }
}

pub(crate) struct RegisterOptions<'a> {
    pub model: &'a str,
    pub locale: &'a str,
}

pub(crate) async fn load_or_register(
    path: &Path,
    opts: &RegisterOptions<'_>,
) -> Result<WarpCredentials> {
    match tokio::fs::read(path).await {
        Ok(raw) => match serde_json::from_slice::<WarpCredentials>(&raw) {
            Ok(creds) => match creds.signing_key() {
                Ok(_) => {
                    info!(path = %path.display(), id = %creds.id, "warp: loaded credentials");
                    return Ok(creds);
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "warp: unusable credentials")
                }
            },
            Err(e) => warn!(path = %path.display(), error = %e, "warp: malformed credentials"),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!(path = %path.display(), "warp: no credentials yet, registering");
        }
        Err(e) => warn!(path = %path.display(), error = %e, "warp: cannot read credentials"),
    }

    let creds = register(opts).await?;
    if let Err(e) = save(path, &creds).await {
        warn!(path = %path.display(), error = %e, "warp: failed to persist credentials");
    }
    Ok(creds)
}

async fn save(path: &Path, creds: &WarpCredentials) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    let body = serde_json::to_vec_pretty(creds)?;
    tokio::fs::write(path, &body).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    info!(path = %path.display(), "warp: credentials saved");
    Ok(())
}

async fn register(opts: &RegisterOptions<'_>) -> Result<WarpCredentials> {
    let client = wreq::Client::builder()
        .no_proxy()
        .build()
        .context("warp: build http client")?;

    let mut wg_key = [0u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut wg_key);
    let mut serial = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut serial);

    let url = format!("{API_URL}/{API_VERSION}/reg");
    let body = json_body(&serde_json::json!({
        "key": B64.encode(wg_key),
        "install_id": "",
        "fcm_token": "",
        "tos": cf_time_string(),
        "model": opts.model,
        "serial_number": hex_lower(&serial),
        "os_version": "",
        "key_type": "curve25519",
        "tunnel_type": "wireguard",
        "locale": opts.locale,
    }))?;
    let account = send(client.post(&url).body(body), "registration").await?;

    let AccountData { id, token, .. } = account;
    if token.is_empty() {
        bail!("warp: registration response did not contain a token");
    }

    let (signing_key, spki) = generate_device_key()?;
    let pkcs8 = signing_key
        .to_pkcs8_der()
        .context("warp: encode device key")?;

    let url = format!("{API_URL}/{API_VERSION}/reg/{id}");
    let body = json_body(&serde_json::json!({
        "key": B64.encode(&spki),
        "key_type": "secp256r1",
        "tunnel_type": "masque",
    }))?;
    let enrolled = send(
        client
            .patch(&url)
            .header("Authorization", format!("Bearer {token}"))
            .body(body),
        "enrollment",
    )
    .await?;

    let AccountConfig { peers, interface } = enrolled.config;
    let peer = peers
        .into_iter()
        .next()
        .context("warp: enrollment response has no peers")?;
    if peer.public_key.is_empty() {
        bail!("warp: enrollment response has no peer public key");
    }

    let creds = WarpCredentials {
        id,
        access_token: token,
        private_key: B64.encode(pkcs8.as_bytes()),
        endpoint_pub_key: peer.public_key,
        ipv4: interface.addresses.v4,
        ipv6: interface.addresses.v6,
        endpoint_v4: strip_port(&peer.endpoint.v4),
        endpoint_v6: strip_port(&peer.endpoint.v6),
    };
    info!(id = %creds.id, ipv4 = %creds.ipv4, "warp: device registered");
    Ok(creds)
}

pub(crate) fn generate_device_key() -> Result<(SigningKey, Vec<u8>)> {
    for _ in 0..16 {
        let mut scalar = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut scalar);
        let Ok(signing_key) = SigningKey::from_slice(&scalar) else {
            continue;
        };
        let spki = signing_key
            .verifying_key()
            .to_public_key_der()
            .context("warp: encode public key")?
            .as_bytes()
            .to_vec();
        return Ok((signing_key, spki));
    }
    bail!("warp: failed to generate a device key");
}

fn strip_port(addr: &str) -> String {
    let addr = addr.trim();
    if let Some(rest) = addr.strip_prefix('[')
        && let Some((host, _)) = rest.split_once(']')
    {
        return format!("[{host}]");
    }
    match addr.rsplit_once(':') {
        Some((host, port))
            if !host.contains(':')
                && !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            host.to_string()
        }
        _ => addr.to_string(),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0F) as u32, 16).unwrap());
    }
    out
}

fn cf_time_string() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = civil_from_unix(secs as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.000+00:00")
}

fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (
        y,
        m,
        d,
        (rem / 3_600) as u32,
        ((rem % 3_600) / 60) as u32,
        (rem % 60) as u32,
    )
}

#[derive(Debug, Deserialize)]
struct AccountData {
    id: String,
    #[serde(default)]
    token: String,
    config: AccountConfig,
}

#[derive(Debug, Deserialize)]
struct AccountConfig {
    #[serde(default)]
    peers: Vec<Peer>,
    #[serde(default)]
    interface: Interface,
}

#[derive(Debug, Deserialize)]
struct Peer {
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    endpoint: PeerEndpoint,
}

#[derive(Debug, Default, Deserialize)]
struct PeerEndpoint {
    #[serde(default)]
    v4: String,
    #[serde(default)]
    v6: String,
}

#[derive(Debug, Default, Deserialize)]
struct Interface {
    #[serde(default)]
    addresses: Addresses,
}

#[derive(Debug, Default, Deserialize)]
struct Addresses {
    #[serde(default)]
    v4: String,
    #[serde(default)]
    v6: String,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    #[serde(default)]
    errors: Vec<ApiErrorItem>,
}

#[derive(Debug, Deserialize)]
struct ApiErrorItem {
    #[serde(default)]
    message: String,
}

fn json_body(value: &serde_json::Value) -> Result<wreq::Body> {
    Ok(wreq::Body::from(serde_json::to_vec(value)?))
}

async fn send(req: wreq::RequestBuilder, stage: &str) -> Result<AccountData> {
    let req = req
        .header("User-Agent", USER_AGENT)
        .header("CF-Client-Version", CLIENT_VERSION)
        .header("Content-Type", "application/json; charset=UTF-8")
        .header("Connection", "Keep-Alive");

    let response = tokio::time::timeout(API_TIMEOUT, req.send())
        .await
        .with_context(|| format!("warp: {stage} request timed out"))?
        .with_context(|| format!("warp: {stage} request failed"))?;
    let status = response.status();
    let body = tokio::time::timeout(API_TIMEOUT, response.bytes())
        .await
        .with_context(|| format!("warp: {stage} response timed out"))?
        .with_context(|| format!("warp: {stage} response failed"))?;

    if !status.is_success() {
        let detail = serde_json::from_slice::<ApiError>(&body)
            .ok()
            .map(|e| {
                e.errors
                    .into_iter()
                    .map(|i| i.message)
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| String::from_utf8_lossy(&body).chars().take(200).collect());
        bail!("warp: {stage} rejected with {status}: {detail}");
    }

    serde_json::from_slice(&body).with_context(|| format!("warp: cannot parse {stage} response"))
}

pub(crate) fn default_path() -> PathBuf {
    PathBuf::from("warp.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_string_matches_cloudflare_format() {
        let (y, mo, d, h, mi, s) = civil_from_unix(1_793_602_800);
        assert_eq!((y, mo, d, h, mi, s), (2026, 11, 2, 7, 0, 0));
    }
    #[test]
    fn hex_encoding_is_lowercase_and_padded() {
        assert_eq!(hex_lower(&[0x0a, 0xff, 0x00]), "0aff00");
    }

    #[test]
    fn strip_port_handles_v4_and_v6() {
        assert_eq!(strip_port("162.159.192.1:500"), "162.159.192.1");
        assert_eq!(strip_port("162.159.192.1"), "162.159.192.1");
        assert_eq!(strip_port("[2606:4700::1]:500"), "[2606:4700::1]");
        assert_eq!(strip_port("[2606:4700:103::2]"), "[2606:4700:103::2]");
        assert_eq!(strip_port("2606:4700:103::2"), "2606:4700:103::2");
    }

    #[test]
    fn endpoint_spki_accepts_pem_and_raw_base64() {
        let (_, spki) = generate_device_key().unwrap();
        let mut creds = WarpCredentials {
            id: "id".into(),
            access_token: "t".into(),
            private_key: "x".into(),
            endpoint_pub_key: B64.encode(&spki),
            ipv4: String::new(),
            ipv6: String::new(),
            endpoint_v4: String::new(),
            endpoint_v6: String::new(),
        };
        assert_eq!(creds.endpoint_spki().unwrap(), spki);

        let body = B64.encode(&spki);
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in body.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        creds.endpoint_pub_key = pem;
        assert_eq!(creds.endpoint_spki().unwrap(), spki);
    }

    #[test]
    fn generated_key_roundtrips_through_credentials() {
        let (key, spki) = generate_device_key().unwrap();
        let creds = WarpCredentials {
            id: "id".into(),
            access_token: "token".into(),
            private_key: B64.encode(key.to_pkcs8_der().unwrap().as_bytes()),
            endpoint_pub_key: B64.encode(&spki),
            ipv4: "172.16.0.2".into(),
            ipv6: "2606:4700:110:8a36::2".into(),
            endpoint_v4: "162.159.192.1".into(),
            endpoint_v6: String::new(),
        };
        let restored = creds.signing_key().unwrap();
        assert_eq!(
            restored
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
            spki.as_slice()
        );
        assert_eq!(creds.endpoint_spki().unwrap(), spki);
    }
}
