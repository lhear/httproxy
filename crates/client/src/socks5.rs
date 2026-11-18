use anyhow::{Context, Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::state::ProxyAuth;

const VERSION: u8 = 5;
const AUTH_VERSION: u8 = 1;
const NO_AUTH: u8 = 0;
const USER_PASS: u8 = 2;
const CONNECT: u8 = 1;
const UDP_ASSOCIATE: u8 = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::Domain(_, port) => *port,
        }
    }

    pub fn tunnel_target(&self) -> String {
        match self {
            Self::Ip(addr) => format!("{}:{}", addr.ip(), addr.port()),
            Self::Domain(host, port) => format!("{host}:{port}"),
        }
    }
}

pub enum Command {
    Connect(Target),
    UdpAssociate(Option<SocketAddr>),
    Unsupported,
}

pub async fn server_handshake(
    version: u8,
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    auth: Option<&ProxyAuth>,
) -> Result<Command> {
    if version != VERSION {
        bail!("invalid SOCKS5 version");
    }
    let mut count = [0];
    reader.read_exact(&mut count).await?;
    if count[0] == 0 {
        writer.write_all(&[VERSION, 0xff]).await?;
        bail!("SOCKS5 client offered no authentication methods");
    }
    let mut methods = vec![0; count[0] as usize];
    reader.read_exact(&mut methods).await?;
    let method = if auth.is_some() { USER_PASS } else { NO_AUTH };
    if !methods.contains(&method) {
        writer.write_all(&[VERSION, 0xff]).await?;
        bail!("SOCKS5 authentication method unavailable");
    }
    writer.write_all(&[VERSION, method]).await?;
    if let Some(auth) = auth {
        let mut header = [0; 2];
        reader.read_exact(&mut header).await?;
        let mut username = vec![0; header[1] as usize];
        reader.read_exact(&mut username).await?;
        let mut password_len = [0];
        reader.read_exact(&mut password_len).await?;
        let mut password = vec![0; password_len[0] as usize];
        reader.read_exact(&mut password).await?;
        let valid = header[0] == AUTH_VERSION
            && username == auth.username.as_bytes()
            && password == auth.password.as_bytes();
        writer.write_all(&[AUTH_VERSION, u8::from(!valid)]).await?;
        if !valid {
            bail!("SOCKS5 authentication failed");
        }
    }

    let mut header = [0; 4];
    reader.read_exact(&mut header).await?;
    if header[0] != VERSION || header[2] != 0 {
        write_reply(writer, 1, None).await?;
        bail!("invalid SOCKS5 request");
    }
    let target = match read_target(reader, header[3]).await {
        Ok(target) => target,
        Err(error) => {
            write_reply(writer, 8, None).await?;
            return Err(error);
        }
    };
    match header[1] {
        CONNECT => Ok(Command::Connect(target)),
        UDP_ASSOCIATE => {
            let requested = match target {
                Target::Ip(addr) if !addr.ip().is_unspecified() || addr.port() != 0 => Some(addr),
                Target::Ip(_) => None,
                Target::Domain(_, _) => {
                    write_reply(writer, 8, None).await?;
                    bail!("SOCKS5 UDP association requires an IP address")
                }
            };
            Ok(Command::UdpAssociate(requested))
        }
        _ => {
            write_reply(writer, 7, None).await?;
            Ok(Command::Unsupported)
        }
    }
}

pub async fn write_reply(
    writer: &mut (impl AsyncWrite + Unpin),
    status: u8,
    address: Option<SocketAddr>,
) -> Result<()> {
    let address = address.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut response = Vec::with_capacity(22);
    response.extend_from_slice(&[VERSION, status, 0]);
    encode_address(&mut response, address.ip());
    response.extend_from_slice(&address.port().to_be_bytes());
    writer.write_all(&response).await?;
    Ok(())
}

pub fn parse_udp_packet(packet: &[u8]) -> Option<(Target, &[u8])> {
    if packet.len() < 4 || packet[..2] != [0, 0] || packet[2] != 0 {
        return None;
    }
    let mut cursor = 3;
    let target = parse_address(packet, &mut cursor)?;
    (cursor < packet.len()).then_some((target, &packet[cursor..]))
}

pub fn encode_udp_packet(target: &Target, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(payload.len() + 22);
    packet.extend_from_slice(&[0, 0, 0]);
    encode_target(&mut packet, target);
    packet.extend_from_slice(payload);
    packet
}

pub async fn client_connect(
    stream: &mut TcpStream,
    target: &Target,
    auth: Option<&ProxyAuth>,
) -> Result<()> {
    let method = if auth.is_some() { USER_PASS } else { NO_AUTH };
    stream.write_all(&[VERSION, 1, method]).await?;
    let mut response = [0; 2];
    stream.read_exact(&mut response).await?;
    if response != [VERSION, method] {
        bail!("local SOCKS5 authentication negotiation failed");
    }
    if let Some(auth) = auth {
        let username = auth.username.as_bytes();
        let password = auth.password.as_bytes();
        let username_len =
            u8::try_from(username.len()).context("SOCKS5 username exceeds 255 bytes")?;
        let password_len =
            u8::try_from(password.len()).context("SOCKS5 password exceeds 255 bytes")?;
        stream.write_all(&[AUTH_VERSION, username_len]).await?;
        stream.write_all(username).await?;
        stream.write_all(&[password_len]).await?;
        stream.write_all(password).await?;
        stream.read_exact(&mut response).await?;
        if response != [AUTH_VERSION, 0] {
            bail!("local SOCKS5 authentication failed");
        }
    }
    let mut request = vec![VERSION, CONNECT, 0];
    encode_target(&mut request, target);
    stream.write_all(&request).await?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != VERSION || header[1] != 0 || header[2] != 0 {
        bail!("local SOCKS5 CONNECT failed with status {}", header[1]);
    }
    let _ = read_target(stream, header[3]).await?;
    Ok(())
}

async fn read_target(reader: &mut (impl AsyncRead + Unpin), atyp: u8) -> Result<Target> {
    let mut address = Vec::with_capacity(260);
    match atyp {
        1 => {
            let mut bytes = [0; 4];
            reader.read_exact(&mut bytes).await?;
            address.extend_from_slice(&bytes);
        }
        4 => {
            let mut bytes = [0; 16];
            reader.read_exact(&mut bytes).await?;
            address.extend_from_slice(&bytes);
        }
        3 => {
            let mut len = [0];
            reader.read_exact(&mut len).await?;
            if len[0] == 0 {
                bail!("empty SOCKS5 domain name");
            }
            address.resize(len[0] as usize, 0);
            reader.read_exact(&mut address).await?;
        }
        _ => bail!("unsupported SOCKS5 address type"),
    }
    let mut port = [0; 2];
    reader.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    match atyp {
        1 => Ok(Target::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                address[0], address[1], address[2], address[3],
            )),
            port,
        ))),
        4 => Ok(Target::Ip(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(address.as_slice()).unwrap(),
            )),
            port,
        ))),
        3 => Ok(Target::Domain(
            String::from_utf8(address).context("invalid SOCKS5 domain name")?,
            port,
        )),
        _ => unreachable!(),
    }
}

fn parse_address(packet: &[u8], cursor: &mut usize) -> Option<Target> {
    let atyp = *packet.get(*cursor)?;
    *cursor += 1;
    let ip = match atyp {
        1 => {
            let bytes: [u8; 4] = packet.get(*cursor..*cursor + 4)?.try_into().ok()?;
            *cursor += 4;
            Some(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        4 => {
            let bytes: [u8; 16] = packet.get(*cursor..*cursor + 16)?.try_into().ok()?;
            *cursor += 16;
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    };
    let domain = if atyp == 3 {
        let len = *packet.get(*cursor)? as usize;
        *cursor += 1;
        let value = std::str::from_utf8(packet.get(*cursor..*cursor + len)?).ok()?;
        if value.is_empty() {
            return None;
        }
        *cursor += len;
        Some(value.to_owned())
    } else {
        None
    };
    let port = u16::from_be_bytes(packet.get(*cursor..*cursor + 2)?.try_into().ok()?);
    *cursor += 2;
    match (ip, domain) {
        (Some(ip), None) => Some(Target::Ip(SocketAddr::new(ip, port))),
        (None, Some(domain)) => Some(Target::Domain(domain, port)),
        _ => None,
    }
}

fn encode_target(buffer: &mut Vec<u8>, target: &Target) {
    match target {
        Target::Ip(address) => encode_address(buffer, address.ip()),
        Target::Domain(domain, _) => {
            buffer.push(3);
            buffer.push(domain.len() as u8);
            buffer.extend_from_slice(domain.as_bytes());
        }
    }
    buffer.extend_from_slice(&target.port().to_be_bytes());
}

fn encode_address(buffer: &mut Vec<u8>, address: IpAddr) {
    match address {
        IpAddr::V4(ip) => {
            buffer.push(1);
            buffer.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buffer.push(4);
            buffer.extend_from_slice(&ip.octets());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_packet_roundtrips_domain_target() {
        let target = Target::Domain("dns.example".to_owned(), 53);
        let packet = encode_udp_packet(&target, b"query");
        let (decoded, payload) = parse_udp_packet(&packet).unwrap();
        assert_eq!(decoded, target);
        assert_eq!(payload, b"query");
    }

    #[test]
    fn fragmented_udp_packet_is_rejected() {
        assert!(parse_udp_packet(&[0, 0, 1, 1, 127, 0, 0, 1, 0, 53, 0]).is_none());
    }

    #[tokio::test]
    async fn handshake_uses_configured_username_and_password() {
        let auth = ProxyAuth {
            http_header: "Basic dXNlcjpwYXNz".to_owned(),
            username: "user".to_owned(),
            password: "pass".to_owned(),
        };
        let (server, mut client) = httproxy_core::test_support::connected_pair().await;
        let (mut reader, mut writer) = server.into_split();
        let handshake = tokio::spawn(async move {
            server_handshake(VERSION, &mut reader, &mut writer, Some(&auth)).await
        });
        client
            .write_all(&[
                1,
                USER_PASS,
                AUTH_VERSION,
                4,
                b'u',
                b's',
                b'e',
                b'r',
                4,
                b'p',
                b'a',
                b's',
                b's',
                VERSION,
                CONNECT,
                0,
                1,
                127,
                0,
                0,
                1,
                0,
                53,
            ])
            .await
            .unwrap();
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [VERSION, USER_PASS]);
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [AUTH_VERSION, 0]);
        assert!(matches!(
            handshake.await.unwrap().unwrap(),
            Command::Connect(_)
        ));
    }
}
