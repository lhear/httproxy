use std::net::IpAddr;

const OPT_TYPE: u16 = 41;
const ECS_CODE: u16 = 8;
const FAMILY_V4: u16 = 1;
const FAMILY_V6: u16 = 2;
const PREFIX_V4: u8 = 24;
const PREFIX_V6: u8 = 56;
const EDNS_PAYLOAD: u16 = 1232;

pub(crate) fn rewrite(query: &[u8], ecs: Option<IpAddr>) -> Option<Vec<u8>> {
    if query.len() < 12 || query.len() > usize::from(u16::MAX) {
        return None;
    }
    let questions = usize::from(u16::from_be_bytes([query[4], query[5]]));
    if questions == 0 || query[6..10] != [0, 0, 0, 0] {
        return None;
    }
    let additional = usize::from(u16::from_be_bytes([query[10], query[11]]));

    let mut pos = 12;
    for _ in 0..questions {
        pos = skip_name(query, pos)?;
        pos = pos.checked_add(4)?;
        if pos > query.len() {
            return None;
        }
    }

    let mut opt = None;
    for _ in 0..additional {
        let name_end = skip_name(query, pos)?;
        let rdata = name_end.checked_add(10)?;
        if rdata > query.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([query[name_end], query[name_end + 1]]);
        let rdlen = usize::from(u16::from_be_bytes([
            query[name_end + 8],
            query[name_end + 9],
        ]));
        let end = rdata.checked_add(rdlen)?;
        if end > query.len() {
            return None;
        }
        if rtype == OPT_TYPE && opt.is_none() {
            opt = Some((name_end + 8, rdata, end));
        }
        pos = end;
    }

    match (opt, ecs) {
        (Some((rdlen_pos, rdata, end)), Some(ip)) => {
            let option = encode_option(ip);
            let mut out = query.to_vec();
            match find_option(query, rdata, end)? {
                Some((start, stop)) => out.splice(start..stop, option),
                None => out.splice(end..end, option),
            };
            set_rdlen(&mut out, query.len(), rdlen_pos, rdata, end)?;
            Some(out)
        }
        (Some((rdlen_pos, rdata, end)), None) => {
            let (start, stop) = find_option(query, rdata, end)??;
            let mut out = query.to_vec();
            out.splice(start..stop, []);
            set_rdlen(&mut out, query.len(), rdlen_pos, rdata, end)?;
            Some(out)
        }
        (None, Some(ip)) => {
            if pos != query.len() || additional == usize::from(u16::MAX) {
                return None;
            }
            let option = encode_option(ip);
            let mut out = query.to_vec();
            out.push(0);
            out.extend_from_slice(&OPT_TYPE.to_be_bytes());
            out.extend_from_slice(&EDNS_PAYLOAD.to_be_bytes());
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&u16::try_from(option.len()).ok()?.to_be_bytes());
            out.extend_from_slice(&option);
            out[10..12].copy_from_slice(&u16::try_from(additional + 1).ok()?.to_be_bytes());
            Some(out)
        }
        (None, None) => None,
    }
}

fn set_rdlen(
    out: &mut [u8],
    old_len: usize,
    rdlen_pos: usize,
    rdata: usize,
    end: usize,
) -> Option<()> {
    let delta = out.len() as isize - old_len as isize;
    let new_end = (end as isize + delta) as usize;
    let rdlen = u16::try_from(new_end.checked_sub(rdata)?).ok()?;
    out.get_mut(rdlen_pos..rdlen_pos + 2)?
        .copy_from_slice(&rdlen.to_be_bytes());
    Some(())
}

fn find_option(msg: &[u8], mut pos: usize, end: usize) -> Option<Option<(usize, usize)>> {
    while pos < end {
        let header = pos.checked_add(4)?;
        if header > end {
            return None;
        }
        let code = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let len = usize::from(u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]));
        let next = header.checked_add(len)?;
        if next > end {
            return None;
        }
        if code == ECS_CODE {
            return Some(Some((pos, next)));
        }
        pos = next;
    }
    (pos == end).then_some(None)
}

fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = usize::from(*msg.get(pos)?);
        match len & 0xC0 {
            0x00 => {
                pos += 1;
                if len == 0 {
                    return Some(pos);
                }
                pos = pos.checked_add(len)?;
                if pos > msg.len() {
                    return None;
                }
            }
            0xC0 => return (pos + 2 <= msg.len()).then_some(pos + 2),
            _ => return None,
        }
    }
}

fn encode_option(ip: IpAddr) -> Vec<u8> {
    let (family, prefix, octets) = match ip {
        IpAddr::V4(v4) => (FAMILY_V4, PREFIX_V4, v4.octets().to_vec()),
        IpAddr::V6(v6) => (FAMILY_V6, PREFIX_V6, v6.octets().to_vec()),
    };
    let address_len = usize::from(prefix).div_ceil(8);
    let mut option = Vec::with_capacity(8 + address_len);
    option.extend_from_slice(&ECS_CODE.to_be_bytes());
    option.extend_from_slice(
        &u16::try_from(4 + address_len)
            .unwrap_or_default()
            .to_be_bytes(),
    );
    option.extend_from_slice(&family.to_be_bytes());
    option.push(prefix);
    option.push(0);
    option.extend_from_slice(&octets[..address_len]);
    option
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn question() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[7]);
        out.extend_from_slice(b"example");
        out.extend_from_slice(&[3]);
        out.extend_from_slice(b"com");
        out.push(0);
        out.extend_from_slice(&[0, 1, 0, 1]);
        out
    }

    fn query(options: &[u8], with_opt: bool) -> Vec<u8> {
        let body = question();
        let mut out = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0];
        out.extend_from_slice(&[0, u8::from(with_opt)]);
        out.extend_from_slice(&body);
        if with_opt {
            out.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0]);
            out.extend_from_slice(&u16::try_from(options.len()).unwrap().to_be_bytes());
            out.extend_from_slice(options);
        }
        out
    }

    fn option(code: u16, data: &[u8]) -> Vec<u8> {
        let mut out = code.to_be_bytes().to_vec();
        out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn ecs_option(prefix: u8, address: &[u8]) -> Vec<u8> {
        let family: u16 = if prefix > 32 { 2 } else { 1 };
        let mut data = family.to_be_bytes().to_vec();
        data.extend_from_slice(&[prefix, 0]);
        data.extend_from_slice(address);
        option(ECS_CODE, &data)
    }

    #[test]
    fn adds_an_opt_record_with_the_configured_subnet() {
        let original = query(&[], false);
        let out = rewrite(&original, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))).unwrap();

        let mut expected = original.clone();
        expected[11] = 1;
        expected.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0]);
        expected.extend_from_slice(&[0, 11]);
        expected.extend_from_slice(&ecs_option(24, &[1, 2, 3]));
        assert_eq!(out, expected);

        let out = rewrite(
            &original,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        )
        .unwrap();
        assert!(out.ends_with(&ecs_option(56, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0])));
    }

    #[test]
    fn replaces_an_existing_ecs() {
        let old = ecs_option(24, &[8, 8, 8]);
        let original = query(&old, true);
        let out = rewrite(&original, Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))).unwrap();

        let new = ecs_option(24, &[1, 1, 1]);
        assert_eq!(out.len(), original.len());
        assert!(out.windows(new.len()).any(|w| w == new.as_slice()));
        assert!(!out.windows(old.len()).any(|w| w == old.as_slice()));
        assert_eq!(&out[..38], &original[..38]);
    }

    #[test]
    fn removes_ecs_only_when_one_is_present() {
        let mut options = option(10, &[1, 2, 3, 4]);
        options.extend_from_slice(&ecs_option(24, &[8, 8, 8]));
        let original = query(&options, true);
        let out = rewrite(&original, None).unwrap();

        let cookie = option(10, &[1, 2, 3, 4]);
        let mut expected = query(&cookie, true);
        expected[38..40].copy_from_slice(&u16::try_from(cookie.len()).unwrap().to_be_bytes());
        assert_eq!(out, expected);

        assert!(rewrite(&query(&[], false), None).is_none());
        assert!(rewrite(&query(&cookie, true), None).is_none());
    }

    #[test]
    fn ignores_malformed_messages() {
        assert!(rewrite(&[0u8; 11], Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))).is_none());

        let mut truncated = query(&[], false);
        truncated.truncate(20);
        assert!(rewrite(&truncated, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))).is_none());

        let mut bad_opt = query(&option(10, &[1, 2]), true);
        let last = bad_opt.len() - 1;
        bad_opt.truncate(last);
        assert!(rewrite(&bad_opt, None).is_none());
    }
}
