//! Bitcoin script encoding helpers.
//!
//! Note: Bitcoin convention uses bare hex (no `0x` prefix) throughout this
//! module. This diverges from the EVM module (arch doc §7).

use crate::crypto::{base58_decode, bech32_decode, sha256d};

pub(crate) fn varint(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

fn base58check_decode(addr: &str) -> Result<(u8, [u8; 20]), String> {
    let bytes = base58_decode(addr)?;
    if bytes.len() != 25 {
        return Err(format!(
            "base58check: expected 25 bytes, got {}",
            bytes.len()
        ));
    }
    let (payload, checksum) = bytes.split_at(21);
    let expected = &sha256d(payload)[..4];
    if checksum != expected {
        return Err("base58check: invalid checksum".into());
    }
    let hash: [u8; 20] = payload[1..].try_into().unwrap();
    Ok((payload[0], hash))
}

/// Extract the 20-byte pubkey hash from a P2WPKH bech32 address.
/// Errors on wrong network, wrong witness version, or non-P2WPKH program length.
pub(crate) fn p2wpkh_pubkey_hash(addr: &str, mainnet: bool) -> Result<[u8; 20], String> {
    let (hrp, version, program) = bech32_decode(addr)
        .map_err(|e| format!("invalid bech32 address '{addr}': {e}"))?;
    let expected_hrp = if mainnet { "bc" } else { "tb" };
    if hrp != expected_hrp {
        return Err(format!(
            "bech32 HRP '{hrp}' does not match network (expected '{expected_hrp}')"
        ));
    }
    if version != 0 {
        return Err(format!("unsupported witness version {version}; only P2WPKH (v0) is supported"));
    }
    if program.len() != 20 {
        return Err(format!(
            "address is not P2WPKH: witness program is {} bytes, expected 20",
            program.len()
        ));
    }
    Ok(program.try_into().unwrap())
}

pub(crate) fn address_to_script(addr: &str, mainnet: bool) -> Result<Vec<u8>, String> {
    if let Ok((hrp, version, program)) = bech32_decode(addr) {
        let expected_hrp = if mainnet { "bc" } else { "tb" };
        if hrp != expected_hrp {
            return Err(format!(
                "bech32 HRP '{hrp}' does not match network (expected '{expected_hrp}')"
            ));
        }
        if version != 0 {
            return Err(format!("unsupported witness version {version}"));
        }
        if program.len() == 20 {
            let mut script = vec![0x00, 0x14];
            script.extend_from_slice(&program);
            return Ok(script);
        }
        if program.len() == 32 {
            let mut script = vec![0x00, 0x20];
            script.extend_from_slice(&program);
            return Ok(script);
        }
        return Err(format!(
            "unsupported witness program length {}",
            program.len()
        ));
    }

    let (version, hash) = base58check_decode(addr)?;
    let script = match version {
        0x00 | 0x6f => {
            let mut s = vec![0x76, 0xa9, 0x14];
            s.extend_from_slice(&hash);
            s.push(0x88);
            s.push(0xac);
            s
        }
        0x05 | 0xc4 => {
            let mut s = vec![0xa9, 0x14];
            s.extend_from_slice(&hash);
            s.push(0x87);
            s
        }
        v => return Err(format!("unsupported base58check version byte 0x{v:02x}")),
    };
    Ok(script)
}
