use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

// ── Hashing ───────────────────────────────────────────────────────────────────

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    let mut out = [0u8; 32];
    h.update(data);
    h.finalize(&mut out);
    out
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// RIPEMD160(SHA256(data)) — used for Bitcoin addresses
pub fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(data)).into()
}

// ── NEAR secp256k1 public key ─────────────────────────────────────────────────
//
// Format: "secp256k1:<base58_of_64_bytes>"
// The 64 bytes are the uncompressed (x ‖ y) without the 0x04 prefix.

pub fn parse_near_secp256k1_pubkey(s: &str) -> Result<[u8; 64], String> {
    let data = s
        .strip_prefix("secp256k1:")
        .ok_or("public key must start with 'secp256k1:'")?;
    let bytes = base58_decode(data)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("expected 64-byte secp256k1 key, got {len} bytes"))
}

/// Compress a 64-byte uncompressed (x ‖ y) key to 33 bytes.
pub fn compress_pubkey(xy: &[u8; 64]) -> [u8; 33] {
    let mut out = [0u8; 33];
    // Even y → 0x02, odd y → 0x03  (y is big-endian, parity from last byte)
    out[0] = if xy[63] & 1 == 0 { 0x02 } else { 0x03 };
    out[1..].copy_from_slice(&xy[..32]); // x coordinate
    out
}

/// Derive the 20-byte Ethereum address from the uncompressed (x ‖ y) key.
pub fn eth_address(xy: &[u8; 64]) -> [u8; 20] {
    keccak256(xy)[12..].try_into().unwrap()
}

// ── Bitcoin address helpers ───────────────────────────────────────────────────

/// Encode a P2WPKH address from a compressed public key.
pub fn p2wpkh_address(pubkey_compressed: &[u8; 33], mainnet: bool) -> String {
    let program = hash160(pubkey_compressed);
    let hrp = if mainnet { "bc" } else { "tb" };
    bech32_encode(hrp, 0, &program)
}

// ── DER ECDSA encoding ────────────────────────────────────────────────────────

/// DER-encode (r, s) and append SIGHASH_ALL (0x01) for use in Bitcoin witness.
pub fn der_encode_ecdsa(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let re = der_int(r);
    let se = der_int(s);
    let inner = 2 + re.len() + 2 + se.len();
    let mut out = Vec::with_capacity(inner + 6);
    out.push(0x30);
    out.push(inner as u8);
    out.push(0x02);
    out.push(re.len() as u8);
    out.extend_from_slice(&re);
    out.push(0x02);
    out.push(se.len() as u8);
    out.extend_from_slice(&se);
    out.push(0x01); // SIGHASH_ALL
    out
}

fn der_int(bytes: &[u8; 32]) -> Vec<u8> {
    let trimmed: Vec<u8> = bytes.iter().copied().skip_while(|&b| b == 0).collect();
    if trimmed.is_empty() {
        return vec![0x00];
    }
    if trimmed[0] & 0x80 != 0 {
        let mut out = vec![0x00];
        out.extend_from_slice(&trimmed);
        out
    } else {
        trimmed
    }
}

// ── Signature JSON serde helper ───────────────────────────────────────────────
//
// `signature_json` fields in Reconstruct* inputs may arrive either as a plain
// JSON string (the agent explicitly stringified the object) or as a nested JSON
// object (the agent passed the raw MPC response directly).  Both are valid;
// this helper normalises to a String so the rest of the code stays unchanged.

pub fn deser_sig_json<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    use serde::Deserialize as _;
    let v = serde_json::Value::deserialize(deserializer)?;
    match v {
        serde_json::Value::String(s) => Ok(s),
        other => serde_json::to_string(&other).map_err(D::Error::custom),
    }
}

// ── MPC signature parsing ─────────────────────────────────────────────────────

pub struct MpcSig {
    /// x-coordinate of ephemeral point R (32 bytes)
    pub r: [u8; 32],
    /// scalar s (32 bytes)
    pub s: [u8; 32],
    /// y_parity for EIP-1559: 0 if R.y is even, 1 if odd
    pub y_parity: u8,
}

/// Parse a `SignatureResponse` JSON returned by the MPC contract.
///
/// Expected shape:
/// ```json
/// {"scheme":"Secp256k1","big_r":{"affine_point":"<hex33>"},"s":{"scalar":"<hex32>"},"recovery_id":0}
/// ```
pub fn parse_mpc_sig(json: &str) -> Result<MpcSig, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("invalid signature JSON: {e}"))?;

    let big_r_hex = v["big_r"]["affine_point"]
        .as_str()
        .ok_or("missing big_r.affine_point")?;
    let s_hex = v["s"]["scalar"].as_str().ok_or("missing s.scalar")?;

    let big_r_bytes =
        hex::decode(big_r_hex).map_err(|e| format!("invalid big_r hex: {e}"))?;
    if big_r_bytes.len() != 33 {
        return Err(format!(
            "big_r must be 33 bytes, got {}",
            big_r_bytes.len()
        ));
    }

    let s_bytes = hex::decode(s_hex).map_err(|e| format!("invalid s hex: {e}"))?;
    if s_bytes.len() != 32 {
        return Err(format!("s must be 32 bytes, got {}", s_bytes.len()));
    }

    // r = x-coordinate of R = bytes 1..33 of the compressed point
    let r: [u8; 32] = big_r_bytes[1..33].try_into().unwrap();
    let s: [u8; 32] = s_bytes.try_into().unwrap();
    // 0x02 → even y → parity 0;  0x03 → odd y → parity 1
    let y_parity = if big_r_bytes[0] == 0x03 { 1 } else { 0 };

    Ok(MpcSig { r, s, y_parity })
}

// ── Hex helpers ───────────────────────────────────────────────────────────────

/// Decode a hex string (optional 0x prefix) into bytes.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    hex::decode(s).map_err(|e| format!("hex decode error: {e}"))
}

/// Parse a 20-byte Ethereum address from a "0x…"-prefixed hex string.
pub fn parse_eth_address(s: &str) -> Result<[u8; 20], String> {
    let bytes = parse_hex(s)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("expected 20-byte Ethereum address, got {len} bytes"))
}

/// Strip 0x prefix and return the minimal big-endian byte encoding of the
/// integer (no leading zero bytes).  "0x0" / "0x" / "" → empty vec (= zero).
pub fn parse_hex_uint(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.is_empty() || s.chars().all(|c| c == '0') {
        return Ok(vec![]);
    }
    let padded = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    let bytes = hex::decode(&padded).map_err(|e| format!("hex decode error: {e}"))?;
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    Ok(bytes[start..].to_vec())
}

// ── MPC Ed25519 signature parsing ─────────────────────────────────────────────

/// Parse a `SignatureResponse` JSON returned by the MPC contract for ed25519.
///
/// Expected shape:
/// ```json
/// {"scheme":"Ed25519","signature":[107,187,...]}
/// ```
/// The `signature` array is 64 bytes: R (32) ‖ S (32).
pub fn parse_mpc_ed25519_sig(json: &str) -> Result<[u8; 64], String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("invalid signature JSON: {e}"))?;

    let arr = v["signature"]
        .as_array()
        .ok_or("missing 'signature' array in Ed25519 response")?;

    if arr.len() != 64 {
        return Err(format!("Ed25519 signature must be 64 bytes, got {}", arr.len()));
    }

    let mut out = [0u8; 64];
    for (i, val) in arr.iter().enumerate() {
        out[i] = val
            .as_u64()
            .ok_or_else(|| format!("signature[{i}] is not a number"))? as u8;
    }
    Ok(out)
}

// ── Base58 ────────────────────────────────────────────────────────────────────

const BASE58_ALPHA: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn base58_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut n: Vec<u8> = vec![0];
    for &c in s.as_bytes() {
        let digit = BASE58_ALPHA
            .iter()
            .position(|&b| b == c)
            .ok_or_else(|| format!("invalid base58 character: '{}'", c as char))?
            as u32;
        // n = n * 58 + digit
        let mut carry = digit;
        for byte in n.iter_mut().rev() {
            let val = (*byte as u32) * 58 + carry;
            *byte = (val & 0xff) as u8;
            carry = val >> 8;
        }
        while carry > 0 {
            n.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Leading '1' characters in base58 represent leading zero bytes
    let leading_zeros = s.bytes().take_while(|&b| b == b'1').count();
    let mut result = vec![0u8; leading_zeros];
    let start = n.iter().position(|&b| b != 0).unwrap_or(n.len());
    result.extend_from_slice(&n[start..]);
    Ok(result)
}

pub fn base58_encode(bytes: &[u8]) -> String {
    // Count leading zero bytes → each maps to a leading '1'
    let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();

    // Treat bytes as a big-endian integer; divide repeatedly by 58
    let mut n: Vec<u8> = bytes.to_vec();
    let mut digits: Vec<u8> = Vec::new();

    // Keep dividing n by 58
    while n.iter().any(|&b| b != 0) {
        let mut remainder: u32 = 0;
        for byte in n.iter_mut() {
            let val = remainder * 256 + *byte as u32;
            *byte = (val / 58) as u8;
            remainder = val % 58;
        }
        digits.push(remainder as u8);
        // Trim leading zeros from n
        let start = n.iter().position(|&b| b != 0).unwrap_or(n.len());
        n = n[start..].to_vec();
    }

    let mut result = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        result.push('1');
    }
    for &d in digits.iter().rev() {
        result.push(BASE58_ALPHA[d as usize] as char);
    }
    result
}

// ── Bech32 ────────────────────────────────────────────────────────────────────
//
// Implements BIP173 bech32 (segwit v0 — P2WPKH / P2WSH).
// Note: segwit v1+ (taproot) uses bech32m — not needed here.

const BECH32_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn bech32_polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let b = (chk >> 25) as u8;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for i in 0..5usize {
            if (b >> i) & 1 != 0 {
                chk ^= BECH32_GEN[i];
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for c in hrp.bytes() {
        out.push(c >> 5);
    }
    out.push(0);
    for c in hrp.bytes() {
        out.push(c & 0x1f);
    }
    out
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, String> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let maxv = (1u32 << to) - 1;
    for &v in data {
        if (v as u32) >> from != 0 {
            return Err("convert_bits: value out of range".to_string());
        }
        acc = (acc << from) | v as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err("invalid bech32 padding".to_string());
    }
    Ok(out)
}

/// Encode a segwit v0 address (bech32).
pub fn bech32_encode(hrp: &str, version: u8, program: &[u8]) -> String {
    let mut data = vec![version];
    data.extend(convert_bits(program, 8, 5, true).unwrap());

    let mut check_input = bech32_hrp_expand(hrp);
    check_input.extend_from_slice(&data);
    check_input.extend_from_slice(&[0u8; 6]);
    let checksum = bech32_polymod(&check_input) ^ 1;

    let mut result = format!("{}1", hrp);
    for &d in &data {
        result.push(BECH32_CHARSET[d as usize] as char);
    }
    for i in 0..6usize {
        result.push(BECH32_CHARSET[((checksum >> (5 * (5 - i))) & 31) as usize] as char);
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eth_address_from_near_pubkey() {
        let pubkey = "secp256k1:3S3g3cgFXSos7YEEr3Z4EttPRFkrxUJsyYV4Ge5HwdMyMo8ur6D3TUxy2QDtD6grFbcLS55V9sXVhg3NDQ6xV8ss";
        let xy = parse_near_secp256k1_pubkey(pubkey).unwrap();
        let addr = eth_address(&xy);
        assert_eq!(
            format!("0x{}", hex::encode(addr)),
            "0x1a3e6cc60d9a2cca864d4be4c75189de7528a3c4",
        );
    }
}

/// Decode a bech32 address. Returns `(hrp, witness_version, witness_program)`.
pub fn bech32_decode(addr: &str) -> Result<(String, u8, Vec<u8>), String> {
    let addr = addr.to_lowercase();
    let sep = addr
        .rfind('1')
        .ok_or("no '1' separator in bech32 address")?;
    if sep == 0 {
        return Err("bech32: empty HRP".to_string());
    }
    let hrp = &addr[..sep];
    let data_str = &addr[sep + 1..];
    if data_str.len() < 7 {
        // at least witness_version + 1 data byte + 6 checksum chars
        return Err("bech32 data too short".to_string());
    }

    let mut data = Vec::new();
    for c in data_str.bytes() {
        let pos = BECH32_CHARSET
            .iter()
            .position(|&b| b == c)
            .ok_or_else(|| format!("invalid bech32 char: '{}'", c as char))?;
        data.push(pos as u8);
    }

    let mut chk_input = bech32_hrp_expand(hrp);
    chk_input.extend_from_slice(&data);
    if bech32_polymod(&chk_input) != 1 {
        return Err("invalid bech32 checksum".to_string());
    }

    let version = data[0];
    let payload_len = data.len() - 6; // strip 6 checksum chars
    let program = convert_bits(&data[1..payload_len], 5, 8, false)?;

    Ok((hrp.to_string(), version, program))
}
