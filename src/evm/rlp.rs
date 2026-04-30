//! Minimal RLP (Recursive Length Prefix) codec for EIP-1559 transactions.
//!
//! Reference: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
//!
//! All helpers are `pub(crate)` — the public EVM API surface lives in `mod.rs`.

/// Encode a u64 as a big-endian RLP integer.
pub(crate) fn rlp_u64(n: u64) -> Vec<u8> {
    if n == 0 {
        return vec![0x80];
    }
    if n < 0x80 {
        return vec![n as u8];
    }
    rlp_uint_bytes(&minimal_be_u64(n))
}

/// Encode a non-negative integer (given as minimal big-endian bytes) as RLP.
/// Empty input → 0x80 (zero).
pub(crate) fn rlp_uint_bytes(b: &[u8]) -> Vec<u8> {
    let b = strip_leading_zeros(b);
    if b.is_empty() {
        return vec![0x80];
    }
    if b.len() == 1 && b[0] < 0x80 {
        return vec![b[0]];
    }
    rlp_bytes(b)
}

/// Encode a byte string as RLP.
pub(crate) fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    let len = b.len();
    if len == 1 && b[0] < 0x80 {
        return vec![b[0]];
    }
    let mut out = encode_length(len, 0x80);
    out.extend_from_slice(b);
    out
}

/// Encode a 20-byte Ethereum address as RLP (always 21 bytes: 0x94 prefix + 20 bytes).
pub(crate) fn rlp_address(a: &[u8; 20]) -> Vec<u8> {
    let mut out = vec![0x94];
    out.extend_from_slice(a);
    out
}

/// Encode a list of pre-encoded RLP items as a single RLP list.
pub(crate) fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    let mut out = encode_length(payload.len(), 0xc0);
    out.extend_from_slice(&payload);
    out
}

/// Strip leading zero bytes from a slice.
pub(crate) fn strip_leading_zeros(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

/// Read a single RLP item starting at `pos` in `data`; return
/// `(item_slice_including_header, next_pos)`.
pub(crate) fn read_item(data: &[u8], pos: usize) -> Result<(&[u8], usize), String> {
    if pos >= data.len() {
        return Err(format!(
            "RLP: position {pos} out of bounds (len={})",
            data.len()
        ));
    }
    let first = data[pos];
    let end = if first < 0x80 {
        pos + 1
    } else if first <= 0xb7 {
        pos + 1 + (first - 0x80) as usize
    } else if first <= 0xbf {
        let len_bytes = (first - 0xb7) as usize;
        let payload_len = read_usize(data, pos + 1, len_bytes)?;
        pos + 1 + len_bytes + payload_len
    } else if first <= 0xf7 {
        pos + 1 + (first - 0xc0) as usize
    } else {
        let len_bytes = (first - 0xf7) as usize;
        let payload_len = read_usize(data, pos + 1, len_bytes)?;
        pos + 1 + len_bytes + payload_len
    };
    if end > data.len() {
        return Err("RLP: item extends past buffer".into());
    }
    Ok((&data[pos..end], end))
}

// ── Private helpers ──────────────────────────────────────────────────────────

fn minimal_be_u64(n: u64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }
    let bytes = n.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[start..].to_vec()
}

fn minimal_be_usize(n: usize) -> Vec<u8> {
    let bytes = (n as u64).to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[start..].to_vec()
}

fn encode_length(len: usize, offset: u8) -> Vec<u8> {
    if len < 56 {
        vec![offset + len as u8]
    } else {
        let len_bytes = minimal_be_usize(len);
        let mut out = vec![offset + 55 + len_bytes.len() as u8];
        out.extend_from_slice(&len_bytes);
        out
    }
}

fn read_usize(data: &[u8], pos: usize, len: usize) -> Result<usize, String> {
    if pos + len > data.len() {
        return Err("RLP: length field extends past buffer".into());
    }
    let mut n: usize = 0;
    for i in 0..len {
        n = (n << 8) | data[pos + i] as usize;
    }
    Ok(n)
}
