//! Minimal ABI encoder for EVM contract calls.
//!
//! Supported types: `address`, `bool`, `uint<N>`, `int<N>`, `bytes<N>`
//! (fixed), `bytes` (dynamic), `string`.

use crate::crypto::{keccak256, parse_hex};

/// Encode an ABI function call as `selector ++ encoded_args`.
pub(crate) fn encode_function_call(abi: &str, args: &[String]) -> Result<Vec<u8>, String> {
    let (_, types) = parse_abi_sig(abi)?;
    if types.len() != args.len() {
        return Err(format!(
            "ABI signature has {} parameter(s) but {} arg(s) provided",
            types.len(),
            args.len()
        ));
    }
    let selector = abi_selector(abi)?;
    let values: Vec<AbiValue> = types
        .iter()
        .zip(args.iter())
        .map(|(ty, val)| encode_abi_arg(ty, val))
        .collect::<Result<Vec<_>, _>>()?;

    // Head: one 32-byte slot per argument (static value or dynamic offset).
    // Tail: dynamic data appended after the head.
    let head_size = values.len() * 32;
    let mut head = Vec::<u8>::with_capacity(head_size);
    let mut tail = Vec::<u8>::new();
    let mut dyn_offset = head_size;

    for value in &values {
        match value {
            AbiValue::Static(word) => head.extend_from_slice(word),
            AbiValue::Dynamic(data) => {
                let mut offset_word = [0u8; 32];
                let off_be = (dyn_offset as u64).to_be_bytes();
                offset_word[24..].copy_from_slice(&off_be);
                head.extend_from_slice(&offset_word);
                tail.extend_from_slice(data);
                dyn_offset += data.len();
            }
        }
    }

    let mut calldata = Vec::with_capacity(4 + head.len() + tail.len());
    calldata.extend_from_slice(&selector);
    calldata.extend_from_slice(&head);
    calldata.extend_from_slice(&tail);
    Ok(calldata)
}

// ── Internal ─────────────────────────────────────────────────────────────────

/// Strip leading/trailing whitespace from each comma-separated type token and
/// return `(function_name, [type, …])`.
fn parse_abi_sig(sig: &str) -> Result<(&str, Vec<&str>), String> {
    let open = sig.find('(').ok_or("ABI signature missing '('")?;
    let close = sig.rfind(')').ok_or("ABI signature missing ')'")?;
    if close < open {
        return Err("ABI signature: ')' appears before '('".into());
    }
    let name = sig[..open].trim();
    let inner = sig[open + 1..close].trim();
    let types = if inner.is_empty() {
        vec![]
    } else {
        inner.split(',').map(|t| t.trim()).collect()
    };
    Ok((name, types))
}

/// Compute the canonical signature string and return its 4-byte
/// keccak256 selector.
fn abi_selector(sig: &str) -> Result<[u8; 4], String> {
    let (name, types) = parse_abi_sig(sig)?;
    let canonical = format!("{}({})", name, types.join(","));
    let hash = keccak256(canonical.as_bytes());
    Ok([hash[0], hash[1], hash[2], hash[3]])
}

enum AbiValue {
    /// Occupies exactly one 32-byte slot in-place.
    Static([u8; 32]),
    /// Occupies a 32-byte offset slot in the head; length+data in the tail.
    Dynamic(Vec<u8>),
}

fn encode_abi_arg(ty: &str, value: &str) -> Result<AbiValue, String> {
    if ty == "address" {
        let bytes = parse_hex(value).map_err(|e| format!("address '{value}': {e}"))?;
        if bytes.len() != 20 {
            return Err(format!("address must be 20 bytes, got {}", bytes.len()));
        }
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(&bytes);
        return Ok(AbiValue::Static(word));
    }

    if ty == "bool" {
        let mut word = [0u8; 32];
        match value {
            "true" | "1" => word[31] = 1,
            "false" | "0" => {}
            _ => return Err(format!("invalid bool value '{value}'; use 'true' or 'false'")),
        }
        return Ok(AbiValue::Static(word));
    }

    if ty == "uint" || (ty.starts_with("uint") && ty[4..].chars().all(|c| c.is_ascii_digit())) {
        let word = decimal_str_to_u256(value).map_err(|e| format!("{ty} '{value}': {e}"))?;
        return Ok(AbiValue::Static(word));
    }

    if ty == "int" || (ty.starts_with("int") && ty[3..].chars().all(|c| c.is_ascii_digit())) {
        let word = decimal_str_to_i256(value).map_err(|e| format!("{ty} '{value}': {e}"))?;
        return Ok(AbiValue::Static(word));
    }

    if ty.starts_with("bytes") && ty != "bytes" {
        let n: usize = ty[5..]
            .parse()
            .map_err(|_| format!("invalid fixed bytes type '{ty}'"))?;
        if n == 0 || n > 32 {
            return Err(format!("bytes<N> must have 1 ≤ N ≤ 32, got '{ty}'"));
        }
        let bytes = parse_hex(value).map_err(|e| format!("{ty} '{value}': {e}"))?;
        if bytes.len() != n {
            return Err(format!(
                "{ty} expects exactly {n} bytes, got {} (value: '{value}')",
                bytes.len()
            ));
        }
        let mut word = [0u8; 32];
        word[..n].copy_from_slice(&bytes);
        return Ok(AbiValue::Static(word));
    }

    if ty == "bytes" {
        let bytes = parse_hex(value).map_err(|e| format!("bytes '{value}': {e}"))?;
        return Ok(AbiValue::Dynamic(abi_dynamic_bytes(&bytes)));
    }

    if ty == "string" {
        return Ok(AbiValue::Dynamic(abi_dynamic_bytes(value.as_bytes())));
    }

    Err(format!(
        "unsupported ABI type '{ty}'; supported: address, bool, uint<N>, int<N>, bytes<N>, bytes, string"
    ))
}

/// Encode a non-negative decimal (or 0x-hex) string as a big-endian
/// 256-bit word.
fn decimal_str_to_u256(s: &str) -> Result<[u8; 32], String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        let bytes = parse_hex(s)?;
        if bytes.len() > 32 {
            return Err("value overflows uint256".into());
        }
        let mut word = [0u8; 32];
        word[32 - bytes.len()..].copy_from_slice(&bytes);
        return Ok(word);
    }
    let mut word = [0u8; 32];
    for ch in s.chars() {
        if !ch.is_ascii_digit() {
            return Err(format!("invalid decimal character '{ch}'"));
        }
        let digit = ch as u32 - b'0' as u32;
        let mut carry = digit as u64;
        for byte in word.iter_mut().rev() {
            let val = (*byte as u64) * 10 + carry;
            *byte = (val & 0xff) as u8;
            carry = val >> 8;
        }
        if carry != 0 {
            return Err("value overflows uint256".into());
        }
    }
    Ok(word)
}

/// Encode a signed decimal string as a two's-complement big-endian 256-bit word.
fn decimal_str_to_i256(s: &str) -> Result<[u8; 32], String> {
    if let Some(magnitude) = s.strip_prefix('-') {
        let mag = decimal_str_to_u256(magnitude)?;
        let mut word: [u8; 32] = mag.map(|b| !b);
        let mut carry: u16 = 1;
        for byte in word.iter_mut().rev() {
            let val = *byte as u16 + carry;
            *byte = (val & 0xff) as u8;
            carry = val >> 8;
        }
        Ok(word)
    } else {
        decimal_str_to_u256(s)
    }
}

/// Encode a byte slice as ABI dynamic data:
/// `length_word ++ data_right_padded_to_32`.
fn abi_dynamic_bytes(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let padded_len = (len + 31) / 32 * 32;
    let mut out = Vec::with_capacity(32 + padded_len);
    let mut len_word = [0u8; 32];
    let len_be = (len as u64).to_be_bytes();
    len_word[24..].copy_from_slice(&len_be);
    out.extend_from_slice(&len_word);
    out.extend_from_slice(data);
    out.extend(std::iter::repeat(0u8).take(padded_len - len));
    out
}
