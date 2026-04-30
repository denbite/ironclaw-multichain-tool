//! Decimal-ETH-string → minimal big-endian wei bytes.
//!
//! The EVM API accepts ETH amounts as decimal strings (e.g. `"0.001"`,
//! `"1.5"`) rather than `f64` to avoid floating-point precision loss. This
//! module performs the conversion. Up to 18 fractional digits are supported
//! (1-wei precision); more is rejected.

/// Parse a non-negative decimal-ETH string into its wei value as minimal
/// big-endian bytes (`vec![]` represents zero).
pub(crate) fn eth_decimal_to_wei_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("value_eth: empty string".into());
    }
    if s.starts_with('-') {
        return Err("value_eth: must be non-negative".into());
    }

    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };

    if !int_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("value_eth: invalid integer part '{int_part}'"));
    }
    if !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("value_eth: invalid fractional part '{frac_part}'"));
    }
    if frac_part.len() > 18 {
        return Err(format!(
            "value_eth: too many fractional digits ({}); max 18 (1-wei precision)",
            frac_part.len()
        ));
    }

    // Build the decimal-wei string: <int><frac><pad-to-18-zeros>
    let pad = 18 - frac_part.len();
    let mut wei_decimal = String::with_capacity(int_part.len() + 18);
    if int_part.is_empty() {
        wei_decimal.push('0');
    } else {
        wei_decimal.push_str(int_part);
    }
    wei_decimal.push_str(frac_part);
    for _ in 0..pad {
        wei_decimal.push('0');
    }

    let trimmed = wei_decimal.trim_start_matches('0');
    if trimmed.is_empty() {
        return Ok(vec![]);
    }
    let wei: u128 = trimmed
        .parse()
        .map_err(|_| format!("value_eth: overflow ({trimmed} wei exceeds u128)"))?;

    if wei == 0 {
        return Ok(vec![]);
    }
    let bytes = wei.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
    Ok(bytes[start..].to_vec())
}
