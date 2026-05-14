//! Decimal-BTC-string → integer satoshis.
//!
//! Bitcoin has 8 decimal places (1 BTC = 100_000_000 sats, 1-sat precision).

/// Parse a non-negative decimal-BTC string (e.g. `"0.001"`, `"1.5"`) into satoshis.
pub(crate) fn btc_decimal_to_sats(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("btc: empty string".into());
    }
    if s.starts_with('-') {
        return Err("btc: must be non-negative".into());
    }

    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };

    if !int_part.is_empty() && !int_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("btc: invalid integer part '{int_part}'"));
    }
    if !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("btc: invalid fractional part '{frac_part}'"));
    }
    if frac_part.len() > 8 {
        return Err(format!(
            "btc: too many fractional digits ({}); max 8 (1-sat precision)",
            frac_part.len()
        ));
    }

    // Build integer sat string: <int><frac><pad-to-8-zeros>
    let pad = 8 - frac_part.len();
    let mut sat_str = String::with_capacity(int_part.len() + 8);
    if int_part.is_empty() {
        sat_str.push('0');
    } else {
        sat_str.push_str(int_part);
    }
    sat_str.push_str(frac_part);
    for _ in 0..pad {
        sat_str.push('0');
    }

    let trimmed = sat_str.trim_start_matches('0');
    if trimmed.is_empty() {
        return Ok(0);
    }
    trimmed
        .parse::<u64>()
        .map_err(|_| format!("btc: overflow ({trimmed} sats exceeds u64)"))
}
