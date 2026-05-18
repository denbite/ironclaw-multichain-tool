/// Parse a non-negative decimal-SOL string into lamports (1 SOL = 1e9 lamports).
/// Up to 9 fractional digits supported (1-lamport precision); more is rejected.
pub(crate) fn parse_value(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("amount_sol: empty string".into());
    }
    if s.starts_with('-') {
        return Err("amount_sol: must be non-negative".into());
    }

    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };

    if !int_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("amount_sol: invalid integer part '{int_part}'"));
    }
    if !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("amount_sol: invalid fractional part '{frac_part}'"));
    }
    if frac_part.len() > 9 {
        return Err(format!(
            "amount_sol: too many fractional digits ({}); max 9 (1-lamport precision)",
            frac_part.len()
        ));
    }

    let pad = 9 - frac_part.len();
    let mut decimal = String::with_capacity(int_part.len() + 9);
    if int_part.is_empty() {
        decimal.push('0');
    } else {
        decimal.push_str(int_part);
    }
    decimal.push_str(frac_part);
    for _ in 0..pad {
        decimal.push('0');
    }

    let trimmed = decimal.trim_start_matches('0');
    if trimmed.is_empty() {
        return Ok(0);
    }
    trimmed
        .parse::<u64>()
        .map_err(|_| format!("amount_sol: overflow ({trimmed} lamports exceeds u64)"))
}
