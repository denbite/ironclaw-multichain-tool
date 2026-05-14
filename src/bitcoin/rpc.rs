//! HTTP I/O for Bitcoin: mempool.space fee-rate, UTXO lookup, and broadcast.

/// Fetch the recommended fee rate (sat/vbyte) from mempool.space.
/// Tries 6-block target first; falls back to longer horizons; testnet falls back to 1.
pub(crate) fn fetch_fee_rate(
    mainnet: bool,
    http: &impl Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
) -> Result<u64, String> {
    let url = if mainnet {
        "https://mempool.space/api/fee-estimates"
    } else {
        "https://mempool.space/testnet4/api/fee-estimates"
    };

    let (status, body) = http("GET", url, "{}", None)?;
    if status < 200 || status >= 300 {
        return Err(format!("fee-estimates failed with status {status}"));
    }

    let estimates: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| format!("invalid fee-estimates response: {e}"))?;

    for target in &["6", "3", "1", "10", "20", "144", "504", "1008"] {
        if let Some(rate) = estimates[target].as_f64() {
            return Ok((rate.ceil() as u64).max(1));
        }
    }

    // Testnet4 mempool is often empty — fall back to minimum relay fee
    if !mainnet {
        return Ok(1);
    }

    Err("no usable fee estimate in mempool.space response".into())
}

/// Fetch all UTXOs for a Bitcoin address from mempool.space.
/// Returns them sorted largest-first.
pub(crate) fn fetch_utxos(
    address: &str,
    mainnet: bool,
    http: &impl Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
) -> Result<Vec<super::BtcUtxo>, String> {
    let url = if mainnet {
        format!("https://mempool.space/api/address/{address}/utxo")
    } else {
        format!("https://mempool.space/testnet4/api/address/{address}/utxo")
    };

    let (status, body) = http("GET", &url, "{}", None)?;
    if status < 200 || status >= 300 {
        return Err(format!("UTXO fetch failed with status {status}"));
    }

    let raw: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| format!("invalid UTXO response: {e}"))?;

    let arr = raw
        .as_array()
        .ok_or_else(|| "UTXO response is not a JSON array".to_string())?;

    let mut utxos: Vec<super::BtcUtxo> = arr
        .iter()
        .map(|u| {
            let txid = u["txid"].as_str().ok_or("missing txid")?.to_string();
            let vout = u["vout"].as_u64().ok_or("missing vout")? as u32;
            let amount_sats = u["value"].as_u64().ok_or("missing value")?;
            let confirmed = u["status"]["confirmed"].as_bool().unwrap_or(false);
            Ok(super::BtcUtxo { txid, vout, amount_sats, confirmed })
        })
        .collect::<Result<Vec<_>, String>>()?;

    // Largest first
    utxos.sort_by(|a, b| b.amount_sats.cmp(&a.amount_sats));
    Ok(utxos)
}

/// Broadcast a signed segwit transaction via mempool.space.
/// `signed_tx_hex` must be bare hex (no `0x` prefix).
/// Returns the txid hex string from the API.
pub(crate) fn broadcast(
    signed_tx_hex: &str,
    mainnet: bool,
    http: &impl Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
) -> Result<String, String> {
    let url = if mainnet {
        "https://mempool.space/api/tx"
    } else {
        "https://mempool.space/testnet4/api/tx"
    };

    let (status, resp_body) = http(
        "POST",
        url,
        r#"{"Content-Type":"text/plain"}"#,
        Some(signed_tx_hex.as_bytes().to_vec()),
    )?;

    if status < 200 || status >= 300 {
        return Err(format!(
            "broadcast failed with status {}: {}",
            status,
            String::from_utf8_lossy(&resp_body)
        ));
    }

    String::from_utf8(resp_body)
        .map(|s| s.trim().to_string())
        .map_err(|_| "broadcast returned non-UTF8 response".to_string())
}
