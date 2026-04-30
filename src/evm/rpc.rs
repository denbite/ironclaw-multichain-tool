//! HTTP I/O for EVM JSON-RPC.
//!
//! All `chain_id → RPC URL` resolution and `eth_*` method dispatch lives
//! here. Pure helpers for hex/integer conversion sit alongside because
//! they're consumed almost exclusively by the RPC parsers.

/// Map a numeric EVM chain_id to its public JSON-RPC endpoint.
pub(crate) fn rpc_url_for_chain(chain_id: u64) -> Result<&'static str, String> {
    match chain_id {
        1 => Ok("https://eth.llamarpc.com"),
        10 => Ok("https://mainnet.optimism.io"),
        8453 => Ok("https://mainnet.base.org"),
        42161 => Ok("https://arb1.arbitrum.io/rpc"),
        11155111 => Ok("https://sepolia.drpc.org"),
        _ => Err(format!(
            "unsupported chain_id {chain_id}; supported: 1 (Ethereum), 10 (Optimism), \
             8453 (Base), 42161 (Arbitrum One), 11155111 (Sepolia)"
        )),
    }
}

/// Make a JSON-RPC POST request and return the `result` field.
fn rpc_call<F>(
    http: &F,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
    let (status, resp_bytes) = http(
        "POST",
        url,
        r#"{"Content-Type":"application/json"}"#,
        Some(body_bytes),
    )?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "RPC {method} failed with status {status}: {}",
            String::from_utf8_lossy(&resp_bytes)
        ));
    }
    let resp: serde_json::Value = serde_json::from_slice(&resp_bytes)
        .map_err(|e| format!("invalid RPC response for {method}: {e}"))?;
    if let Some(err) = resp.get("error") {
        return Err(format!("RPC {method} error: {err}"));
    }
    Ok(resp["result"].clone())
}

/// `eth_getTransactionCount(from, "pending")` → next nonce for `from`.
pub(crate) fn fetch_nonce<F>(http: &F, chain_id: u64, from: &str) -> Result<u64, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let url = rpc_url_for_chain(chain_id)?;
    let result = rpc_call(
        http,
        url,
        "eth_getTransactionCount",
        serde_json::json!([from, "pending"]),
    )?;
    let s = result
        .as_str()
        .ok_or("eth_getTransactionCount: result not a string")?;
    Ok(hex_to_u128(s)? as u64)
}

/// `eth_gasPrice` → wei value.
pub(crate) fn fetch_gas_price<F>(http: &F, chain_id: u64) -> Result<u128, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let url = rpc_url_for_chain(chain_id)?;
    let result = rpc_call(http, url, "eth_gasPrice", serde_json::json!([]))?;
    let s = result.as_str().ok_or("eth_gasPrice: result not a string")?;
    hex_to_u128(s)
}

/// `eth_maxPriorityFeePerGas` → wei value. Falls back to 1 Gwei if the node
/// doesn't implement the method.
pub(crate) fn fetch_priority_fee<F>(http: &F, chain_id: u64) -> Result<u128, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let url = rpc_url_for_chain(chain_id)?;
    match rpc_call(http, url, "eth_maxPriorityFeePerGas", serde_json::json!([])) {
        Ok(result) => {
            let s = result
                .as_str()
                .ok_or("eth_maxPriorityFeePerGas: result not a string")?;
            hex_to_u128(s)
        }
        Err(_) => Ok(1_000_000_000), // fallback: 1 Gwei
    }
}

/// `eth_estimateGas` → raw gas estimate (no buffer applied; caller decides).
pub(crate) fn fetch_estimate_gas<F>(
    http: &F,
    chain_id: u64,
    from: &str,
    to: &str,
    value_hex: &str,
    data_hex: &str,
) -> Result<u64, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let url = rpc_url_for_chain(chain_id)?;
    // Geth/most RPCs reject "0x" for `value` — normalise to "0x0".
    let value_norm = if value_hex.is_empty() || value_hex.eq_ignore_ascii_case("0x") {
        "0x0".to_string()
    } else {
        value_hex.to_string()
    };
    let data_norm = if data_hex.is_empty() {
        "0x".to_string()
    } else {
        data_hex.to_string()
    };
    let result = rpc_call(
        http,
        url,
        "eth_estimateGas",
        serde_json::json!([{
            "from": from,
            "to": to,
            "value": value_norm,
            "data": data_norm,
        }]),
    )?;
    let s = result
        .as_str()
        .ok_or("eth_estimateGas: result not a string")?;
    Ok(hex_to_u128(s)? as u64)
}

/// `eth_sendRawTransaction` → tx_hash returned by the node.
pub(crate) fn send_raw_tx<F>(
    http: &F,
    chain_id: u64,
    signed_tx_hex: &str,
) -> Result<String, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let url = rpc_url_for_chain(chain_id)?;
    let raw_hex = if signed_tx_hex.starts_with("0x") || signed_tx_hex.starts_with("0X") {
        signed_tx_hex.to_string()
    } else {
        format!("0x{signed_tx_hex}")
    };
    let result = rpc_call(
        http,
        url,
        "eth_sendRawTransaction",
        serde_json::json!([raw_hex]),
    )?;
    Ok(result
        .as_str()
        .ok_or("eth_sendRawTransaction: result not a string")?
        .to_string())
}

// ── Pure helpers ─────────────────────────────────────────────────────────────

/// Parse a 0x-prefixed (or plain) hex string as a u128.
pub(crate) fn hex_to_u128(s: &str) -> Result<u128, String> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u128::from_str_radix(s, 16).map_err(|e| format!("invalid hex number '{s}': {e}"))
}

/// Convert a u128 to its minimal big-endian byte representation.
/// Zero → empty `Vec`.
pub(crate) fn u128_to_min_be(n: u128) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }
    let bytes = n.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
    bytes[start..].to_vec()
}
