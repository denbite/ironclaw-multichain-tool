use base64::{
    engine::general_purpose::{STANDARD as B64, STANDARD_NO_PAD as B64_NO_PAD},
    Engine as _,
};

const MIN_PRIORITY_MICRO_LAMPORTS: u64 = 5_000;

fn rpc_url(network: &str) -> Result<&'static str, String> {
    match network {
        "mainnet" => Ok("https://api.mainnet-beta.solana.com"),
        "devnet" => Ok("https://api.devnet.solana.com"),
        n => Err(format!(
            "unsupported Solana network '{n}'; expected 'mainnet' or 'devnet'"
        )),
    }
}

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
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params
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
            "Solana RPC {method} failed with status {status}: {}",
            String::from_utf8_lossy(&resp_bytes)
        ));
    }
    let resp: serde_json::Value = serde_json::from_slice(&resp_bytes)
        .map_err(|e| format!("invalid Solana RPC response for {method}: {e}"))?;
    if let Some(err) = resp.get("error") {
        return Err(format!("Solana RPC {method} error: {err}"));
    }
    Ok(resp["result"].clone())
}

pub(crate) fn get_recent_blockhash<F>(network: &str, http: &F) -> Result<String, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let url = rpc_url(network)?;
    // Use "confirmed" commitment so the blockhash is only 2-3 slots old
    // instead of ~32 slots old, preserving most of the ~60-second validity window.
    let result = rpc_call(
        http,
        url,
        "getLatestBlockhash",
        serde_json::json!([{"commitment": "confirmed"}]),
    )?;
    result["value"]["blockhash"]
        .as_str()
        .ok_or_else(|| "missing blockhash in getLatestBlockhash response".to_string())
        .map(|s| s.to_string())
}

pub(crate) fn get_priority_fee<F>(network: &str, http: &F) -> Result<u64, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let url = rpc_url(network)?;
    let fee = match rpc_call(http, url, "getRecentPrioritizationFees", serde_json::json!([])) {
        Ok(arr) => arr
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .filter_map(|item| item["prioritizationFee"].as_u64())
                    .filter(|&fee| fee > 0)
                    .max()
            })
            .unwrap_or(0)
            .max(MIN_PRIORITY_MICRO_LAMPORTS),
        Err(_) => MIN_PRIORITY_MICRO_LAMPORTS,
    };
    Ok(fee)
}

pub(crate) fn send_signed_tx<F>(
    network: &str,
    signed_tx_base64: &str,
    http: &F,
) -> Result<String, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let url = rpc_url(network)?;

    // Normalise: decode then re-encode to ensure correctly-padded standard base64.
    let raw = B64
        .decode(signed_tx_base64)
        .or_else(|_| B64_NO_PAD.decode(signed_tx_base64.trim_end_matches('=')))
        .map_err(|e| format!("invalid signed_tx: {e}"))?;
    let tx_b64 = B64.encode(&raw);

    let result = rpc_call(
        http,
        url,
        "sendTransaction",
        serde_json::json!([
            tx_b64,
            {"encoding": "base64", "preflightCommitment": "confirmed"}
        ]),
    )?;

    result
        .as_str()
        .ok_or_else(|| "sendTransaction: result is not a string".to_string())
        .map(|s| s.to_string())
}
