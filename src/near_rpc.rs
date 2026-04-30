use crate::crypto::{
    compress_pubkey, eth_address, p2wpkh_address, parse_near_secp256k1_pubkey,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct GetDerivedPubkeyInput {
    pub near_account: String,
    pub path: String,
    pub near_network: String,
}

#[derive(Debug, Serialize)]
pub struct GetDerivedPubkeyOutput {
    /// Raw NEAR format: "secp256k1:<base58>"
    pub pubkey_near: String,
    /// Compressed 33-byte pubkey as hex
    pub pubkey_compressed_hex: String,
    /// 0x-prefixed Ethereum address (checksum not applied — lowercase hex)
    pub evm_address: String,
    /// Bitcoin mainnet P2WPKH address (bech32 bc1…)
    pub btc_address_mainnet: String,
    /// Bitcoin testnet P2WPKH address (bech32 tb1…)
    pub btc_address_testnet: String,
    /// Solana address (base58-encoded 32-byte ed25519 public key)
    pub solana_address: String,
}

/// Call `derived_public_key` on the MPC contract and return the raw quoted-string result.
fn call_derived_public_key(
    rpc_url: &str,
    near_account: &str,
    path: &str,
    domain_id: u8,
    http: &impl Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
) -> Result<String, String> {
    let args_json = serde_json::json!({
        "path": path,
        "predecessor": near_account,
        "domain_id": domain_id,
    });
    let args_b64 = B64.encode(args_json.to_string().as_bytes());

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "dontcare",
        "method": "query",
        "params": {
            "request_type": "call_function",
            "finality": "final",
            "account_id": "v1.signer-prod.testnet",
            "method_name": "derived_public_key",
            "args_base64": args_b64,
        }
    });

    let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
    let headers = r#"{"Content-Type":"application/json"}"#;

    let (status, resp_bytes) = http("POST", rpc_url, headers, Some(body_bytes))?;
    if status < 200 || status >= 300 {
        return Err(format!(
            "NEAR RPC returned status {}: {}",
            status,
            String::from_utf8_lossy(&resp_bytes)
        ));
    }

    let resp: serde_json::Value = serde_json::from_slice(&resp_bytes)
        .map_err(|e| format!("invalid NEAR RPC response: {e}"))?;

    if let Some(err) = resp.get("error") {
        return Err(format!("NEAR RPC error: {err}"));
    }

    let result_bytes: Vec<u8> = resp["result"]["result"]
        .as_array()
        .ok_or("missing result.result array in NEAR RPC response")?
        .iter()
        .map(|v| {
            v.as_u64()
                .ok_or("result byte is not a number")
                .map(|n| n as u8)
        })
        .collect::<Result<Vec<u8>, &str>>()?;

    let json_str = String::from_utf8(result_bytes)
        .map_err(|_| "NEAR RPC result is not valid UTF-8".to_string())?;

    // Result is a JSON-quoted string — unwrap it
    serde_json::from_str(&json_str).map_err(|e| format!("failed to parse pubkey JSON: {e}"))
}

pub fn get_derived_pubkey(
    input: &GetDerivedPubkeyInput,
    http: impl Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
) -> Result<GetDerivedPubkeyOutput, String> {
    let rpc_url = match input.near_network.as_str() {
        "testnet" => "https://rpc.testnet.near.org",
        "mainnet" => "https://rpc.mainnet.near.org",
        n => return Err(format!("unknown near_network '{n}', expected 'testnet' or 'mainnet'")),
    };

    // ── secp256k1 key (domain_id=0) ───────────────────────────────────────────
    let pubkey_near =
        call_derived_public_key(rpc_url, &input.near_account, &input.path, 0, &http)?;

    let xy = parse_near_secp256k1_pubkey(&pubkey_near)?;
    let compressed = compress_pubkey(&xy);
    let evm_addr = eth_address(&xy);
    let btc_mainnet = p2wpkh_address(&compressed, true);
    let btc_testnet = p2wpkh_address(&compressed, false);

    // ── ed25519 key (domain_id=1 → Solana) ───────────────────────────────────
    let pubkey_near_ed25519 =
        call_derived_public_key(rpc_url, &input.near_account, &input.path, 1, &http)?;

    // "ed25519:<base58_32bytes>" — the base58 part IS the Solana address
    let solana_address = pubkey_near_ed25519
        .strip_prefix("ed25519:")
        .ok_or_else(|| {
            format!("expected 'ed25519:' prefix in ed25519 pubkey, got: {pubkey_near_ed25519}")
        })?
        .to_string();

    // Sanity-check: decoded key must be 32 bytes
    let sol_key_bytes = crate::crypto::base58_decode(&solana_address)
        .map_err(|e| format!("invalid ed25519 base58 key: {e}"))?;
    if sol_key_bytes.len() != 32 {
        return Err(format!(
            "ed25519 key must be 32 bytes, got {}",
            sol_key_bytes.len()
        ));
    }

    Ok(GetDerivedPubkeyOutput {
        pubkey_near,
        pubkey_compressed_hex: hex::encode(compressed),
        evm_address: format!("0x{}", hex::encode(evm_addr)),
        btc_address_mainnet: btc_mainnet,
        btc_address_testnet: btc_testnet,
        solana_address,
    })
}
