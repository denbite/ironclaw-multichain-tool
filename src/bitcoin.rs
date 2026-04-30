use crate::crypto::{
    base58_decode, bech32_decode, compress_pubkey, der_encode_ecdsa, hash160,
    parse_mpc_sig, parse_near_secp256k1_pubkey, sha256d,
};
use serde::{Deserialize, Serialize};

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn varint(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

fn base58check_decode(addr: &str) -> Result<(u8, [u8; 20]), String> {
    let bytes = base58_decode(addr)?;
    if bytes.len() != 25 {
        return Err(format!(
            "base58check: expected 25 bytes, got {}",
            bytes.len()
        ));
    }
    let (payload, checksum) = bytes.split_at(21);
    let expected = &sha256d(payload)[..4];
    if checksum != expected {
        return Err("base58check: invalid checksum".into());
    }
    let hash: [u8; 20] = payload[1..].try_into().unwrap();
    Ok((payload[0], hash))
}

pub fn address_to_script(addr: &str, mainnet: bool) -> Result<Vec<u8>, String> {
    if let Ok((hrp, version, program)) = bech32_decode(addr) {
        let expected_hrp = if mainnet { "bc" } else { "tb" };
        if hrp != expected_hrp {
            return Err(format!(
                "bech32 HRP '{hrp}' does not match network (expected '{expected_hrp}')"
            ));
        }
        if version != 0 {
            return Err(format!("unsupported witness version {version}"));
        }
        if program.len() == 20 {
            let mut script = vec![0x00, 0x14];
            script.extend_from_slice(&program);
            return Ok(script);
        }
        if program.len() == 32 {
            let mut script = vec![0x00, 0x20];
            script.extend_from_slice(&program);
            return Ok(script);
        }
        return Err(format!(
            "unsupported witness program length {}",
            program.len()
        ));
    }

    let (version, hash) = base58check_decode(addr)?;
    let script = match version {
        0x00 | 0x6f => {
            let mut s = vec![0x76, 0xa9, 0x14];
            s.extend_from_slice(&hash);
            s.push(0x88);
            s.push(0xac);
            s
        }
        0x05 | 0xc4 => {
            let mut s = vec![0xa9, 0x14];
            s.extend_from_slice(&hash);
            s.push(0x87);
            s
        }
        v => return Err(format!("unsupported base58check version byte 0x{v:02x}")),
    };
    Ok(script)
}

// ── Fee estimation ────────────────────────────────────────────────────────────

/// Fetch the recommended fee rate (sat/vbyte) from Blockstream Esplora.
/// Uses the 6-block target; falls back to 3, then 1.
fn fetch_fee_rate(
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
        return Err(format!("Esplora fee-estimates failed with status {status}"));
    }

    let estimates: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| format!("invalid fee-estimates response: {e}"))?;

    // Try targets in increasing horizon order; testnet often only has long-range estimates
    for target in &["6", "3", "1", "10", "20", "144", "504", "1008"] {
        if let Some(rate) = estimates[target].as_f64() {
            // Round up to nearest sat/vbyte, minimum 1
            return Ok((rate.ceil() as u64).max(1));
        }
    }

    // Testnet4 mempool is often empty — fall back to minimum relay fee
    if !mainnet {
        return Ok(1);
    }

    Err("no usable fee estimate in Esplora response".into())
}

/// Compute the segwit transaction vsize for 1 P2WPKH input and the given output scripts.
///
/// Formula:
///   stripped_size = 4 (version) + 1 (in_count) + 41 (input) + 1 (out_count) + sum(outputs) + 4 (locktime)
///   witness_size  = 2 (marker+flag) + 1 (stack_items) + 1 (sig_len) + 72 (max DER+SIGHASH) + 1 (pk_len) + 33 (pubkey)
///   weight        = stripped_size * 4 + witness_size
///   vsize         = ceil(weight / 4)
fn tx_vsize(out_scripts: &[Vec<u8>]) -> u64 {
    let outputs_bytes: usize = out_scripts
        .iter()
        .map(|s| 8 + varint(s.len() as u64).len() + s.len())
        .sum();

    let stripped_size = 4 + 1 + 41 + varint(out_scripts.len() as u64).len() + outputs_bytes + 4;
    // witness: marker(1) + flag(1) + item_count(1) + sig_len(1) + max_sig(72) + pk_len(1) + pk(33)
    let witness_size = 2 + 1 + 1 + 72 + 1 + 33;
    let weight = stripped_size * 4 + witness_size;
    ((weight + 3) / 4) as u64 // ceil
}

// ── fetch_utxos (private helper) ─────────────────────────────────────────────

/// Fetch all UTXOs for a Bitcoin address from Blockstream Esplora.
/// Returns them sorted largest-first so callers can trivially pick the best one.
fn fetch_utxos(
    address: &str,
    mainnet: bool,
    http: &impl Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
) -> Result<Vec<BtcInput>, String> {
    let url = if mainnet {
        format!("https://mempool.space/api/address/{address}/utxo")
    } else {
        format!("https://mempool.space/testnet4/api/address/{address}/utxo")
    };

    let (status, body) = http("GET", &url, "{}", None)?;
    if status < 200 || status >= 300 {
        return Err(format!("Esplora UTXO fetch failed with status {status}"));
    }

    let raw: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| format!("invalid UTXO response: {e}"))?;

    let arr = raw
        .as_array()
        .ok_or_else(|| "UTXO response is not a JSON array".to_string())?;

    let mut utxos: Vec<BtcInput> = arr
        .iter()
        .filter_map(|u| {
            let txid = u["txid"].as_str()?.to_string();
            let vout = u["vout"].as_u64()? as u32;
            let amount_sats = u["value"].as_u64()?;
            Some(BtcInput { txid, vout, amount_sats })
        })
        .collect();

    if utxos.is_empty() {
        return Err(format!(
            "no UTXOs found for {address} — fund the address before sending"
        ));
    }

    // Largest first so the caller can trivially pick the best candidate
    utxos.sort_by(|a, b| b.amount_sats.cmp(&a.amount_sats));
    Ok(utxos)
}

// ── get_btc_utxos ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GetBtcUtxosInput {
    pub network: String,
    pub address: String,
}

#[derive(Debug, Serialize)]
pub struct BtcUtxo {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    pub confirmed: bool,
}

#[derive(Debug, Serialize)]
pub struct GetBtcUtxosOutput {
    pub utxos: Vec<BtcUtxo>,
}

pub fn get_btc_utxos(
    input: &GetBtcUtxosInput,
    http: impl Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
) -> Result<GetBtcUtxosOutput, String> {
    let mainnet = match input.network.as_str() {
        "mainnet" => true,
        "testnet" => false,
        n => return Err(format!("unknown network '{n}', expected 'mainnet' or 'testnet'")),
    };

    let url = if mainnet {
        format!("https://mempool.space/api/address/{}/utxo", input.address)
    } else {
        format!("https://mempool.space/testnet4/api/address/{}/utxo", input.address)
    };

    let (status, body) = http("GET", &url, "{}", None)?;
    if status < 200 || status >= 300 {
        return Err(format!("Esplora UTXO fetch failed with status {status}"));
    }

    let raw: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| format!("invalid UTXO response: {e}"))?;

    let arr = raw.as_array().ok_or("expected JSON array from Esplora")?;
    let utxos = arr
        .iter()
        .map(|u| {
            let txid = u["txid"].as_str().ok_or("missing txid")?.to_string();
            let vout = u["vout"].as_u64().ok_or("missing vout")? as u32;
            let amount_sats = u["value"].as_u64().ok_or("missing value")?;
            let confirmed = u["status"]["confirmed"].as_bool().unwrap_or(false);
            Ok(BtcUtxo { txid, vout, amount_sats, confirmed })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(GetBtcUtxosOutput { utxos })
}

// ── Action types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BtcInput {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
}

#[derive(Debug, Deserialize)]
pub struct BtcOutput {
    pub address: String,
    pub amount_sats: u64,
}

#[derive(Debug, Deserialize)]
pub struct BuildBtcPayloadInput {
    pub network: String,
    pub pubkey_near: String,
    /// Exactly 1 UTXO input. If omitted (or empty), the largest UTXO for the
    /// derived address is fetched automatically from Esplora.
    #[serde(default)]
    pub inputs: Vec<BtcInput>,
    /// Recipient outputs only — do NOT include a change output.
    pub outputs: Vec<BtcOutput>,
    /// Where to return the change. Defaults to the P2WPKH address derived from
    /// pubkey_near when omitted.
    pub change_address: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BuildBtcPayloadOutput {
    pub payload_hex: String,
    pub unsigned_tx_hex: String,
    pub input_address: String,
    /// TXID of the UTXO being spent (auto-selected when not provided by the caller).
    pub utxo_txid: String,
    pub utxo_vout: u32,
    pub utxo_amount_sats: u64,
    /// Informational — the fetched fee rate used.
    pub fee_rate_sat_vbyte: u64,
    /// Computed miner fee in satoshis.
    pub fee_sats: u64,
    /// Change sent back to change_address.
    pub change_sats: u64,
}

#[derive(Debug, Deserialize)]
pub struct ReconstructBtcInput {
    pub network: String,
    pub unsigned_tx_hex: String,
    pub pubkey_near: String,
    #[serde(deserialize_with = "crate::crypto::deser_sig_json")]
    pub signature_json: String,
}

#[derive(Debug, Serialize)]
pub struct ReconstructBtcOutput {
    /// Hex-encoded segwit (witness) serialization of the signed transaction.
    pub signed_tx_hex: String,
    /// SHA256D of the non-witness serialization, reversed (= Bitcoin txid).
    pub tx_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct BroadcastBtcInput {
    pub network: String,
    /// signed_tx_hex returned by reconstruct_btc_tx (plain hex or 0x-prefixed).
    pub signed_tx_hex: String,
}

#[derive(Debug, Serialize)]
pub struct BroadcastBtcOutput {
    pub tx_hash: String,
}

// ── build_btc_payload ─────────────────────────────────────────────────────────

pub fn build_btc_payload(
    input: &BuildBtcPayloadInput,
    http: impl Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
) -> Result<BuildBtcPayloadOutput, String> {
    let mainnet = match input.network.as_str() {
        "mainnet" => true,
        "testnet" => false,
        n => return Err(format!("unknown network '{n}', expected 'mainnet' or 'testnet'")),
    };

    // Derive compressed pubkey and input address up-front — needed for auto-fetch
    let xy = parse_near_secp256k1_pubkey(&input.pubkey_near)?;
    let compressed = compress_pubkey(&xy);
    let pubkey_hash = hash160(&compressed);
    let input_address = crate::crypto::p2wpkh_address(&compressed, mainnet);

    // Resolve which UTXO to spend
    let inp: BtcInput = if input.inputs.is_empty() {
        // Auto-fetch all UTXOs and pick the largest one
        let mut utxos = fetch_utxos(&input_address, mainnet, &http)?;
        utxos.remove(0) // sorted largest-first by fetch_utxos
    } else if input.inputs.len() == 1 {
        BtcInput {
            txid: input.inputs[0].txid.clone(),
            vout: input.inputs[0].vout,
            amount_sats: input.inputs[0].amount_sats,
        }
    } else {
        return Err(format!(
            "v1 supports exactly 1 input, got {}",
            input.inputs.len()
        ));
    };

    // change_address defaults to the address derived from pubkey_near
    let change_addr_str: String = input
        .change_address
        .clone()
        .unwrap_or_else(|| input_address.clone());
    let change_address: &str = &change_addr_str;

    let txid_hex = inp.txid.strip_prefix("0x").unwrap_or(&inp.txid);
    let mut txid_bytes =
        hex::decode(txid_hex).map_err(|e| format!("invalid txid hex: {e}"))?;
    if txid_bytes.len() != 32 {
        return Err(format!("txid must be 32 bytes, got {}", txid_bytes.len()));
    }
    txid_bytes.reverse();

    let vout_le = inp.vout.to_le_bytes();

    // Build recipient output scripts
    let recipient_scripts: Vec<Vec<u8>> = input
        .outputs
        .iter()
        .map(|o| address_to_script(&o.address, mainnet))
        .collect::<Result<Vec<_>, _>>()?;

    let change_script = address_to_script(change_address, mainnet)?;

    // Include change output in vsize calculation (we always plan for it)
    let mut scripts_with_change = recipient_scripts.clone();
    scripts_with_change.push(change_script.clone());

    // Fetch fee rate and compute fee
    let fee_rate = fetch_fee_rate(mainnet, &http)?;
    let vsize = tx_vsize(&scripts_with_change);
    let fee_sats = fee_rate * vsize;

    // Compute change
    let total_in = inp.amount_sats;
    let total_out: u64 = input.outputs.iter().map(|o| o.amount_sats).sum();

    if total_out + fee_sats > total_in {
        return Err(format!(
            "insufficient funds: input {total_in} sats < output {total_out} + fee {fee_sats} sats"
        ));
    }

    let change_sats = total_in - total_out - fee_sats;

    // Add change output if above dust (546 sats); otherwise donate remainder to miner
    let mut all_outputs: Vec<(u64, Vec<u8>)> = input
        .outputs
        .iter()
        .zip(recipient_scripts.iter())
        .map(|(o, s)| (o.amount_sats, s.clone()))
        .collect();

    if change_sats >= 546 {
        all_outputs.push((change_sats, change_script));
    }
    // Sub-dust change (< 546 sats) is donated to the miner rather than creating a dust output.

    // BIP143 sighash preimage
    let mut script_code = Vec::with_capacity(26);
    script_code.push(0x19);
    script_code.push(0x76);
    script_code.push(0xa9);
    script_code.push(0x14);
    script_code.extend_from_slice(&pubkey_hash);
    script_code.push(0x88);
    script_code.push(0xac);

    let mut prevouts = Vec::new();
    prevouts.extend_from_slice(&txid_bytes);
    prevouts.extend_from_slice(&vout_le);
    let hash_prevouts = sha256d(&prevouts);

    let seq_bytes: [u8; 4] = 0xffff_fffd_u32.to_le_bytes();
    let hash_sequence = sha256d(&seq_bytes);

    let mut outputs_concat = Vec::new();
    for (amount, script) in &all_outputs {
        outputs_concat.extend_from_slice(&amount.to_le_bytes());
        outputs_concat.extend_from_slice(&varint(script.len() as u64));
        outputs_concat.extend_from_slice(script);
    }
    let hash_outputs = sha256d(&outputs_concat);

    let mut preimage = Vec::new();
    preimage.extend_from_slice(&1u32.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    preimage.extend_from_slice(&txid_bytes);
    preimage.extend_from_slice(&vout_le);
    preimage.extend_from_slice(&script_code);
    preimage.extend_from_slice(&inp.amount_sats.to_le_bytes());
    preimage.extend_from_slice(&0xffff_fffd_u32.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&0u32.to_le_bytes());
    preimage.extend_from_slice(&1u32.to_le_bytes());

    let payload = sha256d(&preimage);

    // Unsigned raw tx
    let mut unsigned_tx = Vec::new();
    unsigned_tx.extend_from_slice(&1u32.to_le_bytes());
    unsigned_tx.extend_from_slice(&varint(1));
    unsigned_tx.extend_from_slice(&txid_bytes);
    unsigned_tx.extend_from_slice(&vout_le);
    unsigned_tx.push(0x00); // empty scriptSig
    unsigned_tx.extend_from_slice(&0xffff_fffd_u32.to_le_bytes());
    unsigned_tx.extend_from_slice(&varint(all_outputs.len() as u64));
    for (amount, script) in &all_outputs {
        unsigned_tx.extend_from_slice(&amount.to_le_bytes());
        unsigned_tx.extend_from_slice(&varint(script.len() as u64));
        unsigned_tx.extend_from_slice(script);
    }
    unsigned_tx.extend_from_slice(&0u32.to_le_bytes());

    Ok(BuildBtcPayloadOutput {
        payload_hex: hex::encode(payload),
        unsigned_tx_hex: hex::encode(&unsigned_tx),
        input_address,
        utxo_txid: inp.txid.clone(),
        utxo_vout: inp.vout,
        utxo_amount_sats: inp.amount_sats,
        fee_rate_sat_vbyte: fee_rate,
        fee_sats,
        change_sats: if change_sats >= 546 { change_sats } else { 0 },
    })
}

// ── reconstruct_btc_tx ────────────────────────────────────────────────────────
//
// Pure computation — no HTTP. Combines the unsigned P2WPKH tx with the MPC
// signature to produce a fully-signed segwit transaction and its txid.

pub fn reconstruct_btc_tx(
    input: &ReconstructBtcInput,
) -> Result<ReconstructBtcOutput, String> {
    let xy = parse_near_secp256k1_pubkey(&input.pubkey_near)?;
    let compressed = compress_pubkey(&xy);

    let sig = parse_mpc_sig(&input.signature_json)?;
    let der_sig = der_encode_ecdsa(&sig.r, &sig.s);

    let raw = hex::decode(
        input
            .unsigned_tx_hex
            .strip_prefix("0x")
            .unwrap_or(&input.unsigned_tx_hex),
    )
    .map_err(|e| format!("invalid unsigned_tx_hex: {e}"))?;

    if raw.len() < 50 {
        return Err("unsigned_tx_hex too short".into());
    }

    let version = &raw[0..4];
    let locktime = &raw[raw.len() - 4..];
    let middle = &raw[4..raw.len() - 4];

    let mut segwit_tx = Vec::new();
    segwit_tx.extend_from_slice(version);
    segwit_tx.push(0x00); // segwit marker
    segwit_tx.push(0x01); // segwit flag
    segwit_tx.extend_from_slice(middle);

    // Witness for input 0
    segwit_tx.push(0x02); // 2 witness items
    segwit_tx.extend_from_slice(&varint(der_sig.len() as u64));
    segwit_tx.extend_from_slice(&der_sig);
    segwit_tx.push(0x21); // 33 bytes
    segwit_tx.extend_from_slice(&compressed);

    segwit_tx.extend_from_slice(locktime);

    // txid = SHA256D of the non-witness serialization (= raw), then reversed
    let mut txid = sha256d(&raw);
    txid.reverse();

    Ok(ReconstructBtcOutput {
        signed_tx_hex: hex::encode(&segwit_tx),
        tx_hash: hex::encode(txid),
    })
}

// ── broadcast_btc ─────────────────────────────────────────────────────────────
//
// Takes a fully-signed segwit transaction (from reconstruct_btc_tx) and
// submits it to Blockstream Esplora.

pub fn broadcast_btc(
    input: &BroadcastBtcInput,
    http: impl Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
) -> Result<BroadcastBtcOutput, String> {
    let mainnet = match input.network.as_str() {
        "mainnet" => true,
        "testnet" => false,
        n => return Err(format!("unknown network '{n}'")),
    };

    // Accept both plain hex and 0x-prefixed
    let tx_hex = input
        .signed_tx_hex
        .strip_prefix("0x")
        .unwrap_or(&input.signed_tx_hex)
        .to_string();

    let url = if mainnet {
        "https://mempool.space/api/tx"
    } else {
        "https://mempool.space/testnet4/api/tx"
    };

    let (status, resp_body) = http(
        "POST",
        url,
        r#"{"Content-Type":"text/plain"}"#,
        Some(tx_hex.into_bytes()),
    )?;

    if status < 200 || status >= 300 {
        return Err(format!(
            "Esplora broadcast failed with status {}: {}",
            status,
            String::from_utf8_lossy(&resp_body)
        ));
    }

    let tx_hash = String::from_utf8(resp_body)
        .map_err(|_| "Esplora returned non-UTF8 response".to_string())?
        .trim()
        .to_string();

    Ok(BroadcastBtcOutput { tx_hash })
}
