use crate::crypto::{base58_decode, base58_encode, parse_mpc_ed25519_sig};
use base64::{
    engine::general_purpose::{STANDARD as B64, STANDARD_NO_PAD as B64_NO_PAD},
    Engine as _,
};
use serde::{Deserialize, Serialize};

// ── Compact-U16 (Solana wire format) ─────────────────────────────────────────
//
// Solana encodes array lengths with a 1–3 byte little-endian variable-length
// integer. Values 0–127 fit in one byte; larger values use continuation bits.

fn compact_u16(mut n: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(3);
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
    out
}

// ── Serialised instruction (internal) ────────────────────────────────────────

struct SerializedInstruction {
    program_id_index: u8,
    account_indices: Vec<u8>,
    data: Vec<u8>,
}

// ── Solana v0 message serialisation ──────────────────────────────────────────
//
// Layout (Solana versioned message v0):
//   0x80                          — version prefix (v0)
//   [num_req_sigs, num_ro_signed, num_ro_unsigned]  — 3-byte MessageHeader
//   compact_u16(n_accts) + accounts × 32 bytes
//   recent_blockhash (32 bytes)
//   compact_u16(n_ixs) + serialised instructions
//   compact_u16(0)                — no address table lookups

fn serialize_v0_message(
    num_required_sigs: u8,
    num_readonly_signed: u8,
    num_readonly_unsigned: u8,
    accounts: &[[u8; 32]],
    recent_blockhash: &[u8; 32],
    instructions: &[SerializedInstruction],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x80); // v0 version prefix
    out.push(num_required_sigs);
    out.push(num_readonly_signed);
    out.push(num_readonly_unsigned);
    out.extend_from_slice(&compact_u16(accounts.len() as u16));
    for acc in accounts {
        out.extend_from_slice(acc);
    }
    out.extend_from_slice(recent_blockhash);
    out.extend_from_slice(&compact_u16(instructions.len() as u16));
    for ix in instructions {
        out.push(ix.program_id_index);
        out.extend_from_slice(&compact_u16(ix.account_indices.len() as u16));
        out.extend_from_slice(&ix.account_indices);
        out.extend_from_slice(&compact_u16(ix.data.len() as u16));
        out.extend_from_slice(&ix.data);
    }
    out.extend_from_slice(&compact_u16(0)); // no address table lookups
    out
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

fn parse_sol_pubkey(s: &str) -> Result<[u8; 32], String> {
    let bytes = base58_decode(s).map_err(|e| format!("invalid Solana pubkey '{s}': {e}"))?;
    bytes.try_into().map_err(|_| format!("Solana pubkey must be 32 bytes: '{s}'"))
}

// ── ComputeBudget helpers ─────────────────────────────────────────────────────
//
// Solana transactions with zero priority fee are accepted by the RPC but are
// rarely included by block leaders — they sit in the mempool until the
// blockhash expires (~150 slots / ~1 min).  Adding ComputeBudget instructions
// is the correct fix.
//
// ComputeBudget program: ComputeBudget111111111111111111111111111111
// Instruction discriminants (u8 prefix, little-endian payload):
//   SetComputeUnitLimit(u32)  → discriminant 2
//   SetComputeUnitPrice(u64)  → discriminant 3  (price in micro-lamports / CU)

const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";

/// A plain SOL transfer typically consumes ~150–300 compute units.
/// 5 000 is a safe ceiling that keeps the priority fee bounded.
const TRANSFER_COMPUTE_UNIT_LIMIT: u32 = 5_000;

fn ix_set_compute_unit_price(micro_lamports: u64) -> Vec<u8> {
    let mut d = vec![3u8];
    d.extend_from_slice(&micro_lamports.to_le_bytes());
    d
}

fn ix_set_compute_unit_limit(units: u32) -> Vec<u8> {
    let mut d = vec![2u8];
    d.extend_from_slice(&units.to_le_bytes());
    d
}

// ── RPC helpers ───────────────────────────────────────────────────────────────

fn sol_rpc_url(network: &str) -> Result<&'static str, String> {
    match network {
        "mainnet" => Ok("https://api.mainnet-beta.solana.com"),
        "devnet"  => Ok("https://api.devnet.solana.com"),
        n => Err(format!(
            "unsupported Solana network '{n}'; expected 'mainnet' or 'devnet'"
        )),
    }
}

fn sol_rpc_call(
    http: &impl Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
    let (status, resp_bytes) = http(
        "POST",
        url,
        r#"{"Content-Type":"application/json"}"#,
        Some(body_bytes),
    )?;
    if status < 200 || status >= 300 {
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

// ── Action types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BuildSolPayloadInput {
    pub network: String,
    /// Base58 Solana address from get_derived_pubkey (solana_address field).
    /// Acts as the fee payer and is the only required signer.
    pub from_pubkey: String,
    /// Recipient Base58 Solana address.
    pub to: String,
    /// Amount of SOL to transfer as a decimal number (e.g. 0.001, 0.5, 1.0).
    pub amount_sol: f64,
}

#[derive(Debug, Serialize)]
pub struct BuildSolPayloadOutput {
    /// Hex-encoded serialised v0 message.
    /// Send this verbatim as payload_v2.Eddsa to the NEAR MPC contract.
    pub payload_hex: String,
    /// Same bytes — pass to reconstruct_sol_tx after signing.
    pub unsigned_tx_hex: String,
    /// Recent blockhash used (informational).
    pub recent_blockhash: String,
}

#[derive(Debug, Deserialize)]
pub struct ReconstructSolTxInput {
    /// unsigned_tx_hex returned by build_sol_payload
    pub unsigned_tx_hex: String,
    /// Full SignatureResponse JSON from the MPC contract (scheme = Ed25519).
    /// Accepted as either a JSON-encoded string or a raw JSON object.
    #[serde(deserialize_with = "crate::crypto::deser_sig_json")]
    pub signature_json: String,
}

#[derive(Debug, Serialize)]
pub struct ReconstructSolTxOutput {
    /// Base64-encoded signed transaction — ready for broadcast_sol.
    pub signed_tx_base64: String,
    /// Solana transaction ID = base58(first_signature).
    pub tx_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct BroadcastSolInput {
    pub network: String,
    /// signed_tx_base64 returned by reconstruct_sol_tx
    pub signed_tx_base64: String,
}

#[derive(Debug, Serialize)]
pub struct BroadcastSolOutput {
    pub tx_hash: String,
}

// ── build_and_serialize_transfer ──────────────────────────────────────────────
//
// Pure (no I/O). Builds a System Program SOL transfer instruction, assembles
// the ordered account table, and serialises everything as a versioned v0
// message ready to be signed by the NEAR MPC contract.
//
// Account ordering in the static accounts table:
//   1. Writable signers   (fee payer always lands first within this group)
//   2. Readonly signers
//   3. Writable non-signers
//   4. Readonly non-signers  (program IDs land here unless they also sign)
//
// If the same pubkey appears in multiple instructions the most permissive flags
// win (writable beats readonly, signer beats non-signer).

pub(crate) fn build_and_serialize_transfer(
    from: &str,
    to: &str,
    lamports: u64,
    block_hash: &str,
    _last_valid_block_height: u64,
    // Priority fee in micro-lamports per compute unit.  Pass 0 to omit
    // ComputeBudget instructions (useful for offline test vectors).
    priority_micro_lamports: u64,
) -> Result<Vec<u8>, String> {
    let fee_payer = parse_sol_pubkey(from)?;
    let to_pubkey = parse_sol_pubkey(to)?;

    let bh_vec =
        base58_decode(block_hash).map_err(|e| format!("invalid blockhash '{block_hash}': {e}"))?;
    if bh_vec.len() != 32 {
        return Err(format!("blockhash must be 32 bytes, got {}", bh_vec.len()));
    }
    let recent_blockhash: [u8; 32] = bh_vec.try_into().unwrap();

    // ── Build System Program transfer instruction ──────────────────────────────
    // (pubkey, is_signer, is_writable)
    struct PIx {
        program_id: [u8; 32],
        accounts: Vec<([u8; 32], bool, bool)>,
        data: Vec<u8>,
    }

    // System Program transfer: discriminant 2 (LE u32) + lamports (LE u64)
    let mut transfer_data = vec![2u8, 0, 0, 0];
    transfer_data.extend_from_slice(&lamports.to_le_bytes());

    let transfer_ix = PIx {
        program_id: [0u8; 32], // System Program
        accounts: vec![
            (fee_payer, true, true),  // from — writable signer (fee payer)
            (to_pubkey, false, true), // to   — writable non-signer
        ],
        data: transfer_data,
    };

    // Prepend ComputeBudget instructions when a non-zero priority fee is requested.
    // Both instructions reference the same program ID; the account-dedup loop below
    // ensures it appears only once in the static accounts table.
    let parsed: Vec<PIx> = if priority_micro_lamports > 0 {
        let cb = parse_sol_pubkey(COMPUTE_BUDGET_PROGRAM)
            .map_err(|e| format!("ComputeBudget program key: {e}"))?;
        vec![
            PIx { program_id: cb, accounts: vec![], data: ix_set_compute_unit_price(priority_micro_lamports) },
            PIx { program_id: cb, accounts: vec![], data: ix_set_compute_unit_limit(TRANSFER_COMPUTE_UNIT_LIMIT) },
            transfer_ix,
        ]
    } else {
        vec![transfer_ix]
    };

    // ── Build ordered account list ─────────────────────────────────────────────
    // Insertion-ordered deduplication; fee_payer starts as (signer=true, writable=true).
    let mut keys: Vec<[u8; 32]> = vec![fee_payer];
    let mut flags: std::collections::HashMap<[u8; 32], (bool, bool)> =
        std::collections::HashMap::new();
    flags.insert(fee_payer, (true, true));

    for pix in &parsed {
        flags.entry(pix.program_id).or_insert((false, false));
        if !keys.contains(&pix.program_id) {
            keys.push(pix.program_id);
        }
        for &(pk, is_signer, is_writable) in &pix.accounts {
            let e = flags.entry(pk).or_insert((false, false));
            if is_signer {
                e.0 = true;
            }
            if is_writable {
                e.1 = true;
            }
            if !keys.contains(&pk) {
                keys.push(pk);
            }
        }
    }

    let mut writable_signers: Vec<[u8; 32]> = Vec::new();
    let mut readonly_signers: Vec<[u8; 32]> = Vec::new();
    let mut writable_nonsigners: Vec<[u8; 32]> = Vec::new();
    let mut readonly_nonsigners: Vec<[u8; 32]> = Vec::new();

    for key in &keys {
        match flags[key] {
            (true, true) => writable_signers.push(*key),
            (true, false) => readonly_signers.push(*key),
            (false, true) => writable_nonsigners.push(*key),
            (false, false) => readonly_nonsigners.push(*key),
        }
    }

    let ordered: Vec<[u8; 32]> = writable_signers
        .iter()
        .chain(&readonly_signers)
        .chain(&writable_nonsigners)
        .chain(&readonly_nonsigners)
        .copied()
        .collect();

    let num_required_sigs = (writable_signers.len() + readonly_signers.len()) as u8;
    let num_readonly_signed = readonly_signers.len() as u8;
    let num_readonly_unsigned = readonly_nonsigners.len() as u8;

    // ── Serialise instructions ─────────────────────────────────────────────────
    let index_of = |key: &[u8; 32]| -> Result<u8, String> {
        ordered
            .iter()
            .position(|k| k == key)
            .map(|i| i as u8)
            .ok_or_else(|| "account not found in ordered list".to_string())
    };

    let serialized_ixs: Vec<SerializedInstruction> = parsed
        .iter()
        .map(|pix| {
            let program_id_index = index_of(&pix.program_id)?;
            let account_indices = pix
                .accounts
                .iter()
                .map(|(pk, _, _)| index_of(pk))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(SerializedInstruction {
                program_id_index,
                account_indices,
                data: pix.data.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    // ── Serialise message ──────────────────────────────────────────────────────
    Ok(serialize_v0_message(
        num_required_sigs,
        num_readonly_signed,
        num_readonly_unsigned,
        &ordered,
        &recent_blockhash,
        &serialized_ixs,
    ))
}

// ── build_sol_payload ─────────────────────────────────────────────────────────

pub fn build_sol_payload(
    input: &BuildSolPayloadInput,
    http: impl Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
) -> Result<BuildSolPayloadOutput, String> {
    let rpc_url = sol_rpc_url(&input.network)?;

    let lamports = (input.amount_sol * 1_000_000_000.0).round() as u64;
    if lamports == 0 {
        return Err(
            "amount_sol rounds to 0 lamports — use a larger value (minimum ~0.000000001 SOL)"
                .to_string(),
        );
    }

    // ── Fetch recent blockhash ────────────────────────────────────────────────
    // Use "confirmed" (not "finalized") so the blockhash is only 2-3 slots old
    // instead of ~32 slots old.  "finalized" eats ~13 seconds of the ~60-second
    // validity window before we even start the NEAR MPC signing step.
    let bh_result = sol_rpc_call(
        &http,
        rpc_url,
        "getLatestBlockhash",
        serde_json::json!([{"commitment": "confirmed"}]),
    )?;
    let bh_str = bh_result["value"]["blockhash"]
        .as_str()
        .ok_or("missing blockhash in getLatestBlockhash response")?
        .to_string();
    let last_valid_block_height =
        bh_result["value"]["lastValidBlockHeight"].as_u64().unwrap_or(0);

    // ── Fetch priority fee ────────────────────────────────────────────────────
    // Without a priority fee, leaders almost never include the transaction and
    // the blockhash expires before it lands.  We take the max non-zero fee from
    // getRecentPrioritizationFees and floor it at 5 000 µL/CU (~0.025 lamports
    // for a 5 000-CU transfer — negligible but enough to get picked up).
    const MIN_PRIORITY_MICRO_LAMPORTS: u64 = 5_000;
    let priority_micro_lamports: u64 = match sol_rpc_call(
        &http,
        rpc_url,
        "getRecentPrioritizationFees",
        serde_json::json!([]),
    ) {
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

    let msg = build_and_serialize_transfer(
        &input.from_pubkey,
        &input.to,
        lamports,
        &bh_str,
        last_valid_block_height,
        priority_micro_lamports,
    )?;

    if msg.len() > 1232 {
        return Err(format!(
            "serialised message is {} bytes, exceeding the 1232-byte Solana limit",
            msg.len()
        ));
    }

    let payload_hex = hex::encode(&msg);
    Ok(BuildSolPayloadOutput {
        payload_hex: payload_hex.clone(),
        unsigned_tx_hex: payload_hex,
        recent_blockhash: bh_str,
    })
}

// ── reconstruct_sol_tx ────────────────────────────────────────────────────────
//
// Pure — no HTTP. Prepends the ed25519 signature to the serialised message to
// produce a signed Solana versioned transaction.
//
// Wire format: compact_u16(1) ‖ signature[64] ‖ message_bytes

pub fn reconstruct_sol_tx(
    input: &ReconstructSolTxInput,
) -> Result<ReconstructSolTxOutput, String> {
    let msg = hex::decode(
        input.unsigned_tx_hex.strip_prefix("0x").unwrap_or(&input.unsigned_tx_hex),
    )
    .map_err(|e| format!("invalid unsigned_tx_hex: {e}"))?;

    let sig = parse_mpc_ed25519_sig(&input.signature_json)?;

    // [0x01] + [64-byte sig] + [message bytes]
    let mut signed_tx = Vec::with_capacity(1 + 64 + msg.len());
    signed_tx.push(0x01); // compact_u16(1)
    signed_tx.extend_from_slice(&sig);
    signed_tx.extend_from_slice(&msg);

    let signed_tx_base64 = B64.encode(&signed_tx);
    let tx_hash = base58_encode(&sig); // Solana tx ID = base58(first signature)

    Ok(ReconstructSolTxOutput { signed_tx_base64, tx_hash })
}

// ── broadcast_sol ─────────────────────────────────────────────────────────────

pub fn broadcast_sol(
    input: &BroadcastSolInput,
    http: impl Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
) -> Result<BroadcastSolOutput, String> {
    let rpc_url = sol_rpc_url(&input.network)?;

    // Normalise: decode to raw bytes then re-encode as correctly-padded standard
    // base64.  This tolerates several malformed inputs that arise in practice:
    //   • valid padded base64 (4k chars)           — passes through unchanged
    //   • unpadded base64 (4k+2 or 4k+3 chars)    — padding is added
    //   • spurious/misaligned `=` chars at the end — stripped then re-padded
    let raw = B64
        .decode(&input.signed_tx_base64)
        .or_else(|_| B64_NO_PAD.decode(input.signed_tx_base64.trim_end_matches('=')))
        .map_err(|e| format!("invalid signed_tx_base64: {e}"))?;
    let tx_b64 = B64.encode(&raw);

    let result = sol_rpc_call(
        &http,
        rpc_url,
        "sendTransaction",
        serde_json::json!([
            tx_b64,
            {"encoding": "base64", "preflightCommitment": "confirmed"}
        ]),
    )?;

    let tx_hash = result
        .as_str()
        .ok_or("sendTransaction: result is not a string")?
        .to_string();

    Ok(BroadcastSolOutput { tx_hash })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test vectors ──────────────────────────────────────────────────────────
    //
    // Real Solana devnet SOL transfer signed via NEAR MPC:
    //   from (fee payer, writable signer):
    //     2791582e52712e961ed47c9a406cbe81ef42bde8f27df59292c6338351e56db6
    //   to (writable non-signer):
    //     03b91d138e42f1bb723c70b52fa49bb324c41b64d23aa8fec610720470fec2ce
    //   system program (readonly non-signer):
    //     0000000000000000000000000000000000000000000000000000000000000000
    //   blockhash:
    //     13584c79b2adb5ff52f5d01ac2b2e5269f852525c0d530a5052f5ffbb34a3ac0
    //   amount: 1_000_000 lamports (0.001 SOL)

    const REAL_PAYLOAD_HEX: &str = concat!(
        "80",     // v0 prefix
        "010001", // header: 1 req-sig, 0 ro-signed, 1 ro-unsigned
        "03",     // 3 accounts
        // [0] from (writable signer)
        "2791582e52712e961ed47c9a406cbe81ef42bde8f27df59292c6338351e56db6",
        // [1] to (writable non-signer)
        "03b91d138e42f1bb723c70b52fa49bb324c41b64d23aa8fec610720470fec2ce",
        // [2] system program (readonly non-signer)
        "0000000000000000000000000000000000000000000000000000000000000000",
        // recent_blockhash
        "13584c79b2adb5ff52f5d01ac2b2e5269f852525c0d530a5052f5ffbb34a3ac0",
        "01",     // 1 instruction
        "02",     // program_id_index = 2 (system program)
        "02",     // 2 account indices
        "0001",   // [from=0, to=1]
        "0c",     // 12 bytes of data
        // Transfer discriminant (2 as LE u32) + 1_000_000 lamports as LE u64
        "020000004042",
        "0f0000000000",
        "00",     // 0 address table lookups
    );

    // Signature bytes as returned by NEAR MPC (scheme = Ed25519)
    const SIG_JSON: &str = r#"{
        "scheme": "Ed25519",
        "signature": [
            107, 187, 225, 239, 130,  65,  67,  88, 117,  58, 234,
             65,  21, 208, 170, 213, 102,  68, 123, 185, 229,  71,
            152,  88, 220, 121, 159,  68, 111, 166,  52, 196, 109,
            251, 220, 185,  14, 131, 101, 172,  94, 126, 175, 148,
            169,  81,  61, 203,   3, 161,   0, 201, 106,  29, 181,
            129,   5, 182,  35, 244,  32, 225, 174,   8
        ]
    }"#;

    const EXPECTED_SIG_HEX: &str =
        "6bbbe1ef82414358753aea4115d0aad566447bb9e5479858dc799f446fa634c46dfbdcb90e8365ac5e7eaf94a9513dcb03a100c96a1db58105b623f420e1ae08";

    const EXPECTED_TX_HASH: &str =
        "39vsitpUonYqMupnvL4HHaR8hmFLPpKgeyqsBS4mZM2ZzJrUf8ntAkU3oXVFSFgafRwnvCiugbmE33WPHUFPZTLs";

    // ── compact_u16 ───────────────────────────────────────────────────────────

    #[test]
    fn compact_u16_single_byte() {
        assert_eq!(compact_u16(0), vec![0x00]);
        assert_eq!(compact_u16(1), vec![0x01]);
        assert_eq!(compact_u16(127), vec![0x7f]);
    }

    #[test]
    fn compact_u16_two_bytes() {
        // 128 → low 7 bits = 0 with continuation, high = 1 → [0x80, 0x01]
        assert_eq!(compact_u16(128), vec![0x80, 0x01]);
        // 300 = 0x12c → [0xac, 0x02]
        assert_eq!(compact_u16(300), vec![0xac, 0x02]);
    }

    // ── parse_mpc_ed25519_sig ─────────────────────────────────────────────────

    #[test]
    fn parse_ed25519_sig_correct_bytes() {
        let sig = parse_mpc_ed25519_sig(SIG_JSON).unwrap();
        assert_eq!(hex::encode(sig), EXPECTED_SIG_HEX);
    }

    #[test]
    fn parse_ed25519_sig_rejects_wrong_length() {
        let bad = r#"{"scheme":"Ed25519","signature":[1,2,3]}"#;
        assert!(parse_mpc_ed25519_sig(bad).is_err());
    }

    // ── base58_encode ─────────────────────────────────────────────────────────

    #[test]
    fn base58_encode_signature_gives_expected_tx_hash() {
        let sig_bytes = hex::decode(EXPECTED_SIG_HEX).unwrap();
        assert_eq!(base58_encode(&sig_bytes), EXPECTED_TX_HASH);
    }

    #[test]
    fn base58_roundtrip() {
        let original = hex::decode(EXPECTED_SIG_HEX).unwrap();
        let encoded = base58_encode(&original);
        let decoded = base58_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    // ── serialize_v0_message ──────────────────────────────────────────────────

    #[test]
    fn serialize_v0_message_matches_real_payload() {
        let from: [u8; 32] =
            hex::decode("2791582e52712e961ed47c9a406cbe81ef42bde8f27df59292c6338351e56db6")
                .unwrap()
                .try_into()
                .unwrap();
        let to: [u8; 32] =
            hex::decode("03b91d138e42f1bb723c70b52fa49bb324c41b64d23aa8fec610720470fec2ce")
                .unwrap()
                .try_into()
                .unwrap();
        let system: [u8; 32] = [0u8; 32];
        let bh: [u8; 32] =
            hex::decode("13584c79b2adb5ff52f5d01ac2b2e5269f852525c0d530a5052f5ffbb34a3ac0")
                .unwrap()
                .try_into()
                .unwrap();

        // Transfer(1_000_000): [2,0,0,0] + LE-u64
        let mut data = vec![2u8, 0, 0, 0];
        data.extend_from_slice(&1_000_000u64.to_le_bytes());

        let ix = SerializedInstruction {
            program_id_index: 2,
            account_indices: vec![0, 1],
            data,
        };

        let msg = serialize_v0_message(1, 0, 1, &[from, to, system], &bh, &[ix]);
        assert_eq!(hex::encode(&msg), REAL_PAYLOAD_HEX);
    }

    // ── build_and_serialize_transfer ─────────────────────────────────────────

    #[test]
    fn build_and_serialize_transfer_matches_expected() {
        // Test vector: real addresses and blockhash, 1_000_000 lamports
        let expected: Vec<u8> = hex::decode(concat!(
            "80",     // v0 prefix
            "010001", // header: 1 req-sig, 0 ro-signed, 1 ro-unsigned
            "03",     // 3 accounts
            // [0] from (writable signer)
            "2791582e52712e961ed47c9a406cbe81ef42bde8f27df59292c6338351e56db6",
            // [1] to (writable non-signer)
            "03b91d138e42f1bb723c70b52fa49bb324c41b64d23aa8fec610720470fec2ce",
            // [2] system program (readonly non-signer)
            "0000000000000000000000000000000000000000000000000000000000000000",
            // recent blockhash
            "ba60ccb97fa824b47943b568d301c8b2ac60698c52684c6f6c7fcb0250b9509d",
            "01",   // 1 instruction
            "02",   // program_id_index = 2 (system program)
            "02",   // 2 account indices
            "0001", // [from=0, to=1]
            "0c",   // 12 bytes of data
            // Transfer discriminant (2 as LE u32) + 1_000_000 lamports as LE u64
            "020000004042",
            "0f0000000000",
            "00", // 0 address table lookups
        ))
        .unwrap();

        let msg = build_and_serialize_transfer(
            "3fTSjEAhZH7Zx4VnzvzGjHCW382wF9VpbmeP9V7BkAFo",
            "FXwS41XZGN8zDhHjg8UswKXGNUxVCvTSp3iAZ8P7BKb",
            1_000_000,
            "DYYSdfbWFwfjeULX8yipVSnJpntwwnXmiXnRDeoYchet",
            356_551_892,
            0, // no ComputeBudget instructions — keeps the test vector stable
        )
        .unwrap();

        assert_eq!(msg, expected);
    }

    // ── build_sol_payload (mock HTTP) ─────────────────────────────────────────

    #[test]
    fn build_sol_payload_produces_correct_message() {
        // Derive the base58 blockhash that the real payload uses
        let bh_bytes: [u8; 32] =
            hex::decode("13584c79b2adb5ff52f5d01ac2b2e5269f852525c0d530a5052f5ffbb34a3ac0")
                .unwrap()
                .try_into()
                .unwrap();
        let bh_b58 = base58_encode(&bh_bytes);

        let mock_http = {
            let bh_b58 = bh_b58.clone();
            move |_method: &str, _url: &str, _headers: &str, body: Option<Vec<u8>>| {
                // Route by RPC method name embedded in the JSON body.
                let body_str = String::from_utf8(body.unwrap_or_default()).unwrap_or_default();
                if body_str.contains("getRecentPrioritizationFees") {
                    // Return an empty array → fallback floor of 5 000 µL/CU is used.
                    let resp = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": [] });
                    return Ok((200u16, serde_json::to_vec(&resp).unwrap()));
                }
                let resp = serde_json::json!({
                    "jsonrpc": "2.0", "id": 1,
                    "result": {
                        "value": { "blockhash": bh_b58, "lastValidBlockHeight": 999999 },
                        "context": { "slot": 1 }
                    }
                });
                Ok((200u16, serde_json::to_vec(&resp).unwrap()))
            }
        };

        let from_bytes =
            hex::decode("2791582e52712e961ed47c9a406cbe81ef42bde8f27df59292c6338351e56db6")
                .unwrap();
        let to_bytes =
            hex::decode("03b91d138e42f1bb723c70b52fa49bb324c41b64d23aa8fec610720470fec2ce")
                .unwrap();
        let from_b58 = base58_encode(&from_bytes);
        let to_b58 = base58_encode(&to_bytes);

        // 1_000_000 lamports = 0.001 SOL
        let input = BuildSolPayloadInput {
            network: "devnet".to_string(),
            from_pubkey: from_b58,
            to: to_b58,
            amount_sol: 0.001,
        };

        let output = build_sol_payload(&input, mock_http).unwrap();
        // The payload now includes ComputeBudget instructions so it differs from
        // the plain-transfer REAL_PAYLOAD_HEX.  Verify structural invariants instead.
        let bytes = hex::decode(&output.payload_hex).unwrap();
        assert_eq!(bytes[0], 0x80, "message must have v0 prefix");
        assert_eq!(bytes[1], 1, "1 required signer");
        assert_eq!(bytes[2], 0, "0 readonly signers");
        assert_eq!(bytes[3], 2, "2 readonly unsigned (ComputeBudget + System Program)");
        assert!(
            output.payload_hex.len() > REAL_PAYLOAD_HEX.len(),
            "payload with ComputeBudget instructions must be longer than bare transfer"
        );
        assert_eq!(output.recent_blockhash, bh_b58);
    }

    // ── reconstruct_sol_tx ────────────────────────────────────────────────────

    #[test]
    fn reconstruct_tx_gives_correct_hash() {
        let input = ReconstructSolTxInput {
            unsigned_tx_hex: REAL_PAYLOAD_HEX.to_string(),
            signature_json: SIG_JSON.to_string(),
        };
        let out = reconstruct_sol_tx(&input).unwrap();
        assert_eq!(out.tx_hash, EXPECTED_TX_HASH);
    }

    #[test]
    fn reconstruct_tx_signed_bytes_layout() {
        let input = ReconstructSolTxInput {
            unsigned_tx_hex: REAL_PAYLOAD_HEX.to_string(),
            signature_json: SIG_JSON.to_string(),
        };
        let out = reconstruct_sol_tx(&input).unwrap();
        let raw = B64.decode(&out.signed_tx_base64).unwrap();

        // byte 0 = 0x01  (compact_u16: one signature)
        assert_eq!(raw[0], 0x01);
        // bytes 1..65 = the 64-byte signature
        assert_eq!(hex::encode(&raw[1..65]), EXPECTED_SIG_HEX);
        // bytes 65.. = the original message
        assert_eq!(&raw[65..], hex::decode(REAL_PAYLOAD_HEX).unwrap().as_slice());
    }

    // ── broadcast_sol (mock HTTP) ─────────────────────────────────────────────

    #[test]
    fn broadcast_sol_returns_tx_hash() {
        let mock_http = |_method: &str, _url: &str, _headers: &str, _body: Option<Vec<u8>>| {
            let resp = serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": EXPECTED_TX_HASH,
            });
            Ok((200u16, serde_json::to_vec(&resp).unwrap()))
        };

        let out = broadcast_sol(
            &BroadcastSolInput {
                network: "devnet".to_string(),
                signed_tx_base64: "dGVzdA==".to_string(),
            },
            mock_http,
        )
        .unwrap();
        assert_eq!(out.tx_hash, EXPECTED_TX_HASH);
    }
}
