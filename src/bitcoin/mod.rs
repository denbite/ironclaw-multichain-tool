//! Bitcoin cross-chain signing — public API surface.
//!
//! Each `pub fn` here maps 1:1 to a JSON action dispatched by `lib.rs`.
//! The functions are thin orchestrators: they parse inputs, delegate to
//! `pub(crate)` helpers in the sub-modules, and format outputs.
//!
//! Hex convention: **no `0x` prefix** — Bitcoin convention uses bare hex
//! (txids, sighashes, tx bytes). This diverges from arch doc §7 which uses
//! `0x` for EVM.

mod rpc;
mod script;
mod tx;
mod value;

use serde::{Deserialize, Serialize};

use crate::crypto::{compress_pubkey, parse_mpc_sig, parse_near_secp256k1_pubkey};

// ── Shared types ─────────────────────────────────────────────────────────────

/// One UTXO input (agent-provided, not auto-fetched).
#[derive(Debug, Deserialize)]
pub struct BtcInput {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
}

/// One recipient output.
#[derive(Debug, Deserialize)]
pub struct BtcOutput {
    pub address: String,
    pub amount_sats: u64,
}

/// UTXO as returned by `btc_get_utxos`.
#[derive(Debug, Serialize)]
pub struct BtcUtxo {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    pub confirmed: bool,
}

// ── btc_parse_value ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ParseValueInput {
    pub btc: String,
}

#[derive(Debug, Serialize)]
pub struct ParseValueOutput {
    pub sats: u64,
}

pub fn parse_value(input: &ParseValueInput) -> Result<ParseValueOutput, String> {
    let sats = value::btc_decimal_to_sats(&input.btc)?;
    Ok(ParseValueOutput { sats })
}

// ── btc_get_utxos ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GetUtxosInput {
    pub network: String,
    pub address: String,
}

#[derive(Debug, Serialize)]
pub struct GetUtxosOutput {
    pub utxos: Vec<BtcUtxo>,
}

pub fn get_utxos<F>(input: &GetUtxosInput, http: F) -> Result<GetUtxosOutput, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let mainnet = parse_network(&input.network)?;
    let utxos = rpc::fetch_utxos(&input.address, mainnet, &http)?;
    Ok(GetUtxosOutput { utxos })
}

// ── btc_get_fee_rate ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GetFeeRateInput {
    pub network: String,
}

#[derive(Debug, Serialize)]
pub struct GetFeeRateOutput {
    pub fee_rate_sat_vbyte: u64,
}

pub fn get_fee_rate<F>(input: &GetFeeRateInput, http: F) -> Result<GetFeeRateOutput, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let mainnet = parse_network(&input.network)?;
    let fee_rate_sat_vbyte = rpc::fetch_fee_rate(mainnet, &http)?;
    Ok(GetFeeRateOutput { fee_rate_sat_vbyte })
}

// ── btc_build_transfer_mpc_payload ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BuildTransferInput {
    pub network: String,
    pub from: String,
    pub inputs: Vec<BtcInput>,
    pub outputs: Vec<BtcOutput>,
    pub change_address: Option<String>,
    pub fee_rate_sat_vbyte: u64,
}

#[derive(Debug, Serialize)]
pub struct BuildTransferOutput {
    /// Bare hex unsigned tx (non-witness serialization).
    pub tx: String,
    /// One BIP143 sighash (bare hex) per input — sign each via MPC.
    pub mpc_payloads: Vec<String>,
}

/// Pure: build unsigned P2WPKH tx and return one BIP143 sighash per input.
/// All inputs must be funded from the address derived from `pubkey_near`.
pub fn build_transfer_mpc_payload(
    input: &BuildTransferInput,
) -> Result<BuildTransferOutput, String> {
    if input.inputs.is_empty() {
        return Err("inputs must not be empty — fetch UTXOs with btc_get_utxos first".into());
    }
    if input.outputs.is_empty() {
        return Err("outputs must not be empty".into());
    }

    let mainnet = parse_network(&input.network)?;

    let pubkey_hash = script::p2wpkh_pubkey_hash(&input.from, mainnet)?;

    let change_addr = input
        .change_address
        .clone()
        .unwrap_or_else(|| input.from.clone());

    // Build output scripts
    let recipient_scripts: Vec<Vec<u8>> = input
        .outputs
        .iter()
        .map(|o| script::address_to_script(&o.address, mainnet))
        .collect::<Result<Vec<_>, _>>()?;

    let change_script = script::address_to_script(&change_addr, mainnet)?;

    // Compute fee using vsize that includes the change output
    let mut scripts_with_change = recipient_scripts.clone();
    scripts_with_change.push(change_script.clone());

    let vsize = tx::tx_vsize(input.inputs.len(), &scripts_with_change);
    let fee_sats = input.fee_rate_sat_vbyte * vsize;

    let total_in: u64 = input.inputs.iter().map(|i| i.amount_sats).sum();
    let total_out: u64 = input.outputs.iter().map(|o| o.amount_sats).sum();

    if total_out + fee_sats > total_in {
        return Err(format!(
            "insufficient funds: input {total_in} sats < output {total_out} + fee {fee_sats} sats"
        ));
    }

    let change_sats = total_in - total_out - fee_sats;

    // Build full output list (recipient outputs + change if above dust)
    let mut all_outputs: Vec<(u64, Vec<u8>)> = input
        .outputs
        .iter()
        .zip(recipient_scripts.iter())
        .map(|(o, s)| (o.amount_sats, s.clone()))
        .collect();

    if change_sats >= 546 {
        all_outputs.push((change_sats, change_script));
    }
    // Sub-dust change (< 546 sats) is donated to the miner.

    let (unsigned_tx, sighashes) =
        tx::build_unsigned_tx(&input.inputs, &all_outputs, &pubkey_hash)?;

    Ok(BuildTransferOutput {
        tx: hex::encode(&unsigned_tx),
        mpc_payloads: sighashes.iter().map(hex::encode).collect(),
    })
}

// ── btc_attach_mpc_signature_to_tx ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AttachSignatureInput {
    pub network: String,
    /// Bare hex unsigned tx from `btc_build_transfer_mpc_payload`.
    pub tx: String,
    pub pubkey_near: String,
    /// One SignatureResponse JSON string per input, in `mpc_payloads` order.
    /// Must be strict JSON strings — no nested object form accepted.
    pub signatures_json: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AttachSignatureOutput {
    /// Bare hex segwit (witness) serialization of the signed transaction.
    pub signed_tx: String,
    /// SHA256D of the non-witness serialization, reversed (= Bitcoin txid), bare hex.
    pub tx_hash: String,
}

/// Pure: attach MPC signatures to an unsigned tx and return the signed segwit tx.
pub fn attach_mpc_signature_to_tx(
    input: &AttachSignatureInput,
) -> Result<AttachSignatureOutput, String> {
    parse_network(&input.network)?; // validate early even though unused in pure path
    if input.signatures_json.is_empty() {
        return Err("signatures_json must not be empty".into());
    }

    let xy = parse_near_secp256k1_pubkey(&input.pubkey_near)?;
    let compressed = compress_pubkey(&xy);

    let tx_hex = input.tx.strip_prefix("0x").unwrap_or(&input.tx);
    let unsigned_tx = hex::decode(tx_hex).map_err(|e| format!("invalid tx hex: {e}"))?;

    let signatures = input
        .signatures_json
        .iter()
        .enumerate()
        .map(|(i, json)| parse_mpc_sig(json).map_err(|e| format!("signatures_json[{i}]: {e}")))
        .collect::<Result<Vec<_>, String>>()?;

    let (signed_tx, txid) = tx::attach_signatures(&unsigned_tx, &signatures, &compressed)?;

    Ok(AttachSignatureOutput {
        signed_tx: hex::encode(&signed_tx),
        tx_hash: hex::encode(&txid),
    })
}

// ── btc_send_signed_tx ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SendSignedTxInput {
    pub network: String,
    /// Bare hex signed tx from `btc_attach_mpc_signature_to_tx`.
    pub signed_tx: String,
}

#[derive(Debug, Serialize)]
pub struct SendSignedTxOutput {
    pub tx_hash: String,
}

pub fn send_signed_tx<F>(input: &SendSignedTxInput, http: F) -> Result<SendSignedTxOutput, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let mainnet = parse_network(&input.network)?;
    // Strip 0x if accidentally present
    let tx_hex = input
        .signed_tx
        .strip_prefix("0x")
        .unwrap_or(&input.signed_tx);
    let tx_hash = rpc::broadcast(tx_hex, mainnet, &http)?;
    Ok(SendSignedTxOutput { tx_hash })
}

// ── Internal helpers ─────────────────────────────────────────────────────────

fn parse_network(s: &str) -> Result<bool, String> {
    match s {
        "mainnet" => Ok(true),
        "testnet" => Ok(false),
        n => Err(format!(
            "unknown network '{n}', expected 'mainnet' or 'testnet'"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_value ──────────────────────────────────────────────────────────

    #[test]
    fn parse_value_fractional_small() {
        assert_eq!(
            parse_value(&ParseValueInput {
                btc: "0.00002741".into()
            })
            .unwrap()
            .sats,
            2741
        );
    }

    #[test]
    fn parse_value_zero() {
        assert_eq!(
            parse_value(&ParseValueInput { btc: "0".into() })
                .unwrap()
                .sats,
            0
        );
    }

    #[test]
    fn parse_value_one_btc() {
        assert_eq!(
            parse_value(&ParseValueInput { btc: "1".into() })
                .unwrap()
                .sats,
            100_000_000
        );
    }

    #[test]
    fn parse_value_centi_btc() {
        assert_eq!(
            parse_value(&ParseValueInput { btc: "0.01".into() })
                .unwrap()
                .sats,
            1_000_000
        );
    }

    // ── build_transfer_mpc_payload ───────────────────────────────────────────

    #[test]
    fn build_transfer_single_input_known_vector() {
        let out = build_transfer_mpc_payload(&BuildTransferInput {
            network: "testnet".into(),
            from: "tb1q7ypla7z839gm7az67nvc4vjkj7nfz9pyahvdau".into(),
            inputs: vec![BtcInput {
                txid: "347bbef8c9b1ddfce4d2a27b7a4be6dc8bf1b45cb846241f721be4c521f06be9".into(),
                vout: 1,
                amount_sats: 49279,
            }],
            outputs: vec![BtcOutput {
                address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into(),
                amount_sats: 482,
            }],
            change_address: None,
            fee_rate_sat_vbyte: 2,
        }).unwrap();

        assert_eq!(
            out.tx,
            "0100000001e96bf021c5e41b721f2446b85cb4f18bdce64b7a7ba2d2e4fcddb1c9f8be7b340100000000fdffffff02e201000000000000160014751e76e8199196d454941c45d1b3a323f1433bd683bd000000000000160014f103fef8478951bf745af4d98ab25697a691142400000000"
        );
        assert_eq!(
            out.mpc_payloads,
            vec!["ba35d96032b8b3b3b9922b72d678916d335380ce8578d86367ad4551a25d2970"]
        );
    }

    // ── attach_mpc_signature_to_tx ───────────────────────────────────────────

    #[test]
    fn attach_signature_single_input_known_vector() {
        let out = attach_mpc_signature_to_tx(&AttachSignatureInput {
            network: "testnet".into(),
            tx: "0100000001e96bf021c5e41b721f2446b85cb4f18bdce64b7a7ba2d2e4fcddb1c9f8be7b340100000000fdffffff02e201000000000000160014751e76e8199196d454941c45d1b3a323f1433bd683bd000000000000160014f103fef8478951bf745af4d98ab25697a691142400000000".into(),
            pubkey_near: "secp256k1:2bbNWEkGCodwJnd1gjZ3jatUYtR5Gb9HZHJF69gSgVQTyfkWzKLK8r7ikEqgfkwghx6JpqyDzHkGmR1BL1WiG9fg".into(),
            signatures_json: vec![
                "{\"big_r\":{\"affine_point\":\"034b9927bbbf142f56f03748448dd19f3dfd18c2459c884d10acd0f59be9894319\"},\"recovery_id\":0,\"s\":{\"scalar\":\"0be5763dde2d1762c94c2bd8488702a9862a454c1029fa63bd4680ab6185f264\"},\"scheme\":\"Secp256k1\"}".into(),
            ],
        }).unwrap();

        assert_eq!(
            out.signed_tx,
            "01000000000101e96bf021c5e41b721f2446b85cb4f18bdce64b7a7ba2d2e4fcddb1c9f8be7b340100000000fdffffff02e201000000000000160014751e76e8199196d454941c45d1b3a323f1433bd683bd000000000000160014f103fef8478951bf745af4d98ab25697a69114240247304402204b9927bbbf142f56f03748448dd19f3dfd18c2459c884d10acd0f59be989431902200be5763dde2d1762c94c2bd8488702a9862a454c1029fa63bd4680ab6185f2640121034fd92d00a2e29e93f41dd5e2172a4585171e8f032f7eb41b25d424aafde007ed00000000"
        );
    }
}
