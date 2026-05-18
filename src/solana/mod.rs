mod abi;
mod borsh;
mod rpc;
mod tx;
mod value;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::crypto::{base58_encode, parse_mpc_ed25519_sig};

// ── Input / output structs ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ParseValueInput {
    pub amount_sol: String,
}
#[derive(Debug, Serialize)]
pub struct ParseValueOutput {
    pub lamports: u64,
}

#[derive(Debug, Deserialize)]
pub struct GetRecentBlockhashInput {
    pub network: String,
}
#[derive(Debug, Serialize)]
pub struct GetRecentBlockhashOutput {
    pub recent_blockhash: String, // base58
}

#[derive(Debug, Deserialize)]
pub struct GetPriorityFeeInput {
    pub network: String,
}
#[derive(Debug, Serialize)]
pub struct GetPriorityFeeOutput {
    pub priority_fee: u64, // micro-lamports per compute unit
}

#[derive(Debug, Deserialize)]
pub struct BuildTransferInput {
    pub from_pubkey: String, // base58
    pub to_pubkey: String,   // base58
    pub lamports: u64,
    pub recent_blockhash: String, // base58
    pub priority_fee: u64,        // micro-lamports per CU; 0 = omit ComputeBudget ix
}
#[derive(Debug, Serialize)]
pub struct BuildPayloadOutput {
    pub tx: String,          // base64 of serialised v0 message
    pub mpc_payload: String, // same bytes as tx, raw hex, no 0x prefix
}

#[derive(Debug, Deserialize)]
pub struct AttachSignatureInput {
    pub tx: String,             // base64 of unsigned v0 message
    pub signature_json: String, // strict JSON-encoded Ed25519 SignatureResponse
}
#[derive(Debug, Serialize)]
pub struct AttachSignatureOutput {
    pub signed_tx: String, // base64 of signed transaction
    pub tx_hash: String,   // base58(signature) — Solana tx ID
}

#[derive(Debug, Deserialize)]
pub struct SendSignedTxInput {
    pub network: String,
    pub signed_tx: String, // base64 of signed transaction
}
#[derive(Debug, Serialize)]
pub struct SendSignedTxOutput {
    pub tx_hash: String,
}

// ── Public actions ────────────────────────────────────────────────────────────

pub fn parse_value(inp: &ParseValueInput) -> Result<ParseValueOutput, String> {
    let lamports = value::parse_value(&inp.amount_sol)?;
    Ok(ParseValueOutput { lamports })
}

pub fn get_recent_blockhash<F>(
    inp: &GetRecentBlockhashInput,
    http: F,
) -> Result<GetRecentBlockhashOutput, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let recent_blockhash = rpc::get_recent_blockhash(&inp.network, &http)?;
    Ok(GetRecentBlockhashOutput { recent_blockhash })
}

pub fn get_priority_fee<F>(
    inp: &GetPriorityFeeInput,
    http: F,
) -> Result<GetPriorityFeeOutput, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let priority_fee = rpc::get_priority_fee(&inp.network, &http)?;
    Ok(GetPriorityFeeOutput { priority_fee })
}

pub fn build_transfer_mpc_payload(inp: &BuildTransferInput) -> Result<BuildPayloadOutput, String> {
    let msg = tx::build_transfer(
        &inp.from_pubkey,
        &inp.to_pubkey,
        inp.lamports,
        &inp.recent_blockhash,
        inp.priority_fee,
    )?;

    if msg.len() > 1232 {
        return Err(format!(
            "serialised message is {} bytes, exceeding the 1232-byte Solana limit",
            msg.len()
        ));
    }

    let tx = B64.encode(&msg);
    let mpc_payload = hex::encode(&msg);

    Ok(BuildPayloadOutput { tx, mpc_payload })
}

pub fn attach_mpc_signature_to_tx(
    inp: &AttachSignatureInput,
) -> Result<AttachSignatureOutput, String> {
    let msg = B64
        .decode(&inp.tx)
        .map_err(|e| format!("invalid tx (expected base64): {e}"))?;

    let sig = parse_mpc_ed25519_sig(&inp.signature_json)?;

    let signed_tx_bytes = tx::attach_signature(&msg, &sig);
    let signed_tx = B64.encode(&signed_tx_bytes);
    let tx_hash = base58_encode(&sig);

    Ok(AttachSignatureOutput { signed_tx, tx_hash })
}

pub fn send_signed_tx<F>(inp: &SendSignedTxInput, http: F) -> Result<SendSignedTxOutput, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let tx_hash = rpc::send_signed_tx(&inp.network, &inp.signed_tx, &http)?;
    Ok(SendSignedTxOutput { tx_hash })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_value_milisol() {
        let out = parse_value(&ParseValueInput {
            amount_sol: "0.001".into(),
        })
        .unwrap();
        assert_eq!(out.lamports, 1_000_000);
    }

    #[test]
    fn parse_value_fractional_5_digits() {
        let out = parse_value(&ParseValueInput {
            amount_sol: "0.02941".into(),
        })
        .unwrap();
        assert_eq!(out.lamports, 29_410_000);
    }

    #[test]
    fn parse_value_zero() {
        let out = parse_value(&ParseValueInput {
            amount_sol: "0".into(),
        })
        .unwrap();
        assert_eq!(out.lamports, 0);
    }

    #[test]
    fn parse_value_one_sol() {
        let out = parse_value(&ParseValueInput {
            amount_sol: "1".into(),
        })
        .unwrap();
        assert_eq!(out.lamports, 1_000_000_000);
    }

    #[test]
    fn parse_value_integer_and_fraction() {
        let out = parse_value(&ParseValueInput {
            amount_sol: "100.5".into(),
        })
        .unwrap();
        assert_eq!(out.lamports, 100_500_000_000);
    }

    #[test]
    fn parse_value_one_lamport() {
        let out = parse_value(&ParseValueInput {
            amount_sol: "0.000000001".into(),
        })
        .unwrap();
        assert_eq!(out.lamports, 1);
    }

    #[test]
    fn parse_value_rejects_non_numeric() {
        assert!(parse_value(&ParseValueInput {
            amount_sol: "abc".into()
        })
        .is_err());
    }

    #[test]
    fn parse_value_rejects_too_many_decimals() {
        assert!(parse_value(&ParseValueInput {
            amount_sol: "1.0000000001".into()
        })
        .is_err());
    }

    #[test]
    fn build_transfer_mpc_payload_test() {
        let out = build_transfer_mpc_payload(&BuildTransferInput {
            from_pubkey: "3fTSjEAhZH7Zx4VnzvzGjHCW382wF9VpbmeP9V7BkAFo".into(),
            to_pubkey: "FXwS41XZGN8zDhHjg8UswKXGNUxVCvTSp3iAZ8P7BKb".into(),
            lamports: 29_410_000,
            recent_blockhash: "7jFFfprzGrtnPehRd1HBmemC7g21JxetcLWM4p2HXzrH".into(),
            priority_fee: 5_000,
        })
        .unwrap();

        assert_eq!(out.mpc_payload, "80010002042791582e52712e961ed47c9a406cbe81ef42bde8f27df59292c6338351e56db603b91d138e42f1bb723c70b52fa49bb324c41b64d23aa8fec610720470fec2ce0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000000000000000000000000000000000000000000000000000000000000000000063f8a1a156798c0983d00fc6efba69b94d35a98f2dff7e697622d2341603eebe030200090388130000000000000200050288130000030200010c02000000d0c2c0010000000000");
        assert_eq!(out.tx, "gAEAAgQnkVguUnEulh7UfJpAbL6B70K96PJ99ZKSxjODUeVttgO5HROOQvG7cjxwtS+km7MkxBtk0jqo/sYQcgRw/sLOAwZGb+UhFzL/7K26csOb57yM5bvF9xJrLEObOkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGP4oaFWeYwJg9APxu+6ablNNamPLf9+aXYi0jQWA+6+AwIACQOIEwAAAAAAAAIABQKIEwAAAwIAAQwCAAAA0MLAAQAAAAAA");
    }

    #[test]
    fn attach_signature_test() {
        let out = attach_mpc_signature_to_tx(&AttachSignatureInput {
            tx: "gAEAAgQnkVguUnEulh7UfJpAbL6B70K96PJ99ZKSxjODUeVttgO5HROOQvG7cjxwtS+km7MkxBtk0jqo/sYQcgRw/sLOAwZGb+UhFzL/7K26csOb57yM5bvF9xJrLEObOkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGP4oaFWeYwJg9APxu+6ablNNamPLf9+aXYi0jQWA+6+AwIACQOIEwAAAAAAAAIABQKIEwAAAwIAAQwCAAAA0MLAAQAAAAAA".into(),
            signature_json: "{\"scheme\":\"Ed25519\",\"signature\":[44,141,202,241,212,214,157,118,214,100,227,76,78,221,13,67,61,155,133,163,141,95,28,225,202,65,251,165,149,22,242,206,39,227,150,120,233,223,118,72,38,22,109,246,24,46,195,27,235,101,116,12,105,200,50,127,251,249,51,194,97,214,249,12]}".into(),
        })
        .unwrap();
        assert_eq!(out.signed_tx, "ASyNyvHU1p121mTjTE7dDUM9m4WjjV8c4cpB+6WVFvLOJ+OWeOnfdkgmFm32GC7DG+tldAxpyDJ/+/kzwmHW+QyAAQACBCeRWC5ScS6WHtR8mkBsvoHvQr3o8n31kpLGM4NR5W22A7kdE45C8btyPHC1L6SbsyTEG2TSOqj+xhByBHD+ws4DBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY/ihoVZ5jAmD0A/G77ppuU01qY8t/35pdiLSNBYD7r4DAgAJA4gTAAAAAAAAAgAFAogTAAADAgABDAIAAADQwsABAAAAAAA=");
        assert_eq!(out.tx_hash, "tfZqbysJxFRbapAydQNVoQBMubqDWDMPeNW1Ppro5iVx4gMaxCgjF4RLknZNrnC1bBMfdJSRjuah8AMDattMuFZ");
    }
}
