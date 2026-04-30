//! EVM cross-chain signing — public API surface.
//!
//! Each `pub fn` here maps 1:1 to a JSON action dispatched by `lib.rs`.
//! The functions are thin orchestrators: they parse inputs, delegate to
//! `pub(crate)` helpers in the sub-modules, and format outputs. All
//! HTTP I/O lives in `rpc`; assembly/encoding is pure and testable.
//!
//! See `.claude/rules/chain-module-architecture.md` for the full module
//! layout rationale.

mod abi;
mod rlp;
mod rpc;
mod tx;
mod value;

use serde::{Deserialize, Serialize};

use crate::crypto::{keccak256, parse_eth_address, parse_hex, parse_hex_uint, parse_mpc_sig};

// ── Inputs and outputs ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ParseValueInput {
    pub value_eth: String,
}
#[derive(Debug, Serialize)]
pub struct ParseValueOutput {
    pub value_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct EncodeDataInput {
    pub abi: String,
    pub args: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct EncodeDataOutput {
    pub data_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct GetNonceInput {
    pub chain_id: u64,
    pub from: String,
}
#[derive(Debug, Serialize)]
pub struct GetNonceOutput {
    pub nonce: u64,
}

#[derive(Debug, Deserialize)]
pub struct GetGasPriceInput {
    pub chain_id: u64,
}
#[derive(Debug, Serialize)]
pub struct GetGasPriceOutput {
    pub gas_price: String,
}

#[derive(Debug, Deserialize)]
pub struct GetPriorityFeeInput {
    pub chain_id: u64,
    pub gas_price: String,
}
#[derive(Debug, Serialize)]
pub struct GetPriorityFeeOutput {
    pub priority_fee: String,
    pub max_fee_per_gas: String,
}

#[derive(Debug, Deserialize)]
pub struct EstimateGasInput {
    pub chain_id: u64,
    pub from: String,
    pub to: String,
    pub value_hex: String,
    pub data_hex: String,
}
#[derive(Debug, Serialize)]
pub struct EstimateGasOutput {
    pub gas_limit: u64,
}

#[derive(Debug, Deserialize)]
pub struct BuildTransferInput {
    pub chain_id: u64,
    pub from: String,
    pub to: String,
    pub value_hex: String,
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: String,
    pub max_priority_fee_per_gas: String,
}

#[derive(Debug, Deserialize)]
pub struct BuildFunctionCallInput {
    pub chain_id: u64,
    pub from: String,
    pub to: String,
    pub value_hex: String,
    pub data_hex: String,
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: String,
    pub max_priority_fee_per_gas: String,
}

#[derive(Debug, Serialize)]
pub struct BuildPayloadOutput {
    /// `0x`-prefixed RLP-encoded unsigned EIP-1559 tx (0x02 type prefix + list).
    pub tx: String,
    /// Raw hex (NO `0x` prefix). Pasted directly into the `near-cli-rs` sign
    /// command's `payload_v2.Ecdsa` field.
    pub mpc_payload: String,
}

#[derive(Debug, Deserialize)]
pub struct AttachSignatureInput {
    pub tx: String,
    pub signature_json: String,
}
#[derive(Debug, Serialize)]
pub struct AttachSignatureOutput {
    pub signed_tx: String,
    pub tx_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct SendSignedTxInput {
    pub chain_id: u64,
    pub signed_tx: String,
}
#[derive(Debug, Serialize)]
pub struct SendSignedTxOutput {
    pub tx_hash: String,
}

// ── Public actions ───────────────────────────────────────────────────────────

/// Convert a decimal-ETH string (e.g. `"0.001"`, `"1.5"`) into wei,
/// returned as a `0x`-prefixed minimal big-endian hex string.
pub fn parse_value(input: &ParseValueInput) -> Result<ParseValueOutput, String> {
    let bytes = value::eth_decimal_to_wei_bytes(&input.value_eth)?;
    Ok(ParseValueOutput {
        value_hex: fmt_hex_0x(&bytes),
    })
}

/// Encode an ABI function call (`abi` signature + `args`) as `0x`-prefixed
/// hex calldata.
pub fn encode_data(input: &EncodeDataInput) -> Result<EncodeDataOutput, String> {
    let calldata = abi::encode_function_call(&input.abi, &input.args)?;
    Ok(EncodeDataOutput {
        data_hex: fmt_hex_0x(&calldata),
    })
}

/// Fetch the next pending nonce for `from` on `chain_id`.
pub fn get_nonce<F>(input: &GetNonceInput, http: F) -> Result<GetNonceOutput, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let nonce = rpc::fetch_nonce(&http, input.chain_id, &input.from)?;
    Ok(GetNonceOutput { nonce })
}

/// Fetch `eth_gasPrice` on `chain_id` and return it as `0x`-prefixed hex wei.
pub fn get_gas_price<F>(input: &GetGasPriceInput, http: F) -> Result<GetGasPriceOutput, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let gas_price = rpc::fetch_gas_price(&http, input.chain_id)?;
    Ok(GetGasPriceOutput {
        gas_price: fmt_hex_0x(&rpc::u128_to_min_be(gas_price)),
    })
}

/// Fetch `eth_maxPriorityFeePerGas` (with 1-Gwei fallback) and combine it
/// with the supplied `gas_price` to produce a safe `max_fee_per_gas`:
/// `max(2 × gas_price, priority_fee)`.
pub fn get_priority_fee_wei_per_gas<F>(
    input: &GetPriorityFeeInput,
    http: F,
) -> Result<GetPriorityFeeOutput, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let priority_fee_wei = rpc::fetch_priority_fee(&http, input.chain_id)?;
    let gas_price_wei = rpc::hex_to_u128(&input.gas_price)?;
    // Doubling the gas_price gives headroom against next-block base-fee
    // bumps. The `.max(priority_fee_wei)` clause guarantees the EIP-1559
    // invariant `max_fee_per_gas ≥ max_priority_fee_per_gas`.
    let max_fee_per_gas_wei = gas_price_wei.saturating_mul(2).max(priority_fee_wei);
    Ok(GetPriorityFeeOutput {
        priority_fee: fmt_hex_0x(&rpc::u128_to_min_be(priority_fee_wei)),
        max_fee_per_gas: fmt_hex_0x(&rpc::u128_to_min_be(max_fee_per_gas_wei)),
    })
}

/// Run `eth_estimateGas` and return a buffered `gas_limit` (raw + 20%) to
/// absorb minor gas drift between estimation and execution.
pub fn estimate_gas<F>(input: &EstimateGasInput, http: F) -> Result<EstimateGasOutput, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let raw = rpc::fetch_estimate_gas(
        &http,
        input.chain_id,
        &input.from,
        &input.to,
        &input.value_hex,
        &input.data_hex,
    )?;
    let gas_limit = raw + raw / 5; // +20%
    Ok(EstimateGasOutput { gas_limit })
}

/// Build an unsigned EIP-1559 tx for a plain ETH transfer (empty data).
/// Returns the RLP-encoded `tx` and the keccak256 `mpc_payload` to be
/// signed by the NEAR MPC contract.
pub fn build_transfer_mpc_payload(
    input: &BuildTransferInput,
) -> Result<BuildPayloadOutput, String> {
    // Validate `from` parses as a 20-byte address even though it doesn't end
    // up in the RLP (sender is recovered from the signature). Catches typos
    // before they reach the MPC contract.
    parse_eth_address(&input.from)?;
    let to = parse_eth_address(&input.to)?;
    let value_bytes = parse_hex_uint(&input.value_hex)?;
    let max_fee = rpc::hex_to_u128(&input.max_fee_per_gas)?;
    let max_priority = rpc::hex_to_u128(&input.max_priority_fee_per_gas)?;

    let tx_bytes = tx::build_unsigned_eip1559_tx(
        input.chain_id,
        input.nonce,
        max_priority,
        max_fee,
        input.gas_limit,
        &to,
        &value_bytes,
        &[], // no calldata for plain transfers
    );
    let payload = keccak256(&tx_bytes);

    Ok(BuildPayloadOutput {
        tx: fmt_hex_0x(&tx_bytes),
        mpc_payload: hex::encode(payload),
    })
}

/// Build an unsigned EIP-1559 tx for a contract call. `data_hex` should be
/// the output of `encode_data`. Returns `tx` and `mpc_payload` (raw hex).
pub fn build_function_call_mpc_payload(
    input: &BuildFunctionCallInput,
) -> Result<BuildPayloadOutput, String> {
    // Validate `from` (see note in build_transfer_mpc_payload).
    parse_eth_address(&input.from)?;
    let to = parse_eth_address(&input.to)?;
    let value_bytes = parse_hex_uint(&input.value_hex)?;
    let data_bytes = parse_hex(&input.data_hex)?;
    let max_fee = rpc::hex_to_u128(&input.max_fee_per_gas)?;
    let max_priority = rpc::hex_to_u128(&input.max_priority_fee_per_gas)?;

    let tx_bytes = tx::build_unsigned_eip1559_tx(
        input.chain_id,
        input.nonce,
        max_priority,
        max_fee,
        input.gas_limit,
        &to,
        &value_bytes,
        &data_bytes,
    );
    let payload = keccak256(&tx_bytes);

    Ok(BuildPayloadOutput {
        tx: fmt_hex_0x(&tx_bytes),
        mpc_payload: hex::encode(payload),
    })
}

/// Combine an unsigned tx with the MPC `signature_json` (a JSON-encoded
/// `SignatureResponse` string) to produce a fully-signed, broadcast-ready
/// `signed_tx` and its on-chain `tx_hash`. Pure computation.
pub fn attach_mpc_signature_to_tx(
    input: &AttachSignatureInput,
) -> Result<AttachSignatureOutput, String> {
    let unsigned = parse_hex(&input.tx)?;
    let sig = parse_mpc_sig(&input.signature_json)?;
    let (signed_tx, tx_hash) = tx::attach_signature(&unsigned, &sig)?;
    Ok(AttachSignatureOutput {
        signed_tx: fmt_hex_0x(&signed_tx),
        tx_hash: fmt_hex_0x(&tx_hash),
    })
}

/// Submit a fully-signed tx via `eth_sendRawTransaction` and return the
/// node-confirmed tx_hash.
pub fn send_signed_tx<F>(input: &SendSignedTxInput, http: F) -> Result<SendSignedTxOutput, String>
where
    F: Fn(&str, &str, &str, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String>,
{
    let tx_hash = rpc::send_raw_tx(&http, input.chain_id, &input.signed_tx)?;
    Ok(SendSignedTxOutput { tx_hash })
}

// ── Internal helpers ─────────────────────────────────────────────────────────

fn fmt_hex_0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_value_decimal_001942() {
        let out = parse_value(&ParseValueInput {
            value_eth: "0.001942".to_string(),
        })
        .unwrap();
        assert_eq!(out.value_hex, "0x06e63d1c276000");
    }

    #[test]
    fn parse_value_one_eth() {
        let out = parse_value(&ParseValueInput {
            value_eth: "1".to_string(),
        })
        .unwrap();
        assert_eq!(out.value_hex, "0x0de0b6b3a7640000");
    }

    #[test]
    fn parse_value_decimal_001() {
        let out = parse_value(&ParseValueInput {
            value_eth: "0.01".to_string(),
        })
        .unwrap();
        assert_eq!(out.value_hex, "0x2386f26fc10000");
    }

    #[test]
    fn parse_value_one_gwei() {
        let out = parse_value(&ParseValueInput {
            value_eth: "0.000000001".to_string(),
        })
        .unwrap();
        assert_eq!(out.value_hex, "0x3b9aca00");
    }

    #[test]
    fn parse_value_decimal_0248291() {
        let out = parse_value(&ParseValueInput {
            value_eth: "0.0248291".to_string(),
        })
        .unwrap();
        assert_eq!(out.value_hex, "0x5835ef5597b800");
    }

    #[test]
    fn parse_value_zero() {
        let out = parse_value(&ParseValueInput {
            value_eth: "0".to_string(),
        })
        .unwrap();
        assert_eq!(out.value_hex, "0x");
    }

    #[test]
    fn build_transfer_sepolia_vector_1() {
        let out = build_transfer_mpc_payload(&BuildTransferInput {
            chain_id: 11155111,
            from: "0x1a3e6cc60d9a2cca864d4be4c75189de7528a3c4".to_string(),
            to: "0x2f318C334780961FB129D2a6c30D0763d9a5C970".to_string(),
            value_hex: "0x06e63d1c276000".to_string(),
            nonce: 19,
            gas_limit: 39688,
            max_fee_per_gas: "0x1e9936".to_string(),
            max_priority_fee_per_gas: "0x0f4240".to_string(),
        })
        .unwrap();
        assert_eq!(
            out.mpc_payload,
            "861e34cc275d0b5d3d426ffff2898ef67ea47db2443a2a300289e4fdf83ea8fa"
        );
        assert_eq!(
            out.tx,
            "0x02ef83aa36a713830f4240831e9936829b08942f318c334780961fb129d2a6c30d0763d9a5c9708706e63d1c27600080c0"
        );
    }

    #[test]
    fn build_transfer_sepolia_vector_2() {
        let out = build_transfer_mpc_payload(&BuildTransferInput {
            chain_id: 11155111,
            from: "0x1a3e6cc60d9a2cca864d4be4c75189de7528a3c4".to_string(),
            to: "0x2f318C334780961FB129D2a6c30D0763d9a5C970".to_string(),
            value_hex: "0x5835ef5597b800".to_string(),
            nonce: 20,
            gas_limit: 39688,
            max_fee_per_gas: "0x232bbc".to_string(),
            max_priority_fee_per_gas: "0x0f4240".to_string(),
        })
        .unwrap();
        assert_eq!(
            out.mpc_payload,
            "ce5735b80ac65a0af5240de2a80a7238a4ea986db9e04293c4b7837636b4303e"
        );
        assert_eq!(
            out.tx,
            "0x02ef83aa36a714830f424083232bbc829b08942f318c334780961fb129d2a6c30d0763d9a5c970875835ef5597b80080c0"
        );
    }

    #[test]
    fn attach_signature_sepolia_vector_1() {
        let out = attach_mpc_signature_to_tx(&AttachSignatureInput {
            tx: "0x02ef83aa36a713830f4240831e9936829b08942f318c334780961fb129d2a6c30d0763d9a5c9708706e63d1c27600080c0".to_string(),
            signature_json: r#"{"scheme":"Secp256k1","big_r":{"affine_point":"031ee7385ab76e1848db151c3b82f76073c10b0e3997ea056a1f7768e5432ec530"},"s":{"scalar":"5858f1e998b2a2fa98d5707d9ffc21cf8c8b485f49ba2fced315f254adff7d77"},"recovery_id":1}"#.to_string(),
        })
        .unwrap();
        assert_eq!(
            out.signed_tx,
            "0x02f87283aa36a713830f4240831e9936829b08942f318c334780961fb129d2a6c30d0763d9a5c9708706e63d1c27600080c001a01ee7385ab76e1848db151c3b82f76073c10b0e3997ea056a1f7768e5432ec530a05858f1e998b2a2fa98d5707d9ffc21cf8c8b485f49ba2fced315f254adff7d77"
        );
    }

    #[test]
    fn attach_signature_sepolia_vector_2() {
        let out = attach_mpc_signature_to_tx(&AttachSignatureInput {
            tx: "0x02ef83aa36a714830f424083232bbc829b08942f318c334780961fb129d2a6c30d0763d9a5c970875835ef5597b80080c0".to_string(),
            signature_json: r#"{"scheme":"Secp256k1","big_r":{"affine_point":"0238c65b084b38aca107941803d5485293bf6ac31c5369e632aaf230bcc80a51ef"},"s":{"scalar":"7027fa2b248e4c0dbbe0d7b16ff4c7f16d6af413b1afa71ea2789a6b69f4b34f"},"recovery_id":0}"#.to_string(),
        })
        .unwrap();
        assert_eq!(
            out.signed_tx,
            "0x02f87283aa36a714830f424083232bbc829b08942f318c334780961fb129d2a6c30d0763d9a5c970875835ef5597b80080c080a038c65b084b38aca107941803d5485293bf6ac31c5369e632aaf230bcc80a51efa07027fa2b248e4c0dbbe0d7b16ff4c7f16d6af413b1afa71ea2789a6b69f4b34f"
        );
    }

    #[test]
    fn encode_data_set_uint256() {
        let out = encode_data(&EncodeDataInput {
            abi: "set(uint256)".to_string(),
            args: vec!["5829412".to_string()],
        })
        .unwrap();
        assert_eq!(
            out.data_hex,
            "0x60fe47b1000000000000000000000000000000000000000000000000000000000058f324"
        );
    }

    #[test]
    fn build_function_call_sepolia_vector() {
        let out = build_function_call_mpc_payload(&BuildFunctionCallInput {
            chain_id: 11155111,
            from: "0x1a3e6cc60d9a2cca864d4be4c75189de7528a3c4".to_string(),
            to: "0xFf3171733b73Cfd5A72ec28b9f2011Dc689378c6".to_string(),
            value_hex: "0x".to_string(),
            data_hex: "0x60fe47b1000000000000000000000000000000000000000000000000000000000058f324"
                .to_string(),
            nonce: 21,
            gas_limit: 32390,
            max_fee_per_gas: "0x2bc416".to_string(),
            max_priority_fee_per_gas: "0x0f4240".to_string(),
        })
        .unwrap();
        assert_eq!(
            out.mpc_payload,
            "1697acd187d0c479c913fb4dc05b9c1b24bcf9571d1091be32a03b2faf9466f7"
        );
        assert_eq!(
            out.tx,
            "0x02f84c83aa36a715830f4240832bc416827e8694ff3171733b73cfd5a72ec28b9f2011dc689378c680a460fe47b1000000000000000000000000000000000000000000000000000000000058f324c0"
        );
    }

    #[test]
    fn attach_signature_function_call_sepolia_vector() {
        let out = attach_mpc_signature_to_tx(&AttachSignatureInput {
            tx: "0x02f84c83aa36a715830f4240832bc416827e8694ff3171733b73cfd5a72ec28b9f2011dc689378c680a460fe47b1000000000000000000000000000000000000000000000000000000000058f324c0".to_string(),
            signature_json: r#"{"big_r":{"affine_point":"03ed577c868632641f40ca4184b7ddd46f538ddb76a0dea7a99d152ee82f068166"},"recovery_id":1,"s":{"scalar":"6d5a7e6ccb11dc1f098c0aea5b97dec7db7920bd9bc66adbbdd4cc8573f24a1b"},"scheme":"Secp256k1"}"#.to_string(),
        })
        .unwrap();
        assert_eq!(
            out.signed_tx,
            "0x02f88f83aa36a715830f4240832bc416827e8694ff3171733b73cfd5a72ec28b9f2011dc689378c680a460fe47b1000000000000000000000000000000000000000000000000000000000058f324c001a0ed577c868632641f40ca4184b7ddd46f538ddb76a0dea7a99d152ee82f068166a06d5a7e6ccb11dc1f098c0aea5b97dec7db7920bd9bc66adbbdd4cc8573f24a1b"
        );
    }
}
