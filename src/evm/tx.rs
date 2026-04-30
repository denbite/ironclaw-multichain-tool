//! EIP-1559 transaction assembly: build the unsigned tx, attach an MPC
//! signature to produce a fully-signed, broadcast-ready tx.
//!
//! Pure computation — no I/O.

use super::{rlp, rpc};
use crate::crypto::{keccak256, MpcSig};

/// Build the `0x02`-prefixed RLP-encoded EIP-1559 unsigned transaction
/// (9 fields: chain_id, nonce, max_priority_fee, max_fee, gas_limit, to,
/// value, data, access_list).
pub(crate) fn build_unsigned_eip1559_tx(
    chain_id: u64,
    nonce: u64,
    max_priority_fee_wei: u128,
    max_fee_wei: u128,
    gas_limit: u64,
    to: &[u8; 20],
    value_bytes: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let max_priority_bytes = rpc::u128_to_min_be(max_priority_fee_wei);
    let max_fee_bytes = rpc::u128_to_min_be(max_fee_wei);

    let items: Vec<Vec<u8>> = vec![
        rlp::rlp_u64(chain_id),
        rlp::rlp_u64(nonce),
        rlp::rlp_uint_bytes(&max_priority_bytes),
        rlp::rlp_uint_bytes(&max_fee_bytes),
        rlp::rlp_u64(gas_limit),
        rlp::rlp_address(to),
        rlp::rlp_uint_bytes(value_bytes),
        rlp::rlp_bytes(data),
        rlp::rlp_list(&[]), // empty access list
    ];

    let list_encoded = rlp::rlp_list(&items);
    let mut tx_bytes = Vec::with_capacity(1 + list_encoded.len());
    tx_bytes.push(0x02);
    tx_bytes.extend_from_slice(&list_encoded);
    tx_bytes
}

/// Combine an unsigned EIP-1559 tx (`0x02`-prefixed RLP) with an MPC
/// signature and return `(signed_tx, tx_hash)`. `tx_hash` is the
/// keccak256 of `signed_tx`, which equals the on-chain transaction hash.
pub(crate) fn attach_signature(
    unsigned_tx: &[u8],
    sig: &MpcSig,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    if unsigned_tx.is_empty() || unsigned_tx[0] != 0x02 {
        return Err("unsigned tx must start with 0x02 (EIP-1559 type)".into());
    }
    let list_data = &unsigned_tx[1..];
    let (list_raw, _) = rlp::read_item(list_data, 0)?;

    // Skip past the list header to find item-payload start.
    let first = list_raw[0];
    let payload_start = if first <= 0xf7 {
        1
    } else {
        1 + (first - 0xf7) as usize
    };

    let mut items: Vec<Vec<u8>> = Vec::with_capacity(12);
    let mut pos = payload_start;
    while pos < list_raw.len() {
        let (item, next) = rlp::read_item(list_raw, pos)?;
        items.push(item.to_vec());
        pos = next;
    }
    if items.len() != 9 {
        return Err(format!(
            "expected 9 RLP items in EIP-1559 unsigned tx, got {}",
            items.len()
        ));
    }

    let r_stripped = rlp::strip_leading_zeros(&sig.r).to_vec();
    let s_stripped = rlp::strip_leading_zeros(&sig.s).to_vec();

    items.push(rlp::rlp_u64(sig.y_parity as u64));
    items.push(rlp::rlp_uint_bytes(&r_stripped));
    items.push(rlp::rlp_uint_bytes(&s_stripped));

    let signed_list = rlp::rlp_list(&items);
    let mut signed_tx = Vec::with_capacity(1 + signed_list.len());
    signed_tx.push(0x02);
    signed_tx.extend_from_slice(&signed_list);

    let tx_hash = keccak256(&signed_tx);
    Ok((signed_tx, tx_hash))
}
