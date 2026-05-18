use crate::crypto::base58_decode;

use super::{abi, borsh};

const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";

// A plain SOL transfer consumes ~150-300 compute units; 5 000 is a safe ceiling.
const TRANSFER_COMPUTE_UNIT_LIMIT: u32 = 5_000;

fn parse_pubkey(s: &str) -> Result<[u8; 32], String> {
    let bytes = base58_decode(s).map_err(|e| format!("invalid Solana pubkey '{s}': {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("Solana pubkey must be 32 bytes: '{s}'"))
}

/// Assemble and serialise a Solana v0 SOL transfer message.
///
/// Account table layout (insertion order determines header counts):
///   [0]    fee_payer          — writable signer
///   [1]    to_pubkey          — writable non-signer
///   [2]    ComputeBudget prog — readonly non-signer (only when priority_fee > 0)
///   [last] System program     — readonly non-signer
pub(crate) fn build_transfer(
    from: &str,
    to: &str,
    lamports: u64,
    blockhash: &str,
    priority_fee: u64,
) -> Result<Vec<u8>, String> {
    let fee_payer = parse_pubkey(from)?;
    let to_pubkey = parse_pubkey(to)?;

    let bh_vec =
        base58_decode(blockhash).map_err(|e| format!("invalid blockhash '{blockhash}': {e}"))?;
    if bh_vec.len() != 32 {
        return Err(format!("blockhash must be 32 bytes, got {}", bh_vec.len()));
    }
    let recent_blockhash: [u8; 32] = bh_vec.try_into().unwrap();

    let system_program = [0u8; 32];
    let has_priority = priority_fee > 0;

    // Build the static accounts table in Solana-canonical order:
    // writable signers → readonly signers → writable non-signers → readonly non-signers
    let mut accounts: Vec<[u8; 32]> = vec![fee_payer, to_pubkey];
    if has_priority {
        let cb = parse_pubkey(COMPUTE_BUDGET_PROGRAM)
            .map_err(|e| format!("ComputeBudget program key: {e}"))?;
        accounts.push(cb);
    }
    accounts.push(system_program);

    let system_idx = accounts.len() as u8 - 1;
    let cb_idx = if has_priority { system_idx - 1 } else { 0 };

    let num_required_sigs = 1u8;
    let num_readonly_signed = 0u8;
    let num_readonly_unsigned = if has_priority { 2u8 } else { 1u8 };

    let mut instructions = Vec::new();
    if has_priority {
        instructions.push(abi::encode_compute_budget_price(cb_idx, priority_fee));
        instructions.push(abi::encode_compute_budget_limit(cb_idx, TRANSFER_COMPUTE_UNIT_LIMIT));
    }
    instructions.push(abi::encode_system_transfer(0, 1, system_idx, lamports));

    Ok(borsh::serialize_v0_message(
        num_required_sigs,
        num_readonly_signed,
        num_readonly_unsigned,
        &accounts,
        &recent_blockhash,
        &instructions,
    ))
}

/// Prepend the Ed25519 signature to the unsigned v0 message.
///
/// Wire format: `0x01 ‖ sig[64] ‖ message_bytes`
/// (0x01 is compact_u16 encoding of "1 signature")
pub(crate) fn attach_signature(unsigned_msg: &[u8], sig: &[u8; 64]) -> Vec<u8> {
    let mut signed_tx = Vec::with_capacity(1 + 64 + unsigned_msg.len());
    signed_tx.push(0x01);
    signed_tx.extend_from_slice(sig);
    signed_tx.extend_from_slice(unsigned_msg);
    signed_tx
}
