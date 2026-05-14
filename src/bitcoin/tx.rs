//! P2WPKH transaction assembly (BIP143 sighash) and witness attachment.
//!
//! Supports N inputs: `build_unsigned_tx` returns one BIP143 sighash per input;
//! `attach_signatures` attaches one witness per signature in the same order.

use crate::crypto::{der_encode_ecdsa, sha256d, MpcSig};
use super::script::varint;
use super::BtcInput;

/// Compute the segwit vsize for N P2WPKH inputs and the given output scripts.
///
/// weight = (stripped_size × 4) + witness_size
/// vsize  = ⌈weight / 4⌉
pub(crate) fn tx_vsize(n_inputs: usize, out_scripts: &[Vec<u8>]) -> u64 {
    let outputs_bytes: usize = out_scripts
        .iter()
        .map(|s| 8 + varint(s.len() as u64).len() + s.len())
        .sum();

    let stripped_size = 4                                         // version
        + varint(n_inputs as u64).len()                          // input count varint
        + n_inputs * 41                                          // per input: txid(32)+vout(4)+scriptSig(1)+seq(4)
        + varint(out_scripts.len() as u64).len()                 // output count varint
        + outputs_bytes                                          // outputs
        + 4;                                                     // locktime

    let witness_size = 2                                         // segwit marker + flag
        + n_inputs * (1 + 1 + 72 + 1 + 33);                    // per input: item_count+sig_len+sig+pk_len+pk

    let weight = stripped_size * 4 + witness_size;
    ((weight + 3) / 4) as u64
}

/// Build the unsigned (non-witness) transaction and compute one BIP143 sighash
/// per input. All inputs are assumed to be P2WPKH from the same `pubkey_hash`.
///
/// Returns `(unsigned_tx_bytes, sighashes)` where `sighashes[i]` is the
/// 32-byte hash to be signed for `inputs[i]`.
pub(crate) fn build_unsigned_tx(
    inputs: &[BtcInput],
    all_outputs: &[(u64, Vec<u8>)],
    pubkey_hash: &[u8; 20],
) -> Result<(Vec<u8>, Vec<[u8; 32]>), String> {
    let n = inputs.len();
    if n == 0 {
        return Err("at least one input required".into());
    }

    // Parse txids: big-endian hex → little-endian bytes (as Bitcoin serializes)
    let txid_le: Vec<[u8; 32]> = inputs
        .iter()
        .map(|inp| {
            let hex_str = inp.txid.strip_prefix("0x").unwrap_or(&inp.txid);
            let mut b = hex::decode(hex_str)
                .map_err(|e| format!("invalid txid '{}': {e}", inp.txid))?;
            if b.len() != 32 {
                return Err(format!("txid must be 32 bytes, got {}", b.len()));
            }
            b.reverse();
            Ok(b.try_into().unwrap())
        })
        .collect::<Result<Vec<_>, String>>()?;

    let seq: u32 = 0xffff_fffd;
    let seq_le = seq.to_le_bytes();

    // BIP143: hashPrevouts = SHA256D(all outpoints concatenated)
    let mut prevouts_cat = Vec::new();
    for (i, inp) in inputs.iter().enumerate() {
        prevouts_cat.extend_from_slice(&txid_le[i]);
        prevouts_cat.extend_from_slice(&inp.vout.to_le_bytes());
    }
    let hash_prevouts = sha256d(&prevouts_cat);

    // BIP143: hashSequence = SHA256D(all sequences concatenated)
    let mut seq_cat = Vec::new();
    for _ in 0..n {
        seq_cat.extend_from_slice(&seq_le);
    }
    let hash_sequence = sha256d(&seq_cat);

    // BIP143: hashOutputs = SHA256D(all outputs concatenated)
    let mut outputs_cat = Vec::new();
    for (amount, script) in all_outputs {
        outputs_cat.extend_from_slice(&amount.to_le_bytes());
        outputs_cat.extend_from_slice(&varint(script.len() as u64));
        outputs_cat.extend_from_slice(script);
    }
    let hash_outputs = sha256d(&outputs_cat);

    // P2WPKH scriptCode: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    // Prefixed with its own length (0x19 = 25) as the BIP143 script_code field.
    let mut script_code = Vec::with_capacity(26);
    script_code.push(0x19); // length of what follows
    script_code.push(0x76); // OP_DUP
    script_code.push(0xa9); // OP_HASH160
    script_code.push(0x14); // push 20 bytes
    script_code.extend_from_slice(pubkey_hash);
    script_code.push(0x88); // OP_EQUALVERIFY
    script_code.push(0xac); // OP_CHECKSIG

    // Compute BIP143 sighash for each input
    let sighashes: Vec<[u8; 32]> = inputs
        .iter()
        .enumerate()
        .map(|(i, inp)| {
            let mut preimage = Vec::new();
            preimage.extend_from_slice(&1u32.to_le_bytes());   // nVersion
            preimage.extend_from_slice(&hash_prevouts);
            preimage.extend_from_slice(&hash_sequence);
            preimage.extend_from_slice(&txid_le[i]);           // outpoint txid
            preimage.extend_from_slice(&inp.vout.to_le_bytes()); // outpoint vout
            preimage.extend_from_slice(&script_code);          // scriptCode
            preimage.extend_from_slice(&inp.amount_sats.to_le_bytes()); // value
            preimage.extend_from_slice(&seq_le);               // nSequence
            preimage.extend_from_slice(&hash_outputs);
            preimage.extend_from_slice(&0u32.to_le_bytes());   // nLocktime
            preimage.extend_from_slice(&1u32.to_le_bytes());   // SIGHASH_ALL
            sha256d(&preimage)
        })
        .collect();

    // Build unsigned (non-witness / legacy) transaction
    let mut unsigned_tx = Vec::new();
    unsigned_tx.extend_from_slice(&1u32.to_le_bytes()); // version
    unsigned_tx.extend_from_slice(&varint(n as u64));   // input count
    for (i, inp) in inputs.iter().enumerate() {
        unsigned_tx.extend_from_slice(&txid_le[i]);
        unsigned_tx.extend_from_slice(&inp.vout.to_le_bytes());
        unsigned_tx.push(0x00); // empty scriptSig (SegWit P2WPKH)
        unsigned_tx.extend_from_slice(&seq_le);
    }
    unsigned_tx.extend_from_slice(&varint(all_outputs.len() as u64)); // output count
    for (amount, script) in all_outputs {
        unsigned_tx.extend_from_slice(&amount.to_le_bytes());
        unsigned_tx.extend_from_slice(&varint(script.len() as u64));
        unsigned_tx.extend_from_slice(script);
    }
    unsigned_tx.extend_from_slice(&0u32.to_le_bytes()); // locktime

    Ok((unsigned_tx, sighashes))
}

/// Attach MPC signatures to an unsigned tx, producing the segwit serialization
/// and the Bitcoin txid (= SHA256D of the non-witness serialization, reversed).
///
/// `signatures` must be in the same order as the inputs (and `mpc_payloads`).
pub(crate) fn attach_signatures(
    unsigned_tx: &[u8],
    signatures: &[MpcSig],
    compressed_pubkey: &[u8; 33],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if unsigned_tx.len() < 8 {
        return Err("unsigned tx too short".into());
    }
    if signatures.is_empty() {
        return Err("at least one signature required".into());
    }

    let version = &unsigned_tx[0..4];
    let locktime = &unsigned_tx[unsigned_tx.len() - 4..];
    let middle = &unsigned_tx[4..unsigned_tx.len() - 4];

    let mut segwit_tx = Vec::new();
    segwit_tx.extend_from_slice(version);
    segwit_tx.push(0x00); // segwit marker
    segwit_tx.push(0x01); // segwit flag
    segwit_tx.extend_from_slice(middle);

    // One witness stack per input, in input order
    for sig in signatures {
        let der_sig = der_encode_ecdsa(&sig.r, &sig.s);
        segwit_tx.push(0x02); // 2 witness stack items
        segwit_tx.extend_from_slice(&varint(der_sig.len() as u64));
        segwit_tx.extend_from_slice(&der_sig);
        segwit_tx.push(0x21); // 33-byte compressed pubkey
        segwit_tx.extend_from_slice(compressed_pubkey);
    }

    segwit_tx.extend_from_slice(locktime);

    // txid = SHA256D of non-witness serialization, then reversed (Bitcoin display order)
    let mut txid = sha256d(unsigned_tx);
    txid.reverse();

    Ok((segwit_tx, txid.to_vec()))
}
