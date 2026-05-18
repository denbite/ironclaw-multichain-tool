use super::abi::SerializedInstruction;

pub(crate) fn compact_u16(mut n: u16) -> Vec<u8> {
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

pub(crate) fn serialize_v0_message(
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
