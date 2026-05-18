pub(crate) struct SerializedInstruction {
    pub(crate) program_id_index: u8,
    pub(crate) account_indices: Vec<u8>,
    pub(crate) data: Vec<u8>,
}

pub(crate) fn encode_system_transfer(
    from_idx: u8,
    to_idx: u8,
    system_program_idx: u8,
    lamports: u64,
) -> SerializedInstruction {
    // System::Transfer discriminant = 2 (LE u32) followed by lamports (LE u64)
    let mut data = vec![2u8, 0, 0, 0];
    data.extend_from_slice(&lamports.to_le_bytes());
    SerializedInstruction {
        program_id_index: system_program_idx,
        account_indices: vec![from_idx, to_idx],
        data,
    }
}

pub(crate) fn encode_compute_budget_price(
    cb_program_idx: u8,
    micro_lamports: u64,
) -> SerializedInstruction {
    // SetComputeUnitPrice discriminant = 3, payload = u64 LE
    let mut data = vec![3u8];
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    SerializedInstruction {
        program_id_index: cb_program_idx,
        account_indices: vec![],
        data,
    }
}

pub(crate) fn encode_compute_budget_limit(
    cb_program_idx: u8,
    units: u32,
) -> SerializedInstruction {
    // SetComputeUnitLimit discriminant = 2, payload = u32 LE
    let mut data = vec![2u8];
    data.extend_from_slice(&units.to_le_bytes());
    SerializedInstruction {
        program_id_index: cb_program_idx,
        account_indices: vec![],
        data,
    }
}
