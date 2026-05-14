---
name: near-mpc
version: 0.5.2
description: Sign and broadcast EVM, Bitcoin, and Solana transactions using NEAR's MPC chain-signatures contract
activation:
  keywords:
    - sepolia
    - Sepolia
    - .testnet
    - ethereum
    - bitcoin
    - eth
    - ETH
    - btc
    - BTC
    - solana
    - Solana
    - SOL
    - sol
    - mpc
  patterns:
    - "transfer.*[Ee][Tt][Hh]"
    - "send.*[Ee][Tt][Hh]"
    - "transfer.*[Bb][Tt][Cc]"
    - "send.*[Bb][Tt][Cc]"
    - ".*\\.testnet"
    - "sign.*transaction.*near"
    - "broadcast.*evm"
    - "broadcast.*bitcoin"
    - "broadcast.*solana"
    - "near.*mpc.*sign"
    - "chain.?signatures"
    - "transfer.*[Ss][Oo][Ll]"
    - "send.*[Ss][Oo][Ll]"
    - "near mpc"
  tags:
    - blockchain
    - near
    - signing
  max_context_tokens: 4000
---

# NEAR MPC Cross-Chain Signing Skill

Use this skill whenever the user wants to sign and broadcast a transaction
on an EVM-compatible chain, Bitcoin, or Solana using NEAR's MPC contract
(`v1.signer-prod.testnet`).

The skill is split into four sections: a **Common** preamble that applies
to every flow, then one section per chain (**EVM Flow**, **Bitcoin Flow**,
**Solana Flow**). Pick the chain section matching the user's destination
and follow it top-to-bottom. Every action shows both an input and output
JSON example.

---

## Overview

The agent orchestrates the following at a high level:

1. Derive the cross-chain address from the user's NEAR account
2. Build an unsigned transaction + signing payload
3. Call the NEAR MPC contract to sign the payload (via `near-cli-rs`)
4. Attach the MPC signature to produce the broadcast-ready signed tx
5. Broadcast the signed tx to the destination chain

EVM exposes a granular per-step API (one action per RPC call); Bitcoin and
Solana use bundled actions today. A future refactor will give them the
same granularity.

---

## Common — NEAR setup

Every flow starts with these steps.

### 1. Identify destination chain and intent

Determine:

- **Destination chain**: EVM (Ethereum, Base, Arbitrum, Optimism, Sepolia,
  …), Bitcoin (mainnet/testnet), or Solana (mainnet/devnet).
- **User intent**: transfer, contract call, etc.

### 2. Gather NEAR credentials

Ask the user for:

- **NEAR account ID** (e.g. `alice.testnet`)
- **Derivation path** (e.g. `0`, `random_text`, `ethereum`, `name`)
- **NEAR network** — `testnet` or `mainnet`

### 3. `get_derived_pubkey` — derive cross-chain addresses

**Input:**

```json
{
  "action": "get_derived_pubkey",
  "near_account": "alice.testnet",
  "path": "ethereum",
  "near_network": "testnet"
}
```

**Output:**

```json
{
  "pubkey_near": "secp256k1:3S3g3cgFXSos7YEEr3Z4EttPRFkrxUJsyYV4Ge5HwdMyMo8ur6D3TUxy2QDtD6grFbcLS55V9sXVhg3NDQ6xV8ss",
  "evm_address": "0x1a3e6cc60d9a2cca864d4be4c75189de7528a3c4",
  "btc_address_mainnet": "bc1q...",
  "btc_address_testnet": "tb1q...",
  "solana_address": "BasE58SolAddR3sS..."
}
```

Show the user their address and confirm they have funded it before
proceeding. Pick the field matching the destination chain:

- EVM → `evm_address`
- Bitcoin → `btc_address_mainnet` / `btc_address_testnet` (use as `from` in BTC build action)
- Solana → `solana_address`
- Bitcoin (attach) → `pubkey_near` (still needed by `btc_attach_mpc_signature_to_tx`).

### 4. NEAR MPC sign command (used by every flow)

When you reach the "sign payload via MPC" step in any flow, run the
appropriate `near-cli-rs` command in the user's shell. The command shape
depends on the signature scheme.

**EVM and Bitcoin** (secp256k1, `domain_id=0`):

```bash
near contract call-function as-transaction v1.signer-prod.testnet sign \
  json-args '{"request": {"path":"<PATH>","payload_v2":{"Ecdsa":"<MPC_PAYLOAD>"},"domain_id":0} }' \
  prepaid-gas '250 Tgas' attached-deposit '1 yoctoNEAR' \
  sign-as <NEAR_ACCOUNT> network-config <NEAR_NETWORK> sign-with-keychain send
```

The output contains:

```json
{
  "scheme": "Secp256k1",
  "big_r": { "affine_point": "<hex33>" },
  "s": { "scalar": "<hex32>" },
  "recovery_id": 0
}
```

**Solana** (ed25519, `domain_id=1`):

```bash
near contract call-function as-transaction v1.signer-prod.testnet sign \
  json-args '{"request": {"path":"<PATH>","payload_v2":{"Eddsa":"<MPC_PAYLOAD>"},"domain_id":1}}' \
  prepaid-gas '250 Tgas' attached-deposit '1 yoctoNEAR' \
  sign-as <NEAR_ACCOUNT> network-config <NEAR_NETWORK> sign-with-keychain send
```

Output:

```json
{ "scheme": "Ed25519", "signature": [107, 187, 225, ...] }
```

**Substitution rules (apply to either command):**

- `<PATH>` = derivation path (Common §2)
- `<NEAR_ACCOUNT>` = user's NEAR account ID
- `<NEAR_NETWORK>` = `testnet` or `mainnet`
- `<MPC_PAYLOAD>` = the `mpc_payload` field returned by the build action
  for that flow. **The build action emits `mpc_payload` as raw hex with
  no `0x` prefix specifically so it can be pasted here directly.** Do
  NOT add or strip any prefix.

When the command returns, JSON-encode its output (the `SignatureResponse`
object) into a single string and pass it to the chain's
`*_attach_mpc_signature_to_tx` (or `reconstruct_*_tx`) action as
`signature_json`.

---

## EVM Flow

### 1. Gather EVM transaction parameters

Ask the user for:

- `chain_id` — numeric EVM chain ID for the target network (table below)
- `from` — sender address (the `evm_address` from Common §3)
- `to` — destination address (`0x`-prefixed)
- `value_eth` — amount as a decimal-ETH string (e.g. `"1.5"`,
  `"0.001"`, `"0"`)
- `abi` and `args` — only for contract calls; see `evm_encode_data` below
  for encoding rules.

**Supported `chain_id` values:**

| Network          | `chain_id` |
| ---------------- | ---------- |
| Ethereum mainnet | `1`        |
| Optimism         | `10`       |
| Base             | `8453`     |
| Arbitrum One     | `42161`    |
| Sepolia testnet  | `11155111` |

### 2. `evm_parse_value` — convert decimal ETH to wei hex

**Input:**

```json
{ "action": "evm_parse_value", "value_eth": "0.001" }
```

**Output:**

```json
{ "value_hex": "0x038d7ea4c68000" }
```

For zero-value calls, pass `"0"` and you'll get `value_hex: "0x"`.

### 3. `evm_encode_data` — encode contract calldata (CONTRACT CALLS ONLY)

**Skip this step for plain ETH transfers** — instead, use `data_hex: "0x"`
in subsequent steps.

`args` is required even for no-arg functions (use `[]`).

Argument encoding rules:

- `address` → `"0x<40 hex chars>"`
- `uint<N>` / `int<N>` → decimal string, e.g. `"1000000000000000000"`
  (negatives allowed only for `int`)
- `bool` → `"true"` or `"false"`
- `bytes<N>` → `"0x<2N hex chars>"`
- `bytes` → `"0x<hex>"`
- `string` → raw UTF-8 value

**Input:**

```json
{
  "action": "evm_encode_data",
  "abi": "transfer(address,uint256)",
  "args": ["0xAb5801a7D398351b8bE11C439e05C5B3259aec9B", "1000000000000000000"]
}
```

**Output:**

```json
{
  "data_hex": "0xa9059cbb000000000000000000000000ab5801a7d398351b8be11c439e05c5b3259aec9b0000000000000000000000000000000000000000000000000de0b6b3a7640000"
}
```

### 4. `evm_get_nonce` — fetch next pending nonce

**Input:**

```json
{
  "action": "evm_get_nonce",
  "chain_id": 11155111,
  "from": "0x1a3e6cc60d9a2cca864d4be4c75189de7528a3c4"
}
```

**Output:**

```json
{ "nonce": 18 }
```

### 5. `evm_get_gas_price` — fetch eth_gasPrice

**Input:**

```json
{ "action": "evm_get_gas_price", "chain_id": 11155111 }
```

**Output:**

```json
{ "gas_price": "0x4de9d0b4" }
```

### 6. `evm_get_priority_fee_wei_per_gas` — derive priority_fee + max_fee_per_gas

Takes the `gas_price` from step 5. Applies the policy
`max_fee_per_gas = max(2 × gas_price, priority_fee)` to produce both
fee fields ready for the build step.

**Input:**

```json
{
  "action": "evm_get_priority_fee_wei_per_gas",
  "chain_id": 11155111,
  "gas_price": "0x4de9d0b4"
}
```

**Output:**

```json
{ "priority_fee": "0xf4240", "max_fee_per_gas": "0x9bd3a168" }
```

### 7. `evm_estimate_gas` — fetch gas_limit (with 20% buffer)

`data_hex` is `"0x"` for transfers; for contract calls, pass the value
returned by `evm_encode_data` in step 3.

**Input:**

```json
{
  "action": "evm_estimate_gas",
  "chain_id": 11155111,
  "from": "0x1a3e6cc60d9a2cca864d4be4c75189de7528a3c4",
  "to": "0xff3171733b73cfd5a72ec28b9f2011dc689378c6",
  "value_hex": "0x038d7ea4c68000",
  "data_hex": "0x"
}
```

**Output:**

```json
{ "gas_limit": 25200 }
```

### 8. `evm_build_transfer_mpc_payload` OR `evm_build_function_call_mpc_payload`

Use the **transfer** variant for a plain ETH send (no calldata).

**Input (transfer):**

```json
{
  "action": "evm_build_transfer_mpc_payload",
  "chain_id": 11155111,
  "from": "0x1a3e6cc60d9a2cca864d4be4c75189de7528a3c4",
  "to": "0xff3171733b73cfd5a72ec28b9f2011dc689378c6",
  "value_hex": "0x038d7ea4c68000",
  "nonce": 18,
  "gas_limit": 25200,
  "max_fee_per_gas": "0x9bd3a168",
  "max_priority_fee_per_gas": "0xf4240"
}
```

**Output:**

```json
{
  "tx": "0x02f0...",
  "mpc_payload": "<32-byte hex, no 0x prefix>"
}
```

Use the **function-call** variant for a contract call. Identical schema
plus a `data_hex` field.

**Input (function call):**

```json
{
  "action": "evm_build_function_call_mpc_payload",
  "chain_id": 11155111,
  "from": "0x1a3e6cc60d9a2cca864d4be4c75189de7528a3c4",
  "to": "0xff3171733b73cfd5a72ec28b9f2011dc689378c6",
  "value_hex": "0x",
  "data_hex": "0x60fe47b1000000000000000000000000000000000000000000000000000000000000001f",
  "nonce": 18,
  "gas_limit": 26968,
  "max_fee_per_gas": "0x4de9d0b4",
  "max_priority_fee_per_gas": "0xf4240"
}
```

**Output:**

```json
{
  "tx": "0x02f84d83aa36a712830f4240844de9d0b482695894ff3171733b73cfd5a72ec28b9f2011dc689378c680a460fe47b1000000000000000000000000000000000000000000000000000000000000001fc0",
  "mpc_payload": "289773225b98ac124f05c6e61b1f8da632c9483080e4186c8dcb13c4d53cd765"
}
```

`mpc_payload` has **no `0x` prefix** — it's emitted as raw hex so the
agent can paste it directly into the `near-cli-rs` command in the next
step. Do not add or strip any prefix.

### 9. NEAR MPC sign

Run the secp256k1 (`Ecdsa`, `domain_id=0`) command from Common §4 with
`<MPC_PAYLOAD>` = the `mpc_payload` from step 8. Capture the
`SignatureResponse` JSON output.

### 10. `evm_attach_mpc_signature_to_tx` — produce signed tx + tx_hash

Pass the `tx` from step 8 and the JSON-encoded string of the MPC
response.

**Input:**

```json
{
  "action": "evm_attach_mpc_signature_to_tx",
  "tx": "0x02f84d83aa36a712830f4240844de9d0b482695894ff3171733b73cfd5a72ec28b9f2011dc689378c680a460fe47b1000000000000000000000000000000000000000000000000000000000000001fc0",
  "signature_json": "{\"scheme\":\"Secp256k1\",\"big_r\":{\"affine_point\":\"026763b726487cf3ebf752625d86ba03ba3ce69ae1cbf8c6f5f5006d8120e6645e\"},\"s\":{\"scalar\":\"6fea2920925fb0ae0377ccf762c01026043e4af677be9d5c485f04737d60cecd\"},\"recovery_id\":0}"
}
```

**Output:**

```json
{
  "signed_tx": "0x02f89083aa36a712830f4240844de9d0b482695894ff3171733b73cfd5a72ec28b9f2011dc689378c680a460fe47b1000000000000000000000000000000000000000000000000000000000000001fc080a06763b726487cf3ebf752625d86ba03ba3ce69ae1cbf8c6f5f5006d8120e6645ea06fea2920925fb0ae0377ccf762c01026043e4af677be9d5c485f04737d60cecd",
  "tx_hash": "0xaf4af02ffc7bbc2748df93fc104bba3ca65887b48c4edff6f3634351ad946d5a"
}
```

`signature_json` MUST be a JSON-encoded string (not a nested object).

### 11. `evm_send_signed_tx` — broadcast

**Input:**

```json
{
  "action": "evm_send_signed_tx",
  "chain_id": 11155111,
  "signed_tx": "0x02f89083aa36a712830f4240844de9d0b482695894ff3171733b73cfd5a72ec28b9f2011dc689378c680a460fe47b1000000000000000000000000000000000000000000000000000000000000001fc080a06763b726487cf3ebf752625d86ba03ba3ce69ae1cbf8c6f5f5006d8120e6645ea06fea2920925fb0ae0377ccf762c01026043e4af677be9d5c485f04737d60cecd"
}
```

**Output:**

```json
{
  "tx_hash": "0xaf4af02ffc7bbc2748df93fc104bba3ca65887b48c4edff6f3634351ad946d5a"
}
```

### 12. Confirm

Show the user the `tx_hash` from step 10 (which equals step 11) with the
matching block-explorer link from the table at the bottom of this skill.

---

## Bitcoin Flow

### 1. Gather parameters

Ask the user for:

- `network` — `mainnet` or `testnet`
- `outputs` — recipient(s) only: `address` + `amount_sats`. Do **not**
  include a change output.
- Optionally: BTC decimal amount (e.g. `"0.001 BTC"`) if the user hasn't
  specified `amount_sats` yet.

### 2. `btc_parse_value` — convert decimal BTC to sats (if needed)

**Input:**

```json
{ "action": "btc_parse_value", "btc": "0.001" }
```

**Output:**

```json
{ "sats": 100000 }
```

### 3. `btc_get_utxos` — fetch all UTXOs for the sender address

**Input:**

```json
{
  "action": "btc_get_utxos",
  "network": "testnet",
  "address": "tb1q..."
}
```

**Output:**

```json
{
  "utxos": [
    { "txid": "...", "vout": 0, "amount_sats": 150000, "confirmed": true }
  ]
}
```

### 4. `btc_get_fee_rate` — fetch current fee rate

**Input:**

```json
{ "action": "btc_get_fee_rate", "network": "testnet" }
```

**Output:**

```json
{ "fee_rate_sat_vbyte": 2 }
```

### 5. `btc_build_transfer_mpc_payload` — build unsigned tx + one sighash per input

**Input:**

```json
{
  "action": "btc_build_transfer_mpc_payload",
  "network": "testnet",
  "from": "tb1q...",
  "inputs": [{ "txid": "...", "vout": 0, "amount_sats": 150000 }],
  "outputs": [{ "address": "tb1q...", "amount_sats": 100000 }],
  "fee_rate_sat_vbyte": 2
}
```

**Output:**

```json
{
  "tx": "<bare hex unsigned tx>",
  "mpc_payloads": ["<hash1>", "<hash2>"]
}
```

`mpc_payloads` has one entry per input — sign each separately via MPC.

### 6. NEAR MPC sign — repeat once per entry in `mpc_payloads`

For each payload in `mpc_payloads`, run the secp256k1 (`Ecdsa`,
`domain_id=0`) command from Common §4 with `<MPC_PAYLOAD>` = that entry.

Collect all `SignatureResponse` JSON objects; **stringify each one** (the
entire JSON object becomes a single string element in `signatures_json`).

### 7. `btc_attach_mpc_signature_to_tx` — assemble witness for all inputs

**Input:**

```json
{
  "action": "btc_attach_mpc_signature_to_tx",
  "network": "testnet",
  "tx": "<bare hex from step 5>",
  "pubkey_near": "secp256k1:3S3g3cgFXSos7YEEr3Z4EttPRFkrxUJsyYV4Ge5HwdMyMo8ur6D3TUxy2QDtD6grFbcLS55V9sXVhg3NDQ6xV8ss",
  "signatures_json": [
    "{\"scheme\":\"Secp256k1\",\"big_r\":{...},\"s\":{...},\"recovery_id\":0}"
  ]
}
```

**Output:**

```json
{
  "signed_tx": "<bare hex>",
  "tx_hash": "<bare hex txid>"
}
```

### 8. `btc_send_signed_tx` — broadcast

**Input:**

```json
{
  "action": "btc_send_signed_tx",
  "network": "testnet",
  "signed_tx": "<bare hex from step 7>"
}
```

**Output:**

```json
{ "tx_hash": "<bare hex txid>" }
```

### 9. Confirm

Show the user the `tx_hash` with the matching block-explorer link.

---

## Solana Flow

### 1. Gather Solana transaction parameters

Ask the user for:

- `network` — `mainnet` or `devnet`
- `to` — recipient Solana address (base58)
- `amount_sol` — amount in SOL as a decimal number (e.g. `0.5`, `0.001`)

### 2. `build_sol_payload` — build versioned tx message

**Input:**

```json
{
  "action": "build_sol_payload",
  "network": "devnet",
  "from_pubkey": "<solana_address from Common §3>",
  "to": "<recipient base58>",
  "amount_sol": 0.001
}
```

**Output:**

```json
{
  "unsigned_tx_hex": "<hex>",
  "payload_hex": "<message hex sighash>"
}
```

Save both fields for the next steps.

### 3. NEAR MPC sign

Run the ed25519 (`Eddsa`, `domain_id=1`) command from Common §4 with
`<MPC_PAYLOAD>` = the `payload_hex` from step 2.

### 4. `reconstruct_sol_tx` — produce signed tx + tx_hash

**Input:**

```json
{
  "action": "reconstruct_sol_tx",
  "unsigned_tx_hex": "<from step 2>",
  "signature_json": "{\"scheme\":\"Ed25519\",\"signature\":[107,187,...]}"
}
```

**Output:**

```json
{
  "signed_tx_base64": "<base64>",
  "tx_hash": "<base58 signature>"
}
```

### 5. `broadcast_sol` — submit via sendTransaction

**Input:**

```json
{
  "action": "broadcast_sol",
  "network": "devnet",
  "signed_tx_base64": "<from step 4>"
}
```

**Output:**

```json
{ "tx_hash": "<base58 signature>" }
```

### 6. Confirm

Show the user the `tx_hash` with the matching explorer link below.

---

## Block explorer links

Pick the URL matching the chain + network used:

- **Ethereum mainnet**: `https://etherscan.io/tx/<tx_hash>`
- **Sepolia**: `https://sepolia.etherscan.io/tx/<tx_hash>`
- **Base**: `https://basescan.org/tx/<tx_hash>`
- **Arbitrum**: `https://arbiscan.io/tx/<tx_hash>`
- **Optimism**: `https://optimistic.etherscan.io/tx/<tx_hash>`
- **Bitcoin mainnet**: `https://mempool.space/tx/<tx_hash>`
- **Bitcoin testnet**: `https://mempool.space/testnet4/tx/<tx_hash>`
- **Solana mainnet**: `https://explorer.solana.com/tx/<tx_hash>`
- **Solana devnet**: `https://explorer.solana.com/tx/<tx_hash>?cluster=devnet`
