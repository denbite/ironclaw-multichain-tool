wit_bindgen::generate!({
    world: "sandboxed-tool",
    path: "tool.wit",
});

mod bitcoin;
mod crypto;
mod evm;
mod near_rpc;
mod solana;

use serde::Deserialize;

// ── Schema ────────────────────────────────────────────────────────────────────

const SCHEMA: &str = r#"{
  "oneOf": [
    {
      "type": "object",
      "description": "Derive the cross-chain public key and addresses for a NEAR account + path.",
      "properties": {
        "action": { "type": "string", "const": "get_derived_pubkey" },
        "near_account": { "type": "string", "description": "NEAR account ID (e.g. alice.testnet)" },
        "path": { "type": "string", "description": "Derivation path — any arbitrary string (e.g. \"mykey\", \"hot-wallet\", \"account/0\", \"eth-main\", \"1\")" },
        "near_network": { "type": "string", "enum": ["testnet", "mainnet"] }
      },
      "required": ["action", "near_account", "path", "near_network"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "EVM: parse a decimal-ETH string (e.g. '0.001') into a 0x-prefixed hex string of minimal big-endian wei. Pure computation. Up to 18 fractional digits supported (1-wei precision).",
      "properties": {
        "action": { "type": "string", "const": "evm_parse_value" },
        "value_eth": { "type": "string" }
      },
      "required": ["action", "value_eth"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "EVM: encode an ABI function call as 0x-prefixed hex calldata (4-byte selector ++ ABI-encoded args). Pure computation. 'args' is required — use [] for no-arg functions like 'claimReward()'. Argument encoding: address → '0x<40 hex>'; uint<N>/int<N> → decimal string (negatives allowed for int); bool → 'true'/'false'; bytes<N> → '0x<2N hex>'; bytes → '0x<hex>'; string → raw UTF-8 value.",
      "properties": {
        "action": { "type": "string", "const": "evm_encode_data" },
        "abi": { "type": "string", "description": "One-line ABI signature, e.g. 'transfer(address,uint256)'" },
        "args": { "type": "array", "items": { "type": "string" } }
      },
      "required": ["action", "abi", "args"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "EVM: fetch the next pending nonce for `from` via eth_getTransactionCount. Supported chain_id: 1 (Ethereum), 10 (Optimism), 8453 (Base), 42161 (Arbitrum One), 11155111 (Sepolia).",
      "properties": {
        "action": { "type": "string", "const": "evm_get_nonce" },
        "chain_id": { "type": "integer" },
        "from": { "type": "string", "description": "0x-prefixed sender EVM address" }
      },
      "required": ["action", "chain_id", "from"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "EVM: fetch eth_gasPrice and return it as 0x-prefixed hex wei. Pass the result to evm_get_priority_fee_wei_per_gas to derive max_fee_per_gas.",
      "properties": {
        "action": { "type": "string", "const": "evm_get_gas_price" },
        "chain_id": { "type": "integer" }
      },
      "required": ["action", "chain_id"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "EVM: fetch eth_maxPriorityFeePerGas (with 1-Gwei fallback) and combine it with the supplied gas_price to derive a safe max_fee_per_gas = max(2 × gas_price, priority_fee). Returns priority_fee + max_fee_per_gas, both 0x-prefixed hex wei, ready for evm_build_*_mpc_payload.",
      "properties": {
        "action": { "type": "string", "const": "evm_get_priority_fee_wei_per_gas" },
        "chain_id": { "type": "integer" },
        "gas_price": { "type": "string", "description": "0x-prefixed hex wei from evm_get_gas_price" }
      },
      "required": ["action", "chain_id", "gas_price"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "EVM: run eth_estimateGas and return a 20%-buffered gas_limit (raw_estimate + raw_estimate/5) suitable for evm_build_*_mpc_payload.",
      "properties": {
        "action": { "type": "string", "const": "evm_estimate_gas" },
        "chain_id": { "type": "integer" },
        "from": { "type": "string" },
        "to": { "type": "string" },
        "value_hex": { "type": "string", "description": "0x-prefixed hex wei (output of evm_parse_value); use '0x' for zero" },
        "data_hex": { "type": "string", "description": "0x-prefixed hex calldata; use '0x' for plain transfers" }
      },
      "required": ["action", "chain_id", "from", "to", "value_hex", "data_hex"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "EVM: build an unsigned EIP-1559 tx for a plain ETH transfer (no calldata). Pure — takes all gas/nonce/fee parameters as inputs. Returns `tx` (0x-prefixed RLP) and `mpc_payload` (raw 32-byte hex, NO 0x prefix — paste directly into the near-cli-rs sign command's payload_v2.Ecdsa field).",
      "properties": {
        "action": { "type": "string", "const": "evm_build_transfer_mpc_payload" },
        "chain_id": { "type": "integer" },
        "from": { "type": "string" },
        "to": { "type": "string" },
        "value_hex": { "type": "string" },
        "nonce": { "type": "integer" },
        "gas_limit": { "type": "integer" },
        "max_fee_per_gas": { "type": "string" },
        "max_priority_fee_per_gas": { "type": "string" }
      },
      "required": ["action", "chain_id", "from", "to", "value_hex", "nonce", "gas_limit", "max_fee_per_gas", "max_priority_fee_per_gas"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "EVM: build an unsigned EIP-1559 tx for a contract call. Same as evm_build_transfer_mpc_payload but with `data_hex` (calldata from evm_encode_data). Pure.",
      "properties": {
        "action": { "type": "string", "const": "evm_build_function_call_mpc_payload" },
        "chain_id": { "type": "integer" },
        "from": { "type": "string" },
        "to": { "type": "string" },
        "value_hex": { "type": "string" },
        "data_hex": { "type": "string" },
        "nonce": { "type": "integer" },
        "gas_limit": { "type": "integer" },
        "max_fee_per_gas": { "type": "string" },
        "max_priority_fee_per_gas": { "type": "string" }
      },
      "required": ["action", "chain_id", "from", "to", "value_hex", "data_hex", "nonce", "gas_limit", "max_fee_per_gas", "max_priority_fee_per_gas"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "EVM: combine an unsigned tx with the MPC SignatureResponse JSON to produce signed_tx and tx_hash. Pure computation — no network call.",
      "properties": {
        "action": { "type": "string", "const": "evm_attach_mpc_signature_to_tx" },
        "tx": { "type": "string", "description": "0x-prefixed unsigned tx from evm_build_*_mpc_payload" },
        "signature_json": { "type": "string", "description": "JSON-encoded SignatureResponse string from the MPC contract (Secp256k1 scheme)" }
      },
      "required": ["action", "tx", "signature_json"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "EVM: submit a signed tx via eth_sendRawTransaction. Returns tx_hash from the node.",
      "properties": {
        "action": { "type": "string", "const": "evm_send_signed_tx" },
        "chain_id": { "type": "integer" },
        "signed_tx": { "type": "string", "description": "0x-prefixed signed_tx from evm_attach_mpc_signature_to_tx" }
      },
      "required": ["action", "chain_id", "signed_tx"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "Fetch all UTXOs (unspent transaction outputs) for a Bitcoin address from Blockstream Esplora. Useful for inspecting balances; build_btc_payload auto-fetches UTXOs so this step is optional in the normal signing flow.",
      "properties": {
        "action": { "type": "string", "const": "get_btc_utxos" },
        "network": { "type": "string", "enum": ["mainnet", "testnet"] },
        "address": { "type": "string", "description": "Bitcoin address (bech32 P2WPKH, e.g. tb1q... or bc1q...)" }
      },
      "required": ["action", "network", "address"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "Build a P2WPKH Bitcoin unsigned transaction and return the BIP143 sighash payload to be signed by the MPC contract. v1: exactly 1 input. UTXOs, fee rate, and change are all handled automatically — only network, pubkey_near, and outputs are required. The tool fetches the largest UTXO for the derived address from Esplora; supply 'inputs' only to override the auto-selected UTXO.",
      "properties": {
        "action": { "type": "string", "const": "build_btc_payload" },
        "network": { "type": "string", "enum": ["mainnet", "testnet"] },
        "pubkey_near": { "type": "string", "description": "secp256k1:<base58> key returned by get_derived_pubkey" },
        "inputs": {
          "type": "array",
          "maxItems": 1,
          "description": "Optional: exactly 1 UTXO to spend. If omitted, the largest UTXO for the derived address is fetched automatically from Esplora.",
          "items": {
            "type": "object",
            "properties": {
              "txid": { "type": "string", "description": "UTXO transaction ID (hex, big-endian)" },
              "vout": { "type": "integer" },
              "amount_sats": { "type": "integer" }
            },
            "required": ["txid", "vout", "amount_sats"]
          }
        },
        "outputs": {
          "type": "array",
          "minItems": 1,
          "description": "Recipient outputs only — do NOT include a change output.",
          "items": {
            "type": "object",
            "properties": {
              "address": { "type": "string" },
              "amount_sats": { "type": "integer" }
            },
            "required": ["address", "amount_sats"]
          }
        },
        "change_address": { "type": "string", "description": "Optional: where to return the change. Defaults to the P2WPKH address derived from pubkey_near." }
      },
      "required": ["action", "network", "pubkey_near", "outputs"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "Reconstruct a signed P2WPKH segwit transaction from the MPC signature. Returns signed_tx_hex and tx_hash without broadcasting. Use broadcast_btc to send it to the network.",
      "properties": {
        "action": { "type": "string", "const": "reconstruct_btc_tx" },
        "network": { "type": "string", "enum": ["mainnet", "testnet"] },
        "unsigned_tx_hex": { "type": "string", "description": "unsigned_tx_hex returned by build_btc_payload" },
        "pubkey_near": { "type": "string", "description": "secp256k1:<base58> key returned by get_derived_pubkey" },
        "signature_json": { "type": "string", "description": "Full SignatureResponse JSON from the MPC contract" }
      },
      "required": ["action", "network", "unsigned_tx_hex", "pubkey_near", "signature_json"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "Broadcast a signed Bitcoin segwit transaction (from reconstruct_btc_tx) via Blockstream Esplora.",
      "properties": {
        "action": { "type": "string", "const": "broadcast_btc" },
        "network": { "type": "string", "enum": ["mainnet", "testnet"] },
        "signed_tx_hex": { "type": "string", "description": "signed_tx_hex returned by reconstruct_btc_tx" }
      },
      "required": ["action", "network", "signed_tx_hex"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "Build a Solana versioned (v0) transaction message for a native SOL transfer and return the serialised bytes as payload_hex, ready to be sent to the NEAR MPC contract with domain_id=1. Automatically fetches the recent blockhash and priority fee. Supported networks: mainnet (api.mainnet-beta.solana.com), devnet (api.devnet.solana.com). The from_pubkey (MPC-derived Solana address) is the fee payer and the only signer.",
      "properties": {
        "action": { "type": "string", "const": "build_sol_payload" },
        "network": { "type": "string", "enum": ["mainnet", "devnet"] },
        "from_pubkey": { "type": "string", "description": "Base58 Solana address from get_derived_pubkey (solana_address field)" },
        "to": { "type": "string", "description": "Recipient Base58 Solana address" },
        "amount_sol": { "type": "number", "description": "Amount of SOL to transfer as a decimal number (e.g. 0.001, 0.5, 1.0)" }
      },
      "required": ["action", "network", "from_pubkey", "to", "amount_sol"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "Reconstruct a signed Solana versioned transaction from the MPC ed25519 signature. Returns signed_tx_base64 (ready for broadcast_sol) and tx_hash (the Solana transaction ID = base58 of the signature). Pure computation — no network call.",
      "properties": {
        "action": { "type": "string", "const": "reconstruct_sol_tx" },
        "unsigned_tx_hex": { "type": "string", "description": "unsigned_tx_hex returned by build_sol_payload" },
        "signature_json": { "type": "string", "description": "Full SignatureResponse JSON from the MPC contract (scheme=Ed25519)" }
      },
      "required": ["action", "unsigned_tx_hex", "signature_json"],
      "additionalProperties": false
    },
    {
      "type": "object",
      "description": "Broadcast a signed Solana transaction (from reconstruct_sol_tx) via the Solana JSON-RPC sendTransaction method.",
      "properties": {
        "action": { "type": "string", "const": "broadcast_sol" },
        "network": { "type": "string", "enum": ["mainnet", "devnet"] },
        "signed_tx_base64": { "type": "string", "description": "signed_tx_base64 returned by reconstruct_sol_tx" }
      },
      "required": ["action", "network", "signed_tx_base64"],
      "additionalProperties": false
    }
  ]
}"#;

const DESCRIPTION: &str = "\
NEAR MPC cross-chain signing tool. EVM chains expose a granular per-step API; \
Bitcoin and Solana use bundled actions. Available actions:\n\
- get_derived_pubkey: derive secp256k1 (EVM/BTC) and ed25519 (Solana) addresses for a (NEAR account, path) pair\n\
- evm_parse_value: convert decimal-ETH string to 0x-prefixed hex wei (pure)\n\
- evm_encode_data: encode an ABI function call to 0x-prefixed hex calldata (pure)\n\
- evm_get_nonce: fetch next pending nonce via eth_getTransactionCount\n\
- evm_get_gas_price: fetch eth_gasPrice as 0x-prefixed hex wei\n\
- evm_get_priority_fee_wei_per_gas: fetch eth_maxPriorityFeePerGas + derive max_fee_per_gas\n\
- evm_estimate_gas: run eth_estimateGas with a 20% buffer\n\
- evm_build_transfer_mpc_payload: build unsigned EIP-1559 ETH transfer; pure (takes all fees as inputs); returns tx + raw mpc_payload\n\
- evm_build_function_call_mpc_payload: as above but with calldata\n\
- evm_attach_mpc_signature_to_tx: combine unsigned tx + MPC signature into signed_tx + tx_hash (pure)\n\
- evm_send_signed_tx: submit signed tx via eth_sendRawTransaction\n\
- get_btc_utxos: inspect UTXOs for a Bitcoin address (optional — build_btc_payload auto-fetches)\n\
- build_btc_payload: build a P2WPKH unsigned tx; auto-fetches UTXOs and change address from pubkey_near\n\
- reconstruct_btc_tx: combine unsigned Bitcoin tx + MPC signature → signed_tx_hex + tx_hash (no broadcast)\n\
- broadcast_btc: submit a signed Bitcoin segwit tx to Esplora\n\
- build_sol_payload: build a Solana v0 transaction message for a native SOL transfer; auto-fetches recent blockhash and priority fee; network: mainnet or devnet; accepts to + amount_sol\n\
- reconstruct_sol_tx: combine unsigned Solana tx + MPC ed25519 signature → signed_tx_base64 + tx_hash (no broadcast)\n\
- broadcast_sol: submit a signed Solana tx via sendTransaction; network: mainnet or devnet\
";

// ── Dispatch ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum ActionInput {
    GetDerivedPubkey(near_rpc::GetDerivedPubkeyInput),

    // EVM (granular per-step actions; see src/evm/mod.rs)
    EvmParseValue(evm::ParseValueInput),
    EvmEncodeData(evm::EncodeDataInput),
    EvmGetNonce(evm::GetNonceInput),
    EvmGetGasPrice(evm::GetGasPriceInput),
    EvmGetPriorityFeeWeiPerGas(evm::GetPriorityFeeInput),
    EvmEstimateGas(evm::EstimateGasInput),
    EvmBuildTransferMpcPayload(evm::BuildTransferInput),
    EvmBuildFunctionCallMpcPayload(evm::BuildFunctionCallInput),
    EvmAttachMpcSignatureToTx(evm::AttachSignatureInput),
    EvmSendSignedTx(evm::SendSignedTxInput),

    // Bitcoin
    GetBtcUtxos(bitcoin::GetBtcUtxosInput),
    BuildBtcPayload(bitcoin::BuildBtcPayloadInput),
    ReconstructBtcTx(bitcoin::ReconstructBtcInput),
    BroadcastBtc(bitcoin::BroadcastBtcInput),

    // Solana
    BuildSolPayload(solana::BuildSolPayloadInput),
    ReconstructSolTx(solana::ReconstructSolTxInput),
    BroadcastSol(solana::BroadcastSolInput),
}

fn do_http(
    method: &str,
    url: &str,
    headers: &str,
    body: Option<Vec<u8>>,
) -> Result<(u16, Vec<u8>), String> {
    let resp = near::agent::host::http_request(
        method,
        url,
        headers,
        body.as_deref(),
        Some(30_000),
    )?;
    Ok((resp.status, resp.body))
}

fn execute_inner(params: &str) -> Result<String, String> {
    let action: ActionInput =
        serde_json::from_str(params).map_err(|e| format!("invalid parameters: {e}"))?;

    match action {
        ActionInput::GetDerivedPubkey(inp) => {
            let out = near_rpc::get_derived_pubkey(&inp, do_http)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }

        // ── EVM ──────────────────────────────────────────────────────────────
        ActionInput::EvmParseValue(inp) => {
            let out = evm::parse_value(&inp)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }
        ActionInput::EvmEncodeData(inp) => {
            let out = evm::encode_data(&inp)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }
        ActionInput::EvmGetNonce(inp) => {
            let out = evm::get_nonce(&inp, do_http)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }
        ActionInput::EvmGetGasPrice(inp) => {
            let out = evm::get_gas_price(&inp, do_http)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }
        ActionInput::EvmGetPriorityFeeWeiPerGas(inp) => {
            let out = evm::get_priority_fee_wei_per_gas(&inp, do_http)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }
        ActionInput::EvmEstimateGas(inp) => {
            let out = evm::estimate_gas(&inp, do_http)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }
        ActionInput::EvmBuildTransferMpcPayload(inp) => {
            let out = evm::build_transfer_mpc_payload(&inp)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }
        ActionInput::EvmBuildFunctionCallMpcPayload(inp) => {
            let out = evm::build_function_call_mpc_payload(&inp)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }
        ActionInput::EvmAttachMpcSignatureToTx(inp) => {
            let out = evm::attach_mpc_signature_to_tx(&inp)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }
        ActionInput::EvmSendSignedTx(inp) => {
            let out = evm::send_signed_tx(&inp, do_http)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }

        // ── Bitcoin ──────────────────────────────────────────────────────────
        ActionInput::GetBtcUtxos(inp) => {
            let out = bitcoin::get_btc_utxos(&inp, do_http)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }
        ActionInput::BuildBtcPayload(inp) => {
            let out = bitcoin::build_btc_payload(&inp, do_http)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }
        ActionInput::ReconstructBtcTx(inp) => {
            let out = bitcoin::reconstruct_btc_tx(&inp)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }
        ActionInput::BroadcastBtc(inp) => {
            let out = bitcoin::broadcast_btc(&inp, do_http)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }

        // ── Solana ───────────────────────────────────────────────────────────
        ActionInput::BuildSolPayload(inp) => {
            let out = solana::build_sol_payload(&inp, do_http)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }
        ActionInput::ReconstructSolTx(inp) => {
            let out = solana::reconstruct_sol_tx(&inp)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }
        ActionInput::BroadcastSol(inp) => {
            let out = solana::broadcast_sol(&inp, do_http)?;
            serde_json::to_string(&out).map_err(|e| e.to_string())
        }
    }
}

// ── WIT export ────────────────────────────────────────────────────────────────

struct NearTool;

impl exports::near::agent::tool::Guest for NearTool {
    fn execute(req: exports::near::agent::tool::Request) -> exports::near::agent::tool::Response {
        match execute_inner(&req.params) {
            Ok(output) => exports::near::agent::tool::Response {
                output: Some(output),
                error: None,
            },
            Err(e) => exports::near::agent::tool::Response {
                output: None,
                error: Some(e),
            },
        }
    }

    fn schema() -> String {
        SCHEMA.to_string()
    }

    fn description() -> String {
        DESCRIPTION.to_string()
    }
}

export!(NearTool);
