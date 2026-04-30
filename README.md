# near-tool

A WASM tool for [Ironclaw](https://github.com/nearai/ironclaw) that signs and
broadcasts cross-chain transactions on **EVM** chains (Ethereum, Base,
Arbitrum, Optimism, Sepolia), **Bitcoin** (mainnet/testnet), and
**Solana** (mainnet/devnet) using NEAR's MPC chain-signatures contract
(`v1.signer-prod.testnet`). The repo ships both the sandboxed WASM
component and a companion skill (`MPC_SKILL.md`) that drives it through
the full sign-and-broadcast flow.

## Build and install the tool

The Rust toolchain and target are pinned via `rust-toolchain.toml`
(`1.86.0`, `wasm32-wasip2`), so `cargo` will fetch them automatically:

```bash
cargo build --target wasm32-wasip2 --release
ironclaw tool install ./target/wasm32-wasip2/release/near_tool.wasm \
    --capabilities ./near-tool.capabilities.json \
    --name near-mpc-tool \
    --force
```

## Install the skill

```bash
cp MPC_SKILL.md ~/.ironclaw/skills/near-mpc/SKILL.md
```

The skill auto-activates on keywords like `mpc`, `chain-signatures`,
`.testnet`, `eth`/`btc`/`sol`, and on phrases such as
`transfer ETH` or `broadcast solana`.
