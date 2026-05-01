# Gossip Protocol

Gossip Protocol is a multi-resource coordination protocol for checks, browser
journeys, compute jobs, storage contracts, domain routes, swaps, and public
outputs. Validators and delegated agents execute work, exchange signed receipts,
and finalize state only after enough independent witnesses agree.

The protocol is not just a compute queue or a hosting layer. It is a common way
to price, verify, settle, and publish work across resources that normally live in
separate systems.

- Website: https://gossip-protocol.com/
- Docs: https://gossip-protocol.com/docs/
- Source map: https://gossip-protocol.com/repo/
- License: Apache-2.0

The code is public. Live validator participation, network policy, treasury
policy, token issuance, and production operations remain operator-controlled
unless this repository says otherwise.

## What It Coordinates

Gossip Protocol uses one witness layer for many kinds of infrastructure:

- health checks and heartbeat monitors
- deterministic browser journeys with signed artifacts
- sharded WASI compute jobs
- storage contracts, chunks, proofs, and public raw bundles
- DNS offerings, leases, renewals, and storage-backed route binds
- swaps and settlement adapter records
- validator blocks, approvals, receipts, and finalized ledger state

## Resource Markets

| Token | Role |
| --- | --- |
| `HT` | Base credit for health checks, browser journeys, monitor budgets, and swap workflows. |
| `CT` | Pays for sharded compute, WASI execution, replicated receipts, and returned artifacts. |
| `ST` | Pays hosts to keep encrypted or public raw content available and prove it over time. |
| `DNS` | Leases names and binds public routes to active storage-backed content. |

## Lifecycle

1. Submit: users sign checks, browser journeys, compute jobs, storage contracts,
   swaps, or DNS leases.
2. Witness: validators and delegated agents execute work, observe heartbeats,
   prove storage, and sign receipts.
3. Settle: blocks apply balances across `HT`, `CT`, `ST`, and `DNS` while
   rejecting conflicting evidence.
4. Publish: artifacts, monitor state, storage routes, and lease bindings remain
   as verifiable public records.

## Repository Map

| Path | Purpose |
| --- | --- |
| `src/protocol.rs` | Protocol types, transaction variants, token constants, fees, limits, and validation rules. |
| `src/node.rs` | Validator runtime, mempool, peer sync, gossip endpoints, block proposal, approval flow, persistence, and control API. |
| `src/cli.rs` | Command-line interface for wallets, genesis, nodes, transactions, swaps, monitors, browser checks, storage, and agents. |
| `src/ledger.rs` | Chain state, balances, finalized records, monitor state, storage contracts, domain leases, and swaps. |
| `src/compute.rs` | Compute job schemas, reducers, WASI settings, sandbox policy, cost model, output validation, and shard receipts. |
| `src/compute_sandbox.rs` | Isolated compute execution, artifact capture, WASI runtime integration, and resource enforcement. |
| `src/browser.rs` | Browser journey package schema, runtime profile validation, artifact policy, package hashing, and runner IO. |
| `src/storage.rs` | Storage bundle builder, chunk server, Merkle proofs, encrypted bundles, public raw bundles, and domain gateway serving. |
| `src/agent.rs` | Delegated probe, browser, and compute agent runtime with lease verification and signed delegated receipts. |
| `src/wallet.rs` | Wallet files, Ed25519 signing, verification helpers, and typed signature methods. |
| `browser_runner/` | Node/Playwright browser runner used by browser journey execution. |
| `scripts/` | Local smoke tests and first-validator bootstrap tooling. |
| `site/` | Static source for `gossip-protocol.com`. |
| `llms.txt` | Short operating notes for Codex, coding agents, and other LLM tools. |

## Initialize With Codex Or Another Coding Agent

This repo is designed to be understandable by local coding agents. After cloning,
ask the agent to read the repo guidance before changing code.

```bash
git clone https://github.com/vibevibellc/gossip_protocol.git
cd gossip_protocol
```

Suggested first prompt:

```text
Initialize this repository. Read README.md, SECURITY.md, llms.txt, and the docs
under site/docs/. Summarize the architecture, identify the main commands, then
run the standard verification commands. Do not invent live peers, API tokens,
genesis files, validator policies, or production onboarding requirements.
```

`llms.txt` is intentionally short. It gives assistants the current project
shape, safe defaults, common commands, and architecture summary. If your tool
does not automatically read it, paste or reference it explicitly in the first
prompt.

## Local Setup

Required:

- Rust `1.93` or newer
- Python `3`

Optional for browser journey execution:

- Node.js `18` or newer
- npm
- Playwright Chromium

Install browser-runner dependencies only if you plan to run browser checks:

```bash
cd browser_runner
npm install
npx playwright install chromium
cd ..
```

## Verify The Repo

Run the baseline checks before making release claims:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

Run local smoke tests when changing protocol behavior:

```bash
python3 scripts/local_compute_smoke.py
python3 scripts/local_testnet_smoke.py
python3 scripts/local_testnet_stress.py
```

For the browser runner:

```bash
cd browser_runner
npm audit --omit=dev
cd ..
```

## Build

```bash
cargo build --release
```

The resulting binary is:

```text
target/release/gossip_protocol
```

Use the CLI help to inspect the current command surface:

```bash
cargo run -- --help
```

## Documentation

The static docs mirror the current implementation:

- `site/docs/index.html`: documentation entry point
- `site/docs/functionality.html`: validator, agent, storage, browser, compute,
  swap, and DNS behavior
- `site/docs/settings.html`: flags, JSON specs, limits, fees, and endpoint
  defaults
- `site/repo/index.html`: source map for the public website

## Security

Read `SECURITY.md` before exposing validators, storage hosts, or delegated
agents outside a local machine. Public deployments should use TLS, bearer
tokens, reverse-proxy rate limits, peer allowlists for internal gossip endpoints,
and external secret management for wallet passphrases and browser secrets.

If a bearer token is not configured for an API surface, the implementation treats
that surface as unauthenticated. Do not expose public nodes, storage hosts, or
agents without reviewing the security policy.
