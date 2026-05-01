# Security Policy

Gossip Protocol is a reference implementation for a federated validator network.
Public source code does not imply that any public validator set, token issuance
policy, treasury policy, or production network is open for permissionless
participation.

## Reporting Security Issues

Please report suspected vulnerabilities privately through the repository security
advisory flow when available. Do not open public issues for exploitable bugs,
private key exposure, authentication bypasses, sandbox escapes, or denial of
service paths.

## Secrets And Wallets

Do not commit:

- validator wallets or requester wallets
- wallet passphrases
- bearer tokens for control, gossip, storage, or agent APIs
- browser secret-store files
- TLS private keys or certificate renewal configuration
- generated state, journals, blocks, artifacts, logs, or local databases

The default `.gitignore` excludes common local runtime directories and secret
file formats, but operators remain responsible for external secret management.

## Public Node Exposure

The default node, storage-host, and agent bind addresses are loopback-oriented
for local development. Before exposing any endpoint to the internet:

- terminate TLS at a hardened reverse proxy
- set `--control-api-token`, `--gossip-api-token`, and agent `--api-token`
  values where applicable
- rate-limit public submit, quote, ping, and status endpoints
- restrict `/v1/internal/*` to known peer addresses
- keep validator wallets encrypted and load passphrases through environment
  variables or a secret manager
- keep state directories on persistent storage with backups

If a bearer token is not configured for an API surface, the implementation treats
that surface as unauthenticated. Do not rely on network obscurity for public
deployments.

## High-Risk Runtime Flags

The following behaviors are for local testing or tightly controlled internal
networks:

- allowing HTTP health-check targets
- allowing private, loopback, link-local, or otherwise internal health-check
  targets
- executing browser journeys with broad secret-store access
- accepting unreviewed WASI modules or oversized artifacts from unknown users

Public validators should keep SSRF protections enabled, bound request sizes
small, and review resource-cost limits before taking user traffic.

## Compute And Browser Execution

Compute jobs are WASI-module based and browser checks execute through a separate
runner contract. Treat both as untrusted workloads:

- run validators and delegated agents under restricted OS users
- avoid broad filesystem preopens
- isolate artifact directories from operator secrets
- keep browser profiles, cache directories, and secret stores per deployment
- review dependency updates for Wasmtime, Tokio, Axum, Reqwest, and Playwright

## Dependencies

Before a public release, run:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

Also run dependency-vulnerability tooling such as `cargo audit` or `cargo deny`
when available, and `npm audit` for `browser_runner/` when a lockfile is
present.
