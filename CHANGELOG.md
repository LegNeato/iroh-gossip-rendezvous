# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog], and this project adheres to
[Semantic Versioning].

## [Unreleased]

### Changed

- **Breaking (0.3.0):** upgrade to stable Iroh 1.1+, iroh-gossip 0.101,
  and ed25519-dalek 3 with their default features. Consumers using the
  exposed Iroh types must upgrade together.

## [0.2.1] — 2026-05-11

### Changed

- **Fast recovery from `DhtStatus::PublishFailing`.** The write loop
  previously slept the full `write_period` (default 5 min) between
  every iteration and still applied the `1/(n+1)` probability gate,
  so a node stuck in `PublishFailing` could wait many minutes — even
  half an hour with a populated active view — before retrying. The
  loop now checks `dht_status` before sleeping: while failing, it
  uses the new `failure_retry_period` (default 15 s) and bypasses
  the gate, so every tick attempts a write until one succeeds. On
  success the steady-state cadence and gate are restored.

### Added

- `Builder::failure_retry_period(Duration)` — override the recovery
  cadence (additive, non-breaking). Public constant
  `DEFAULT_FAILURE_RETRY_PERIOD = 15 s`.

### Rationale

The probability gate exists to keep N healthy publishers from
storming the DHT with redundant writes — but once *our* publish has
failed, redundancy is irrelevant; we need to land *one* successful
write. Skipping the gate while failing turns the recovery time into
a function of `failure_retry_period`, not of `(n + 1) × write_period`.

## [0.2.0] — 2026-05-11

### Changed

- **Breaking:** bumped `iroh` to `=1.0.0-rc.0` and `iroh-gossip` to `0.99`.
  Public API exposes iroh types (`Endpoint`, `SecretKey`, `PublicKey`,
  `iroh_gossip::api::*`), so consumers must move to the iroh 1.0-rc.0
  ecosystem in lockstep.
- **Breaking:** bumped `ed25519-dalek` to `=3.0.0-pre.7` to match
  iroh-base 1.0.0-rc.0. The version is pinned with `=` because iroh-base
  itself hard-pins the pre-release; drop the `=` when iroh-base relaxes.
- Loosened the `sha2` pin from `=0.11.0-rc.5` to `^0.11`. iroh-base
  1.0.0-rc.0 no longer hard-pins the rc, so we follow the same
  caret-range convention as the rest of the crypto stack.
- Bumped transitive crypto deps via `cargo update`: `mainline` 6.0.1 →
  6.1.2, plus the usual sweep of tokio/hyper/rustls patches.

### Notes

- No source changes were required: the iroh/gossip APIs we touch
  (`Endpoint::builder`, `endpoint::presets::N0`, `SecretKey::generate`,
  `PublicKey`, `iroh_gossip::api::{Event, GossipSender}`) survived the
  bump verbatim.
- All 96 lib tests, property tests, and integration tests pass against
  the new stack.

## [0.1.0] — 2026-04-22

First public release. Passphrase-based peer rendezvous for iroh-gossip
swarms over the public Mainline DHT, keyed from a shared passphrase + an
application salt — no central bootstrap server and no prior knowledge of
peer addresses required.

### Algorithm

- K-sharded BEP 44 mutable-item slots (default `K = 3`), each with its
  own HKDF-derived Ed25519 signing keypair and per-slot AEAD wrapper key.
- Logical aging with random-tie eviction; vouching of up to `V`
  neighbors at age 1; two-layer ChaCha20-Poly1305 AEAD envelope over
  fixed-width entries.
- Seq-ratcheted per-epoch wrapper keys; one-shot body key per record.
- Clock-free: no dependence on wall-time across nodes.
- Full specification lives at [`PROTOCOL.md`][protocol].

### Public API

- `Rendezvous::join(passphrase, app_salt)` — one-call entry point.
- `Rendezvous::builder()` — full `Builder` for endpoint/secret_key/
  parameter overrides.
- `Rendezvous::{sender, subscribe, state, endpoint, node_id, topic_id,
  broadcast, shutdown}` — handle surface.
- `iroh_gossip` types re-exported where useful; otherwise thin wrappers.

### Feature flags

- `sim` — discrete-event simulator + test-support exports.
- `kani` — Kani proof harnesses (off by default).
- `miri-compat` — skip Miri-incompatible tests.
- `mainline-live` — integration tests against the real public Mainline DHT.
- `test-support` — `Builder::dht_backend` for injecting custom `DhtSlots`.

### Correctness evidence shipping with the crate

- **119 tests** across unit, property, integration, and doctest layers;
  all green.
- **Property tests** (`proptest`) on wire format roundtrip, merge
  invariants (`|R'| ≤ B`, age bound, self at age 0), crypto roundtrip
  across epoch boundaries.
- **Integration tests** over real iroh endpoints with an injected
  in-memory DHT: two-node bootstrap, multiple-subscriber fan-out, drop
  cancels background tasks.
- **Mutation testing** (`cargo-mutants`) — **100% catch rate** on
  testable mutations (119 caught, 27 unviable, 0 missed). See
  `.cargo/mutants.toml` for the exclusions and their rationale.
- **Fuzz harnesses** (`cargo-fuzz`) for `decode_entries`.
- **Bounded model checking** (Kani) of undefined-behavior / panic
  absence on `crypto::epoch_of` (full `i64` × `u64 ≥ 1` space) and
  `wire::decode_entries` (arbitrary byte input). Structural invariants
  are covered by the stronger proptest + Stateright combo.
- **Distributed-system model checking** (Stateright): safety invariants
  S1 (record size ≤ B) and S2 (age < A_max) proved exhaustively for
  N ≤ 6, K ≤ 3; liveness witnesses under weak fairness; randomized
  large-N exploration available via `just model-random`.
- **Miri** — UB-free on the synchronous modules (`keys`, `wire`,
  `crypto`, `merge`).
- **Simulator baseline** (`examples/simulator.rs`) — cold-start (8
  nodes) and symmetric partition (5/5) scenarios both heal in 1 round
  at 100%. Asymmetric 1:100 with default `K = 3` is a documented
  limitation in `PROTOCOL.md §8`.

### Supply chain

- MIT-licensed; MSRV 1.93.0; all crypto dependencies from the audited
  RustCrypto stack.
- `cargo-deny` + `cargo-audit` green on every push (transitive
  `unmaintained` advisory from `paste` via `iroh → portmapper →
  netwatch` documented in `deny.toml`).
- `[package.metadata.docs.rs]` configured for all-feature docs builds.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
[protocol]: https://github.com/swaits/iroh-gossip-rendezvous/blob/main/PROTOCOL.md
[Unreleased]: https://github.com/swaits/iroh-gossip-rendezvous/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/swaits/iroh-gossip-rendezvous/releases/tag/v0.1.0
