# Changelog

## v0.2.0

Agent-facing CLI additions (Go SDK API unchanged):

- `fairy batch <targets-file> --out DIR [--jsonl FILE] [--runs N] [--jobs N]`:
  surveys many targets, writes one report per target plus a saved
  `SurveyState`, streams one compact JSON object per run to JSONL, and
  reports per-target failures with a non-zero exit code.
- `fairy compare <setA> <setB> [--json]`: diffs two report sets (one per
  network) — observation status/detail changes, hosts present in only one
  set, finding changes, and instability within a set when multiple runs of
  a host disagree. Sets may be directories, single reports, or `.jsonl`.
- Every machine-readable report now carries run metadata: `schema_version`,
  `fairy_version`, `run_id`, `network_label`, `policy`, `wall_ms`, and the
  report fields stay at the top level for existing consumers.
- Fix (found by `fairy compare` on real adaptive-policy data): inference
  preferred the most recent observation of a layer, so a passing adaptive
  variant (e.g. SNI-less TLS) could mask the failing canonical experiment
  and suppress `tls_specific_failure` / `possible_proxy_interference`.
  Layer verdicts now prefer the canonical experiment.
## v0.1.1

- Fix: `cmd/fairy` (the CLI) was missing from v0.1.0 - an unanchored
  `.gitignore` entry intended for the built binary also excluded the
  `cmd/fairy/` source directory. Ignore rules are now anchored to the
  repository root.
- `go.mod` retracts v0.1.0: install v0.1.1 or later.

## v0.1.0

- Initial project structure.
- README, LICENSE, and community files.
- Frozen public API: `Survey(ctx, url)` and `New(Config)`.
- Frozen dependency set: `miekg/dns`, `quic-go/quic-go`, `golang.org/x/sync`.
- Core model: `Experiment` with deterministic SHA-256 IDs, `Observation`,
  structured `Evidence`, `SurveyState` (JSON-serializable), `Report`,
  `Finding`.
- Probes: DNS (system + explicit public resolver), TCP, TLS, HTTP/1.1 +
  HTTP/2, UDP reachability, QUIC/HTTP-3 (quic-go). Raw errors are
  converted into structured evidence; timeouts report `Timeout`,
  insufficient data reports `Unknown`.
- Policies: `FastPolicy` (deterministic tree, 4–7 probes), basic
  `AdaptivePolicy` (hypothesis-separation scoring), `FactorialPolicy`
  (Cartesian product, bounded) and `TaguchiPolicy` (L9 orthogonal array).
- Inference layer: evidence-first `Finding`s with confidence levels
  (`Confirmed`, `Likely`, `Possible`, `InsufficientEvidence`).
- Runner: round-based execution with per-layer time budgets, errgroup
  concurrency (`MaxConcurrent`, default 4), duplicate experiment
  rejection, and restartable surveys (`Resume`, `--resume`/`--save`).
- CLI: `fairy survey <url> [--json] [--policy …] [--timeout …]
  [--max-probes …] [--concurrency …] [--insecure] [--resume FILE]
  [--save FILE]`.
- Test suite: local fake DNS/TCP/TLS/HTTP/HTTP-3 servers, policy
  determinism, resume, duplicate rejection, context cancellation, and
  inference fixtures.
- Validation fixes (real-network testing on two networks, Windows + WSL Linux):
  - DNS: address families are resolved separately and failures carry honest
    per-family labels (not_found / no_data / temporary / timeout), so
    AAAA-filtered networks no longer masquerade as NXDOMAIN; IPv4 literal
    addresses surfaced as 4-in-6 are counted.
  - Inference: dns_failure is confirmed only for NXDOMAIN/SERVFAIL;
    "no data" stays likely.
  - Inference: a certificate signed by an unknown authority on a path where
    TCP works now reports possible_proxy_interference.
  - Inference: skipped observations (prerequisite missing) no longer produce
    layer-failure findings.
  - TCP/UDP/QUIC: kernel "network unreachable" verdicts report Fail with
    network_unreachable evidence instead of Unknown, so ipv6_path_failure
    fires on v4-only paths.