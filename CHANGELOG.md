# Changelog

## v0.1.0-pre (unreleased)

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
- Implementation underway.
