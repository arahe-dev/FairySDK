# Roadmap

## V0 (current)

- [x] Go API freeze (`Survey`, `New`, `Config`)
- [x] DNS probe
- [x] TCP probe
- [x] TLS probe
- [x] HTTP/1.1 + HTTP/2 probe
- [x] QUIC / HTTP/3 probe
- [x] UDP probe (basic reachability only)
- [x] `FastPolicy` (deterministic tree)
- [x] Basic `AdaptivePolicy` (hypothesis separation scoring)
- [x] Structured `Evidence` + `Finding`
- [x] JSON report output
- [x] CLI (`cmd/fairy`)
- [x] Restartable `SurveyState` (JSON persistence)
- [x] `go test -race ./...` clean
- [ ] v0.1.0-pre release

## Post-V0

- [x] `FactorialPolicy` (Cartesian product, dev/diagnostic mode)
- [x] `TaguchiPolicy` (orthogonal arrays)
- [ ] Additional real-world consumers
- [ ] Evaluate packet capture integration
- [ ] Evaluate distributed execution model

## Explicit non-goals

- Packet capture (V0)
- eBPF
- Traceroute
- Raw ICMP
- DoH / DoT
- Custom proxy protocols
- GUI
- Machine learning inference

No dates are promised. Details evolve as evidence accumulates.
