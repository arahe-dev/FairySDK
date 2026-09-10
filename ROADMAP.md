# Roadmap

## V0 (current)

- [ ] Go API freeze (`Survey`, `New`, `Config`)
- [ ] DNS probe
- [ ] TCP probe
- [ ] TLS probe
- [ ] HTTP/1.1 + HTTP/2 probe
- [ ] QUIC / HTTP/3 probe
- [ ] UDP probe (basic reachability only)
- [ ] `FastPolicy` (deterministic tree)
- [ ] Basic `AdaptivePolicy` (hypothesis separation scoring)
- [ ] Structured `Evidence` + `Finding`
- [ ] JSON report output
- [ ] CLI (`cmd/fairy`)
- [ ] Restartable `SurveyState` (JSON persistence)
- [ ] `go test -race ./...` clean
- [ ] v0.1.0-pre release

## Post-V0

- [ ] `FactorialPolicy` (Cartesian product, dev/diagnostic mode)
- [ ] `TaguchiPolicy` (orthogonal arrays)
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
