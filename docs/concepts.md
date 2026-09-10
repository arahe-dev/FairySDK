# Concepts

## Core objects

- **Target** — a URL, host, and port. The subject of a survey.
- **Layer** — the protocol layer being probed: DNS, TCP, TLS, HTTP, UDP, QUIC.
- **Status** — the outcome of a single probe: Pass, Fail, Timeout, Skipped, Unknown.
- **Observation** — the complete record of one experiment at one layer.
- **Evidence** — a structured fact extracted from a probe result (e.g. `tcp_refused`, `tls_alert`, `http_status`).
- **Finding** — an inference drawn from one or more observations, with a confidence level.
- **Report** — the final output: target, timing, observations, and findings.

## Survey flow

```
Target → Policy.Propose() → [Experiments] → Probe.Run() → Observations
                                                          ↓
                                                      SurveyState
                                                          ↓
                                                     Infer() → Findings
                                                          ↓
                                                        Report
```

The `SurveyState` accumulates observations across rounds. After each round,
the policy proposes additional experiments based on what remains
unresolved. When `Done()` returns true, inference runs and a `Report`
is produced.
