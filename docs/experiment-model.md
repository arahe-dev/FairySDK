# Experiment model

## Determinism

Every experiment has a deterministic ID derived from its canonical
representation:

```go
func ExperimentID(e Experiment) string {
    // canonical serialize -> SHA256 -> first 12 hex chars
}
```

This means:
- Same experiment → same ID (deduplication).
- Same survey state → same policy decisions (reproducibility).
- Interrupted surveys can resume without rerunning completed experiments.

## Layers

| Layer  | Probe   | Depends on          |
|--------|---------|---------------------|
| DNS    | dns.go  | —                   |
| TCP    | tcp.go  | DNS (optional)      |
| TLS    | tls.go  | TCP                 |
| HTTP   | http.go | TLS                 |
| UDP    | udp.go  | —                   |
| QUIC   | quic.go | UDP (reachability)  |

## Survey state

```go
type SurveyState struct {
    SurveyID     string        `json:"survey_id"`
    Round        int           `json:"round"`
    Observations []Observation `json:"observations"`
    Rounds       []Round       `json:"rounds"`
}
```

Every completed observation is immutable. The state is JSON-serializable
for persistence and resume.
