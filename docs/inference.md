# Inference

```go
func Infer(state SurveyState) []Finding
```

## Principles

1. **Evidence first.** Every finding references the observation IDs that
   support it.
2. **Confidence levels.** `Confirmed`, `Likely`, `Possible`,
   `InsufficientEvidence`.
3. **No overclaiming.** If all the evidence shows is "TCP timed out",
   the finding is `tcp_unreachable` — not `firewall_blocked`.

## Finding kinds

| Kind                              | Typical evidence                          |
|-----------------------------------|-------------------------------------------|
| dns_failure                       | nxdomain, servfail, timeout               |
| ipv6_path_failure                 | dns ok, tcp6 timeout                      |
| tcp_unreachable                   | tcp_refused, tcp_reset, timeout           |
| tls_specific_failure              | tls_alert, certificate mismatch           |
| udp_unavailable                   | udp timeout / no response                 |
| quic_unavailable                  | quic_handshake_failure, timeout           |
| http_application_rejection        | http_status 4xx/5xx                       |
| possible_proxy_interference       | inconsistent results across paths         |
