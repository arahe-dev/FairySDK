# Architecture

## What Fairy is

FairySDK produces structured `Report` objects from controlled network
experiments. It is a library and a CLI.

## What Fairy is NOT

Fairy is not:

- a VPN client
- a proxy framework
- a packet capture tool
- a firewall
- a traceroute replacement
- a distributed measurement platform
- a GUI application

## Boundaries

```text
FairySDK
   |
   | Report
   v
Consumer (e.g. Phaethon)
```

Fairy consumes a target URL. It produces a `Report`. It does not consume
or produce routing decisions, proxy configurations, or VPN state.

## Dependencies

| Dependency              | Purpose                        |
|-------------------------|--------------------------------|
| github.com/miekg/dns    | Explicit DNS resolver probes   |
| github.com/quic-go/quic-go | QUIC and HTTP/3 support     |
| golang.org/x/sync       | errgroup concurrency           |

Everything else is standard library.
