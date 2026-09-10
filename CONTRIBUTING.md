# Contributing to FairySDK

Thanks for your interest in contributing!

## Getting started

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/my-change`).
3. Make your changes.
4. Run `go test -race ./...` and `go vet ./...`.
5. Push and open a pull request.

## Guidelines

- Keep the public API small. If you're adding something, argue for why it
  belongs in V0.
- Experiments must be deterministic. Same inputs → same experiment ID.
- Raw errors become structured evidence. Never return a bare error where
  an `Evidence` value communicates more.
- Policies are pure functions. No hidden mutation inside `Propose`.
- `go test -race ./...` must pass.
- New probes implement the `Probe` interface and live in `probe/`.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Reporting security issues

See [SECURITY.md](SECURITY.md).
