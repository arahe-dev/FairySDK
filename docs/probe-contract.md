# Probe contract

## Interface

```go
type Probe interface {
    Run(context.Context, Experiment) Observation
}
```

## Rules

1. **One probe, one layer.** Each probe reports exactly one `Layer`.
2. **No raw errors.** Convert errors into `Evidence` values.
3. **Timeouts become `Status: Timeout`.** Not `Status: Fail`.
4. **Insufficient evidence becomes `Status: Unknown`.** Not a guess.
5. **No global state.** Probes are stateless; everything needed is in the
   `Experiment`.

## Internal dispatch

```go
func run(ctx context.Context, e Experiment) Observation
```

The runner selects the appropriate probe based on `Experiment` fields.
Users do not register probes.
