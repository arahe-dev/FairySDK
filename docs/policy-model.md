# Policy model

```go
type Policy interface {
    Propose(context.Context, SurveyState, int) ([]Experiment, error)
    Done(SurveyState) bool
}
```

## Rules

1. **Purity.** `Propose` is a pure function: same config + same
   `SurveyState` → same experiments.
2. **No hidden mutation.** Policies do not modify the state they receive.
3. **Termination.** `Done` must eventually return true for any finite
   input. Policies that can propose indefinitely are rejected.

## Policies

| Policy       | Strategy                                        |
|--------------|-------------------------------------------------|
| FastPolicy   | Fixed deterministic tree                        |
| Adaptive     | Hypothesis-separation scoring                   |
| Factorial    | Cartesian product (bounded)                     |
| Taguchi      | Orthogonal arrays (L9/L27)                      |
