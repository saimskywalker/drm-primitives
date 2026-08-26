## What this changes

<!-- One or two sentences. What is different after this merges? -->

## Why

<!-- The problem it solves. If it fixes a bug, what was the symptom? -->

## Checklist

- [ ] `cargo fmt --all` leaves no diff
- [ ] `cargo clippy --all-targets -- -D warnings` is clean
- [ ] `cargo test --all-features` passes
- [ ] New public items have doc comments (`missing_docs` is denied in CI)
- [ ] If this fixes a bug: there is a test that fails without the fix
- [ ] No certificate, key or captured licence payload is attached to this PR

## If this changes what bytes come out

<!-- Encryption, key derivation and PSSH serialisation are observable output.
     A change to any of them breaks anyone who stored the old result. Say so
     here, and point at the known-answer test or the spec section that says the
     new output is the right one. -->
