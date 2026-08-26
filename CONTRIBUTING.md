# Contributing

Contributions are welcome. A few things worth knowing before you spend time.

## How changes land

Every change reaches `main` through a pull request that the maintainer reviews
and merges. That includes changes from forks, which is the normal path — you
cannot push to this repository directly, and nothing merges without a review.
If a PR sits without a response, a nudge is fine.

## Never attach key material

This crate handles content keys, certificates and licence payloads, so the
obvious way to demonstrate a bug is the one thing not to do. Do not attach or
paste:

- a FairPlay Streaming certificate, or any `.der` / `.cer` / `.pem` file
- a real content key, master key or IV
- a licence request or response captured from a live device
- a signed key-delivery URL

Every bug in this crate can be reproduced with synthetic bytes. A failing test
that constructs its input from literals is both a better report and a better
fix. `.gitignore` refuses the usual certificate extensions for the same reason,
and that entry is deliberate — please do not remove it to add a fixture.

## Before opening a PR

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all-features
cargo doc --no-deps
```

CI runs the first three. Warnings are denied, and that includes
`missing_docs` — a new public item without a doc comment fails the build.

## What a good bug fix looks like

A test that fails without the fix. Several of the tests here exist because the
code they cover shipped wrong once — a parser that indexed past its input, an
unpadding that truncated instead of rejecting — and the comments say which.
That is the shape worth adding to.

## Things to be careful with

**Anything that reads attacker-controlled bytes.** The `pssh` parser and the
certificate reader take lengths from their own input. Every one of those has to
be bounds-checked before it becomes an index, and the arithmetic that computes
the bound has to be `checked_`, because a `u32` count times 16 overflows. A
panic on malformed input is a bug here, not a rough edge.

**Cryptographic behaviour.** Prefer a reviewed implementation to a hand-rolled
one — the CBC mode and the KDF are both delegated for exactly that reason. If a
change alters what bytes come out for given inputs, it is a breaking change for
anyone who stored the old output, and it needs a known-answer test against a
published vector rather than a round-trip test against itself.

**Doc comments that promise more than the code delivers.** Two functions here
carry a warning that they are heuristics, and one carries a padding-oracle
note. Those warnings are the feature. If a change makes one of them wrong in
either direction, the comment moves with the code.

## Scope

This crate builds and reads the artefacts a DRM system exchanges. It is not a
licence server, it does not speak to one, and it does not try to be a general
X.509 or ISO-BMFF library. A PR that adds a network client, an async runtime or
a TLS stack will be turned down on those grounds alone — a downstream project
that needs one already has one, and it should not arrive through here.
