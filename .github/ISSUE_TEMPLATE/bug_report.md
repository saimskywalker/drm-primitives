---
name: Bug report
about: Something this crate produces or accepts is wrong
labels: bug
---

**What you called**

```rust
// The smallest snippet that shows it. Synthetic inputs please — see below.
```

**What happened**

<!-- The error, the wrong bytes, or the panic with its backtrace. The actual
     output is more useful than a description of it. -->

**What you expected instead**

<!-- If a spec says so, which one and which section. -->

**Environment**

- `drm-primitives` version:
- `rustc --version`:
- Target platform:

**Please do not attach key material**

Do not paste a real certificate, content key, or captured licence payload. Every
bug in this crate reproduces with synthetic bytes — `[0x01; 16]` and a hand-built
box are enough, and a report built that way can go straight into a test.
