---
name: Spec or player conformance
about: Output this crate produces is rejected by a real player, packager or CDM
labels: conformance
---

**What rejected it**

<!-- Shaka Packager, ffmpeg, a Widevine CDM, AVPlayer, dash.js, a specific
     device. Version if you have it. -->

**What this crate produced**

<!-- The bytes, hex-encoded, and the call that produced them. A PSSH box or an
     EXT-X-KEY tag is short enough to paste in full. -->

**What the consumer expected**

<!-- Its error message, and — if you have it — the equivalent output from a
     tool that the consumer does accept. A diff between the two is the single
     most useful thing in a report like this. -->

**The spec, if one settles it**

<!-- ISO/IEC 23001-7 for PSSH and CENC, RFC 8216 for HLS playlist tags, the
     DASH-IF system ID registry for system IDs. Section number if you have it. -->

**Anything unusual about the pipeline**

<!-- e.g. the box is rewritten by a packager between here and the player, the
     key IDs come from a licence service in a different byte order, the asset
     is CBCS rather than CENC. -->
