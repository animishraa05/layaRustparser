## Closes
<!-- e.g. Closes #12 -->

## What changed
<!-- 1-3 lines -->

## Verification
<!-- paste: clippy + fmt + test commands, evaluate numbers if perf-touched -->
- [ ] `cargo clippy --workspace --all-targets -- -A clippy::too_many_arguments -A clippy::field_reassign_with_default -D warnings`
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo test --workspace`
- [ ] Perf-touched? `evaluate --engine all` numbers attached (p50, hit rate, inviolability, GA)

## Requested reviewer
<!-- @animishraa05 or @sudobhavik — prefer someone fresh to the area -->

## Checklist
- [ ] No `to_string()`/`format!` on per-packet hot paths
- [ ] No runtime network calls (air-gap)
- [ ] Raw log preserved byte-for-byte + SHA-256 intact
- [ ] Binary impact considered (< 35 MB)
