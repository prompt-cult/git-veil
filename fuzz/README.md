# Fuzzing Suite (cargo-fuzz / libFuzzer)

Coverage-guided fuzzing for the parsing/trust core.

## Targets (5)

| target | surface | oracles beyond crash/ASAN |
|---|---|---|
| `keyring_parse` | `Keyring::parse` (src/keyring.rs) | emails never contain `:` and a serialize-then-parse roundtrip is stable, field for field |
| `parse_git_remote_url` | `parse_git_remote_url`, `derive_repo_id` | Ok means components lowercase, empty-free, credential-free. `derive_repo_id` deterministic. Derived repo_id never re-parses. Err text never echoes the `scheme://userinfo@` credential prefix |
| `trust_store_load` | `TrustStore::deserialize` | serialize then deserialize roundtrip is stable |
| `sanitize_repo_id` | `TrustPinStore::sanitize_repo_id`, `pin_path` | output stays in `[A-Za-z0-9._%-]`, never `/`, never `.` or `..`, at most 3x input length. Pin path always inside `<home>/trust-pins/` |
| `tracked_files_load` | `validate_tracked_path`, `TrackedFiles::load` | accepted paths stay under the repo root. Load Ok means every entry passes `validate_tracked_path` |

## Running

Requires the nightly toolchain and cargo-fuzz (`cargo install
cargo-fuzz --version 0.13.2 --locked`). mise keeps stable as the default,
so the `+nightly` override is per-invocation only.

```sh
# smoke run
cargo +nightly fuzz run <target> -- -runs=2000 -timeout=25 -max_len=65536

# longer campaigns
cargo +nightly fuzz run <target> -- -max_total_time=1800 -timeout=25 -max_len=65536 -jobs=$(sysctl -n hw.ncpu) -workers=$(sysctl -n hw.ncpu)

# throughput campaigns on this all-safe-Rust crate can double exec/s with:
cargo +nightly fuzz run <target> --sanitizer none -- -max_total_time=1800 -timeout=25

# minimise a crash artifact / the corpus
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<sha>
cargo +nightly fuzz cmin <target>
```

`-timeout=25` is deliberate. libFuzzer's 1200 s default would let a slow
input masquerade as hang-free, and for a secrets tool a 10 s input on
`reveal` is a bug. libFuzzer flags are passed after `--` per invocation
(cargo-fuzz 0.13.2 has no config-file support).

## Corpus policy

`fuzz/corpus/<target>/` holds the committed seed corpus: real key material
generated from this repo's own key-generation path plus handcrafted
adversarial inputs (END-before-BEGIN keyring, credential-shaped URLs,
traversal repo_ids, Windows-prefixed paths, and more).
The generated/live corpus, crash artifacts, and coverage output are
gitignored via `fuzz/.gitignore`. Because `corpus` is ignored wholesale,
new seed files must be added with `git add -f fuzz/corpus/<target>/<file>`.

## Triage policy

1. Reproduce with `cargo fuzz run <target> <artifact>`.
2. Check the panic location. Inside `src/` the bug is in-tree. Minimize
   it (`tmin`), add a failing regression test in `tests/`, fix it, and
   confirm the test passes.
3. Timeout and OOM artifacts are genuine DoS findings for a secrets tool.
   Triage them, never suppress them.
