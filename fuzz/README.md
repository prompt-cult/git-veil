# Fuzzing Suite (cargo-fuzz / libFuzzer)

Coverage-guided fuzzing for the parsing/trust core.

## Targets (10)

| target | surface | oracles beyond crash/ASAN |
|---|---|---|
| `keyring_parse` | `Keyring::parse` (src/keyring.rs) | emails never contain `:` and a serialize-then-parse roundtrip is stable |
| `parse_armored_public_key` | `parse_armored_public_key` + `validate_public_key_for_use` (Certify + Encrypt) | trust gate never panics and base64 encode/decode roundtrip preserves fingerprint |
| `base64_decode_public_key` | `base64_decode_public_key` | non-base64, non-UTF-8-after-decode and non-armour inputs give `Err`; the decode-encode-decode roundtrip preserves the fingerprint |
| `split_armored_blocks` | both `split_armored_*_key_blocks` fns | every block starts at BEGIN and ends at END; Ok means no unterminated BEGIN (truncation-attack invariant) |
| `signature_extraction` | `extract_signature_from_keyring`, `extract_content_to_verify_from_keyring` | extracted sig block is exactly `SIG_BEGIN..SIG_END` and verify content always ends with the END marker |
| `parse_git_remote_url` | `parse_git_remote_url`, `derive_repo_id` | Ok means components lowercase, empty-free, credential-free; `derive_repo_id` deterministic; derived repo_id never re-parses; Err text never echoes the `scheme://userinfo@` credential prefix |
| `trust_store_load` | `TrustStore::deserialize` | serialize then deserialize roundtrip is stable |
| `sanitize_repo_id` | `TrustPinStore::sanitize_repo_id`, `pin_path` | output stays in `[A-Za-z0-9._%-]`, never `/`, never `.`/`..`, ≤3x input length; pin path always inside `<home>/trust-pins/` |
| `tracked_files_load` | `validate_tracked_path`, `TrackedFiles::load` | accepted paths stay under the repo root; load Ok means every entry passes `validate_tracked_path` |
| `decrypt_message` | `decrypt_with_private_key` against one lazily-generated fixed key | error messages never echo the ciphertext or key material |

## Running

Requires the nightly toolchain and cargo-fuzz (`cargo install
cargo-fuzz --version 0.13.2 --locked`). mise keeps stable as the default,
so the `+nightly` override is per-invocation only.

```sh
# smoke run
cargo +nightly fuzz run <target> -- -runs=2000 -timeout=25 -max_len=65536
# the crypto-heavy decrypt target uses fewer runs (key gen + asymmetric ops):
cargo +nightly fuzz run decrypt_message -- -runs=500 -timeout=25 -max_len=65536

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
adversarial inputs (END-before-BEGIN keyring, unterminated armour blocks,
credential-shaped URLs, traversal repo_ids, Windows-prefixed paths, ...).
The generated/live corpus, crash artifacts, and coverage output are
gitignored via `fuzz/.gitignore`. Because `corpus` is ignored wholesale,
new seed files must be added with `git add -f fuzz/corpus/<target>/<file>`.

Upstream corpora worth pulling in, with licence and provenance checked
before vendoring:

- rpgp (`pgp` 0.19 upstream): `tests/` key artifacts incl.
  `draft-bre-openpgp-samples-00/` and `bad_ecdh/` malformed-key corpora,
  plus `fuzz/dictionaries/` (use with `-dict=` for the armoured targets).
- ProtonMail/go-crypto `fuzz/` seed corpora (BSD-3-Clause), convertible 1:1.
- GnuPG `tests/fuzz/` (GPLv2+): generate locally if needed.

## Triage policy

1. Reproduce with `cargo fuzz run <target> <artifact>`.
2. Check the panic location. Inside `src/` the bug is in-tree: minimize
   it (`tmin`), add a failing regression test in `tests/`, fix it, and
   confirm the test passes. Inside `~/.cargo/registry/.../pgp-0.19.0/`
   the bug is upstream (rpgp): file it upstream with the artifact, add
   the artifact to the seed corpus, and do not patch the dependency
   in-tree.
3. Timeout and OOM artifacts are genuine DoS findings for a secrets tool.
   Triage them, never suppress them.
