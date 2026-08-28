# Fuzzing Suite (cargo-fuzz / libFuzzer)

Coverage-guided fuzzing for the parsing/trust core. See the research plan in
`.tmp/fuzzing-research.md` for target ranking, oracle rationale, and the
upstream-corpus strategy.

## Targets (10)

| target | surface | oracles beyond crash/ASAN |
|---|---|---|
| `keyring_parse` | `Keyring::parse` (src/keyring.rs) | emails never contain `:`; `serialize∘parse` roundtrip is stable |
| `parse_armored_public_key` | `parse_armored_public_key` + `validate_public_key_for_use` (Certify + Encrypt) | trust gate never panics; base64 encode/decode roundtrip preserves fingerprint |
| `base64_decode_public_key` | `base64_decode_public_key` | non-base64/non-UTF-8/non-armour ⇒ `Err`; decode∘encode∘decode fingerprint stability |
| `split_armored_blocks` | both `split_armored_*_key_blocks` fns | every block starts at BEGIN / ends at END; Ok ⇒ no unterminated BEGIN (truncation-attack invariant) |
| `signature_extraction` | `extract_signature_from_keyring`, `extract_content_to_verify_from_keyring` | extracted sig block is exactly `SIG_BEGIN..SIG_END`; verify content always ends with the END marker |
| `parse_git_remote_url` | `parse_git_remote_url`, `derive_repo_id` | Ok ⇒ components lowercase, empty-free, credential-free; `derive_repo_id` deterministic; derived repo_id never re-parses; Err text never echoes the `scheme://userinfo@` credential prefix |
| `trust_store_load` | `TrustStore::deserialize` | serialize∘deserialize roundtrip stability |
| `sanitize_repo_id` | `TrustPinStore::sanitize_repo_id`, `pin_path` | output stays in `[A-Za-z0-9._%-]`, never `/`, never `.`/`..`, ≤3x input length; pin path always inside `<home>/trust-pins/` |
| `tracked_files_load` | `validate_tracked_path`, `TrackedFiles::load` | accepted paths stay under the repo root; `load` Ok ⇒ every entry passes `validate_tracked_path` |
| `decrypt_message` | `decrypt_with_private_key` against one lazily-generated fixed key | error messages never echo the ciphertext or key material |

## Running

Requires the nightly toolchain (mise keeps stable as the default; the
`+nightly` override is per-invocation only) and cargo-fuzz (`cargo install
cargo-fuzz --version 0.13.2 --locked`).

```sh
# smoke run (what this suite was accepted with)
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

`-timeout=25` is deliberate: libFuzzer's 1200 s default would let a slow
input masquerade as hang-free, and for a secrets tool a 10 s input on
`reveal` IS a bug. libFuzzer flags are passed after `--` per invocation
(cargo-fuzz 0.13.2 has no config-file support).

## Corpus policy

`fuzz/corpus/<target>/` holds the committed SEED corpus: real key material
generated from this repo's own key-generation path plus handcrafted
adversarial inputs (END-before-BEGIN keyring, unterminated armour blocks,
credential-shaped URLs, traversal repo_ids, Windows-prefixed paths, ...).
The generated/live corpus, crash artifacts, and coverage output are
gitignored via `fuzz/.gitignore`; because `corpus` is ignored wholesale,
new seed files must be added with `git add -f fuzz/corpus/<target>/<file>`.

Upstream corpora worth pulling in (do not vendor blindly — see the research
plan §4B for licence/provenance notes):

- rpgp (`pgp` 0.19 upstream): `tests/` key artifacts incl.
  `draft-bre-openpgp-samples-00/` and `bad_ecdh/` malformed-key corpora,
  plus `fuzz/dictionaries/` (use with `-dict=` for the armoured targets).
- ProtonMail/go-crypto `fuzz/` seed corpora (BSD-3-Clause), convertible 1:1.
- GnuPG `tests/fuzz/` (GPLv2+): generate locally if needed.

## Triage policy

1. Reproduce with `cargo fuzz run <target> <artifact>`.
2. Check the panic location: inside `src/` = in-tree bug → minimize
   (`tmin`), add a Red regression test in `tests/`, fix, go Green.
   Inside `~/.cargo/registry/.../pgp-0.19.0/` = upstream (rpgp) — file
   upstream with the artifact, add the artifact to the seed corpus, do NOT
   patch the dependency in-tree.
3. Timeout/OOM artifacts are genuine DoS findings for a secrets tool —
   triage, never suppress.

## Known findings

- **FIXED (in-tree)**: `Keyring::parse` panicked on an END marker preceding
  the BEGIN marker (`src/keyring.rs` slicing). Regression test:
  `keyring_parse_rejects_end_marker_before_begin` in `tests/features.rs`;
  `fuzz_keyring_parse` now survives the artifact.
- **HARNESS-ONLY (no lib bug)**: three early crashes were over-strong or
  mis-scoped harness oracles (BEGIN-count invariant on the splitters, bare
  serde parse instead of `TrackedFiles::load`'s validate step, echo check on
  the empty string). Harnesses corrected; library unchanged.
- **OPEN — Andon, fix outside fuzzing lane**: `parse_git_remote_url` accepts
  `'@'`/`':'` inside the user/repo capture groups, so credential-shaped
  material lands IN the derived repo_id
  (`https://github.com/user:pass@evil/repo` ⇒ user = `"user:pass@evil"`;
  artifact `fuzz/artifacts/parse_git_remote_url/crash-c38b1035…`). The fix
  belongs in `src/repo_identity.rs` (SSH_SCP_RE / SCHEME_USERINFO_RE user and
  repo groups must exclude `'@'` and `':'`). Red half of the pair pinned as
  `repo_id_components_never_contain_credential_shaped_material` (ignored) in
  `tests/features.rs`; un-ignore when the fix lands. Until then
  `fuzz_parse_git_remote_url` aborts on this known finding; all its other
  oracles (lowercase, idempotence, redaction) held across exploration runs.

## CI (follow-on)

No GitHub Actions config exists in this repo yet. When CI is introduced, add
a `fuzz-smoke` workflow (matrix over the 10 targets,
`cargo +nightly fuzz run <target> -- -runs=20000 -timeout=25
-rss_limit_mb=2048 -max_len=65536`, upload `fuzz/artifacts/` on failure)
after the official rust-fuzz book example; nightly scheduled runs should use
`-max_total_time=1800` per target.
