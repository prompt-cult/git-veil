# Third-party code

| Component | Version and source | License | Use in git-veil |
| --- | --- | --- | --- |
| uutils `uu_shred` | 0.13.0; `src/uu/shred/src/shred.rs` at commit [`7d73dd5`](https://github.com/uutils/coreutils/commit/7d73dd5bd2f01b7499aeeb16e3bc683e3beaab50) | MIT; full text in [`LICENSES/MIT-uutils-coreutils.txt`](LICENSES/MIT-uutils-coreutils.txt) | Adapted for `hide` to overwrite regular files, rename the path, truncate, and unlink; uutils CLI and `uucore` integration were removed. Source and adaptation notes are at the top of [`src/uu_shred.rs`](src/uu_shred.rs). |
