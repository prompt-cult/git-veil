#!/bin/sh
# Regenerate the committed man pages and shell completions from the real
# clap CLI definition. Outputs land in docs/man and docs/completions.
set -eu

repo_root="$(git rev-parse --show-toplevel)"
man_dir="$repo_root/docs/man"
completions_dir="$repo_root/docs/completions"

mkdir -p "$man_dir" "$completions_dir"

cargo run --quiet -- manpages "$man_dir"

for shell in bash zsh fish; do
    cargo run --quiet -- completions "$shell" > "$completions_dir/git-gpg.$shell"
done

echo "man pages:   $man_dir"
echo "completions: $completions_dir"
