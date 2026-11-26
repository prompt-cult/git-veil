# git-veil release cycle automation.
# The GitHub Releases build (release.yml on tag push) is unchanged.
# This automates the rest: bump -> tag -> push -> wait for release -> tap update -> local verify.

set windows-shell := ["cmd", "/c"]

# Full pure-automation cycle: make a x.y.+1 point release, deploy to the tap, verify locally.
release-patch:
    #!/usr/bin/env bash
    set -euo pipefail
    old="$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)"
    IFS='.' read -r major minor patch <<< "$old"
    new="${major}.${minor}.$((patch + 1))"
    echo "bumping $old -> $new"
    sed -i '' "s/^version = \"$old\"/version = \"$new\"/" Cargo.toml
    cargo check -q  # refreshes Cargo.lock to $new
    sh scripts/gen-docs.sh >/dev/null  # committed man pages/completions carry the version
    git add Cargo.toml Cargo.lock docs/man docs/completions
    git commit -m "chore: bump version to $new"
    git tag "v$new"
    git push origin HEAD:main
    git push origin "v$new"
    echo "waiting for release workflow on v$new"
    for i in $(seq 1 60); do
      state=$(gh run list --repo prompt-cult/git-veil --workflow release.yml -L 1 --json status,conclusion -q '.[0] | .status + ":" + (.conclusion // "null")')
      echo "$state"
      case "$state" in *completed:success*) break;; esac
      sleep 20
    done
    just deploy-tap "$new"
    brew tap prompt-cult/tap https://github.com/prompt-cult/tap >/dev/null 2>&1 || true
    brew upgrade prompt-cult/tap/git-veil 2>/dev/null || brew install prompt-cult/tap/git-veil
    got="$(/opt/homebrew/bin/git-veil --version | awk '{print $2}')"
    echo "installed via tap: $got (want $new)"
    test "$got" = "$new"

# Push the tap formula for version $1 (computes sha256 from the published release assets).
deploy-tap version:
    #!/usr/bin/env bash
    set -euo pipefail
    V="{{version}}"
    sha() { curl -sL "https://github.com/prompt-cult/git-veil/releases/download/v${V}/$1" | sha256sum | cut -d' ' -f1; }
    ARM=$(sha git-veil-macos-aarch64); INTEL=$(sha git-veil-macos-x86_64); LINUX=$(sha git-veil-linux-x86_64)
    SHA=$(gh api repos/prompt-cult/tap/contents/Formula/git-veil.rb -q .sha)
    cat > /tmp/git-veil-formula.rb <<EOF
    # typed: false
    # frozen_string_literal: true

    class GitVeil < Formula
      desc "Secret management for git repositories using age X25519 encryption"
      homepage "https://prompt-cult.github.io/git-veil/"
      license any_of: ["MIT", "Apache-2.0"]

      on_macos do
        on_arm do
          url "https://github.com/prompt-cult/git-veil/releases/download/v${V}/git-veil-macos-aarch64"
          sha256 "${ARM}"
        end
        on_intel do
          url "https://github.com/prompt-cult/git-veil/releases/download/v${V}/git-veil-macos-x86_64"
          sha256 "${INTEL}"
        end
      end
      on_linux do
        on_arm do
          url "https://github.com/prompt-cult/git-veil/releases/download/v${V}/git-veil-linux-x86_64"
          sha256 "${LINUX}"
        end
        on_intel do
          url "https://github.com/prompt-cult/git-veil/releases/download/v${V}/git-veil-linux-x86_64"
          sha256 "${LINUX}"
        end
      end

      def install
        bin.install Dir["git-veil-*"].first => "git-veil"
      end

      test do
        assert_match "git-veil #{version}", shell_output("\#{bin}/git-veil --version")
      end
    end
    EOF
    jq -n --arg m "feat: git-veil ${V} (automated)" --arg c "$(base64 -i /tmp/git-veil-formula.rb)" --arg s "$SHA" '{message:$m, content:$c, sha:$s}' > /tmp/payload.json
    gh api -X PUT repos/prompt-cult/tap/contents/Formula/git-veil.rb --input /tmp/payload.json -q .commit.sha

# Verify the tap-installed binary matches the current release.
verify:
    #!/usr/bin/env bash
    set -euo pipefail
    want="$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)"
    got="$(/opt/homebrew/bin/git-veil --version | awk '{print $2}')"
    echo "cargo: $want  tap-installed: $got"
    test "$got" = "$want"

# Windows lane (Win11 host): see scripts/push-winget-fork.ps1 for submission steps.

# Windows mirror of `release-patch`: bump -> tag -> push -> release + MSI assets -> winget prep.
release-patch-windows:
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/release-patch-windows.ps1

# Prep + validate only the winget manifests for version $1 (computed hashes come
# from the published v{{version}} assets; nothing is submitted).
deploy-winget-windows version:
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/gen-winget-manifests.ps1 -Tag v{{version}}

# Windows: push the validated winget manifests for version $1 to the fork (prep only).
push-winget-windows version:
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/push-winget-fork.ps1 -Version {{version}}

# Submit the committed and tested manifest from current main.
submit-winget-windows version:
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/push-winget-fork.ps1 -Version {{version}} -Submit

# Install and remove the committed portable manifest on Windows 11.
test-winget-windows version:
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/e2e-local-manifest.ps1 -Version {{version}}

# Verify the published Windows release, including MSI install and uninstall.
test-windows-release version:
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-windows-release.ps1 -Version {{version}}
