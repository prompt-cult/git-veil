# LOCAL SITE TESTING ONLY - NOT A SHIPPING ARTIFACT.
#
# Purpose: preview the rendered book before GH Pages publishes it, so layout
# and rendering fixes are proven locally (see Dockerfile.site and GH #95).
#
# Run from the repo root:   make -C docs
# Or from this directory:   make
#
# Native arm64 only. Docker talks to the local colima VM; no --platform
# overrides, no x86 emulation. If the build fails on this host, fix the
# Dockerfile; do not force a platform.

.PHONY: serve clean stop

# Build the image and serve the book on http://localhost:8080
# The build context is the repo root (..) so the Dockerfile sees book.toml,
# docs/, scripts/ and the mermaid assets at the paths it copies from.
serve:
	docker build -f Dockerfile.site -t git-veil-site:local ..
	docker rm -f git-veil-site 2>/dev/null || true
	docker run -d --name git-veil-site -p 8080:8080 git-veil-site:local
	@echo "site: http://localhost:8080/  (design: /design.html, trust: /trust-model.html)"

# Stop the detached container started by serve
stop:
	docker rm -f git-veil-site 2>/dev/null || true

# Remove the build output and the image
clean: stop
	docker rmi git-veil-site:local 2>/dev/null || true
	rm -rf ../_book

.DEFAULT_GOAL := serve
