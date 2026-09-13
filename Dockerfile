# syntax=docker/dockerfile:1

# tsportmap is a single static binary embedding one Tailscale node via tsnet.
# tsnet is a userspace network stack, so the container needs no /dev/net/tun, no
# NET_ADMIN capability and no privileged mode — unlike the official tailscale
# container, which runs the kernel client.

# ---- build ------------------------------------------------------------------

# The builder always runs on the native build platform and cross-compiles to the
# target. For a pure-Go binary that is strictly cheaper than emulating the
# target architecture under QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build

# CGO off gives a genuinely static binary with the pure-Go resolver, which is
# what the distroless static base below requires.
#
# GOTOOLCHAIN=auto lets the module's own "go 1.26.6" directive fetch that exact
# patch release if the base image ships an earlier 1.26.x. The base is not
# pinned lower than 1.26 precisely so this stays a rare fallback rather than a
# toolchain download on every build.
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=auto

WORKDIR /src

# Dependency resolution depends only on go.mod/go.sum, so this layer survives
# every source-only change. tailscale.com is the single third-party dependency
# and it is a large one; re-downloading it per build is the slowest thing this
# Dockerfile could do.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

# The build cache is keyed by target platform. A single cache shared across
# GOARCHes thrashes: alternating amd64/arm64 builds would evict each other's
# entries and neither would ever hit.
#
# -trimpath keeps absolute builder paths out of the binary; "-s -w" drops the
# symbol table and DWARF, which is most of the size of a tailscale.com binary.
# -buildvcs=false is required because .dockerignore deliberately excludes .git
# from the build context: with VCS stamping left on auto, the build fails rather
# than silently omitting the stamp. The version therefore arrives as a build
# argument instead.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build,id=tsportmap-gobuild-$TARGETOS-$TARGETARCH \
    GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build \
        -trimpath \
        -buildvcs=false \
        -ldflags "-s -w -X github.com/hakaitech/tsportmap/internal/obs.Version=${VERSION}" \
        -o /out/tsportmap \
        ./cmd/tsportmap

# The state directory is materialised here because the final image has no shell
# to run mkdir in. Docker seeds a fresh named or anonymous volume from whatever
# the image has at the mount point — ownership and mode included — so shipping
# an empty 0700 directory owned by the runtime UID is what makes a first-boot
# volume writable.
RUN mkdir -p /out/state

# ---- runtime ----------------------------------------------------------------

# distroless/static-debian12, not scratch. The node cannot reach the tailnet
# without a CA bundle: tsnet opens TLS connections to the coordination server
# and to DERP relays, and on scratch every one of them fails the handshake with
# "x509: certificate signed by unknown authority". That failure reads like a
# network outage rather than a missing file, so it is worth the ~2MB. The base
# also supplies /etc/passwd (so UID 65532 resolves to a name), tzdata, and an
# empty /tmp — none of which scratch has either.
FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
LABEL org.opencontainers.image.title="tsportmap" \
      org.opencontainers.image.description="Declared bidirectional port mappings over an embedded Tailscale node" \
      org.opencontainers.image.source="https://github.com/hakaitech/tsportmap" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

# The :nonroot tag's user is UID/GID 65532. It is spelled numerically so the
# number is visible to whoever writes the volume mount or the Kubernetes
# securityContext that has to match it.
USER 65532:65532

COPY --from=build /out/tsportmap /usr/local/bin/tsportmap

# tsnet MkdirAlls TSPM_STATE_DIR at 0700 on every start and keeps the node's
# identity (its machine key) there. If UID 65532 cannot write this path the node
# cannot start at all, so the directory ships owned by that UID.
COPY --from=build --chown=65532:65532 --chmod=0700 /out/state /var/lib/tsportmap

COPY LICENSE /LICENSE

# Always set explicitly. An empty Dir makes tsnet fall back to
# os.UserConfigDir(), which errors in a container with no $HOME.
ENV TSPM_STATE_DIR=/var/lib/tsportmap

# Declared so a plain "docker run" still keeps the node identity across a
# restart. Be aware of the two edges: the resulting anonymous volume is
# discarded by "docker rm -v" and orphaned otherwise, so an operator who wants
# the identity to outlive the container must mount a named volume; and platforms
# that ignore VOLUME entirely (Kubernetes, Render, Fly) leave this as a
# container-lifetime directory, where TSPM_EPHEMERAL=true is the honest setting
# — control then reaps the node instead of accumulating dead ones.
VOLUME ["/var/lib/tsportmap"]

# No EXPOSE: every listening port comes from TSPM_OUT_*/TSPM_IN_* at runtime, so
# the image cannot know them. The metrics listener defaults to 127.0.0.1:9090,
# which is unreachable from outside the container until it is pointed at
# 0.0.0.0 — deliberately, because /metrics and /healthz are unauthenticated.
#
# No HEALTHCHECK either: the image has no shell and no HTTP client to run one
# with. Probe TSPM_METRICS_ADDR /healthz from the orchestrator instead.

ENTRYPOINT ["/usr/local/bin/tsportmap"]
