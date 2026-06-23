# pin base image by digest so every build starts from the same bytes
FROM golang:1.25.1-trixie@sha256:ff83f3762390c2cccb53618ccc18af23e556aff9b1db4428637e9f63287c8171 AS builder

# commit timestamp, propagated through the build to clamp file mtimes and normalize embedded dates
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

WORKDIR /app

# apt normally resolves to whatever package versions the mirror serves at build time, so two builds days apart install different bytes
# redirect apt at snapshot.debian.org keyed on SOURCE_DATE_EPOCH so every build installs the exact package set that existed at that instant
# NOTE:(@janezicmatej) taken verbatim from https://github.com/reproducible-containers/repro-sources-list.sh/blob/master/alternative/Dockerfile.debian-13
RUN \
  --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  : "${SOURCE_DATE_EPOCH:=$(stat --format=%Y /etc/apt/sources.list.d/debian.sources)}" && \
  snapshot="$(/bin/bash -euc "printf \"%(%Y%m%dT%H%M%SZ)T\n\" \"${SOURCE_DATE_EPOCH}\"")" && \
  : "Enabling snapshot" && \
  sed -i -e '/Types: deb/ a\Snapshot: true' /etc/apt/sources.list.d/debian.sources && \
  : "Enabling cache" && \
  rm -f /etc/apt/apt.conf.d/docker-clean && \
  echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' >/etc/apt/apt.conf.d/keep-cache && \
  : "Fetching the snapshot and installing ca-certificates in one command" && \
  apt-get install --update --snapshot "${snapshot}" -o Acquire::Check-Valid-Until=false -o Acquire::https::Verify-Peer=false -y ca-certificates && \
  : "Installing the cgo toolchain (gcc + libc6-dev) pinned to the same snapshot, now with tls verification" && \
  apt-get install --snapshot "${snapshot}" -y gcc libc6-dev && \
  : "Clean up for improving reproducibility (optional)" && \
  rm -rf /var/log/* /var/cache/ldconfig/aux-cache

# explicit chmod/chown on COPY so file metadata does not depend on host umask or ownership
COPY --chmod=644 --chown=0:0 go.mod go.sum ./
RUN go mod download
RUN go mod verify

COPY --chmod=644 --chown=0:0 . .
# -trimpath strips build-host paths from the binary
# -buildid= clears go's non-deterministic build id
# -s -w drop symbol and dwarf tables, which contain build-time data
# -buildvcs=false omits embedded vcs metadata
# CGO_ENABLED=1 links the native C libsecp256k1 vendored in go-ethereum, which is substantially faster than the pure-go fallback
# -linkmode=external -extldflags=-static drives the external linker (ld) with -static so the result is a single static binary that still runs under FROM scratch
# the cgo toolchain (gcc, libc6-dev) is pinned via the apt snapshot above, and -trimpath + -s -w together strip the cgo-side path leaks that go's -trimpath does not fully cover (golang/go#24976, #67011)
# tags=netgo,osusergo force the pure-go net and os/user resolvers; the cgo equivalents rely on glibc nss at runtime, which does not work in a statically linked binary
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 GOFLAGS="-buildvcs=false" \
  go build -tags=netgo,osusergo -trimpath \
  -ldflags="-buildid= -s -w -linkmode=external -extldflags=-static" \
  -o /app/server cmd/main.go

# NOTE:(@janezicmatej) buildkit's rewrite-timestamp only clamps mtimes down to SOURCE_DATE_EPOCH (moby/buildkit#3180)
# files older than SOURCE_DATE_EPOCH are left at their original non-deterministic mtime
# touch every path to SOURCE_DATE_EPOCH explicitly so timestamps are normalized in both directions
RUN find /app -exec touch -h -d @${SOURCE_DATE_EPOCH} {} +

# minimal base pinned by digest so every build starts from the same bytes
# distroless/static ships the resolution stubs (nsswitch.conf, passwd, group, resolv.conf, hosts)
# and the ca-certificates bundle that a static go binary needs at runtime, with no shell or package manager
FROM gcr.io/distroless/static-debian12@sha256:20bc6c0bc4d625a22a8fde3e55f6515709b32055ef8fb9cfbddaa06d1760f838

WORKDIR /app

# the only things the final image needs on top of the base: the server binary and the cs attestation root
# the tls trust store (/etc/ssl/certs/ca-certificates.crt) already ships in distroless/static, pinned via the base digest
# google_confidential_space_root.crt is the root used to verify confidential space attestation tokens
# re-apply chmod/chown on each COPY so metadata is pinned here and does not depend on whatever the builder stage left behind
COPY --chmod=755 --chown=0:0 --from=builder /app/server /app/server
COPY --chmod=644 --chown=0:0 --from=builder /app/assets/google_confidential_space_root.crt /app/assets/google_confidential_space_root.crt

# production mode
ENV MODE=0

# run as root: the confidential space launcher exposes its attestation-token IPC at
# /run/container_launcher/teeserver.sock owned by root with no group/other access, and the
# workload cannot chmod a socket the launcher created on the host side; the container is not
# the trust boundary in confidential space anyway, the attested vm is, so dropping privileges
# inside the container does not change what the launch policy attests to
USER 0:0

# confidential space launch policy label: allow the operator to override these env vars at workload launch
# without this, the confidential space VM rejects overrides at attestation time and the values baked here are final
LABEL "tee.launch_policy.allow_env_override"="LOG_LEVEL,PROXY_URL,INITIAL_OWNER,EXTENSION_ID,CHAIN_ID,GOVERNANCE_SIGNERS,GOVERNANCE_THRESHOLD"

EXPOSE 5500

CMD ["./server"]
