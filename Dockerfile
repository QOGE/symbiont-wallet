# QOGE SPHINCS Wallet — Docker build environment
# Extends the eomii/SPHINCS-Wallet Docker pattern for FIPS 205 SLH-DSA.
#
# M1.1 NOTE: This Dockerfile builds liboqs from source to ensure we get
# the correct FIPS 205 parameter sets. The ref repo used a pre-built
# liboqs-go with Round 3 params only.
#
# Once the Open Quantum Safe project publishes a stable FIPS 205 release
# tag on GitHub, pin the LIBOQS_VERSION below to that tag.
# Monitor: https://github.com/open-quantum-safe/liboqs/releases

FROM ubuntu:24.04

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    golang-go \
    libssl-dev \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Build liboqs from source (FIPS 205 parameter sets) ───────────────────────
# M1.1: Set LIBOQS_VERSION to the first tag that includes FIPS 205 final params.
# Current placeholder: build from main until a release tag is available.
ENV LIBOQS_VERSION=main
ENV LIBOQS_INSTALL=/usr/local

WORKDIR /build/liboqs
RUN git clone --depth 1 --branch ${LIBOQS_VERSION} \
    https://github.com/open-quantum-safe/liboqs.git . && \
    cmake -GNinja \
        -DCMAKE_INSTALL_PREFIX=${LIBOQS_INSTALL} \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_USE_OPENSSL=ON \
        # FIPS 205 build flags (verify names in liboqs CMakeLists.txt):
        # These enable SLH-DSA-SHA2-128f under its FIPS 205 designation.
        # Round 3 flag: OQS_ENABLE_SIG_SPHINCS (enables all SPHINCS+ variants)
        # FIPS 205 flag: OQS_ENABLE_SIG_SLH_DSA (confirm this name in release)
        -DOQS_ENABLE_SIG_SPHINCS=ON \
        -DOQS_DIST_BUILD=ON \
        .. && \
    ninja && ninja install

# ── Set up liboqs-go bindings ─────────────────────────────────────────────────
ENV CGO_CFLAGS="-I${LIBOQS_INSTALL}/include"
ENV CGO_LDFLAGS="-L${LIBOQS_INSTALL}/lib -loqs"
ENV LD_LIBRARY_PATH="${LIBOQS_INSTALL}/lib:${LD_LIBRARY_PATH}"

# ── Go workspace ─────────────────────────────────────────────────────────────
WORKDIR /app

# Copy go module files first (layer cache optimisation)
COPY go.mod go.sum* ./
RUN go mod download || true  # Allow missing go.sum on first build

# Copy source
COPY . .

# ── Build ─────────────────────────────────────────────────────────────────────
RUN go build -v ./...

# ── Usage ─────────────────────────────────────────────────────────────────────
# Build:  docker build -t qoge-sphincs-wallet .
# Run:    docker run --rm -it --workdir=/app -v ${PWD}:/app qoge-sphincs-wallet /bin/bash
# Then:   go run cmd/main.go
# Tests:  go test ./address/... -v
#         go test ./keystore/... -v
CMD ["/bin/bash"]
