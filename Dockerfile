# syntax=docker/dockerfile:1

ARG ALPINE_VERSION=3.24
ARG SUPERVISOR_VERSION=0.1.0-dev
ARG TRANSMISSION_VERSION=4.1.4
ARG TRANSMISSION_URL=https://github.com/transmission/transmission/releases/download/4.1.4/transmission-4.1.4.tar.xz
ARG TRANSMISSION_SHA256=86e7aa020cdf64826447034bc85f4d3b7c848d8c0891d9dc9b9fddfb2c805d22
ARG OPENVPN_VERSION=2.7.8
ARG OPENVPN_URL=https://build.openvpn.net/downloads/releases/openvpn-2.7.8.tar.gz
ARG OPENVPN_SHA256=c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36
ARG CONTRIB_REVISION=ff3753aadd96cca4b056f60930fa577e6e2986a3
ARG CONTRIB_URL=https://codeload.github.com/haugene/vpn-configs-contrib/tar.gz/ff3753aadd96cca4b056f60930fa577e6e2986a3
ARG CONTRIB_SHA256=20dde604bc6b7c898a9d2783c5837b9f80af326317020a9e79e0b2bbd3e4cfa1
ARG FLOOD_VERSION=1.0.1
ARG FLOOD_URL=https://github.com/johman10/flood-for-transmission/releases/download/v1.0.1/flood-for-transmission.tar.gz
ARG FLOOD_SHA256=0797c3d7c081665bfa876cbc78938204e1c811d5e1d09a3cb7040f365c19aa27
ARG FLOOD_REVISION=6d6c6fda7a507c864085d3c159ca6fe2886de06d
ARG FLOOD_LICENSE_URL=https://raw.githubusercontent.com/johman10/flood-for-transmission/6d6c6fda7a507c864085d3c159ca6fe2886de06d/LICENSE
ARG FLOOD_LICENSE_SHA256=3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986
ARG TRANSMISSIONIC_VERSION=1.9.0
ARG TRANSMISSIONIC_URL=https://github.com/lostinfuture/transmissionic/releases/download/v1.9.0/Transmissionic-webui-v1.9.0.zip
ARG TRANSMISSIONIC_SHA256=3bbeca59cda846041963bf668e57810829ac1ecc3d0ef01c70f2b68234e0e351
ARG TRANSMISSIONIC_REVISION=d5825a48b188c0089c80acb62b57bb54e24e641b
ARG RUSTNET_VERSION=1.7.0
ARG RUSTNET_URL=https://github.com/domcyrus/rustnet/archive/refs/tags/v1.7.0.tar.gz
ARG RUSTNET_SHA256=9d3f6509da06f832c04c5accc7b777c18f3de8b32c885137c9a1346990694dda

FROM alpine:${ALPINE_VERSION} AS transmission-src
ARG TRANSMISSION_URL TRANSMISSION_SHA256
RUN apk add --no-cache ca-certificates wget xz \
    && wget -O /tmp/transmission.tar.xz "${TRANSMISSION_URL}" \
    && echo "${TRANSMISSION_SHA256}  /tmp/transmission.tar.xz" | sha256sum -c \
    && mkdir -p /src \
    && tar -xJf /tmp/transmission.tar.xz -C /src --strip-components=1 \
    && rm /tmp/transmission.tar.xz

FROM alpine:${ALPINE_VERSION} AS openvpn-src
ARG OPENVPN_URL OPENVPN_SHA256
RUN apk add --no-cache ca-certificates wget \
    && wget -O /tmp/openvpn.tar.gz "${OPENVPN_URL}" \
    && echo "${OPENVPN_SHA256}  /tmp/openvpn.tar.gz" | sha256sum -c \
    && mkdir -p /src \
    && tar -xzf /tmp/openvpn.tar.gz -C /src --strip-components=1 \
    && rm /tmp/openvpn.tar.gz

FROM --platform=$BUILDPLATFORM alpine:${ALPINE_VERSION} AS supervisor
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG SUPERVISOR_VERSION
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN apk add --no-cache go \
    && case "${TARGETARCH}" in \
         arm) export GOARM="${TARGETVARIANT#v}" ;; \
       esac \
    && GOTOOLCHAIN=local CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
         go build -trimpath -ldflags "-s -w -X main.version=${SUPERVISOR_VERSION} -X main.transmission=4.1.4 -X main.openvpn=2.7.8" \
         -o /out/ovpn-supervisor ./cmd/ovpn-supervisor

FROM alpine:${ALPINE_VERSION} AS transmission-build
RUN apk add --no-cache \
        build-base cmake samurai pkgconf \
        openssl-dev curl-dev libevent-dev libdeflate-dev libpsl-dev linux-headers libcap
COPY --from=transmission-src /src /src
WORKDIR /src
RUN cmake -S . -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DENABLE_DAEMON=ON \
        -DENABLE_GTK=OFF \
        -DENABLE_QT=OFF \
        -DENABLE_MAC=OFF \
        -DENABLE_CLI=OFF \
        -DENABLE_UTILS=OFF \
        -DENABLE_TESTS=OFF \
        -DENABLE_NLS=OFF \
        -DINSTALL_LIB=OFF \
        -DINSTALL_DOC=ON \
        -DREBUILD_WEB=OFF \
        -DINSTALL_WEB=ON \
        -DENABLE_UTP=ON \
        -DWITH_CRYPTO=openssl \
        -DWITH_SYSTEMD=OFF \
        -DUSE_SYSTEM_EVENT2=ON \
        -DUSE_SYSTEM_DEFLATE=ON \
        -DUSE_SYSTEM_PSL=ON \
        -DUSE_SYSTEM_MINIUPNPC=OFF \
        -DUSE_SYSTEM_NATPMP=OFF \
        -DUSE_SYSTEM_DHT=OFF \
        -DUSE_SYSTEM_UTP=OFF \
        -DUSE_SYSTEM_B64=OFF \
    && cmake --build build \
    && cmake --install build \
    && test -x /usr/bin/transmission-daemon \
    && test -d /usr/share/transmission/public_html \
    && test ! -e /usr/bin/transmission-remote \
    && if getcap /usr/bin/transmission-daemon | grep -q .; then exit 1; fi

FROM alpine:${ALPINE_VERSION} AS openvpn-build
RUN apk add --no-cache \
        build-base pkgconf openssl-dev linux-headers \
        libnl3-dev libcap-ng-dev iproute2 libcap
COPY --from=openvpn-src /src /src
WORKDIR /src
RUN ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --with-crypto-library=openssl \
        --enable-dco \
        --disable-plugin-auth-pam \
        --disable-plugins \
        --disable-lzo \
        --disable-lz4 \
        --disable-pkcs11 \
    && make -j"$(nproc)" \
    && make install \
    && test -x /usr/sbin/openvpn \
    && if getcap /usr/sbin/openvpn | grep -q .; then exit 1; fi

FROM alpine:${ALPINE_VERSION} AS contrib
ARG CONTRIB_URL CONTRIB_SHA256
RUN apk add --no-cache ca-certificates wget python3
COPY scripts/extract-contrib.py /tmp/extract-contrib.py
RUN wget -O /tmp/contrib.tar.gz "${CONTRIB_URL}" \
    && echo "${CONTRIB_SHA256}  /tmp/contrib.tar.gz" | sha256sum -c \
    && python3 /tmp/extract-contrib.py /tmp/contrib.tar.gz /out \
    && rm /tmp/contrib.tar.gz \
    && test -f /out/airvpn/default.ovpn \
    && test -f /out/blackvpn/ssl/ca.crt \
    && test -f /out/fastestvpn/default.ovpn \
    && test ! -d /out/custom \
    && if find /out -type l | grep -q .; then echo "symlink left in snapshot" >&2; exit 1; fi \
    && if find /out \( -name '*.sh' -o -name '*.py' \) | grep -q .; then echo "script left in snapshot" >&2; exit 1; fi

FROM alpine:${ALPINE_VERSION} AS flood
ARG FLOOD_URL FLOOD_SHA256 FLOOD_LICENSE_URL FLOOD_LICENSE_SHA256 FLOOD_REVISION
RUN apk add --no-cache ca-certificates wget tar \
    && wget -O /tmp/flood.tar.gz "${FLOOD_URL}" \
    && echo "${FLOOD_SHA256}  /tmp/flood.tar.gz" | sha256sum -c \
    && mkdir -p /opt/transmission-ui \
    && tar -xzf /tmp/flood.tar.gz -C /opt/transmission-ui \
    && test -f /opt/transmission-ui/flood-for-transmission/index.html \
    && mkdir -p /usr/share/licenses/flood-for-transmission \
    && wget -O /usr/share/licenses/flood-for-transmission/LICENSE "${FLOOD_LICENSE_URL}" \
    && echo "${FLOOD_LICENSE_SHA256}  /usr/share/licenses/flood-for-transmission/LICENSE" | sha256sum -c \
    && printf '%s\n' \
        "https://github.com/johman10/flood-for-transmission/releases/tag/v1.0.1" \
        "${FLOOD_URL}" \
        "${FLOOD_REVISION}" \
        > /usr/share/licenses/flood-for-transmission/SOURCE \
    && rm /tmp/flood.tar.gz

FROM alpine:${ALPINE_VERSION} AS transmissionic
ARG TRANSMISSIONIC_VERSION TRANSMISSIONIC_URL TRANSMISSIONIC_SHA256 TRANSMISSIONIC_REVISION
RUN apk add --no-cache ca-certificates wget unzip \
    && wget -O /tmp/transmissionic.zip "${TRANSMISSIONIC_URL}" \
    && echo "${TRANSMISSIONIC_SHA256}  /tmp/transmissionic.zip" | sha256sum -c \
    && mkdir -p /tmp/unpack \
    && unzip -q /tmp/transmissionic.zip -d /tmp/unpack \
    && test -f /tmp/unpack/web/index.html \
    && test -f /tmp/unpack/web/LICENSE \
    && test -f /tmp/unpack/web/NOTICE \
    && test -f /tmp/unpack/web/default.json \
    && grep -q "Copyright (c) 2021 Transmissionic" /tmp/unpack/web/LICENSE \
    && grep -q "Copyright (c) 2026 lostinfuture" /tmp/unpack/web/NOTICE \
    && grep -q "script-src 'self'" /tmp/unpack/web/index.html \
    && grep -q 'src="js/' /tmp/unpack/web/index.html \
    && mkdir -p /opt/transmission-ui /usr/share/licenses/transmissionic \
    && mv /tmp/unpack/web /opt/transmission-ui/transmissionic \
    && cp /opt/transmission-ui/transmissionic/LICENSE /usr/share/licenses/transmissionic/LICENSE \
    && cp /opt/transmission-ui/transmissionic/NOTICE /usr/share/licenses/transmissionic/NOTICE \
    && printf '%s\n' \
        "https://github.com/lostinfuture/transmissionic/releases/tag/v${TRANSMISSIONIC_VERSION}" \
        "${TRANSMISSIONIC_URL}" \
        "${TRANSMISSIONIC_REVISION}" \
        > /usr/share/licenses/transmissionic/SOURCE \
    && rm -rf /tmp/transmissionic.zip /tmp/unpack \
    && if find /opt/transmission-ui/transmissionic \( -name '*.sh' -o -name '*.py' \) | grep -q .; then echo "script left in transmissionic" >&2; exit 1; fi

FROM alpine:${ALPINE_VERSION} AS rustnet
ARG TARGETARCH RUSTNET_URL RUSTNET_SHA256 RUSTNET_VERSION
RUN mkdir -p /out/bin /out/licenses \
    && if [ "${RUSTNET_SHA256}" = "UNPINNED" ]; then echo "RUSTNET_SHA256 is UNPINNED" >&2; exit 1; fi \
    && case "${TARGETARCH}" in \
         amd64|arm64) \
           apk add --no-cache ca-certificates wget build-base \
             cargo rustfmt clang llvm linux-headers \
             libpcap-dev elfutils-dev zlib-dev pkgconf \
           && wget -O /tmp/rustnet.tar.gz "${RUSTNET_URL}" \
           && echo "${RUSTNET_SHA256}  /tmp/rustnet.tar.gz" | sha256sum -c \
           && mkdir -p /src \
           && tar -xzf /tmp/rustnet.tar.gz -C /src --strip-components=1 \
           && rm /tmp/rustnet.tar.gz \
           && cd /src \
           && cargo build --release --locked \
           && test -x /src/target/release/rustnet \
           && cp /src/target/release/rustnet /out/bin/rustnet \
           && cp /src/LICENSE /out/licenses/LICENSE \
           && test -s /out/licenses/LICENSE \
           ;; \
         *) \
           echo "skipping rustnet on ${TARGETARCH}" \
           ;; \
       esac

FROM alpine:${ALPINE_VERSION}
RUN apk add --no-cache \
        ca-certificates \
        tzdata \
        iptables \
        iproute2 \
        openssl \
        libnl3 \
        libcap-ng \
        libevent \
        libcurl \
        libpsl \
        libdeflate \
        libstdc++ \
        libgcc \
        libcap \
        libpcap \
        libelf \
        zlib \
    && apk upgrade --no-cache
COPY --from=transmission-build /usr/bin/transmission-daemon /usr/bin/transmission-daemon
COPY --from=transmission-build /usr/share/transmission/public_html /usr/share/transmission/public_html
COPY --from=transmission-src /src/COPYING /usr/share/licenses/transmission/COPYING
COPY --from=openvpn-build /usr/sbin/openvpn /usr/bin/openvpn
COPY --from=supervisor /out/ovpn-supervisor /usr/bin/ovpn-supervisor
COPY --from=supervisor /src/internal/provider/pia/testdata/ca.rsa.4096.crt /usr/share/transmission-openvpn/pia/ca.rsa.4096.crt
COPY --from=contrib /out/ /etc/openvpn/
COPY --from=flood /opt/transmission-ui/flood-for-transmission /opt/transmission-ui/flood-for-transmission
COPY --from=flood /usr/share/licenses/flood-for-transmission /usr/share/licenses/flood-for-transmission
COPY --from=transmissionic /opt/transmission-ui/transmissionic /opt/transmission-ui/transmissionic
COPY --from=transmissionic /usr/share/licenses/transmissionic /usr/share/licenses/transmissionic
COPY --from=rustnet /out/ /tmp/rustnet/
COPY sbom/rustnet.cdx.json /usr/share/licenses/rustnet/rustnet.cdx.json
RUN set -o pipefail \
    && if [ -x /tmp/rustnet/bin/rustnet ]; then \
         mv /tmp/rustnet/bin/rustnet /usr/bin/rustnet \
         && mkdir -p /usr/share/licenses/rustnet \
         && mv /tmp/rustnet/licenses/LICENSE /usr/share/licenses/rustnet/LICENSE \
         && chmod 0755 /usr/bin/rustnet; \
       fi \
    && rm -rf /tmp/rustnet \
    && chmod 0755 /usr/bin/transmission-daemon /usr/bin/openvpn /usr/bin/ovpn-supervisor \
    && bins="/usr/bin/transmission-daemon /usr/bin/openvpn" \
    && if [ -x /usr/bin/rustnet ]; then bins="$bins /usr/bin/rustnet"; fi \
    && ldd $bins | tee /tmp/ldd.out \
    && ! grep -E -q 'not found|Error relocating|Error loading' /tmp/ldd.out \
    && rm /tmp/ldd.out \
    && if getcap $bins | grep -q .; then exit 1; fi \
    && if [ -x /usr/bin/rustnet ]; then \
         test -s /usr/share/licenses/rustnet/LICENSE \
         && grep -q "Apache License" /usr/share/licenses/rustnet/LICENSE \
         && grep -q '"name": "rustnet"' /usr/share/licenses/rustnet/rustnet.cdx.json \
         && grep -q 'pkg:github/domcyrus/rustnet@v1.7.0' /usr/share/licenses/rustnet/rustnet.cdx.json \
         && grep -q '"value": "absent"' /usr/share/licenses/rustnet/rustnet.cdx.json; \
       fi \
    && apk del libcap \
    && /usr/bin/ovpn-supervisor check-snapshot \
    && test -f /opt/transmission-ui/flood-for-transmission/index.html \
    && test -s /usr/share/licenses/flood-for-transmission/LICENSE \
    && grep -q 6d6c6fda7a507c864085d3c159ca6fe2886de06d /usr/share/licenses/flood-for-transmission/SOURCE \
    && test -f /opt/transmission-ui/transmissionic/index.html \
    && test -s /usr/share/licenses/transmissionic/LICENSE \
    && grep -q "Copyright (c) 2021 Transmissionic" /usr/share/licenses/transmissionic/LICENSE \
    && grep -q d5825a48b188c0089c80acb62b57bb54e24e641b /usr/share/licenses/transmissionic/SOURCE \
    && test -s /usr/share/transmission-openvpn/pia/ca.rsa.4096.crt \
    && grep -q "BEGIN CERTIFICATE" /usr/share/transmission-openvpn/pia/ca.rsa.4096.crt \
    && ! command -v natpmpc
ARG SUPERVISOR_VERSION
LABEL org.opencontainers.image.title=transmission-openvpn \
      org.opencontainers.image.description="Transmission and OpenVPN in one container, with a kill switch." \
      org.opencontainers.image.version="${SUPERVISOR_VERSION}" \
      org.opencontainers.image.source=https://github.com/lostinfuture/transmission-openvpn \
      org.opencontainers.image.licenses="Apache-2.0 AND MIT AND (GPL-2.0-only OR GPL-3.0-only) AND GPL-2.0-only WITH openvpn-openssl-exception AND GPL-3.0-only" \
      dev.lostinfuture.transmission.version=4.1.4 \
      dev.lostinfuture.openvpn.version=2.7.8 \
      dev.lostinfuture.flood.revision=6d6c6fda7a507c864085d3c159ca6fe2886de06d \
      dev.lostinfuture.vpn-configs.revision=ff3753aadd96cca4b056f60930fa577e6e2986a3 \
      dev.lostinfuture.transmissionic.version=1.9.0 \
      dev.lostinfuture.rustnet.version=1.7.0 \
      autoheal=true
EXPOSE 9091
VOLUME ["/data", "/config"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/usr/bin/ovpn-supervisor", "healthcheck"]
ENTRYPOINT ["/usr/bin/ovpn-supervisor"]
CMD ["run"]
