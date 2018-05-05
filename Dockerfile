### STAGE 1: Build ###

FROM debian:buster-slim as builder

ENV COMPILER=ldc \
    COMPILER_VERSION=1.9.0

RUN apt-get update && apt-get install -y curl libcurl3 build-essential zlib1g-dev libssl-dev \
 && curl -fsS -o /tmp/install.sh https://dlang.org/install.sh \
 && bash /tmp/install.sh -p /dlang install "${COMPILER}-${COMPILER_VERSION}" \
 && rm /tmp/install.sh \
 && apt-get auto-remove -y curl build-essential \
 && apt-get install -y gcc cmake \
 && rm -rf /var/cache/apt /dlang/${COMPILER}-*/lib32 /dlang/dub-1.0.0/dub.tar.gz

ENV PATH=/dlang/${COMPILER}-${COMPILER_VERSION}/bin:${PATH} \
    LD_LIBRARY_PATH=/dlang/${COMPILER}-${COMPILER_VERSION}/lib \
    LIBRARY_PATH=/dlang/${COMPILER}-${COMPILER_VERSION}/lib

WORKDIR /src

COPY . .

RUN dub build -b release --compiler=ldc2

### STAGE 2:Setup ###

FROM busybox:1.28.3-glibc

COPY --from=builder /lib/x86_64-linux-gnu/librt.so.1 \
                    /lib/x86_64-linux-gnu/libdl.so.2 \
                    /lib/x86_64-linux-gnu/libanl.so.1 \
                    /lib/x86_64-linux-gnu/libgcc_s.so.1 \
                    /usr/lib/x86_64-linux-gnu/libssl.so.1.1 \
                    /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 \
                    /lib/x86_64-linux-gnu/libz.so.1 \
                    /usr/local/lib/

COPY --from=builder /src/socks5d /socks5d

ENV LD_LIBRARY_PATH="/usr/local/lib"

ENTRYPOINT ["/socks5d", "--address=0.0.0.0"]
