### STAGE 1: Build ###

FROM debian:buster-slim as builder

RUN apt-get update && \
    apt-get install -y libc6-dev gcc curl && \
    curl -L -o /dmd.deb http://downloads.dlang.org/releases/2.x/2.076.1/dmd_2.076.1-0_amd64.deb && \
    dpkg -i /dmd.deb

COPY . .

RUN dub build -b release

### STAGE 2:Setup ###

FROM busybox:1.27.2-glibc

COPY --from=builder /lib/x86_64-linux-gnu/librt.so.1 \
                    /lib/x86_64-linux-gnu/libdl.so.2 \
                    /lib/x86_64-linux-gnu/libgcc_s.so.1 \
                    /usr/local/lib/

COPY --from=builder /socks5d /socks5d

ENV LD_LIBRARY_PATH="/usr/local/lib"

CMD /socks5d --address="0.0.0.0"
