### STAGE 1: Build ###

FROM bitnami/minideb:unstable as builder

RUN install_packages gcc gcc-multilib dub ldc

COPY . .

RUN dub build -b release

### STAGE 2:Setup ###

FROM busybox:1.27.2-glibc

COPY --from=builder /usr/lib/x86_64-linux-gnu/libphobos2-ldc.so.74 \
                    /usr/lib/x86_64-linux-gnu/libdruntime-ldc.so.74 \
                    /lib/x86_64-linux-gnu/ld-2.24.so \
                    /lib/x86_64-linux-gnu/libz.so.1 \
                    /lib/x86_64-linux-gnu/librt.so.1 \
                    /lib/x86_64-linux-gnu/libgcc_s.so.1 \
                    /lib/x86_64-linux-gnu/libdl.so.2 \
                    /usr/local/lib/

COPY --from=builder /socks5d /socks5d

ENV LD_LIBRARY_PATH="/usr/local/lib"

CMD /socks5d --address="0.0.0.0"
