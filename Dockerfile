FROM ubuntu:18.04 as builder

ENV COMPILER=ldc \
    COMPILER_VERSION=1.9.0

RUN apt-get update

RUN apt-get install -y curl libcurl4 build-essential zlib1g-dev libssl-dev \
 && curl -fsS -o /tmp/install.sh https://dlang.org/install.sh \
 && bash /tmp/install.sh -p /dlang install "${COMPILER}-${COMPILER_VERSION}" \
 && rm /tmp/install.sh \
 && apt-get auto-remove -y curl build-essential \
 && rm -rf /var/cache/apt /dlang/${COMPILER}-*/lib32 /dlang/dub-1.0.0/dub.tar.gz

ENV PATH=/dlang/${COMPILER}-${COMPILER_VERSION}/bin:${PATH} \
    LD_LIBRARY_PATH=/dlang/${COMPILER}-${COMPILER_VERSION}/lib \
    LIBRARY_PATH=/dlang/${COMPILER}-${COMPILER_VERSION}/lib

WORKDIR /src

CMD ["/bin/bash"]

