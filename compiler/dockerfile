# build run env
FROM ubuntu:22.04

ENV TZ = Asia/Shanghai

WORKDIR /usr/local/src

RUN apt-get update -y && apt-get install -y --no-install-recommends libelf1 libelf-dev zlib1g-dev clang make llvm libclang-13-dev && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

COPY ./. /usr/local/src

RUN make install
RUN tar -zxf wasi-sdk-16.0-linux.tar.gz && mkdir /opt/wasi-sdk/ && mv wasi-sdk-16.0/* /opt/wasi-sdk/

VOLUME /data/

ENTRYPOINT ["make"]
CMD ["build"]
