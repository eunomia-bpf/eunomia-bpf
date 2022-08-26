# build run env
FROM ubuntu:22.04

ENV TZ = Asia/Shanghai

WORKDIR /usr/local/src

RUN apt-get update -y && apt-get install -y libssl-dev libcurl4-openssl-dev libcurl4 libelf-dev

RUN apt-get install cmake -y

RUN apt-get install clang -y
RUN apt-get install llvm -y
RUN apt-get install python-is-python3 -y

COPY ./. /usr/local/src
RUN make ecli install-deps
RUN make eunomia-bpf
RUN make ecli

VOLUME /data/

ENTRYPOINT ["/bin/bash","-l","-c"]
CMD ["make build"]
