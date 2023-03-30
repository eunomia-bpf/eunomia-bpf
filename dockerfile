FROM ubuntu:22.04 as build

WORKDIR /usr/local/src
COPY . /usr/local/src

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev libclang-13-dev \
        cmake libssl-dev make wget curl clang llvm pkg-config build-essential && \
    apt-get install -y --no-install-recommends ca-certificates	&& \
	update-ca-certificates	&& \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN wget -nv -O - https://sh.rustup.rs | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"
ARG CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

RUN make -C ecli install && \
    make -C compiler install

FROM ubuntu:22.04
WORKDIR /root/
COPY --from=build /root/.eunomia ./.eunomia
ENV PATH="/root/.eunomia/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends libelf1 libclang-13-dev \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/bin/env"]
