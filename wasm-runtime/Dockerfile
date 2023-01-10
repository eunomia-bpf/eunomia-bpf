FROM ubuntu:latest
COPY ./ /root

WORKDIR /root

RUN apt-get update && \
    apt-get -y install gcc libelf-dev --no-install-recommends && \
    apt-get clean

CMD ["/bin/bash"]