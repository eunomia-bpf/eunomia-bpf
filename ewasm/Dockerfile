FROM ubuntu:latest

COPY ./ /root

WORKDIR /root

RUN apt-get update && \
    apt-get -y install gcc libelf-dev

CMD ["/bin/bash"]