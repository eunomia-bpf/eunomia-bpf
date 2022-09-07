FROM ubuntu:latest

ENV UBUNTU_SOURCE /etc/apt

COPY ./ /root

WORKDIR /root

ADD sources.list $UBUNTU_SOURCE/

RUN apt-get update && \
    apt-get -y install gcc libelf-dev

#CMD ./ecli run /root/my/package.json
CMD ["/bin/bash"]