FROM alpine:latest

COPY ./ /root

WORKDIR /root

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk update && \
    apk install gcc libelf gcompat

#CMD ./ecli run /root/my/package.json