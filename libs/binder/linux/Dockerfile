# ./release.sh
# docker build -t linux-binder .
# docker run linux-binder
# docker ps | grep linux-binder | cut -f1 -d' ' | xargs docker kill

FROM gcc:9

RUN echo 'deb http://deb.debian.org/debian bullseye-backports main' >> /etc/apt/sources.list && \
    apt-get update -y && \
    apt-get install -y python3 golang-1.19 cmake ninja-build libgtest-dev wget

RUN apt list golang -a
RUN go version
RUN which go
#RUN ls -la `which go`
RUN dpkg-query -L golang-1.19-go
RUN /usr/lib/go-1.19/bin/go version
ENV PATH="/usr/lib/go-1.19/bin:$PATH"

ADD linux-binder.tar.gz /
WORKDIR /linux-binder
ENV ANDROID_BUILD_TOP=/linux-binder \
    ANDROID_HOST_OUT=/linux-binder/prebuilts/host/linux-x86
RUN /usr/local/bin/g++ --version
RUN /linux-binder/frameworks/native/libs/binder/linux/build.sh

ENTRYPOINT [ "/linux-binder/frameworks/native/libs/binder/linux/build/binder_rpc_test" ]
