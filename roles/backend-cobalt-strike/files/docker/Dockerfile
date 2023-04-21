FROM ubuntu:20.04
LABEL maintainer="Geert Smelt <geert.smelt@secura.com>"

ARG DEBIAN_FRONTEND=noninteractive
ARG LICENSE_KEY

RUN apt -qq update && apt -qq install -y \
    openssh-server \
    openvpn \
    syslog-ng \
    rsync \
    cron \
    nano \
    net-tools \
    dnsutils \
    iputils-ping \
    openssl \
    openjdk-11-jre-headless \
    2>&1 > /dev/null

ADD cobaltstrike-dist.tgz /opt

WORKDIR /opt/cobaltstrike
RUN chown -R root:root /opt/cobaltstrike && echo ${LICENSE_KEY} | ./update

# Create Docker volumes for data persistence
RUN mkdir c2-profiles aggressor-scripts data logs
ADD aggressor-scripts aggressor-scripts
ADD c2-profiles c2-profiles
VOLUME ["/opt/cobaltstrike/c2-profiles", "/opt/cobaltstrike/aggressor-scripts", "/opt/cobaltstrike/data", "/opt/cobaltstrike/logs"]

COPY cobaltstrike.ovpn /root/cobaltstrike.ovpn

RUN mkdir /docker-entrypoint.d

COPY docker-entrypoint.sh /
COPY 10-start-openvpn.sh /docker-entrypoint.d
COPY 20-update-teamserver.sh /docker-entrypoint.d

# TODO: Somehow after Ansible copies the whole folder, the executable permissions are lost
RUN chmod +x /docker-entrypoint.sh && chmod +x /docker-entrypoint.d/*.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["./teamserver"]
