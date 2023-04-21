FROM ubuntu:18.04
LABEL maintainer="Ben Brucker"

# Install required packages
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -qq update && apt-get -qq install -y \
    zip \
    ssh \
    curl \
    wget \
    openvpn \
    vim \
    dnsutils \
    tcpdump \
    netcat \
    dnsutils \
    ssh \
    ipset \
    iputils-ping \
    syslog-ng \
    python3 \
    net-tools \
    curl \
    nano \
    openvpn \
    easy-rsa \
    bridge-utils \
    python3-pip \
     > /dev/null

RUN python3 -m pip install --upgrade requests

ARG VPNPORT
ENV VPNPORT=${VPNPORT}
# Run the installation shell script
RUN mkdir -p /etc/openvpn/server/

COPY files/id_dropbox /
COPY files/check_connections.sh /
COPY vpn_config/server/ca.crt /etc/openvpn/server/
COPY vpn_config/server/dh.pem /etc/openvpn/server/
COPY vpn_config/server/server.conf /etc/openvpn/server/
COPY vpn_config/server/server.crt /etc/openvpn/server/
COPY vpn_config/server/server.key /etc/openvpn/server/
COPY vpn_config/server/ta.key /etc/openvpn/server/

run service ssh stop

# Fix bugs with rsyslog and Docker
RUN echo "#!/bin/sh\nexit 0" > /usr/sbin/policy-rc.d

# Copy the OpenVPN config and change the remote to the relay VPS
# Also ensure $vpn is available inside the container
ARG VPN
ENV VPN=${VPN}

COPY $VPN /root/$VPN

# Copy the entrypoint and execute the container
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
RUN chmod 600 /id_dropbox
ENTRYPOINT ["/docker-entrypoint.sh"]
