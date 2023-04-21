FROM ubuntu:18.04
LABEL maintainer="Stefan Vlems <stefan.vlems@secura.com>"

# Install required packages
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -qq update && apt-get -qq install -y \
    zip \
    git \
    curl \
    wget \
    openvpn \
    vim \
    dnsutils \
    tcpdump \
    netcat \
    dnsutils \
    ipset \
    iputils-ping \
    syslog-ng \
    python3 \
    net-tools \
    curl \
    nano \
    bridge-utils \
    python3-pip \
     > /dev/null

RUN python3 -m pip install --upgrade requests

# Set and create the gophish installation directory
ARG GOPHISHDIR
ARG GOPHISHVERSION
ARG CONTACT_EMAIL

ENV GOPHISHDIR=${GOPHISHDIR}
ENV GOPHISHVERSION=${GOPHISHVERSION}
ENV CONTACT_EMAIL=${CONTACT_EMAIL}

RUN mkdir -p ${GOPHISHDIR}/tmp 2>/dev/null

# Run the installation shell script
COPY files/gophish_goget.sh /tmp/goget.sh
RUN /bin/sh /tmp/goget.sh $GOPHISHVERSION $GOPHISHDIR

# Fix bugs with rsyslog and Docker
RUN echo "#!/bin/sh\nexit 0" > /usr/sbin/policy-rc.d

# Copy the OpenVPN config and change the remote to the relay VPS
# Also ensure $vpn is available inside the container
ARG VPN
ENV VPN=${VPN}


COPY $VPN /root/$VPN
# Create a GoPhish service
# COPY files/gophish.service /etc/init.d/gophish
# RUN chmod +x /etc/init.d/gophish

# Set-up the GoPhish config
COPY files/gophish-config.json $GOPHISHDIR/config.json
RUN sed -i "s/\"contact_address\": \"\"/\"contact_address\": \"$CONTACT_EMAIL\"/g" $GOPHISHDIR/config.json
COPY files/gophish_api.py $GOPHISHDIR/gophish_api.py

# Copy the entrypoint and execute the container
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
