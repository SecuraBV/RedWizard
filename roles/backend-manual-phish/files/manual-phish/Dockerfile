FROM ubuntu:18.04
LABEL maintainer="Ben Brucker <ben.brucker@secura.com>"

# Install required packages
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -qq update && apt-get -qq install -y \
    zip \
    curl \
    wget \
    openvpn \
    vim \
    net-tools \
    tcpdump \
    netcat \
    dnsutils \
    ipset \
    curl \
    nano \
    bridge-utils \
    dnsutils \
    iputils-ping \
    syslog-ng \
    python3 \
    python3-pip \
    mutt \
    msmtp \
    tzdata \
     > /dev/null


# Set the locale (I want to use German Umlauts)
RUN locale-gen en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# Set the timezone (change this to your local timezone)
RUN echo "Europe/Amsterdam" | tee /etc/timezone
RUN dpkg-reconfigure --frontend noninteractive tzdata

RUN adduser --disabled-login --gecos '' mutt
WORKDIR /home/mutt
USER mutt

COPY files/.muttrc /home/mutt/
COPY files/.msmtprc /home/mutt/
COPY files/* /home/mutt/

USER root
# Fix bugs with rsyslog and Docker

# Copy the OpenVPN config and change the remote to the relay VPS
# Also ensure $vpn is available inside the container
ARG VPN
ENV VPN=${VPN}

COPY $VPN /root/$VPN

# Copy the entrypoint and execute the container
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
