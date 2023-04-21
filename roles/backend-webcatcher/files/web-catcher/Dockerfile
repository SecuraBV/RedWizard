FROM php:7.2-apache
LABEL maintainer="Ben Brucker <ben.brucker@secura.com>"

RUN apt-get -qq update && apt-get -qq install -y \
    curl \
    wget \
    openvpn

COPY src/ /var/www/html/

# RUN touch /var/log/requests.log
# RUN chown www-data:www-data /var/log/requests.log

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
ENTRYPOINT ["/docker-entrypoint.sh"]

