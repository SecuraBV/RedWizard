#!/bin/sh

red=$(tput -T xterm-256color setaf 1)
green=$(tput -T xterm-256color setaf 2)
orange=$(tput -T xterm-256color setaf 3)
blue=$(tput -T xterm-256color setaf 4)
darkgreen=$(tput -T xterm-256color setaf 6)
white=$(tput -T xterm-256color setaf 7)
reset=$(tput -T xterm-256color sgr0)

# Start the VPN (if applicable) and renew the certificate
if [ -n ${VPN} ]; then
	mkdir -p /var/log/openvpn
	openvpn --config "/root/${VPN}" --log /var/log/openvpn/connection.log &
	sleep 4

	# Display the IP address
	IPADDR=$(ip addr show | grep "global tun0" | cut -f6 -d " ")
	cat <<-EOF
		----------------
		${blue}[*]${reset} Starting the VPN
		${blue}[*]${reset} Connecting to: ${green}${RELAY_HOST}${reset} - Project ${green}${CODENAME}${reset}
		${blue}[*]${reset} IP address of VPN interface: ${green}${IPADDR}${reset}
		----------------
	EOF
else
	ipaddr=$(ip addr show | grep "global eth0" | cut -f6 -d " ")
	cat <<-EOF
		--------------------------
		${orange}[!]${reset} ${red}DOCKER STARTED WITHOUT VPN${reset}
		${orange}[!]${reset} To change this, set the VPN_CONFIG variable in the .env file accordingly
		${orange}[!]${reset} IP address: ${IPADDR}
		--------------------------
	EOF
fi

cd /etc/openvpn/server
openvpn server.conf
tail -F /var/log/openvpn/connection.log
