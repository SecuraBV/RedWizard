#!/bin/sh

touch /var/log/gophish-log.log

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

echo "Starting goPhish version ${GOPHISHVERSION}"

export gf_add="python3 ${GOPHISHDIR}/gophish_api.py -H ${SMTP_HOST}"

if [ -n ${SMTP_USER} ]; then
	gf_add="$gf_add -u ${SMTP_USER} -p ${SMTP_PASSWORD}"
fi

if [ -n ${SMTP_PORT} ]; then
	gf_add="$gf_add -P ${SMTP_PORT}"
fi

if [ -n ${SMTP_FROMS} ]; then
	gf_add="$gf_add -f ${SMTP_FROMS}"
fi

if [ -n ${GOPHISH_INITIAL_ADMIN_API_TOKEN} ]; then
	gf_add="$gf_add -k ${GOPHISH_INITIAL_ADMIN_API_TOKEN}"
fi

echo "Create users command: $gf_add"
bash -c "sleep 10 ; $gf_add" &>/dev/null &

exec sh -c "cd ${GOPHISHDIR} && ./gophish"
