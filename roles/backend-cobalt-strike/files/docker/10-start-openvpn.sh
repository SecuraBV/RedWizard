#!/usr/bin/env bash

red=$(tput -T xterm-256color setaf 1)
green=$(tput -T xterm-256color setaf 2)
orange=$(tput -T xterm-256color setaf 3)
blue=$(tput -T xterm-256color setaf 4)
darkgreen=$(tput -T xterm-256color setaf 6)
white=$(tput -T xterm-256color setaf 7)
reset=$(tput -T xterm-256color sgr0)

if [ ${DISABLE_VPN} ]; then
        echo "${orange}[!] VPN explicitly disabled${reset}"
        exit 0
fi

# TODO: make this a docker volume instead of hardcoding into the image
sed -i -e "/remote / s/ .*/ ${RELAYVPS} 1194/" /root/*.ovpn

# TODO: make this log file persistent as well
openvpn --config "/root/${VPN}" --log /var/log/openvpn/connection.log --daemon

cat <<-EOF
	${blue}[*]${reset} Starting the VPN
	${blue}[*]${reset} Connecting to: ${green}${RELAYVPS}${reset} - Project ${green}${CODENAME}${reset}

EOF

until [[ $(grep -i 'Initialization sequence completed' /var/log/openvpn/connection.log 2>/dev/null) ]]; do
	# Waiting for VPN connection to be established
	sleep 1
done

cat <<-EOF
	${green}[+]${green} VPN connection established
	${blue}[*]${reset} IP address of VPN interface: ${green}$(ip -4 address show dev tun0 | awk '/inet/ { print $2 }')${reset}
EOF

exit 0
