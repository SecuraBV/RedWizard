#!/bin/bash

orange=$(printf '\033[0;33m')
green=$(printf '\033[0;32m')
reset=$(printf '\033[0;00m')
blue=$(printf '\033[0;34m')
red=$(printf '\033[0;31m')
yellow=$(printf '\033[0;93m')
purple=$(printf '\033[0;95m')
cyan=$(printf '\033[1;36m')

bold=$(printf '\033[1m')
underline=$(printf '\033[4m')
reversed=$(printf '\033[7m')

echo
echo "__________           .___  __      __.__                         .___"
echo "\______   \ ____   __| _/ /  \    /  \__|____________ _______  __| _/"
echo " |       _// __ \ / __ |  \   \/\/   /  \___   /\__  \\_  __ \/ __ |"
echo " |    |   \  ___// /_/ |   \        /|  |/    /  / __ \|  | \/ /_/ |"
echo " |____|_  /\___  >____ |    \__/\  / |__/_____ \(____  /__|  \____ |"
echo "        \/     \/     \/         \/           \/     \/           \/"
echo
echo "                      ---  First Time Setup ---                     "
echo
echo

echo -e "${cyan}[*] Performing first time setup${reset}\n\n"

echo -e "${cyan}\n[*] Installing required packages via apt${reset}\n\n"
sudo apt-get install python3 python3-pip ssh-askpass

echo -e "${cyan}\n[*] Installing required Python packages${reset}\n\n"
python3 -m pip install -r requirements.txt

echo -e "${cyan}\n[+] Installation complete.${reset}\n\n"
echo -e "${yellow}[ ] Manual follow up required!${reset}\n"
echo -e "${yellow}    Step 1: Edit the globals.yml file via 'ansible-vault edit globals.yml'${reset}"
echo -e "${yellow}            The password is 'ansible'${reset}\n"
echo -e "${yellow}    Step 2: Set a sensible password for your globals.yml via 'ansible-vault rekey globals.yml'${reset}\n"

