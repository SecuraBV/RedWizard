#!/usr/bin/env bash

USER=$(id -nu)

if [ $USER != "mutt" ]; then
	echo "Refusing to send mail as the '"${USER}"' user. Switch to the 'mutt' user and try again."
	exit 1
else
	echo "Logged in as 'mutt' user. Continuing..."
fi


echo "Sending mails containing links"
echo "user name"
sleep 15
/bin/bash send-link.sh rt-test@example.com https://example.com/tracking.png https://phishing-domain.com/marketing-update.doc
sleep 15

echo "Sending mails with attachment"
echo "user name"
sleep 15
/bin/bash send-attachment.sh rt-test@example.com https://example.com/tracking.png
