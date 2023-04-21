#!/bin/bash

USER=$(id -nu)

if [ $USER != mutt ]; then
	echo "Refusing to send mail as the '"${USER}"' user. Switch to the 'mutt' user and try again."
	exit 1
else
	echo "Logged in as '${USER}' user. Continuing..."
fi

if [ "$#" -ne 3 ]; then
    echo "Use: $0 <target-email-address> <tracking-pixel-url> <link-url>"
    exit
fi

# TO = Email Address
# TRACK = Tracking Pixel Name
# LINK = Link to the phishing page / file download
TO=$1
TRACK=$2
LINK=$3

subject="XXX SUBJECT XXX"

html_file="./EMAIL-Source-with-link.html"
WORK_FILE="./TEMP-link.html"

START=`date`
# Make working copy of the source

cp $html_file $WORK_FILE
# Complete the link
sed -i "s|UNIQUELINK|$LINK|g" $WORK_FILE
# Add tracking pixel
echo "<img src='$TRACK' />" >> $WORK_FILE

# --------------------------------------------------------------------------------------
# send html email
mutt -e "set content_type=text/html" -s "$subject" $TO -- < $WORK_FILE


echo "-------------------------------" >> /var/log/phish-log.log
START=$(date)

echo "START=    $START" >> /var/log/phish-log.log
echo "TARGET=   $TO" >> /var/log/phish-log.log
echo "TYPE=     LINK" >> /var/log/phish-log.log
echo "TRACKING= $TRACK" >> /var/log/phish-log.log
echo "LINK=     $LINK" >> /var/log/phish-log.log
END=$(date)
echo "END=      $END" >> /var/log/phish-log.log
echo "-------------------------------" >> /var/log/phish-log.log


