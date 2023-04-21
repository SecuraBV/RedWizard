#!/bin/bash

USER=$(id -nu)

if [ $USER != "mutt" ]; then
	echo "Refusing to send mail as the '"${USER}"' user. Switch to the 'mutt' user and try again."
	exit 1
else
	echo "Logged in as 'mutt' user. Continuing..."
fi

if [ "$#" -ne 2 ]; then
    echo "Use: $0 <target-email-address> <tracking-pixel-url>"
    exit
fi

TO=$1
TRACK=$2

subject="XXX SUBJECT XXX"
attachments="/home/mutt/XXX-FILENAME-XXX.doc"

html_file="/home/mutt/EMAIL-Source-with-attachment.html"
WORK_FILE="/home/mutt/TEMP-attachment.html"

cat $html_file > $WORK_FILE
# Add tracking pixel
echo "<img src='$TRACK' />" >> $WORK_FILE

START=`date`
# --------------------------------------------------------------------------------------
# send html with pdf attachment
mutt -e "set content_type=text/html" -s "$subject" $TO -a $attachments -- < $WORK_FILE

END=`date`
echo "-------------------------------" >> /var/log/phish-log.log
START=$(date)
echo "START=    $START" >> /var/log/phish-log.log
echo "TARGET=   $TO" >> /var/log/phish-log.log
echo "TYPE=     Attachment" >> /var/log/phish-log.log
echo "ATTACH=   $attachments" >> /var/log/phish-log.log
echo "TRACKING= $TRACK" >> /var/log/phish-log.log
END=$(date)
echo "END=      $END" >> /var/log/phish-log.log
echo "-------------------------------" >> /var/log/phish-log.log
