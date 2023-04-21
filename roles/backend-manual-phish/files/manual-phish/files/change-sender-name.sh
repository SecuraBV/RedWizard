#!/bin/bash
if [[ $# -lt 2 ]] ; then
    echo
    echo 'Changes the sender name of the outgoing phishing email'
    echo 'Usage: ./change-sender-name.sh <Full_name> <Mail_name>'
    echo
    echo 'Example: ./change-sender-name.sh "Jan Klaas Petersen" jk-petersen'
    echo
    exit
fi


sed -ri 's/set realname=.*/set realname='"\"$1\""/ /home/mutt/.muttrc
sed -ri 's/set from=".*\@/set from="'"$2"@/ /home/mutt/.muttrc
sed -ri 's/from .*\@/from '"$2"@/ /home/mutt/.msmtprc
