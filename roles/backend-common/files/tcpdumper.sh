#!/bin/bash
# chkconfig: 2345 20 80

start() {  
   echo "starting tcpdump"
   screen -S tcpmonitor -m -d sh -c 'tcpdump -i ens160 -w /var/log/tcpdump/cap.pcap -C 500 -s 1500 port not 22'
   sleep 2
   echo "tcpdump started with PID of $(ps fax | grep tcpdump | grep -v grep | head -1 | awk '{print $1}') and logging to /var/log/tcpdump/cap.pcap"
   echo "started tcpdump ["$(tput setaf 2)OK$(tput sgr0)"]"
}

stop() {  
   echo "stopping tcpmonitor"
   screen -X -S tcpmonitor quit
   sleep 2
   echo "tcpmonitor stopped ["$(tput setaf 2)OK$(tput sgr0)"]"
}

case "$1" in 
    start)
       start
       ;;
    stop)
       stop
       ;;
    restart)
       stop
       start
       ;;
    *)
       echo "Usage: $0 {start|stop|status|restart}"
esac

exit 0 
