#!/bin/bash

if [[ $# -eq 0 ]] ; then
    echo
    echo 'Usage: ./docker-interact.sh <container name>'
    echo 'run ./docker-info.sh or "sudo docker ps" for all container names'
    echo
    exit
fi

docker exec -it $1 /bin/bash
