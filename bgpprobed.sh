#!/bin/bash

service_name=bgpprobe
network_if=ens38
ip_address=10.10.10.2
input_file=../bgpips.txt

#set -x

script() {
    [ "$#" -ne 1 ] && usage || main "$@"
}

function main {
    case "$1" in
        start)
            echo "Starting "$service_name" ..."
            startService "$@"
            echo "Starting "$service_name" done."
        ;;
        stop) 
            echo "Stopping "$service_name" ..."
            stopService "$@"
            echo "Stopping "$service_name" done."
        ;;
        restart)
            echo "Restarting "$service_name" ..."
            stopService "$@"
            startService "$@"
            echo "Restarting "$service_name" done."
        ;;
        *)
            echo -n "Not correct command syntax"
            usage
            exit 1
        ;;
    esac
}

function startService {
    dir_name="$(cd "$(dirname "$0")"; pwd -P)"
    sudo python2.7 $dir_name/bgpProbe.py -n $network_if -i $ip_address -f $input_file &
}

function stopService {
    sudo killall python2.7
    sudo killall tcpdump
}

function usage {
    self_script_name="$(basename "$(test -L "$0" && readlink "$0" || echo "$0")")"
    echo
    echo "Usage: "
    echo "    ${self_script_name} start|stop|restart"
    echo 
}

script "$@"