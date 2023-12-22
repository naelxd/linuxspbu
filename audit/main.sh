#!/bin/bash

if [ "$1" = "test" ]; then
    sh -c 'ping -D google.com > "pingoutput.txt" &' 
elif [ "$1" = "stoptest" ]; then
    killall ping
elif [ "$1" = "find" ]; then
    cat event_log.txt | grep "$2"
else
    echo "Invalid command"
fi

