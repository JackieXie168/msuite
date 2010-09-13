#!/bin/sh

#
# Loop to create 65535 sessions
# Tcp server listen on 9999 
#
for ((i=1; i<65535; i++))
do
    ./tcpclient 2.0.0.2 &
    if ((i&0xFF == 0)); then
        sleep 1
        echo "Sleep......\n"
    fi
done
