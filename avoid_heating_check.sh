#!/bin/bash

beep()
{
    while true; do
        echo -ne "\007"
        sleep 2
    done
}

while true; do

    . run_daemon.sh || beep
    sleep 60

    for i in {0..18}; do
        cli getblockcount || beep
        sleep 60
    done

    ./stop_daemon.sh || beep   # 5 minute pause to avoid overheating and performance decrease.
    sleep 300

done
