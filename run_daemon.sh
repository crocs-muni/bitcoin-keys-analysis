#!/bin/bash

# Run as ". run_daemon.sh" for alias cli
# Your paths might be different.

CLIENT_DIR="/home/xyakimo1/crocs/bitcoin-client/bin"
DATA_DIR="/home/xyakimo1/crocs/.bitcoin-data"
CONF=$DATA_DIR/bitcoin.conf

$CLIENT_DIR/bitcoind -datadir="$DATA_DIR" -conf="$CONF" || ( echo -ne "\007 \007 \007" && return 1 )
alias cli="$CLIENT_DIR/bitcoin-cli -datadir=$DATA_DIR -conf=$CONF"
