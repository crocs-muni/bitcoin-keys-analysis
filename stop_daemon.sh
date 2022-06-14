#!/bin/bash

CLIENT_DIR="/home/xyakimo1/crocs/bitcoin-client/bin"
DATA_DIR="/home/xyakimo1/crocs/.bitcoin-data"
CONF=$DATA_DIR/bitcoin.conf

$CLIENT_DIR/bitcoin-cli -datadir="$DATA_DIR" -conf="$CONF" stop || ( echo -ne "\007 \007 \007" && exit 1 )
