#!/bin/bash

# Run as ". run_daemon.sh" for cli function
# Your paths might be different.

CLIENT_DIR="/home/xyakimo1/crocs/bitcoin-client/bin"
DATA_DIR="/home/xyakimo1/crocs/.bitcoin-data"
CONF=$DATA_DIR/bitcoin.conf

$CLIENT_DIR/bitcoind -datadir="$DATA_DIR" -conf="$CONF" || ( echo -ne "\007 \007 \007" && exit 1 )

cli()
{
    "$CLIENT_DIR/bitcoin-cli" "-datadir=$DATA_DIR" "-conf=$CONF" "$@"
}
