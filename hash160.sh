#!/bin/bash

###             USAGE
### echo "something" | ./hash160
###

xxd -r -p | openssl sha256 --binary | openssl rmd160 -provider legacy | sed "s/[^ ]* //"
