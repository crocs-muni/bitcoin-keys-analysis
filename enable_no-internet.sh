#!/bin/bash

iptables -A OUTPUT -m owner --gid-owner no-internet -d 192.168.1.0/24 -j ACCEPT
iptables -A OUTPUT -m owner --gid-owner no-internet -d 127.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -m owner --gid-owner no-internet -j DROP


# https://unix.stackexchange.com/questions/68956/block-network-access-of-a-process/454767#454767

# Used this approach to block Bitcoin Core's access to the internet for it not to download and validate new blocks and share already validated blocks accross the network.
# (It needs root priveleges.)
