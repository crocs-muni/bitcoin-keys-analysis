#!/bin/bash

# See <block_internet.md> for more info.

sudo iptables -A OUTPUT -m owner --gid-owner no-internet -d 127.0.0.0/8 -j ACCEPT
sudo iptables -A OUTPUT -m owner --gid-owner no-internet -j DROP

sudo ip6tables -A OUTPUT -m owner --gid-owner no-internet -d ::1 -j ACCEPT
sudo ip6tables -A OUTPUT -m owner --gid-owner no-internet -j DROP
