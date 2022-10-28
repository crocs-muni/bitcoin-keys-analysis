[Original source](https://unix.stackexchange.com/questions/68956/block-network-access-of-a-process/454767#454767)

We use this approach to block Bitcoin Core's access to the internet for it not to download and validate new blocks and share already validated blocks across the network.


1. Create, validate new group; add required users to this group:
    
    Create: `groupadd no-internet`
    
    Validate: `grep no-internet /etc/group`
    
    Add user: `useradd -g no-internet username`


    Note: If you're modifying already existing user you should run: `usermod -a -G no-internet userName`. Check with : `sudo groups userName`

2. Create a script in your path and make it executable:
    
    Create: `nano /home/username/.local/bin/no-internet`
    
    Executable: `chmod 755 /home/username/.local/bin/no-internet`
    
    Content:

        #!/bin/bash
        sg no-internet "$@"

3. Add iptables rule for dropping network activity for group no-internet, but allow network activity within local network for botch IPv4 and IPv6 (we need it for the RPC server):

    `sudo iptables -A OUTPUT -m owner --gid-owner no-internet -d 127.0.0.0/8 -j ACCEPT`

    `sudo iptables -A OUTPUT -m owner --gid-owner no-internet -j DROP`

    `sudo ip6tables -A OUTPUT -m owner --gid-owner no-internet -d ::1 -j ACCEPT`

    `sudo ip6tables -A OUTPUT -m owner --gid-owner no-internet -j DROP`

    You might want to to make the changes permanent, so it would be applied automatically after reboot. Doing it, depends on your Linux distribution. But if you don't want to make the changes permanent, use [enable_no-internet.sh](enable_no-internet.sh) to apply this rules.


4. Check it, for example on Firefox by running:

    `no-internet "firefox"`

5. If you've completed all the steps, but `no-internet` doesn't work (programs still can access internet), try to disable `firewalld`, reboot your computer and see, if it helps:

    `systemctl stop firewalld`

    `systemctl disable firewalld`

    `systemctl mask firewalld` (optional, look what it does at the man page)
