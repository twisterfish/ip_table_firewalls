#!/bin/bash
#
# Author:  Edward Anderson
# Date:  02/05/2013
#
# 1. iptables -P INPUT ACCEPT If connecting remotely we must first temporarily
# set the default policy on the INPUT chain to ACCEPT otherwise once we flush 
# the current rules we will be locked out of our server.
#
# 2. iptables -F We used the -F switch to flush all existing rules so we start 
# with a clean state from which to add new rules.
#
# 3. iptables -A INPUT -i lo -j ACCEPT Now it's time to start adding some
# rules.  We use the -A switch to append (or add) a rule to a specific chain,  
# the INPUT chain in this instance. Then we use the -i switch (for interface) 
# to specify packets matching or destined for the lo (localhost, 127.0.0.1) 
# interface and finally -j (jump) to the target action for packets matching 
# the rule - in this case ACCEPT. So this rule will allow all incoming packets  
# destined for the localhost interface to be accepted. This is generally required 
# as many software applications expect to be able to communicate with the 
# localhost adaptor.
#
# 4. iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT This is 
# the rule that does most of the work, and again we are adding (-A) it to the 
# INPUT chain. Here we're using the -m switch to load a module (state). The  
# state module is able to examine the state of a packet and determine if it is 
# NEW, ESTABLISHED or RELATED. NEW refers to incoming packets that are new  
# incoming connections that weren't initiated by the host system. ESTABLISHED 
# and RELATED refers to incoming packets that are part of an already established  
# connection or related to and already established connection.
#
# 5. iptables -A INPUT -p tcp --dport 22 -j ACCEPT Here we add a rule allowing 
# SSH connections over tcp port 22. This is to prevent accidental lockouts when 
# working on remote systems over an SSH connection. 
#
# 6. iptables -P INPUT DROP The -P switch sets the default policy on the 
# specified chain. So now we can set the default policy on the INPUT chain to DROP.
# This means that if an incoming packet does not match one of the following rules
# it will be dropped. If we were connecting remotely via SSH and had not added the 
# rule above, we would have just locked ourself out of the system at this point.
#
# 7. iptables -P FORWARD DROP Similarly, here we've set the default policy on 
# the FORWARD chain to DROP as we're not using our computer as a router so
# there should not be any packets passing through our computer.
#
# 8. iptables -P OUTPUT ACCEPT and finally, we've set the default policy on the 
# OUTPUT chain to ACCEPT as we want to allow all outgoing traffic (assuming we trust 
# our users).
#
# 9. iptables -L -v Finally, we can list (-L) the rules we've just added to
# check they've been loaded correctly.
#
# iptables -A INPUT -p tcp --dport 80 -j ACCEPT --  will take all traffic

# #############################################################################
# Flush all current rules from iptables
# #############################################################################

iptables -F

# #############################################################################
# Allow SSH connections on tcp port 22
# This is essential when working on remote servers via SSH to prevent locking 
# yourself out of the system. This accepts ALL SSH traffic.
# #############################################################################

#iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# #############################################################################
# Drop brute force attacks on SSH - limit 3 tries per 10 seconds
# #############################################################################

#iptables -A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -m recent --set -j ACCEPT
#iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 6 -j REJECT

#iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
#iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 8 --rttl --name SSH -j REJECT

iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 3 -j DROP

# #############################################################################
# Drop invalid packets immediately
# #############################################################################

iptables -A INPUT -m state --state INVALID -j DROP
#iptables -A FORWARD -m state --state INVALID -j DROP

# #############################################################################
# Port scans
# Anyone who tried to portscan us is locked out.
# The default on the database server is to block everything - so this isn't really
# necessary
# #############################################################################

# These rules add scanners to the portscan list, and log the attempt.
#iptables -A INPUT   -p tcp -m tcp --dport 3306 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
#iptables -A INPUT -p tcp -m tcp --dport 3306 -m recent --name portscan --set -j DROP

# #############################################################################
# Force Fragments packets check
# Drop packets with incoming fragments. This attack results into Linux server 
# panic such as data loss.
# #############################################################################

iptables -A INPUT -f -j DROP

# #############################################################################
# Drop invalid packets immediately
# #############################################################################

iptables -A INPUT -m state --state INVALID -j DROP
#iptables -A FORWARD -m state --state INVALID -j DROP
#iptables -A OUTPUT  -m state --state INVALID -j DROP

# #############################################################################
# Significant IP addresses
# #############################################################################

# External IPs for maintenance
HOME="111.111.111.XXX"
WEB="111.111.111.XXX"
PRIVATE="111.111.111.XXX"
PUBLIC="111.111.111.XXX"


# #############################################################################
# The IPs that are allowed to connect to the database
# dport is destination port - sport is source port
# #############################################################################

# define who is allowed to connect externally and to what ports
ext_loc=($HOME $PRIVATE $WEB $PUBLIC)

for ips in "${ext_loc[@]}"
do
	# SSL ports as destination
	#iptables -A INPUT -p tcp -s $ips --dport 443 -j ACCEPT 
	#iptables -A INPUT -p tcp -s $ips --dport 8443 -j ACCEPT
	
	# Database port as destination
	iptables -A INPUT -i eth0 -p tcp -s $ips --dport 3306 -j ACCEPT
	
	# Apache port as destination
	#iptables -A INPUT -p tcp -s $ips --dport 80 -j ACCEPT
	#iptables -A INPUT -p tcp -s $ips --dport 8080 -j ACCEPT
	
	# SSH ports
	iptables -A INPUT -i eth0 -p tcp -s $ips --dport 22 -j ACCEPT
done


# #############################################################################
# Set default policies for INPUT, FORWARD and OUTPUT chains
# #############################################################################

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# #############################################################################
# Set access for localhost
# #############################################################################

 iptables -A INPUT -i lo -j ACCEPT

# #############################################################################
# Accept packets belonging to established and related connections
# #############################################################################

 iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# #############################################################################
# Tell iptables to save the settings when you are sure they work
# #############################################################################

#/sbin/service iptables save

# #############################################################################
# List the updated rules after you have run the script
# #############################################################################

iptables -nvL
