#!/bin/sh

# create the tow OVS
ovs-vsctl add-br brdn
ovs-vsctl add-br brup

#remove all the forwarding rules for the switches
ovs-ofctl del-flows brdn
ovs-ofctl del-flows brup

#eth0 is connected to my router
ovs-vsctl add-port brup eth0
ovs-vsctl add-port brdn eth1

######### CREATE LINKS ################
#add a veth pair
ip link delete veth3
ip link delete veth0
ip link delete veth4
ip link delete veth6

ip link add type veth
ip link add type veth
ip link add type veth
ip link add type veth

ovs-vsctl add-port brup veth0 
ovs-vsctl add-port brdn veth1
ovs-vsctl add-port brup veth2
ovs-vsctl add-port brdn veth3
ovs-vsctl add-port brup veth4
ovs-vsctl add-port brdn veth5
ovs-vsctl add-port brup veth6
ovs-vsctl add-port brdn veth7

# add peering link between switches
ovs-vsctl set interface veth1 options:peer=veth0
ovs-vsctl set interface veth0 options:peer=veth1
ovs-vsctl set interface veth3 options:peer=veth2
ovs-vsctl set interface veth2 options:peer=veth3
ovs-vsctl set interface veth5 options:peer=veth4
ovs-vsctl set interface veth4 options:peer=veth5
ovs-vsctl set interface veth7 options:peer=veth6
ovs-vsctl set interface veth6 options:peer=veth7



# Up all the interfaces and set them to promiscous mode
ifconfig eth0 up promisc
ifconfig eth1 up promisc
ifconfig veth0 up 
ifconfig veth1 up
ifconfig veth2 up 
ifconfig veth3 up 
ifconfig veth4 up
ifconfig veth5 up
ifconfig veth6 up
ifconfig veth7 up

# Enable Spanning tree for both OVS POSSIBLE PROBLEM
#ovs-vsctl --no-wait set bridge brdn stp_enable=true
#ovs-vsctl --no-wait set bridge brup stp_enable=true

# SET UP TC FOR ports
#ovs-vsctl set Interface veth1 ingress_policing_rate=10000
#ovs-vsctl set Interface veth0 ingress_policing_rate=10000
#ovs-vsctl set Interface veth1 ingress_policing_burst=10000
#ovs-vsctl set Interface veth0 ingress_policing_burst=10000

ovs-vsctl set-controller brdn tcp:0.0.0.0:6633
ovs-vsctl set-fail-mode brdn secure
ovs-vsctl set-controller brup tcp:0.0.0.0:6633
ovs-vsctl set-fail-mode brup secure

dhclient eth0

ovs-vsctl show
ovs-ofctl dump-flows brdn
ovs-ofctl show brdn
ovs-ofctl show brup
