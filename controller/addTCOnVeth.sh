#!/bin/sh 

#add TC using tc
tc qdisc add dev veth1 root tbf rate 5000Mbit burst 5000kbit limit 10000kbit
tc qdisc add dev veth0 root tbf rate 5000Kbit burst 5000kbit limit 10000kbit
tc qdisc add dev veth2 root tbf rate 3500Kbit burst 3500kbit limit 10000kbit
tc qdisc add dev veth3 root tbf rate 3500Kbit burst 3500kbit limit 10000kbit
tc qdisc add dev veth4 root tbf rate 500Kbit burst 500kbit limit 1000kbit
tc qdisc add dev veth5 root tbf rate 500Kbit burst 500kbit limit 1000kbit
tc qdisc add dev veth6 root tbf rate 500kbit burst 500kbit limit 1Mbit
tc qdisc add dev veth7 root tbf rate 500kbit burst 500kbit limit 1Mbit


#show results
tc qdisc show
