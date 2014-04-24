#Sharing all on one link
tc qdisc add dev veth6 root tbf rate 4000kbit burst 4000kbit limit 1Mbit
tc qdisc add dev veth7 root tbf rate 4000kbit burst 4000kbit limit 1Mbit