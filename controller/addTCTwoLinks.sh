
#Streaming Link
tc qdisc add dev veth2 root tbf rate 3500Kbit burst 3500kbit limit 10000kbit
tc qdisc add dev veth3 root tbf rate 3500Kbit burst 3500kbit limit 10000kbit

#File Download Link
tc qdisc add dev veth6 root tbf rate 500kbit burst 500kbit limit 1Mbit
tc qdisc add dev veth7 root tbf rate 500kbit burst 500kbit limit 1Mbit