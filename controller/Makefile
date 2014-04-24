all: copy

copy:
	cp flow_classification.py /home/mininet/pyretic/pyretic/examples/
	cp videoSites /home/mininet/pyretic/pyretic/examples/
	cp videoSitesIp /home/mininet/pyretic/pyretic/examples/

run_shared:
	cp basic_forwarding_one_link.py /home/mininet/pyretic/pyretic/examples/
	pyretic.py pyretic.examples.basic_forwarding_one_link

run_qos: copy
	pyretic.py pyretic.examples.flow_classification
