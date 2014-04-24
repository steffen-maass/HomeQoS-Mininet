#!/bin/sh 
ovs-vsctl del-controller brdn 
ovs-vsctl del-fail-mode brdn
ovs-vsctl del-controller brup
ovs-vsctl del-fail-mode brup

