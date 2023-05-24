#!/bin/bash

export node wlx3c7c3fa9c1e8

$PWD/wifiraw 0 $node

socat TUN:10.0.1.1/24,tun-name=groundtuntx,iff-no-pi,tun-type=tun,iff-up udp-sendto:127.0.0.1:14800 > /dev/null 2>&1 &
socat udp-listen:14900,reuseaddr,fork  TUN:10.0.1.1/24,tun-name=groundtunrx,iff-no-pi,tun-type=tun,iff-up > /dev/null 2>&1 &
sleep 1
ifconfig groundtuntx mtu 1400 up &
while [ ! "`sysctl -w net.ipv4.conf.groundtunrx.rp_filter=2`" = "net.ipv4.conf.groundtunrx.rp_filter = 2" ];do sleep 1; done
