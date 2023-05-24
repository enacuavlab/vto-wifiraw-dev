#!/bin/bash

export node wlx3c7c3fa9c1e8

$PWD/wifiraw 1 $node &

socat TUN:10.0.1.2/24,tun-name=airtuntx,iff-no-pi,tun-type=tun,iff-up udp-sendto:127.0.0.1:14900 > /dev/null 2>&1 &
socat udp-listen:14800,reuseaddr,fork TUN:10.0.1.2/24,tun-name=airtunrx,iff-no-pi,tun-type=tun,iff-up > /dev/null 2>&1 &
sleep 1
ifconfig airtuntx mtu 1400 up &
while [ ! "`sysctl -w net.ipv4.conf.airtunrx.rp_filter=2`" = "net.ipv4.conf.airtunrx.rp_filter = 2" ];do sleep 1; done
route add default airtuntx  > /dev/null 2>&1 &
