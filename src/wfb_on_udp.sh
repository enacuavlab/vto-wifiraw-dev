#!/bin/bash

HOME_PRJ=/home/pprz/Projects/vto-wifiraw-dev/src

PIDFILE=/tmp/wfb_udp.pid
touch $PIDFILE
sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1 
$HOME_PRJ/mux > /dev/null 2>&1 &
echo $! | tee $PIDFILE > /dev/null 2>&1 
$HOME_PRJ/video.sh $PIDFILE > /dev/null 2>&1 &
echo $! | tee -a $PIDFILE > /dev/null 2>&1 
