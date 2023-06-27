#!/bin/bash

# Find suitable rtl88XXau and set link down
# Device is considered suitable, when in Monitor mode the link is up

DEVICES=/proc/net/rtl88XXau
FILES=/tmp/wfp_*.pid

WLS=()

if [ "$(uname -r)" = "4.9.253-tegra" ]; then TEGRA=true; else TEGRA=false; fi
if [ -d "$DEVICES" ]; then
  dirs=( "$DEVICES"/*/ )
  for d in "${dirs[0]}"; do
    wl=`basename $d`
    if $TEGRA; then
      if [[ $(iwconfig $wl | grep -c "Mode:Monitor") == 1 ]]; then WLS+=($wl); fi
    else
       ty=`iw dev $wl info | grep "type" | awk '{print $2}'`
       if [[ $ty = "monitor" ]]; then WLS+=($wl); fi
    fi
  done
  if [ -n "$WLS" ]; then
    wl=${WLS[0]}
    if $TEGRA; then ifconfig $wl down; else ip link set $wl down; fi
    pidfile="/tmp/wfb_"$wl".pid"
    if [ -f "$pidfile" ]; then
      kill `cat $pidfile` > /dev/null 2>&1 
      rm $pidfile  > /dev/null 2>&1 
    fi
  fi
fi
