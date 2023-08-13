#!/bin/bash

# Find available rtl88XXau and set monitor mode, channel and link up
# Device is considered available, when in Managed mode whatever the link, 
# or when in Monitor mode the link is down

HOME_PRJ=/home/pprz/Projects/vto-wifiraw-dev/src

DEVICES=/proc/net/rtl88XXau
FILES=/tmp/wfb_*.pid

#CHANNEL=140
CHANNEL=36

WLS=()

if [ "$(uname -r)" = "4.9.253-tegra" ]; then TEGRA=true; else TEGRA=false; fi
if [ -d "$DEVICES" ]; then
  dirs=( "$DEVICES"/*/ )
  for d in "${dirs[0]}"; do
    wl=`basename $d`
    if $TEGRA; then
      if [[ $(iwconfig $wl | grep -c "Mode:Managed") == 1 ]]; then WLS+=($wl)
      else
        if [[ $(ifconfig | grep -c $wl) == 0 ]]; then WLS+=($wl); fi
      fi
    else
       ty=`iw dev $wl info | grep "type" | awk '{print $2}'`
       if [[ $ty == "managed" ]]; then WLS+=($wl);
        else
          if [[ $(ifconfig | grep -c $wl) == 0 ]]; then WLS+=($wl); fi
	fi
    fi
  done
  if [ -n "$WLS" ]; then
    wl=${WLS[0]}
    ph=`iw dev $wl info | grep wiphy | awk '{print "phy"$2}'`
    nb=`rfkill --raw | grep $ph | awk '{print $1}'`
    st=`rfkill --raw | grep $ph | awk '{print $4}'`
    if [ $st == "blocked" ];then `rfkill unblock $nb`;fi
    if $TEGRA;then
      systemctl stop wpa_supplicant.service
      systemctl stop NetworkManager.service
      ifconfig $wl down
      ifconfig $wl up
      iwconfig $wl mode monitor
      iw reg set DE
      iwconfig $wl channel $CHANNEL
    else
      ip link set $wl down
      iw dev $wl set type monitor
      ip link set $wl up
      iw dev $wl set channel $CHANNEL
    fi
    PIDFILE=/tmp/wfb_${wl}.pid
    touch $PIDFILE
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    $HOME_PRJ/wfb $wl > /dev/null 2>&1 &
    echo $! | tee -a $PIDFILE > /dev/null 2>&1 
#    $HOME_PRJ/video.sh $PIDFILE > /dev/null 2>&1 &
#    echo $! | tee -a $PIDFILE > /dev/null 2>&1 
  fi
fi
