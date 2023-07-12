#!/bin/bash

# sudo setmon.sh

CHANNEL=140
#
# Get set given wifi dongle or look for one available
#
if [ "$#" -eq 0 ]; then
  DEVICES=/proc/net/rtl88XXau
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
         if [[ $ty = "managed" ]]; then WLS+=($wl);
          else
            if [[ $(ifconfig | grep -c $wl) == 0 ]]; then WLS+=($wl); fi
  	fi
      fi
    done
    if [ -n "$WLS" ]; then
      wl=${WLS[0]}
    fi
  fi
fi

if [ "$#" -eq 1 ]; then
  wl=$1
fi

if [ -n "$wl" ]; then
  echo "$dongle"
  if $TEGRA;then
    systemctl stop wpa_supplicant.service
    systemctl stop NetworkManager.service
    ifconfig $wl down
    ifconfig $wl up
    iwconfig $wl mode monitor
    iwconfig $wl channel $CHANNEL
  else
    ip link set $wl down
    iw dev $wl set type monitor
    ip link set $wl up
    iw dev $wl set channel $CHANNEL
  fi
fi
