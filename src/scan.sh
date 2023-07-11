#!/bin/bash

DEVICES=/proc/net/rtl88XXau
DUMPFILE=/tmp/wfb.tshark
echo -n > $DUMPFILE

CHAN=()

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
       if [[ $ty = "managed" ]]; then WLS+=($wl);
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
    canstr=`iw phy $ph channels | grep '*' | awk '{gsub(/\[|\]/,"",$NF);print $2" "$NF}'`
    readarray -t lines <<< "$canstr"
    declare -A arr
    for i in "${!lines[@]}"; do
      IFS=' ' read -r -a elements <<< "${lines[i]}"
      for j in "${!elements[@]}"; do
        arr[$i,$j]=${elements[j]}
      done
    done

    if $TEGRA;then
      systemctl stop wpa_supplicant.service
      systemctl stop NetworkManager.service
      ifconfig $wl down
      ifconfig $wl up
      iwconfig $wl mode monitor
    else
      ip link set $wl down
      iw dev $wl set type monitor
      ip link set $wl up
    fi

    for (( i=0;i<${#lines[@]};i++)); do
      freq="${arr[$i,0]}"
      chan="${arr[$i,1]}"
      echo ${can[1]}
      if $TEGRA;then
        iwconfig $wl channel $chan
      else
        iw dev $wl set channel $chan
      fi
      tsh=`tshark -a duration:5 -i $wl | wc -l` 
      echo $chan' '$freq' '$tsh >> $DUMPFILE 
    done
  fi
fi
