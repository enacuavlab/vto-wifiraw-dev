#!/bin/bash

# sudo nvidia_launch.sh 
#
DEVICES=/proc/net/rtl88XXau
if [ -d "$DEVICES" ]; then
  dirs=( "$DEVICES"/*/ )
  device=${dirs[0]}
  wl=`basename $device`
  echo $wl
  ifconfig $wl down
fi  
