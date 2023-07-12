#!/bin/bash

# sudo nvidia_down
#
DEVICES=/proc/net/rtl88XXau
if [ -d "$DEVICES" ]; then
  dirs=( "$DEVICES"/*/ )
  device=${dirs[0]}
  wl=`basename $device`
  echo $wl
  ./wfb $wl
fi  
