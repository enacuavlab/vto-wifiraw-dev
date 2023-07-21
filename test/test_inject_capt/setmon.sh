declare -a usbwifidongles=(wlx3c7c3fa9bdc6)

for dongle in "${usbwifidongles[@]}"
do 
  echo "$dongle"
  sudo ip link set $dongle down
  sudo iw dev $dongle set type monitor
  sudo ip link set $dongle up
  sudo iw dev $dongle set channel 14
done
