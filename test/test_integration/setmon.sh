declare -a usbwifidongles=(wlx7c10c91c408e wlx3c7c3fa9c1e8)

for dongle in "${usbwifidongles[@]}"
do 
  echo "$dongle"
  sudo ip link set $dongle down
  sudo iw dev $dongle set type monitor
  sudo ip link set $dongle up
  sudo iw dev $dongle set channel 140
done
