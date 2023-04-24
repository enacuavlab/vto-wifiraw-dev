declare -a usbwifidongles=(wlx3c7c3fa9c1e8 wlxfc34972ed57c)
#declare -a usbwifidongles=(wlxfc349725a319 wlxfc349725a317)

for dongle in "${usbwifidongles[@]}"
do 
  echo "$dongle"
  sudo ip link set $dongle down
  sudo iw dev $dongle set type monitor
  sudo ip link set $dongle up
  sudo iw dev $dongle set channel 140
done
