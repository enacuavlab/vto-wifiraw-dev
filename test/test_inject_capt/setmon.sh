declare -a usbwifidongles=(wlx3c7c3fa9bdca wlxfc349725a319)

for dongle in "${usbwifidongles[@]}"
do 
  echo "$dongle"
  sudo ip link set $dongle down
  sudo iw dev $dongle set type monitor
  sudo ip link set $dongle up
  sudo iw dev $dongle set channel 165
#  sudo ifconfig $dongle down
#  sudo ifconfig $dongle up
#  sudo iwconfig $dongle mode monitor
#  sudo iw reg set DE
#  sudo iwconfig $dongle channel 165
done
