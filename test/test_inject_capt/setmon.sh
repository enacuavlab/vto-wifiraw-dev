sudo systemctl stop  NetworkManager

declare -a usbwifidongles=(wlx7c10c91c408e wlx3c7c3fa9c1e8)
#declare -a usbwifidongles=(wlx7c10c91c408e wlxfc34972ed57c)
#declare -a usbwifidongles=(wlxfc349725a319 wlxfc349725a317)

for dongle in "${usbwifidongles[@]}"
do 
  echo "$dongle"
#  sudo ifconfig $dongle down
#  sudo ifconfig $dongle up
#  sudo iwconfig $dongle mode monitor
#  sudo iwconfig $dongle channel 140
#  sudo ifconfig $dongle down
  sudo ip link set $dongle down
  sudo iw dev $dongle set type monitor
  sudo ip link set $dongle up
  sudo iw dev $dongle set channel 140
done

#sudo iwlist $dongle channel
#sudo iw dev $dongle set channel 1 HT40
 #sudo iw dev $dongle set channel 1 HT20
