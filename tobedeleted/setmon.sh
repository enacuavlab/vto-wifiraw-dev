#declare -a usbwifidongles=(wlx3c7c3fa9c1e4 wlxfc34972ed57c)
declare -a usbwifidongles=(wlxfc349725a319 wlxfc349725a317)

for dongle in "${usbwifidongles[@]}"
do 
  echo "$dongle"
  sudo ifconfig $dongle down
  sudo ifconfig $dongle up
  sudo iwconfig $dongle mode monitor
  sudo iwconfig $dongle channel 36
done
