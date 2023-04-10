#declare -a usbwifidongles=(wlx7c10c91c408e wlxfc34972ed57c)
declare -a usbwifidongles=(wlxfc349725a319 wlxfc349725a317)

for dongle in "${usbwifidongles[@]}"
do 
  echo "$dongle"
  sudo ifconfig $dongle down
  sudo ifconfig $dongle up
  sudo iwconfig $dongle mode monitor
  sudo iwconfig $dongle channel 140
done

#sudo iwlist $dongle channel
