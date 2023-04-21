/etc/modprobe.d/8812au.conf
options 88XXau rtw_monitor_disable_1m=1

Channel 140 , width 20MHz, MCS 5 => 20 Mbitps

sudo ./capt_raw $node
sudo ./inject_raw $node
(or pcap option files)

-------------------------------------------------------------
check (be carefull with filename, or you might saturate and freeze the all system)
/etc/modprobe.d/8812au.conf
"
options 88XXau rtw_led_ctrl=0
options 88XXau rtw_monitor_disable_1m=1
"
Led NOT blinking ( rtw_led_ctrl=0 ) on startup means that rtw_monitor_disable_1m is set
(default behaviour is blinking)

-------------------------------------------------------------
? 
sudo sysctl -w net.core.rmem_max=33554432
sudo sysctl -w net.core.wmem_max=33554432
sudo sysctl -w net.core.rmem_default=33554432
sudo sysctl -w net.core.wmem_default=33554432
?
