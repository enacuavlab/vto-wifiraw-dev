/etc/modprobe.d/8812au.conf
options 88XXau rtw_monitor_disable_1m=1

Channel 140 // width 20MHz, MCS 1 to 5 with SGI 
same as 54Mb for MCS 5 (=> 4 Mb/s ?)


Radiotap :
#define LEGACY
0x0c // x 500kHz = 6Mb
0x48 // x 500kHz = 36Mb
0x60 // x 500kHz = 48Mb
0x6C // x 500kHz = 54Mb

sudo ./test_raw_capt_burst $node
sudo ./test_raw_inject_burst $node
(or pcap version)

--------
wait_n.tv_nsec=800000; // 800 micro s

--------
wait_n.tv_nsec=400000; // 400 micro s


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
