No options on modprobe
Channel 140

#define LEGACY
0x0c // x 500kHz = 6Mb
0x48 // x 500kHz = 36Mb
(0x60 // x 500kHz = 48Mb not significant)

sudo ./test_pcap_capt_burst $node
sudo ./test_pcap_inject_burst $node

----
wait_n.tv_nsec=10000000 // 10 ms

Big packet:
800 x 2248 (2311) = 1.8 M
8199.959
=> 220 Kbs
Latency: 4.45 ms

Medium packet:
800 x 1447 (2311)
Latency: 2.270 ms

----
wait_n.tv_nsec=1000000 // 1 ms

Big packet:
800 x 2311
! System Crash !

Medium packet:
800 x 1447 (1510) = 1.16 M
---
0x0c
1269.469
=> 914 Kbs
Latency: 194 ms
---
0x48
965.097
=> 1.6 Mps 
Latency: 1.593

----
wait_n.tv_nsec=100000 // 0.1 ms

Medium packet:
800 x 1447 (1510)
! Packets lost !

Small packet:
800 x 437 (500) = 350 K
---
0x0c
! Packets lost !
---
0x48
156.449
=> 2.2 Kbs
Latency 1.087

-------------------------------------------------------------
check
/etc/modprobe.d/8812au.conf
"
options 88XXau rtw_led_ctrl=1
options 88XXau rtw_monitor_disable_1m=1
"
Led blinking on startup means that rtw_monitor_disable_1m is set

? 
sudo sysctl -w net.core.rmem_max=33554432
sudo sysctl -w net.core.wmem_max=33554432
sudo sysctl -w net.core.rmem_default=33554432
sudo sysctl -w net.core.wmem_default=33554432
?

-------------------------------------------------------------

Channel 140
----------

sudo ./test_capt_once $node

sudo ./test_inject_once $node

=> latency in milliseconds (ex. 2 to 3 ms)


OK for legacy bitrate setting 0x48 or 0x60

OK for no legacy: (https://mcsindex.com/)
- #define MCS_FLAGS  (IEEE80211_RADIOTAP_MCS_BW_20)
  #define MCS_INDEX  1 -> bad
 ...
  #define MCS_INDEX  7 -> good

