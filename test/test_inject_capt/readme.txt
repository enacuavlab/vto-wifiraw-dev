No options on modprobe
Channel 140
#ifdef LEGACY
0x48
sudo ./test_capt_burst $node
sudo ./test_inject_burst $node

800 x 2311 (2248)
wait_n.tv_nsec=1000000
=> 1.8 Mbs

wait_n.tv_nsec=100000
=> CRASH



-------------------------------------------------------------
check
/etc/modprobe.d/8812au.conf
"
options 88XXau rtw_led_ctrl=1
options 88XXau rtw_monitor_disable_1m=1
"
Led blinking on startup means that rtw_monitor_disable_1m is set

sudo sysctl -w net.core.wmem_max=2621440

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

