/etc/modprobe.d/8812au.conf
options 88XXau rtw_monitor_disable_1m=1

Channel 165 // width 20MHz, MCS #1 (QPSK 1/2) with long GI.

Radiotap :
#define LEGACY
0x0c // x 500kHz = 6Mb
0x48 // x 500kHz = 36Mb
0x60 // x 500kHz = 48Mb
0x6C // x 500kHz = 54Mb

0x81 to 0x87 (1000 0007 : MCS 7) 


sudo ./test_pcap_capt_burst $node
sudo ./test_pcap_inject_burst $node

--------
wait_n.tv_nsec=1000000; // 1 ms

----
Big packet:
800 x 2250 (2311) = 1.8 M
--
0x0c
1175.528
=> 1.5 Mbs
Latency: 180 ms
--
0x48
930.103
=> 1.9 Mbs
Latency: 2 ms
--
0x60
952.795
=> 2 Mbs
Latency 2 ms
--
0x6c
967.211
=> 1.9 Mbs
Latency 1.6 ms

----
Medium packet:
800 x 1449 (1510) = 1.2 M
--
0x0c
! Packet lost !
--
0x48
951.887
=> 1.3 Mbs
--
0x60
925.402
=> 1.3 Mbs
--
0x6c
958.109
=> 1.2 Mbs
Latency 1.5 ms

--------
wait_n.tv_nsec=800000; // 800 micro s

----
Big packet:
800 x 2250 (2311) = 1.8 M
--
0x0c
! Packet lost !
--
0x48
786.422
=> 2 Mb
Latency 2 ms
--
0x60
774.404
=> 2.4 Mbs
Latency 1.8 ms
--
0x6c
771.725
=> 2.3 Mbs
Latency 1.6 ms

----
Medium packet:
800 x 1449 (1510) = 1.2 M
--
0x0c
! Packet lost !
--
0x48
! Packet lost !
--
0x60
761.538
=> 1.6 Mbs
Latency 1.5 ms
--
0x6c
769.878
=> 1.6 Mbq
Latency 1.5 ms

--------
wait_n.tv_nsec=400000; // 400 micro s

----
Big packet:
800 x 2250 (2311) = 1.8 M
--
0x60
1.210
=> 1.5 Mbs
Latency 0.4 ms
--
0x6c
400.488
=> 4.4 Mbps
Latency 1.2 ms

----
Medium packet:
800 x 1449 (1510) = 1.2 M
--
0x60
1.515
=> 805 Kbs
Latency 0.4 ms
--
0x6c
405.454
=> 3 Mbps
Latency 1 ms

--------
wait_n.tv_nsec=100000; // 100 micro s
----
Big packet:
800 x 2250 (2311) = 1.8 M
--
0x60
30.813
=> 60 Kbs
--
0x6c
! Packet lost !

----
Medium packet:
800 x 1449 (1510) = 1.2 M
--
0x60
29.765
=> 40 Kbs
--
0x6c
! Packet lost !


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
