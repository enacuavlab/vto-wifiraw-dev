git clone --recurse-submodules  https://github.com/enacuavlab/vto-wifiraw-dev.git

(git clone --recurse-submodules  git@github.com:enacuavlab/vto-wifiraw-dev.git)

./install.sh
or
./uninstall.sh

-------------------------------------------------------------------------------
src 
-----
Extract from src_1 with external TAP
muultiple packet
external FEC

-------------------------------------------------------------------------------
src 1
-----
Extract from src_0 with external TAP
single packet !
NO FEC

=> Packet lost !

-------------------------------------------------------------------------------
src_0
-----
https://github.com/rodizio1/EZ-WifiBroadcast.git

Unidirectionnal transmission with own FEC and TAP

1920x1080p 30fps Resolution and up to 12Mbit video bitrate 

----
export node=wlx3c7c3fa9bdc1
export node=wlx3c7c3fa9c1e4

sudo ifconfig $node down
sudo ifconfig $node up
sudo iwconfig $node mode monitor
sudo iwconfig $node channel 36

export NB_DATA_PKT=8
export NB_FEC_PKT=4
export NB_BYTES_PKT=1450


export MBITES_RATE=36
export BITES_RATE=10000

gst-launch-1.0 videotestsrc ! video/x-raw,width=1940,height=1080 ! timeoverlay ! x264enc tune=zerolatency byte-stream=true bitrate=$BITES_RATE ! fdsink \
| sudo ./tx -b $NB_DATA_PKT -r $NB_FEC_PKT -f $NB_BYTES_PKT -d $MBITES_RATE -t 1 -y 0 $node


sudo ./rx -b $NB_DATA_PKT -r $NB_FEC_PKT -f $NB_BYTES_PKT $node 2>/tmp/log.txt \
| gst-launch-1.0 fdsrc ! h264parse ! avdec_h264 ! videoconvert ! autovideosink sync=false


sudo tail -f /tmp/log.txt
=>
adap 0 rec 1fd0a blk 2a6b crc 1 len 1454 


-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
sudo apt install -y gstreamer1.0-tools
sudo apt install -y gstreamer1.0-plugins-base
sudo apt install -y gstreamer1.0-libav
sudo apt install -y gstreamer1.0-plugins-ugly
sudo apt install -y gstreamer1.0-plugins-bad

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------

https://tahoe-lafs.org/trac/zfec/
https://github.com/tahoe-lafs/zfec.git
zfec-1.5.7.2 (feb 24,2022)
=> fec.c, fec.h

https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-ieee80211-radiotap.c
wireshark-4.0.3 (Jul 16, 2022)
=> packet-ieee80211-radiotap.c

https://github.com/radiotap/radiotap-library.git
master Jun 22, 2020
=> radiotap.c radiotap.h 

inspired from https://warmcat.com/
git clone https://warmcat.com/repo/packetspammer
(Release 0.6, 16 years)

https://www.kernel.org/doc/Documentation/networking/radiotap-headers.txt
https://www.kernel.org/doc/Documentation/networking/mac80211-injection.txt

https://github.com/svpcom/wfb-ng/tree/release-21.08 (feb 14,2022)

- 1:1 map of RTP to IEEE80211 packets for minimum latency (doesn't serialize to byte steam)
- Smart FEC support (immediately yeild packet to video decoder if FEC pipeline without gaps)
