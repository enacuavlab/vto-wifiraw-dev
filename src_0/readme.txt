---
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

