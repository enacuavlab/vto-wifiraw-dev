
sudo ./packetspammer -n 1 -s 2259 $node
                          -s 52

tshark -i $node -Y 'frame.len==2291'
                               84

tshark -i $node
=>
42 208.599438451 23:23:23:23:23:23 → Broadcast    LLC 2291 U, func=UI; SNAP, OUI 0x000000 (Officially Xerox, but 0:0:0:0:0:0 is more common), PID 0x88B5

-------------------------------------------------------------------------------
sudo ./rx_fec $node | gst-launch-1.0 fdsrc ! h264parse ! avdec_h264 ! videoconvert ! autovideosink sync=false


gst-launch-1.0 videotestsrc ! video/x-raw,width=1940,height=1080 ! timeoverlay ! tee name=t t. ! queue ! autovideosink sync=false t. ! queue ! x264enc tune=zerolatency byte-stream=true bitrate=10000 ! fdsink | sudo ./tx_fec $node
gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720 ! timeoverlay ! tee name=t t. ! queue ! autovideosink sync=false t. ! queue ! x264enc tune=zerolatency byte-stream=true bitrate=2000000  ! fdsink | sudo ./tx_fec $node

gst-inspect-1.0 x264enc
=>
  bitrate             : Bitrate in kbit/sec
                        flags: readable, writable, changeable in NULL, READY, PAUSED or PLAYING state
                        Unsigned Integer. Range: 1 - 2048000 Default: 2048 

16000000
2000000
bitrate=24000000
24.0 Mb/s

WIDTH=1280
HEIGHT=720
FPS=30

v4l2h264enc
video_bitrate=3000000

20Mbit/s, but does at 1920x1088
