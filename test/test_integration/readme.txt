sudo ./wfb_tx_video $node
sudo ./wfb_rx_video $node


From PC
-------
gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720,framerate=30/1  ! timeoverlay !  x264enc bitrate=2000   ! rtph264pay mtu=1400 config-interval=-1 ! udpsink port=5600 host=127.0.0.1

gst-launch-1.0 -v udpsrc port=5700 ! "application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264, payload=(int)96" ! rtph264depay ! h264parse ! avdec_h264 ! videoconvert ! autovideosink


From PI
-------
gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720,framerate=30/1  ! timeoverlay !  v4l2h264enc extra-controls="controls,video_bitrate=4000000"  !  video/x-h264,level="(string)4" ! rtph264pay mtu=1400 config-interval=-1 ! udpsink port=5600 host=127.0.0.1

socat udp-listen:5600,reuseaddr,fork udp-sendto:192.168.2.1:5700
