gst-launch-1.0 -v videotestsrc ! 'video/x-raw,width=1280,height=720,format=NV12,framerate=30/1' ! timeoverlay !  tee name=t ! queue ! x264enc  tune=zerolatency bitrate=5000 speed-preset=superfast ! rtph264pay mtu=1400 ! udpsink port=5000 host=127.0.0.1 t. ! queue leaky=1 ! decodebin ! videoconvert ! autovideosink sync=false

gst-launch-1.0 -v udpsrc port=5000 ! "application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264, payload=(int)96" ! rtph264depay ! h264parse ! avdec_h264 ! videoconvert ! autovideosink

sudo ./tx_raw $node 

