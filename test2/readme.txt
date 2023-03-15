sudo ./rx_fec $node | gst-launch-1.0 fdsrc ! h264parse ! avdec_h264 ! videoconvert ! autovideosink sync=false


gst-launch-1.0 videotestsrc ! video/x-raw,width=1940,height=1080 ! timeoverlay ! tee name=t t. ! queue ! autovideosink sync=false t. ! queue ! x264enc tune=zerolatency byte-stream=true bitrate=20000 ! fdsink | sudo ./tx_fec $node
