socat -u udp-listen:4244,reuseaddr,fork -

/home/pprz/Projects/paparazzi/sw/ground_segment/tmtc/server  -no_md5_check option
/home/pprz/Projects/paparazzi/sw/tools/gcs_launch.py
/home/pprz/Projects/paparazzi/sw/ground_segment/tmtc/link_py.py -d /dev/ttyUSB0 -t xbee -s 57600 -ac 114:127.0.0.1:4244:4245

gst-launch-1.0 udpsrc port=5600 ! application/x-rtp, encoding-name=H264, payload=96 ! rtph264depay ! h264parse ! queue ! avdec_h264 !  videoconvert ! autovideosink sync=false
