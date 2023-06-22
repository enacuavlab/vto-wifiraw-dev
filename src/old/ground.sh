#!/bin/bash

#export node wlx3c7c3fa9c1e8

#$PWD/wifiraw 0 $node &

#gst-launch-1.0 udpsrc port=5600 ! application/x-rtp, encoding-name=H264, payload=96 ! rtph264depay ! h264parse ! queue ! avdec_h264 !  videoconvert ! autovideosink sync=false
