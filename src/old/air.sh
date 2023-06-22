#!/bin/bash

sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1

#export node wlx3c7c3fa9c1e8

#$PWD/wifiraw 1 $node &

#gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720,framerate=30/1,format=NV12,interlace-mode=progressive,colorimetry=bt709 ! timeoverlay ! v4l2h264enc extra-controls="controls,video_bitrate_mode=0,h264_minimum_qp_value=35,h264_maximum_qp_value=35,h264_i_frame_period=30,h264_profile=0,h264_level=11,video_bitrate=1500;" ! video/x-h264,level="(string)4" ! rtph264pay mtu=1400 config-interval=-1 ! udpsink port=5600 host=127.0.0.1

#gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720,framerate=30/1  ! timeoverlay !  v4l2h264enc extra-controls="controls,video_bitrate=1500"  !  video/x-h264,level="(string)4" ! rtph264pay mtu=1400 config-interval=-1 ! udpsink port=5600 host=127.0.0.1


#gst-launch-1.0 libcamerasrc ! video/x-raw,width=1280,height=720,framerate=30/1,format=NV12,interlace-mode=progressive,colorimetry=bt709 ! timeoverlay ! v4l2h264enc extra-controls="controls,video_bitrate_mode=0,h264_minimum_qp_value=35,h264_maximum_qp_value=35,h264_i_frame_period=30,h264_profile=0,h264_level=11,video_bitrate=1500;" ! video/x-h264,level="(string)4" ! rtph264pay mtu=1400 config-interval=-1 ! udpsink port=5600 host=127.0.0.1

#gst-launch-1.0 libcamerasrc ! video/x-raw,width=1280,height=720,framerate=30/1,format=NV12,interlace-mode=progressive,colorimetry=bt709 ! timeoverlay ! v4l2h264enc ! video/x-h264,level="(string)4" ! rtph264pay mtu=1400 config-interval=-1 ! udpsink port=5600 host=127.0.0.1

#gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720,framerate=30/1  ! timeoverlay !  x264enc bitrate=2000   ! rtph264pay mtu=1400 config-interval=-1 ! udpsink port=5600 host=127.0.0.1

