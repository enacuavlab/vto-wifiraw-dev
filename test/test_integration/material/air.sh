#!/bin/bash

#export node wlx3c7c3fa9c1e8

#$PWD/wifiraw 1 $node &

#socat TUN:10.0.1.2/24,tun-name=airtuntx,iff-no-pi,tun-type=tun,iff-up udp-sendto:127.0.0.1:14900 > /dev/null 2>&1 &
#socat udp-listen:14800,reuseaddr,fork TUN:10.0.1.2/24,tun-name=airtunrx,iff-no-pi,tun-type=tun,iff-up > /dev/null 2>&1 &
#sleep 1
#ifconfig airtuntx mtu 1400 up &
#while [ ! "`sysctl -w net.ipv4.conf.airtunrx.rp_filter=2`" = "net.ipv4.conf.airtunrx.rp_filter = 2" ];do sleep 1; done
#route add default airtuntx  > /dev/null 2>&1 &

gst-launch-1.0     videotestsrc ! video/x-raw,width=1280,height=720,framerate=30/1,format=NV12,interlace-mode=progressive,colorimetry=bt709 !     v4l2h264enc extra-controls="controls,video_bitrate_mode=0,h264_minimum_qp_value=35,h264_maximum_qp_value=35,h264_i_frame_period=30,h264_profile=0,h264_level=11,video_bitrate=2000;" ! video/x-h264,level="(string)4" ! rtph264pay mtu=1400 config-interval=-1 ! udpsink port=5600 host=127.0.0.1

gst-launch-1.0     libcamerasrc ! video/x-raw,width=1280,height=720,framerate=30/1,format=NV12,interlace-mode=progressive,colorimetry=bt709 !     v4l2h264enc extra-controls="controls,video_bitrate_mode=0,h264_minimum_qp_value=35,h264_maximum_qp_value=35,h264_i_frame_period=30,h264_profile=0,h264_level=11,video_bitrate=2000;" ! video/x-h264,level="(string)4" ! rtph264pay mtu=1400 config-interval=-1 ! udpsink port=5600 host=127.0.0.1


