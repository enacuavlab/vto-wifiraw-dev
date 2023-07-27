Using RAW (wifidongle)

Makefile (PROT := RAW)
sudo ./test_tv_tx $node
sudo ./test_tv_rx $node
sudo ./test_tun $node

-------------------------------------------
Not using RAW (udp 5100)

Makefile (#PROT := RAW)
sudo ./test_tv_tx
sudo ./test_tv_rx
sudo ./test_tun

-------------------------------------------

From PC
-------
gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720,framerate=30/1  ! timeoverlay !  x264enc bitrate=2000   ! rtph264pay mtu=1400 config-interval=-1 ! udpsink port=5600 host=127.0.0.1

gst-launch-1.0 -v udpsrc port=5700 ! "application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264, payload=(int)96" ! rtph264depay ! h264parse ! avdec_h264 ! videoconvert ! autovideosink


From PI
-------
gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720,framerate=30/1  ! timeoverlay !  v4l2h264enc extra-controls="controls,video_bitrate=4000000"  !  video/x-h264,level="(string)4" ! rtph264pay mtu=1400 config-interval=-1 ! udpsink port=5600 host=127.0.0.1

gst-launch-1.0 libcamerasrc ! video/x-raw,width=1280,height=720,framerate=30/1,format=NV12,interlace-mode=progressive,colorimetry=bt709 ! timeoverlay ! v4l2h264enc extra-controls="controls,video_bitrate=4000000" ! video/x-h264,level="(string)4" ! rtph264pay mtu=1400 config-interval=-1 ! udpsink port=5600 host=127.0.0.1

socat -b1400 udp-listen:5600,reuseaddr,fork udp-sendto:192.168.2.1:5700

--------------------------------------------
-------------------------------------------
Check temperature is under 40°c
External fan must be needed !!

/opt/vc/bin/vcgencmd measure_temp
cat /sys/class/thermal/thermal_zone0/temp

-------------------------------------------
Check temperature is under 40°c
Set MCS index of 2
