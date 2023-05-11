-------------------------------------------------------------------------------
Test simple echo:
----------------
sudo ./rx_raw $node

sudo ./tx_raw $node

----------------
echo "hello" | sudo ./tx_raw $node


-------------------------------------------------------------------------------
Test file transfert: 
-------------------
openssl rand 8 > /tmp/1B.log
openssl rand 512 > /tmp/512B.log
openssl rand 1024 > /tmp/1K.log
=> OK for  MCS 5

openssl rand 10240 > /tmp/10K.log 
openssl rand 102400 > /tmp/100K.log
openssl rand 1024000 > /tmp/1G.log
openssl rand 10240000 > /tmp/10G.log
=> OK for MCS 4 (missing packet above) 
10 Gb in 8 secs

cat /tmp/10G.log | pv -r | sudo ./tx_raw $node > /tmp/10G_tx.log 
[1,32MiB/s]

diff /tmp/10G.log /tmp/10G_tx.log

sudo ./rx_raw $node | pv -r > /tmp/10G_rx.log
[1,32MiB/s]

diff /tmp/10G.log /tmp/10G_rx.log

note:
This test can also check if TX NOACK is set or not. So the driver "might" resend the packets.


-------------------------------------------------------------------------------
Test streaming with fdsink/stdin, stdout/fdsrc :
------------------------------------------------
gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720,framerate=25/1 ! timeoverlay !  x264enc tune=zerolatency byte-stream=true bitrate=2500 ! fdsink | pv -r | sudo ./tx_raw $node | gst-launch-1.0 fdsrc ! h264parse ! avdec_h264 ! videoconvert ! autovideosink sync=false
[1,14MiB/s]

sudo ./rx_raw $node | pv -r | gst-launch-1.0 fdsrc ! h264parse ! avdec_h264 ! videoconvert ! autovideosink sync=false
[1,14MiB/s]

Issue: Image blurred, RTP needed ?

-------------------------------------------------------------------------------
Test streaming UDP with udpsink/udp, udp/udpsrc :
---------------------------------------------
gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720,framerate=25/1 ! timeoverlay !  x264enc tune=zerolatency byte-stream=true bitrate=2500 ! udpsink port=5000 host=127.0.0.1

(sudo tcpdump -i lo -n udp port 5000)
(UDP, length 18355)

sudo ./tx_raw 127.0.0.1:5000 $node

sudo ./rx_raw 127.0.0.1:6000 $node

gst-launch-1.0  udpsrc port=6000 ! h264parse ! avdec_h264 ! videoconvert ! autovideosink sync=false

Issue: Image blurred, RTP needed ?

-------------------------------------------------------------------------------
Test streaming RTP with udpsink/udp, udp/udpsrc :
---------------------------------------------
gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720,framerate=25/1 ! timeoverlay !  x264enc tune=zerolatency byte-stream=true bitrate=2500 ! rtph264pay mtu=1400 ! udpsink port=5000 host=127.0.0.1

(gst-launch-1.0  udpsrc port=5000 ! application/x-rtp !  rtph264depay ! h264parse ! avdec_h264 ! videoconvert ! autovideosink sync=false)

(sudo tcpdump -i lo -n udp port 5000)
(UDP, length range 14 to 1400)

sudo ./tx_raw 127.0.0.1:5000 $node

sudo ./rx_raw 127.0.0.1:6000 $node

(sudo tcpdump -i lo -n udp port 6000)
(UDP, length fixed 1400)

(socat udp-listen:5000,reuseaddr,fork udp:localhost:6000)

gst-launch-1.0 udpsrc port=6000 ! application/x-rtp ! rtph264depay ! h264parse ! queue ! avdec_h264 ! xvimagesink sync=false async=false
(no videoconvert needed !)

(gst-launch-1.0 -v udpsrc port=6000 ! "application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264, payload=(int)96" ! rtph264depay ! h264parse ! avdec_h264 ! videoconvert ! autovideosink)

Issue: No image


-------------------------------------------------------------------------------
-------------------------------------------------------------------------------


gst-launch-1.0 videotestsrc ! 'video/x-raw,width=1280,height=720,format=NV12,framerate=30/1' ! timeoverlay !  tee name=t ! queue ! x264enc  tune=zerolatency bitrate=5000 speed-preset=superfast ! rtph264pay mtu=1400 ! udpsink port=5000 host=127.0.0.1 t. ! queue leaky=1 ! decodebin ! videoconvert ! autovideosink sync=false

gst-launch-1.0 -v udpsrc port=5000 ! "application/x-rtp, media=(string)video, clock-rate=(int)90000, encoding-name=(string)H264, payload=(int)96" ! rtph264depay ! h264parse ! avdec_h264 ! videoconvert ! autovideosink


-------------------------------------------------------------------------------

gst-launch-1.0 videotestsrc ! video/x-raw,width=1940,height=1080 ! timeoverlay ! tee name=t t. ! queue ! autovideosink sync=false t. ! queue ! x264enc tune=zerolatency byte-stream=true bitrate=10000 ! fdsink | sudo ./tx_raw $node

sudo ./rx_raw $node | gst-launch-1.0 fdsrc ! h264parse ! avdec_h264 ! videoconvert ! autovideosink sync=false

---------------------------
fd_in = STDIN_FILENO
write(STDOUT_FILENO
gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720 ! timeoverlay ! tee name=t t. ! queue ! autovideosink sync=false t. ! queue ! x264enc tune=zerolatency byte-stream=true bitrate=10000 ! fdsink | sudo ./tx_raw $node | gst-launch-1.0 fdsrc ! h264parse ! avdec_h264 ! videoconvert ! autovideosink sync=false


-------------------------------------------------------------------------------
DEBUG:

sudo tcpdump -i lo -n udp port 5000

------
gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720 ! timeoverlay !  x264enc tune=zerolatency byte-stream=true bitrate=5000 ! fdsink | sudo ./tx_raw $node | hexdump 

sudo ./rx_raw $node | hexdump 


------
sudo gdb ./tx_raw

b main
r wlxfc34972ed57c < <(gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720 ! timeoverlay !  x264enc tune=zerolatency byte-stream=true bitrate=5000)
