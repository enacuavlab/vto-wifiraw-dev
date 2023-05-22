sudo ./multi_aio-raw 0 $node
sudo ./multi_aio-raw 1 $node

-------------------------------------------------------------------------------
Test video streaming
--------------------
sudo ./aio-raw 0 $node
tail -f /tmp/tx.log
=> kbytesec(46)

sudo ./aio-raw 1 $node
tail -f /tmp/rx.log
=> kbytesec(42)fails(0)drops(6)dbm(-24)

gst-launch-1.0 videotestsrc ! video/x-raw,width=1280,height=720,framerate=25/1 ! timeoverlay !  tee name=t ! queue ! x264enc tune=zerolatency bitrate=5000 ! rtph264pay mtu=1400 config-interval=-1 ! udpsink port=5000 host=127.0.0.1  t. ! queue ! videoconvert ! autovideosink sync=false

gst-launch-1.0 udpsrc port=6000 ! application/x-rtp, encoding-name=H264, payload=96 ! rtph264depay ! h264parse ! queue ! avdec_h264 !  videoconvert ! autovideosink sync=false

Note: latency 0.4 sec 

-------------------------------------------------------------------------------
Test simple echo:
----------------
sudo ./aio-raw 0 $node
sudo ./aio-raw 1 $node

echo "message 1" | socat - udp:127.0.0.1:5000

socat - udp4-listen:6000,reuseaddr,fork

-------------------------------------------------------------------------------
Test file transfert: 
-------------------
sudo ./aio-raw 0 $node
sudo ./aio-raw 1 $node
socat - udp4-listen:6000,reuseaddr,fork > /tmp/rx_dump.log

openssl rand 10240000 > /tmp/10M.log

cat /tmp/10M.log | pv -L 512K |  socat - udp:127.0.0.1:5000

diff /tmp/rx_dump.log /tmp/10M.log 

Issue: failure in file transfert should be log in recetion

