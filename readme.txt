git clone --recurse-submodules  http://github.com/enacuavlab/vto-wifiraw-dev.git

git clone --recurse-submodules  https://github.com/enacuavlab/vto-wifiraw-dev.git

(git clone --recurse-submodules  git@github.com:enacuavlab/vto-wifiraw-dev.git)

./install.sh
or
./uninstall.sh

-------------------------------------------------------------------------------
Usages:
------
1) Remote shell
ssh $USER@10.0.1.2

2) File transfert (tunnel mtu range 700,1400)
rsync -vP --bwlimit=5000  $USER@10.0.1.2:/tmp/100M.log .
(openssl rand 102400000 > /tmp/100M.log)

3) Video streaming (h264 parsing mtu range 400,1400)
gst-launch-1.0 udpsrc port=5600 ! application/x-rtp, encoding-name=H264, payload=96 ! \
rtph264depay ! h264parse ! queue ! avdec_h264 !  videoconvert ! autovideosink sync=false

4) Telemetry-datalink
link_py.py -d /dev/ttyUSB0 -t xbee -s 57600 -ac 122:127.0.0.1:4244:4245

5) Payload-datalink
socat udp-listen:5800,reuseaddr,fork -
socat - udp-sendto:5900

etc ...

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
Note:
You may need to switchoff your usual wireless connection to have full access to this service
