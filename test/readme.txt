Unix Domain Sockets
-------------------
socat unix-recvfrom:/tmp/datagram.sock,fork STDOUT

echo "hello" | nc -uU /tmp/datagram.sock
echo "hello" | nc -uU -w1 /tmp/datagram.sock


socat -x -d UNIX-RECVFROM:socket -
echo 'test' | socat - UNIX-SEND:socket


-------------------------------------------------------------------------------
sysctl net.unix.max_dgram_qlen
=>
net.unix.max_dgram_qlen = 512


-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
test /
gst-launch-1.0 videotestsrc ! video/x-raw,width=1940,height=1080 ! timeoverlay ! x264enc tune=zerolatency byte-stream=true bitrate=$BITES_RATE ! fdsink | sudo ./tx $node

test/
sudo ./rx $node

test/
sudo ./sniffer $node

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
time socat -b100000 OPEN:/dev/urandom,readbytes=100000 UNIX-SEND:socket

time socat -x -d UNIX-RECVFROM:socket - | hexdump -C
=>
real    0m2,247s
user    0m0,025s
sys     0m0,020s


-------------------------------------------------------------------------------
socat -b1000000000 "SYSTEM:dd if=/dev/shm/data.dump bs=1M count=1024" UNIX-SEND:socket

time socat -x -d UNIX-RECVFROM:socket - | hexdump -C
=>
real    0m2,840s
user    0m0,007s
sys     0m0,006s


-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
time openssl rand 1000000000 > /dev/shm/data.dump
real    0m7,108s
user    0m6,271s
sys     0m0,836s

time dd if=/dev/urandom of=/dev/shm/data-urandom.dump bs=1000000000 count=1
1+0 records in
1+0 records out
1000000000 bytes (1,0 GB, 954 MiB) copied, 6,62855 s, 151 MB/s
real    0m6,875s
user    0m0,000s
sys     0m6,873s
