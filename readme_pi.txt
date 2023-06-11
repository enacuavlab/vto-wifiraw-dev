PI flash & headless configure
-----------------------------
(sudo apt install rpi-imager
or custom conf below)

PI4
2022-09-22-raspios-bullseye-arm64-lite.img.xz
(uname -a 
OK : Linux raspberrypi 5.15.61-v8+ #1579 SMP PREEMPT Fri Aug 26 11:16:44 BST 2022 aarch64 GNU/Linux
OK : Linux raspberrypi 6.1.21-v8+ #1642 SMP PREEMPT Mon Apr  3 17:24:16 BST 2023 aarch64 GNU/Linux)

(wget https://downloads.raspberrypi.org/raspios_lite_arm64/images/raspios_lite_arm64-2022-09-26/2022-09-22-raspios-bullseye-arm64-lite.img.xz)
(unxz 2022-09-22-raspios-bullseye-arm64-lite.img.xz)
(dd if=2022-09-22-raspios-bullseye-arm64-lite.img of=/dev/sdf bs=4M status=progress)
(partprobe /dev/sdf)
(mount /dev/sdc1 /mnt)

PI3
2023-02-21-raspios-bullseye-arm64-lite.img.xz

PI0.2
2023-05-03-raspios-bullseye-arm64-lite.img.xz
(uname -a
Linux raspberrypi 6.1.21-v8+ #1642 SMP PREEMPT Mon Apr  3 17:24:16 BST 2023 aarch64 GNU/Linux)

-------------------------------------------------------------------------------------------
cd /media/.../boot
sudo touch ssh

sudo vi wpa_supplicant.conf
"
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=FR
network={
  ssid="Androidxp"
  psk="pprzpprz"
}
network={
  ssid="pprz_router"
  key_mgmt=NONE
  }
"

-------------------------------------------------------------------------------------------
sudo vi /media/../rootfs/etc/dhcpcd.conf
Add "denyinterfaces wlan1" to the end of the file (but above any other added interface lines).
"
denyinterfaces wlan1
# It is possible to fall back to a static IP if DHCP fails:
# define static profile
profile static_eth0
static ip_address=192.168.3.2/24
static routers=192.168.3.1
static domain_name_servers=8.8.8.8
# fallback to static profile on eth0
interface eth0
fallback static_eth0
"

-------------------------------------------------------------------------------------------
/boot/userconf

username:password-hash

echo "pprz" | openssl passwd -6 -stdin
pi:$6$38HiUnL.... 

(echo -n pi: ; echo 'pprz' | openssl passwd -6 -stdin) | sudo tee userconf)

-------------------------------------------------------------------------------------------
Connect
sudo nmap -sn 192.168.1.1/24
ssh pi@...

-------------------------------------------------------------------------------------------
Post setup
-----------
/boot/config.txt
#Disable onboard Bluetooth on Pi 3B, 3B+, 3A+, 4B and Zero W, restoring UART0/ttyAMA0 over GPIOs 14 (pin 8) & 15 (pin10). 
dtoverlay=disable-bt

sudo systemctl disable hciuart.service
sudo systemctl disable bluealsa.service
sudo systemctl disable bluetooth.service

sudo reboot

# sudo systemctl stop serial-getty@ttyAMA0.service
# sudo systemctl disable serial-getty@ttyAMA0.service
# sudo systemctl stop hciuart
# sudo systemctl disable hciuart

sudo apt update && sudo apt upgrade -y

sudo apt-get install git -y;\
sudo apt-get install gstreamer1.0-plugins-good -y;\
sudo apt-get install gstreamer1.0-plugins-bad -y;\
sudo apt-get install gstreamer1.0-plugins-ugly -y;\
sudo apt-get install gstreamer1.0-plugins-base -y;\

sudo apt-get install gstreamer1.0-tools gstreamer1.0-alsa \
     gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
     gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
     gstreamer1.0-libav
sudo apt-get install libgstreamer1.0-dev \
     libgstreamer-plugins-base1.0-dev \
     libgstreamer-plugins-bad1.0-dev

-----------
sudo pip3 install pyserial
