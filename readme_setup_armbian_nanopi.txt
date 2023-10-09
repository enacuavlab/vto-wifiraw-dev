Linux choubaka 6.2.0-34-generic

----------------------------------------------------------------------------------------------
sudo apt update
sudo apt install apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
apt-cache policy docker-ce
sudo apt install docker-ce
sudo systemctl start docker
sudo systemctl status docker
sudo usermod -aG docker ${USER}
su - ${USER}
groups
(sudo usermod -aG docker username)

----------------------------------------------------------------------------------------------
git clone --depth=1 --branch=main https://github.com/armbian/build
cd build

vi config/kernel/linux-rockchip64-current.config
"
CONFIG_88XXAU=m
to
# CONFIG_88XXAU is not set
"

----------------------------------------------------------------------------------------------
./compile.sh docker-shell
=>
root@93af75bb020d:/armbian#

./compile.sh BOARD=nanopineo3 BRANCH=current RELEASE=bookworm BUILD_MINIMAL=yes BUILD_DESKTOP=no KERNEL_CONFIGURE=no INSTALL_HEADERS=yes ALLOW_ROOT=yes
=> 
[🐳|🌱] Preparing bare kernel git tree [ this might take a long time ]

[🐳|🌿] Done building image [ nanopineo3 ]

[🐳|🌿] Done building image [ nanopineo3 ]
[🐳|🌱] Runtime [ 197:05 min ]

-rw-rw-r-- 1 root root 1769996288 oct.   7 19:53 output/images/Armbian_23.11.0-trunk_Nanopineo3_bookworm_current_6.1.56_minimal.img

exit


----------------------------------------------------------------------------------------------
cd output/images
dd if=Armbian_23.11.0-trunk_Nanopineo3_bookworm_current_6.1.56_minimal.img of=/dev/mmcblkX bs=1M status=progress
sync

(xzcat Armbian_23.11.0-trunk_Nanopineo3_bookworm_current_6.1.56_minimal.img.xz | pv | dd of=/dev/mmcblkX bs=1M)

sudo dmesg -w
sudo gparted

----------------------------------------------------------------------------------------------
cd /media/pprz/armbi_root/boot
sudo cp armbian_first_run.txt.template armbian_first_run.txt
sudo vi armbian_first_run.txt
"
FR_net_change_defaults=1

FR_net_ethernet_enabled=1

FR_net_use_static=1
FR_net_static_ip='192.168.3.2'
FR_net_static_mask='255.255.255.0'
FR_net_static_gateway='192.168.3.1'
FR_net_static_dns='8.8.8.8 8.8.4.4' #2 entries max, seperated by a space.
"

----------------------------------------------------------------------------------------------
rm /home/pprz/.ssh/known_hosts
ssh root@192.168.3.2
1234

create user pprz

----------------------------------------------------------------------------------------------
wlp1s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.19  netmask 255.255.255.0  broadcast 192.168.1.255

ip route
default via 192.168.1.1 dev wlp1s0 proto dhcp metric 600

connect with IPV4 address 192.168.3.1, netmask 255.255.255.0, gateway 192.168.3.1

ip route
default via 192.168.3.1 dev eno1 proto static metric 100
default via 192.168.1.1 dev wlp1s0 proto dhcp metric 600

sudo iptables -t nat -A POSTROUTING -o wlp1s0 -j MASQUERADE
sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i eno1 -o wlp1s0 -j ACCEPT
sudo sysctl net.ipv4.ip_forward=1
sudo route del default

ip route
default via 192.168.1.1 dev wlp1s0 proto dhcp metric 600 

----------------------------------------------------------------------------------------------
ssh pprz@192.168.3.2
pprz

uname -a
=> Linux nanopineo3 6.1.56-current-rockchip64 #1 SMP PREEMPT Fri Oct  6 12:57:07 UTC 2023 aarch64 GNU/Linux

sudo apt-get update

sudo apt-get install vim git 

----------------------------------------------------------------------------------------------
mkdir Projects
cd Projects
git clone --recurse-submodules  http://github.com/enacuavlab/vto-wifiraw-dev.git

cd vto-wifiraw-dev
./install.sh

----------------------------------------------------------------------------------------------
docker images
docker rmi
