#!/bin/bash
STR="-------------------------------------------------------------------------\n"
STR+="This script will setup the communication system \n"
STR+="It must be run on ground and board sides \n\n"
STR+="The system, will start as soon as the USB dongle is inserted, or while booting \n"
STR+="with an already inserted dongle \n\n"
STR+="From the ground side you can check the communication (according the configuration):\n\n"
STR+="ssh pprz@10.0.1.2 \n\n"
STR+="-------------------------------------------------------------------------\n"
STR+="When using a Virtual machine for the installation, make sure you set \n"
STR+="Virtual Machine Setting / Hardware / USB Controller / USB compatibility USB 3.1 \n\n"
STR+="-------------------------------------------------------------------------\n"
STR+="Do you want to proceed with the installation (Internet and sudo required) " 
echo -e $STR
USER=`basename $PWD`
PROJ=$PWD
read -p "for this side in $PROJ (y/n) ?" ANSWER
if [ ! $ANSWER = "y" ] || [ -z $ANSWER ]; then exit -1; fi
if ! groups | grep -q 'sudo'; then exit -1; fi
sudo apt-get install -y socat git net-tools wireless-tools rfkill v4l-utils
cd $PROJ/rtl8812au
if uname -a | grep -cs "4.9.253-tegra"> /dev/null 2>&1;then git checkout 4ab079f7; fi
git apply ../material/rtl8812au_v5.6.4.2.patch
DKMS=false
if uname -a | grep -cs "Ubuntu"> /dev/null 2>&1;then DKMS=true; fi
if uname -a | grep -cs "4.9.253-tegra"> /dev/null 2>&1;then DKMS=true; fi
if uname -a | grep -cs "rockchip64"> /dev/null 2>&1;then DKMS=true; fi
if uname -a | grep -cs "rock-5b"> /dev/null 2>&1;then DKMS=true; fi
if $DKMS; then
  echo "blacklist rtl8812au" |sudo tee -a /etc/modprobe.d/blacklist.conf > /dev/null 2>&1
  sudo apt-get install -y dkms
  sudo make dkms_install
else 
  if uname -a | grep -cs "aarch64"; then
    # RPI 02 ,3B+ & 4 (with OS 64b)
    sed -i 's/CONFIG_PLATFORM_I386_PC = y/CONFIG_PLATFORM_I386_PC = n/g' Makefile
    sed -i 's/CONFIG_PLATFORM_ARM64_RPI = n/CONFIG_PLATFORM_ARM64_RPI = y/g' Makefile
  else
    #  RPI 0 & 3 & 4 (with OS 32)
    sed -i 's/CONFIG_PLATFORM_I386_PC = y/CONFIG_PLATFORM_I386_PC = n/g' Makefile
    sed -i 's/CONFIG_PLATFORM_ARM_RPI = n/CONFIG_PLATFORM_ARM_RPI = y/g' Makefile
  fi
  if uname -r | grep -cs "5.15.61-v8+"; then
    wget https://archive.raspberrypi.org/debian/pool/main/r/raspberrypi-firmware/raspberrypi-kernel-headers_1.20220830-1_arm64.deb
    sudo apt-get install ./raspberrypi-kernel-headers_1.20220830-1_arm64.deb
  else
    sudo apt-get install linux-headers
  fi
  make
  sudo make install
fi  
if uname -a | grep -cs "Ubuntu"> /dev/null 2>&1; then 
  sudo cp $PROJ/material/wfb.conf /etc/NetworkManager/conf.d
  sudo systemctl reload NetworkManager.service 
fi
sudo cp $PROJ/material/8812au.conf /etc/modprobe.d
sudo cp $PROJ/material/wfb.service /etc/systemd/system
sudo cp $PROJ/material/60-wfb.rules /etc/udev/rules.d
sudo udevadm control --reload-rules
sudo systemctl enable wfb.service
sudo systemctl start wfb.service
