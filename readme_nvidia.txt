4.9.253-tegra (xavier nx)
-------------------------

sudo iwlist wlan0 scan
sudo wpa_passphrase "Androidxp" "pprzpprz" | sudo tee ./wpa_supplicant.conf
sudo systemctl stop wpa_supplicant.service
sudo wpa_supplicant -B -c ./wpa_supplicant.conf -i wlan0
sudo dhclient wlan0

sudo ip route replace default via 192.168.1.1 dev wlan0

------------------------------------------------------------------
cd /lib/modules/4.9.253-tegra/kernel/drivers/net/wireless/realtek/rtl8812au
mv rtl8812au.ko rtl8812au.ko.ref

git clone https://github.com/morrownr/8812au-20210629.git
cd 8812au-20210629
make
sudo make install
(/lib/modules/4.9.253-tegra/kernel/drivers/net/wireless/)

------------------------------------------------------------------
sudo make dkms_install
cp -r * /usr/src/8812au-5.6.4.2_35491.20191025
dkms add -m 8812au -v 5.6.4.2_35491.20191025

Creating symlink /var/lib/dkms/8812au/5.6.4.2_35491.20191025/source ->
                 /usr/src/8812au-5.6.4.2_35491.20191025

DKMS: add completed.
dkms build -m 8812au -v 5.6.4.2_35491.20191025

Kernel preparation unnecessary for this kernel.  Skipping...

Building module:
cleaning build area...
'make' -j4 KVER=4.9.253-tegra KSRC=/lib/modules/4.9.253-tegra/build.....................(bad exit status: 2)
ERROR (dkms apport): binary package for 8812au: 5.6.4.2_35491.20191025 not found
Error! Bad return status for module build on kernel: 4.9.253-tegra (aarch64)
Consult /var/lib/dkms/8812au/5.6.4.2_35491.20191025/build/make.log for more information.
Makefile:1781: recipe for target 'dkms_install' failed
make: *** [dkms_install] Error 10

------------------------------------------------------------------
...

  CC [M]  /home/pprz/Projects/vto-wifiraw-dev/rtl8812au/os_dep/linux/ioctl_cfg80211.o
/home/pprz/Projects/vto-wifiraw-dev/rtl8812au/os_dep/linux/ioctl_cfg80211.c: In function ‘rtw_cfg80211_indicate_connect’:
/home/pprz/Projects/vto-wifiraw-dev/rtl8812au/os_dep/linux/ioctl_cfg80211.c:1201:68: error: ‘NL80211_TIMEOUT_UNSPECIFIED’ undeclared (first use in this function); did you mean ‘NL80211_IFTYPE_UNSPECIFIED’?
                                 , WLAN_STATUS_SUCCESS, GFP_ATOMIC, NL80211_TIMEOUT_UNSPECIFIED);
                                                                    ^~~~~~~~~~~~~~~~~~~~~~~~~~~
                                                                    NL80211_IFTYPE_UNSPECIFIED
/
