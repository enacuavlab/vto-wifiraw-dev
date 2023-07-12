4.9.253-tegra (xavier nx)
-------------------------

sudo iwlist wlan0 scan
sudo wpa_passphrase "Androidxp" "pprzpprz" | sudo tee ./wpa_supplicant.conf
sudo systemctl stop wpa_supplicant.service
sudo wpa_supplicant -B -c ./wpa_supplicant.conf -i wlan0
sudo dhclient wlan0

sudo ip route replace default via 192.168.1.1 dev wlan0

------------------------------------------------------------------
cd rtl8812au
checkout v5.6.4.2

------------------------------------------------------------------

/etc/NetworkManager/system-connections/...

[ipv4]
address1=192.168.2.2/24,192.168.2.1
dns=8.8.8.8;
dns-search=
method=manual
