#!/bin/bash

#socat -b1400 udp-listen:5600,reuseaddr,fork udp-sendto:192.168.2.1:5600
socat udp-listen:4244,reuseaddr,fork udp-sendto:192.168.2.1:4244

