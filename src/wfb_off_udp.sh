#!/bin/bash

pidfile=/tmp/wfb_udp.pid
kill `cat $pidfile` > /dev/null 2>&1 
rm $pidfile > /dev/null 2>&1 
