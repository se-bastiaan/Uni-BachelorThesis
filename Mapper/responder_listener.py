#!/usr/bin/env python2.7

from threading import Thread

import socket

from scapy.all import *
from packets import *
from util import *
import time
import logging
import time
logger = logging.getLogger()
import subprocess

import sys
sys.path.insert(0, "../hostap/tests/hwsim")
sys.path.insert(0, "../hostap/wpaspy")

from wpasupplicant import WpaSupplicant
import hwsim_utils
from hostapd import HostapdGlobal
from hostapd import Hostapd
import hostapd
from utils import HwsimSkip, skip_with_fips
from wlantest import Wlantest
from test_ap_vht import vht_supported

from packets import *
from tdls import *

def pkt_callback(pkt):
    pkt.show() # debug statement
    try:
        if pkt[Ether].src == "20:00:00:00:01:00" and pkt[Ether].dst == "20:00:00:00:00:00" and str(pkt[1]) == "HELLO_RESP":
            msg = create_ping_message(response=True)
            msg.show()
            sendp(msg, iface='wlan0', verbose=False)
    except IndexError:
        pass

def main():
    sniff(iface="wlan0", prn=pkt_callback, lfilter=lambda pkt: pkt.haslayer(Ether) and pkt[Ether].src == "20:00:00:00:01:00" and pkt[Ether].dst == "20:00:00:00:00:00" and pkt[Ether].type == 0x890d)
    verbose = False

if  __name__ =='__main__':main()