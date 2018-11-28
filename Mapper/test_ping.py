#!/usr/bin/env python2.7

from threading import Thread

import socket

from scapy.all import *
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

def main():
    sendp(create_ping_message(response=False), iface='wlan1', verbose=True)

if  __name__ =='__main__':main()