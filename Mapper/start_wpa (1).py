#!/usr/bin/env python2.7

from scapy.all import *
import time
import logging
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


def init_stas():
    stdout_handler = logging.StreamHandler()
    stdout_handler.setLevel(logging.DEBUG)
    logger.addHandler(stdout_handler)    

    dev0 = WpaSupplicant('wlan0', '/tmp/wpas-wlan0')
    dev1 = WpaSupplicant('wlan1', '/tmp/wpas-wlan1')
    dev2 = WpaSupplicant('wlan2', '/tmp/wpas-wlan2')
    dev = [ dev0, dev1, dev2 ]

    for d in dev:
        if not d.ping():
            logger.info(d.ifname + ": No response from wpa_supplicant")
            return
        logger.info("DEV: " + d.ifname + ": " + d.p2p_dev_addr())

    params = hostapd.wpa2_params(ssid="test-wpa2-psk", passphrase="12345678")
    hapd = hostapd.add_ap({"ifname": 'wlan3', "bssid": "02:00:00:00:03:00"}, params)

    Wlantest.setup(hapd)
    wt = Wlantest()
    wt.wlantest_cli = '../hostap/wlantest/wlantest_cli'
    wt.flush()
    wt.add_passphrase("12345678")
    wt.add_wepkey("68656c6c6f")

    dev[0].connect("test-wpa2-psk", psk="12345678", scan_freq="2412")
    dev[1].connect("test-wpa2-psk", psk="12345678", scan_freq="2412")

def main():
    subprocess.call('service NetworkManager stop', shell=True)
    subprocess.call('bash start.sh', shell=True, cwd="../hostap/tests/hwsim/")

    init_stas()

if  __name__ =='__main__':main()
