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
from test_ap_vht import vht_supported


def init_stas():
    stdout_handler = logging.StreamHandler()
    stdout_handler.setLevel(logging.DEBUG)
    logger.addHandler(stdout_handler)

    dev0 = WpaSupplicant('wlan0', '/tmp/wpas-wlan0')
    dev1 = WpaSupplicant('wlan1', '/tmp/wpas-wlan1')
    dev2 = WpaSupplicant('wlan2', '/tmp/wpas-wlan2')
    dev = [ dev0, dev1, dev2 ]
    apdev = [ ]
    apdev.append({"ifname": 'wlan3', "bssid": "02:00:00:00:03:00"})
    apdev.append({"ifname": 'wlan4', "bssid": "02:00:00:00:04:00"})

    for d in dev:
        if not d.ping():
            logger.info(d.ifname + ": No response from wpa_supplicant")
            return
        logger.info("DEV: " + d.ifname + ": " + d.p2p_dev_addr())
    for ap in apdev:
        logger.info("APDEV: " + ap['ifname'])

    hapd = hostapd.add_ap(apdev[0], { "ssid": "test-open" })
    Wlantest.setup(hapd)
    wt = Wlantest()
    wt.wlantest_cli = '../hostap/wlantest/wlantest_cli'
    wt.flush()
    wt.add_passphrase("12345678")
    wt.add_wepkey("68656c6c6f")

    dev[0].connect("test-open", key_mgmt="NONE", scan_freq="2412")
    dev[1].connect("test-open", key_mgmt="NONE", scan_freq="2412")

def main():
    subprocess.call('bash ../hostap/tests/hwsim/start.sh', shell=True)
    subprocess.call('service NetworkManager stop', shell=True)

    init_stas()

if  __name__ =='__main__':main()
