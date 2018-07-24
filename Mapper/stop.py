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
from test_ap_vht import vht_supported

def main():
    subprocess.call('bash stop.sh', shell=True, cwd="../hostap/tests/hwsim/")
    subprocess.call('service NetworkManager start', shell=True)

if  __name__ =='__main__':main()