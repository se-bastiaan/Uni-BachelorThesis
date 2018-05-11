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


class Dot11TDLSAction(Packet):
    name = "802.11 TDLS Action Frame"
    fields_desc=[ 
        ByteField("payload type", 2),
        ByteField("category code", 12),
        ByteEnumField("action", 1, { 0: "setup request", 1: "setup response" , 2: "setup confirm", 3: "teardown", 10: "discovery request" } ),
        ByteField("dialog token", 1),
    ]

class Dot11Cap(Packet):
    """ Our own definition for the supported rates field """
    name = "802.11 Capabilities Information Element"
    fields_desc = [
        BitField("ess", 1, 1),
        BitField("ibss", 1, 1),
        BitField("cfp", 1, 1),
        BitField("cfpr", 1, 1),
        BitField("privacy", 1, 1),
        BitField("shortpreamble", 1, 1),
        BitField("ibss", 1, 1),
        BitField("ess", 1, 1),
        BitField("spectrum", 1, 1),
        BitField("qos", 1, 1),
        BitField("sst", 1, 1),
        BitField("apsd", 1, 1),
        BitField("rm", 1, 1),
        BitField("reserved3", 1, 1),
        BitField("dba", 1, 1),
        BitField("iba", 1, 1),
    ]

class Dot11EltRates(Packet):
    """ Our own definition for the supported rates field """
    name = "802.11 Rates Information Element"
    # We support all the rates
    supported_rates = [0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]
    fields_desc = [ByteField("ID", 1), ByteField("len", len(supported_rates))]
    for index, rate in enumerate(supported_rates):
        fields_desc.append(ByteField("supported_rate{0}".format(index + 1),
                                     rate))

def main():
    packet = (Dot11TDLSAction(action=0) /
        Dot11Cap())

    print(packet)

    sendp(Ether(src='02:00:00:00:00:00', dst='02:00:00:00:01:00', type=0x890d) / 
        Dot11TDLSAction(action=0) /
        Dot11Cap(),
        iface='wlan0', verbose=True )


if  __name__ =='__main__':main()
