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

from packets import *

counter = 0

def custom_action(packet):
    packet.show2()
    # action = Dot11TDLSAction(packet[1].load)
    # capabilities = Dot11Cap(action[1].load)
    # elements = []
    # elts = capabilities[1].load
    # while len(elts) > 0:
    #     element = Dot11Elt(elts)
    #     import pdb
    #     pdb.set_trace()
    #     elements.append(element)
    #     print(element[1])
    #     elts = element[1].load
    # import pdb
    # pdb.set_trace()
    # hexdump(packet[0][1].load)

def main():
    sniff(prn=custom_action, iface='wlan0')

    # print('Sending TDLS Setup Response')
    # sendp(Ether(src='d2:3f:6e:51:81:a0', dst='8e:ff:a4:2f:63:bb', type=0x890d) / 
    #     Raw(load='\x02\x0c\x01\x00\x00\x01 \x04\x01\x08\x02\x04\x0b\x16\x0c\x12\x18$2\x040H`l$\x02\x01\x0b\x7f\x08\x00\x00\x00\x00 \x00\x00\x00\xdd\x07\x00P\xf2\x02\x00\x01\x00;\x02QQ-\x1a~\x10\x1b\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00H\x01\x01e\x12\x1e\xc3jcs\xa6\xd2?nQ\x81\xa0\x8e\xff\xa4/c\xbb'), 
    #     iface='wlan0', verbose=True )

    # print('Sending TDLS Setup Confirm')
    # sendp(Ether(src='d2:3f:6e:51:81:a0', dst='8e:ff:a4:2f:63:bb', type=0x890d) / 
    #     Raw(load="\x02\x0c\x02\x00\x00\x01\xdd\x18\x00P\xf2\x02\x01\x01\x00\x00\x03\xa4\x00\x00'\xa4\x00\x00BC^\x00b2/\x00e\x12\x1e\xc3jcs\xa6\x8e\xff\xa4/c\xbb\xd2?nQ\x81\xa0"), 
    #     iface='wlan0', verbose=True )

    # print('Sending TDLS Teardown')
    # sendp(Ether(src='d2:3f:6e:51:81:a0', dst='8e:ff:a4:2f:63:bb', type=0x890d) / 
    #     Raw(load="\x02\x0c\x03\x03\x00e\x12\x1e\xc3jcs\xa6\x8e\xff\xa4/c\xbb\xd2?nQ\x81\xa0"), 
    #     iface='wlan0', verbose=True )


if  __name__ =='__main__':main()
