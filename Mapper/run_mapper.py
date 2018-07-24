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

global waiting

def create_sniff_action(client):
    def sniff_action(packet):
        if Dot11TDLSAction in packet and waiting:
            client.sendall(str(packet) + "\n")
            # if packet[Dot11TDLSAction].action == 1:
            #     confirm_packet = create_tdls_setup_confirm(gdcs=4, responsePacket=packet)
            #     sendp(confirm_packet, iface='wlan1')
            # elif packet[Dot11TDLSAction].action == 2:
            #     teardown_packet = create_tdls_teardown()
            #     sendp(teardown_packet, iface='wlan1')
    return sniff_action

# def start_sniffer(client):
#     sniff(prn=create_sniff_action(client), iface='wlan3')

def start_timeout(client):
    time.sleep(3000)
    if waiting:
        waiting = False
        client.sendall("\n")

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", 8888))
    s.listen(1)

    (client, address) = s.accept()

    # sniffer = Thread(target=start_sniffer, args=(client,))
    # sniffer.daemon = True
    # sniffer.start()

    while True:
        cmd = client.recv(1024).strip()
        print("Received cmd: {}".format(cmd))

        waiting = True

        if cmd == "SETUP_RESPONSE":
            sendp(create_tdls_setup_response(gdcs=4), iface='wlan1', verbose=True)
        elif cmd == "SETUP_CONFIRM":
            sendp(create_tdls_setup_confirm(gdcs=4), iface='wlan1', verbose=True)
        elif cmd == "SETUP_REQUEST":
            sendp(create_tdls_setup_request(gdcs=4), iface='wlan1', verbose=True)
        elif cmd == "TEARDOWN":
            sendp(create_tdls_teardown(), iface='wlan1', verbose=True)
        elif cmd == "RESET":
            pass

        packets = sniff(iface='wlan3', timeout=5, lfilter = lambda x: Dot11TDLSAction in x)
        if len(packets) > 0:
            print("Packets: {}".format(str(packets[0].action)))
            client.sendall("{}\n".format(str(packets[0].action)))
            print("Sending to learner: `{}`".format(str(packets[0].action)))
        else:
            client.sendall("NO_RESPONSE\n")
            print("Sending to learner: `NO_RESPONSE`")

    # while True:
    #     sniffer.join(600)
    #     if not sniffer.isAlive():
    #         break

if  __name__ =='__main__':main()