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

from packets import *
from tdls import *

def main():
    verbose = False

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 8888))
    s.listen(1)

    (client, address) = s.accept()

    # sniffer = Thread(target=start_sniffer, args=(client,))
    # sniffer.daemon = True
    # sniffer.start()

    setup_response_packet = None
    tpk = None
    connected = False

    bssid, addr0, addr1 = "20:00:00:00:03:00", "20:00:00:00:01:00", "20:00:00:00:00:00"

    while True:
        cmd = client.recv(1024).strip()
        print("Received command: {}".format(cmd))

        timeout_response = "NO_RESPONSE"

        if cmd == "SETUP_CONFIRM":
            # timeout_response = "SETUP_CONFIRM_WITHOUT_RESPONSE_TIMEOUT"
            if setup_response_packet:
                connected = True
                # timeout_response = "SETUP_CONFIRM_WITH_RESPONSE_TIMEOUT"
            # setup_response_packet = Nonecv
            sendp(create_tdls_setup_confirm(gdcs=4, responsePacket=setup_response_packet), iface='wlan1', verbose=verbose)
        elif cmd == "SETUP_REQUEST":
            connected = False
            # timeout_response = "SETUP_REQUEST_TIMEOUT"
            sendp(create_tdls_setup_request(gdcs=4), iface='wlan1', verbose=verbose)
            setup_response_packet = None
        elif cmd == "TEARDOWN":
            connected = False
            # timeout_response = "TEARDOWN_TIMEOUT"
            sendp(create_tdls_teardown(), iface='wlan1', verbose=verbose)
            setup_response_packet = None
        elif cmd == "RESET":
            connected = False
            tpk = None
            setup_response_packet = None
            client.sendall("{}\n".format("NO_RESPONSE"))
            continue
        elif cmd == "CONNECTED":
            timeout_response = "CONNECTED" if connected else "NOT_CONNECTED"

        response_msg = timeout_response
        if not cmd == "CONNECTED":
            packets = sniff(iface='wlan1', timeout=1, lfilter = lambda x: Dot11TDLSAction in x)

            if len(packets) > 0:
                if packets[0].action == 2:
                    response_msg = "SETUP_CONFIRM"
                elif packets[0].action == 1:
                    setup_response_packet = packets[0]
                    response_msg = "SETUP_RESPONSE"
                elif packets[0].action == 3:
                    response_msg = "TEARDOWN"
                else:
                    response_msg = "action: {}".format(packets[0].action)
        
        client.sendall("{}\n".format(response_msg))
        print("Sending to learner: `{}`".format(response_msg))

    # while True:
    #     sniffer.join(600)
    #     if not sniffer.isAlive():
    #         break

if  __name__ =='__main__':main()