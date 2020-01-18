#!/usr/bin/env python2.7

from multiprocessing.pool import ThreadPool

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

def do_sniff():
    return sniff(iface='wlan1', timeout=1, lfilter = lambda x: Dot11TDLSAction in x)

def main():
    verbose = False

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 8888))
    s.listen(1)

    (client, address) = s.accept()

    pool = ThreadPool(processes=1)

    setup_response_packet = None
    tpk = None
    connected = False

    bssid, addr0, addr1 = "20:00:00:00:03:00", "20:00:00:00:01:00", "20:00:00:00:00:00"

    while True:
        cmd = client.recv(1024).strip()
        print("Received command: {}".format(cmd))

        async_sniff = pool.apply_async(do_sniff)

        timeout_response = "NO_RESPONSE"

        if cmd == "SETUP_CONFIRM":
            pkt = setup_response_packet
            if setup_response_packet and setup_response_packet[Dot11TDLSAction].status_code == 0:
                connected = True
            else:
                pkt = None
            sendp(create_tdls_setup_confirm(gdcs=4, responsePacket=pkt), iface='wlan1', verbose=verbose)
            setup_response_packet = None
        elif cmd == "SETUP_REQUEST_OPEN_CORRECT":
            setup_response_packet = None
            connected = False
            sendp(create_tdls_setup_request(gdcs=None), iface='wlan1', verbose=verbose)
        elif cmd == "SETUP_REQUEST_AES_CORRECT":
            setup_response_packet = None
            connected = False
            sendp(create_tdls_setup_request(gdcs=4), iface='wlan1', verbose=verbose)
        elif cmd == "SETUP_REQUEST_OPEN_MALFORMED":
            setup_response_packet = None
            connected = False
            sendp(create_tdls_setup_request(gdcs=None, malformed=True), iface='wlan1', verbose=verbose)
        elif cmd == "SETUP_REQUEST_AES_MALFORMED":
            setup_response_packet = None
            connected = False
            sendp(create_tdls_setup_request(gdcs=4, malformed=True), iface='wlan1', verbose=verbose)
        elif cmd == "TEARDOWN":
            setup_response_packet = None
            connected = False
            sendp(create_tdls_teardown(), iface='wlan1', verbose=verbose)
        elif cmd == "RESET":
            setup_response_packet = None
            connected = False
            tpk = None
            client.sendall("{}\n".format("NO_RESPONSE"))
            continue
        elif cmd == "CONNECTED":
            timeout_response = "CONNECTED" if connected else "NOT_CONNECTED"

        response_msg = timeout_response
        if not cmd == "CONNECTED":
            packets = async_sniff.get()

            if len(packets) > 1:
                packets = packets[1:]
                print('response packet length longer 0')
                if packets[0].action == 2:
                    response_msg = "SETUP_CONFIRM"
                elif packets[0].action == 1:
                    setup_response_packet = packets[0]
                    status = setup_response_packet[Dot11TDLSAction].status_code
                    response_msg = "SETUP_RESPONSE_FAIL_{}".format(status)
                    if status == 0:
                        response_msg = "SETUP_REPONSE_SUCCESS"
                elif packets[0].action == 3:
                    response_msg = "TEARDOWN"
                else:
                    response_msg = "action: {}".format(packets[0].action)
        
        client.sendall("{}\n".format(response_msg))
        print("Sending to learner: `{}`".format(response_msg))


if  __name__ =='__main__':main()