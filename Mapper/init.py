#!/usr/bin/env python2.7
from scapy.all import *

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
    sendp(Ether(src='d2:3f:6e:51:81:a0', dst='8e:ff:a4:2f:63:bb', type=0x890d) / 
        Dot11TDLSAction(action=0) /
        Dot11Cap(),
        iface='wlan0', verbose=True )

    # print('Sending TDLS Setup Request')
    # sendp(Ether(src='d2:3f:6e:51:81:a0', dst='8e:ff:a4:2f:63:bb', type=0x890d) / 
    #     Raw(load='\x02\x0c\x00\x01 \x04\x01\x08\x02\x04\x0b\x16\x0c\x12\x18$2\x040H`l$\x02\x01\x0b\x7f\x08\x00\x00\x00\x00 \x00\x00\x00\xdd\x07\x00P\xf2\x02\x00\x01\x00;\x02QQ-\x1a~\x10\x1b\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00H\x01\x01e\x12\x1e\xc3jcs\xa6\x8e\xff\xa4/c\xbb\xd2?nQ\x81\xa0'), 
    #     iface='wlan0', verbose=True )

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

    netSSID = 'testSSID'       #Network name here
    iface = 'wlan0'         #Interface name here


if  __name__ =='__main__':main()