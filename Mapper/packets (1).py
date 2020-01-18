from scapy.all import *
import binascii
from util import *

class Dot11TDLSAction(Packet):
    name = "802.11 TDLS Action Frame"
    fields_desc=[ 
        ByteField("payload_type", 2),
        ByteField("category_code", 12),
        ByteEnumField("action", 1, { 0: "setup request", 1: "setup response" , 2: "setup confirm", 3: "teardown", 10: "discovery request" } ),
        ConditionalField(ShortField("status_code", 0), lambda pkt:pkt.action>=1 and pkt.action<=3),
        ConditionalField(ByteField("dialog_token", 1), lambda pkt:pkt.action!=3),
    ]

class Dot11Cap(Packet):
    """ Our own definition for the supported rates field """
    name = "802.11 Capabilities Information Element"
    fields_desc = [
        BitField("channelAgility", 0, 1),
        BitField("pbcc", 0, 1),
        BitField("short_preamble", 1, 1),
        BitField("privacy", 0, 1),
        BitField("cfPollRequest", 0, 1),
        BitField("cfPollable", 0, 1),
        BitField("ibss", 0, 1),
        BitField("ess", 0, 1),
        BitField("iba", 0, 1),
        BitField("dba", 0, 1),
        BitField("dsss_ofdm", 0, 1),
        BitField("rm", 0, 1),
        BitField("apsd", 0, 1),
        BitField("sst", 1, 1),
        BitField("cfpReserved", 0, 1),
        BitField("spectrum", 0, 1),
    ]

class Dot11EltRates(Packet):
    """ Our own definition for the supported rates field """
    name = "802.11 Rates Information Element"
    # We support all the rates
    supported_rates = [0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18]
    fields_desc = [ByteField("ID", 1), ByteField("len", len(supported_rates))]
    for index, rate in enumerate(supported_rates):
        fields_desc.append(ByteField("supported_rate{0}".format(index + 1),
                                     rate))

class Dot11EltExtRates(Packet):
    """ Our own definition for the supported rates field """
    name = "802.11 Extended Rates Information Element"
    # We support all the rates
    supported_rates = [0x24, 0x30, 0x48, 0x60, 0x6c]
    fields_desc = [ByteField("ID", 50), ByteField("len", len(supported_rates))]
    for index, rate in enumerate(supported_rates):
        fields_desc.append(ByteField("extended_supported_rate{0}".format(index + 1),
                                     rate))

class Dot11EltChannels(Packet):
    name = "802.11 Channels Information Element"
    fields_desc = [
    	ByteField("ID", 36),
    	ByteField("len", 2),
    	ByteField("channel", 1),
    	ByteField("range", 11),
    ]

class Dot11EltLinkIdentifier(Packet):
    name = "802.11 Link Identifier Element"
    fields_desc = [
        ByteField("ID", 101),
        ByteField("len", 18),
        Dot11AddrMACField("bssid", ETHER_ANY),
        Dot11AddrMACField("initSta", ETHER_ANY),
        Dot11AddrMACField("respSta", ETHER_ANY)
    ]

class Dot11EltCustom(Packet):
    name = "802.11 Information Element"
    fields_desc = [ ByteField("ID", 0),
                    FieldLenField("len", None, "info", "B"),
                    StrLenField("info", "", length_from=lambda x:x.len) ]

bind_layers( Ether, Dot11TDLSAction, {'type':0x890d} )
bind_layers( Dot11TDLSAction, Dot11Cap )
bind_layers( Dot11Cap, Dot11EltCustom )
bind_layers( Dot11EltCustom, Dot11EltCustom )

def create_rsn(gdcsType=4, cipherSuites=[4], akmSuites=[7]):
    info = '\x01\x00' #RSN Version 1
    info += '\x00\x0f\xac' + chr(7) #Group Cipher Suite : 00-0f-ac TKIP
    info += chr(len(cipherSuites)) + '\x00' #2 Pairwise Cipher Suites (next two lines)
    for suite in cipherSuites:
        info += '\x00\x0f\xac' + chr(suite)
    info += chr(len(akmSuites)) + '\x00' #1 Authentication Key Managment Suite (line below)
    for suite in akmSuites:
        info += '\x00\x0f\xac' + chr(suite)
    info += '\x0c\x02'

    return Dot11Elt(ID='RSNinfo', info=info) #RSN Capabilities (no extra capabilities)


def create_fte(SNonce=None, ANonce=None, mic=None):
    info = '\x00\x00' # MIC Control and element count
    info += bit128_to_hex(0) if mic is None else mic

    if SNonce is None:
        ANonce = bit256_to_hex(0)
    elif ANonce is None:
        ANonce = bit256_to_hex(random.randint(0, 2**256 - 1))
    info += ANonce

    if SNonce is None:
        SNonce = bit256_to_hex(random.randint(0, 2**256 - 1))
    info += SNonce

    return Dot11EltCustom(ID=55, info=info)

def create_ti(interval):
    info = '\x02'
    info += struct.pack('L', interval)
    return Dot11EltCustom(ID=56, info=info)



