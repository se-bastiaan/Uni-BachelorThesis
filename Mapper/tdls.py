from scapy.all import *
from packets import *
from util import *
import binascii
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

def _read_fte_values(info):
    mic_control = info[0:2]
    ANonce = info[18:50]
    SNonce = info[50:82]

    return ANonce, SNonce

def _read_link_id_values(info):
    BSSID = info[0:6]
    InitiatorMAC = info[6:12]
    ResponderMAC = info[12:18]

    return BSSID, InitiatorMAC, ResponderMAC

def read_tdls_setup_packet(packet):
    # TODO: Read ANonce
    elts = packet[Dot11EltCustom]
    index = 0
    
    ANonce = None
    SNonce = None
    BSSID = None
    InitiatorMAC = None
    ResponderMAC = None

    while index > -1:
        try:
            elt_info = elts[index].info
            if elts[index].ID == 55:
                ANonce, SNonce = _read_fte_values(elt_info)
            if elts[index].ID == 101:
                BSSID, InitiatorMAC, ResponderMAC = _read_link_id_values(elt_info)
            index += 1
        except IndexError:
            index = -1

    return ANonce, SNonce, BSSID, InitiatorMAC, ResponderMAC

def create_tdls_discovery(bssid="02:00:00:00:03:00",
    initSta="02:00:00:00:01:00", respSta="02:00:00:00:00:00"):
    return (Ether(src=initSta, dst=respSta, type=0x890d) / Dot11TDLSAction(action=10) /
       Dot11EltLinkIdentifier(bssid=bssid, initSta=initSta, respSta=respSta))
        
def create_tdls_setup_request(bssid="02:00:00:00:03:00",
    initSta="02:00:00:00:01:00", respSta="02:00:00:00:00:00",
    gdcs=None):

    packet = (Ether(src=initSta, dst=respSta, type=0x890d) / 
    		Dot11TDLSAction(action=0) /
            Dot11Cap() / 
            Dot11EltRates() / 
            Dot11EltExtRates() / 
            Raw(load='\x7f\x08\x00\x00\x00\x00\x20\x00\x00\x00') /
            Dot11EltChannels(channel=2, range=12) /
            Dot11EltLinkIdentifier(bssid=bssid, initSta=initSta, respSta=respSta))
  
    if gdcs:
        packet /= create_rsn(gdcsType=gdcs)
        packet /= create_fte()
        packet /= create_ti(interval=43200)

    return packet

def read_tdls_setup_request():
    pass

def create_tdls_setup_response(bssid="02:00:00:00:03:00",
    initSta="02:00:00:00:01:00", respSta="02:00:00:00:00:00",
    gdcs=None, success=True, requestPacket=None):
    status = 0 if success else 1
    packet = Ether(src=initSta, dst=respSta, type=0x890d) / Dot11TDLSAction(action=1, status_code=status)
    if success:
        packet /= Dot11Cap()
        packet /= Dot11EltRates()
        packet /= Dot11EltExtRates()
        packet /= Dot11EltChannels(channel=2, range=12)

        LinkIdEl = Dot11EltLinkIdentifier(bssid=bssid, initSta=initSta, respSta=respSta)
        packet /= LinkIdEl

        if gdcs and requestPacket:
            RSNEEl = create_rsn(gdcsType=gdcs)
            ANonce, SNonce, BSSID, InitiatorMAC, ResponderMAC = read_tdls_setup_packet(requestPacket)

            print('ANonce: {}\nSNonce: {}'.format(binascii.hexlify(ANonce), binascii.hexlify(SNonce)))

            tpk = calculate_tpk(ANonce, SNonce, BSSID, InitiatorMAC, ResponderMAC)
            FTEl = create_fte(SNonce=SNonce, ANonce=ANonce, mic=None)
            TimeoutEl = create_ti(interval=43200)
            mic = calculate_mic(tpk, InitiatorMAC, ResponderMAC, 3, LinkIdEl, RSNEEl, TimeoutEl, FTEl)
            packet /= RSNEEl
            packet /= create_fte(SNonce=SNonce, ANonce=ANonce, mic=mic)
            packet /= TimeoutEl
    return packet

def calculate_tpk(ANonce, SNonce, BSSID, InitiatorMAC, ResponderMAC):
    # TPK-Key-Input = SHA-256(min(SNonce, ANonce) || max(SNonce, ANonce))
    tpkKeyInput = hashlib.sha256(min(ANonce , SNonce) + max(ANonce, SNonce)).digest()
    print("TDLS TPK-Key-Input: {}".format(binascii.hexlify(tpkKeyInput))) #CORRECT!

    # TPK-Key-Data = KDF-N_KEY(TPK-Key-Input, "TDLS PMK", min(MAC_I, MAC_R) || max(MAC_I, MAC_R) || BSSID)
    context = min(InitiatorMAC , ResponderMAC) + max(InitiatorMAC, ResponderMAC) + BSSID
    print("TDLS KDF Context: {}".format(binascii.hexlify(context)))
    # TPK = KDFHashLength(keyInput, "TDLS PMK", context)
    tpk = KDFSHA256(tpkKeyInput, b"TDLS PMK", context)
    tpkkck = tpk[0:16]
    tpktk = tpk[16:]

    print('TDLS TPK-KCK: {}\nTDLS TPK-TK: {}'.format(binascii.hexlify(tpkkck), binascii.hexlify(tpktk)))

    return tpk

def calculate_mic(TPK, InitiatorMAC, ResponderMAC, TransSeqNr, LinkIdEl, RSNEEl, TimeoutEl, FTEl):
    frame = InitiatorMAC + ResponderMAC + struct.pack('<B', TransSeqNr) + str(LinkIdEl) + str(RSNEEl) + str(TimeoutEl) + str(FTEl)
    print("Data for FTIE MIC: {}", binascii.hexlify(frame))
    mic = CMAC.new(TPK[0:16], ciphermod=AES)
    mic.update(frame)
    mic_digest = mic.digest()[0:16]
    print("TDLS MIC: {}".format(binascii.hexlify(mic_digest)))
    return mic_digest

def create_tdls_setup_confirm(bssid="02:00:00:00:03:00",
    initSta="02:00:00:00:01:00", respSta="02:00:00:00:00:00",
    gdcs=None, responsePacket=None):
    status = 0
    packet = Ether(src=initSta, dst=respSta, type=0x890d) / Dot11TDLSAction(action=2, status_code=status)
    LinkIdEl = Dot11EltLinkIdentifier(bssid=bssid, initSta=initSta, respSta=respSta)
    packet /= LinkIdEl

    if gdcs and responsePacket:
        RSNEEl = create_rsn(gdcsType=gdcs)
        ANonce, SNonce, BSSID, InitiatorMAC, ResponderMAC = read_tdls_setup_packet(responsePacket)

        print('ANonce: {}\nSNonce: {}'.format(binascii.hexlify(ANonce), binascii.hexlify(SNonce)))

        tpk = calculate_tpk(ANonce, SNonce, BSSID, InitiatorMAC, ResponderMAC)
        FTEl = create_fte(SNonce=SNonce, ANonce=ANonce, mic=None)
        TimeoutEl = create_ti(interval=43200)
        mic = calculate_mic(tpk, InitiatorMAC, ResponderMAC, 3, LinkIdEl, RSNEEl, TimeoutEl, FTEl)
        packet /= RSNEEl
        packet /= create_fte(SNonce=SNonce, ANonce=ANonce, mic=mic)
        packet /= TimeoutEl

    return packet

def create_tdls_teardown(bssid="02:00:00:00:03:00",
    initSta="02:00:00:00:01:00", respSta="02:00:00:00:00:00"):
    return Ether(src=initSta, dst=respSta, type=0x890d)  / Dot11TDLSAction(action=3) / Dot11EltLinkIdentifier(bssid=bssid, initSta=initSta, respSta=respSta)