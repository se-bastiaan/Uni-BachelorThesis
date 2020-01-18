import struct
import hashlib
import hmac
import binascii
from radiotap import radiotap_parse

mask = 0xFFFFFFFFFFFFFFFF

def bit256_to_hex(v):
    return struct.pack('<QQQQ', v&mask, (v>>64)&mask, (v>>128)&mask, (v>>192)&mask)

def hex_to_bit256(hex):
    value = struct.unpack('<QQQQ', hex)
    return value[0] + (value[1] << 64) + (value[2] << 128) + (value[3] << 192)

def bit128_to_hex(v):
    return struct.pack('<QQ', v&mask, (v>>64)&mask)

def hex_to_bit128(hex, big_endian=False):
    value = struct.unpack('<QQ', hex)
    return value[0] + (value[1] << 64)

def KDFSHA256(key, label, context):
    counter = 1
    buffer = ''

    print("KDF Label: {}".format(label))
    print("KDF Context: {}".format(binascii.hexlify(context)))

    pos = 0
    while pos < ((256 + 7) / 8):
    	print("HMAC Input: {}".format(binascii.hexlify(struct.pack('<H', counter) + label + context + struct.pack('<H', 256))))
    	tmp = hmac.new(key, struct.pack('<H', counter) + label + context + struct.pack('<H', 256), hashlib.sha256)
    	buffer = buffer + tmp.digest()
    	pos += 32
    	counter += 1
    print("KDF Counter: {}".format(counter))

    return buffer[:32]

def setBit( value , index ):
    """ Set the index'th bit of value to 1.
    """
    mask = 1 << index
    value &= ~mask
    value |= mask
    return value

def getBit( value , index ):
    """ Get the index'th bit of value.
    """
    return (value >> index) & 1

def hasFCS( packet ):
    """ Check if the Frame Check Sequence (FCS) flag is set in the Radiotap header.
    """
    assert( packet.haslayer( RadioTap ) ), \
        'The packet does not have a Radiotap header.'
    _ , radiotap    = radiotap_parse( str(packet) )
    radiotapFCSFlag = False
    if getBit( radiotap['flags'] , 4 ) == 1:
        radiotapFCSFlag = True
    return radiotapFCSFlag
    
def assertDot11FCS( packet , expectedFCS = None ):
    """ Validates the Frame Check Sequence (FCS) over a Dot11 layer. It is possible to 
        pass an expected FCS; this is necessary when there is no padding layer available,
        usually in the case of encrypted packets.
    """
    if expectedFCS is None:
        fcsDot11    = str(packet.getlayer( Padding ))
    else:
        fcsDot11    = '{0:0{1}x}'.format( expectedFCS , 8 ) # Padding for leading zero.
        fcsDot11    = fcsDot11.decode('hex')
    dataDot11       = str(packet.getlayer(Dot11))[:-4]
    # Calculate the ICV over the Dot11 data, parse it from signed to unsigned, and
    # change the endianness.
    fcsDot11Calculated  = struct.pack( '<L' , crc32( dataDot11 ) % (1<<32) )
    
    # Assert that we have received a valid FCS by comparing the ICV's.
    assert( fcsDot11 == fcsDot11Calculated ), \
        'The received FCS "0x%s" does not match the calculated FCS "0x%s".' \
        % ( fcsDot11.encode('hex') , fcsDot11Calculated.encode('hex') )