import struct
import hashlib
import hmac
import binascii

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