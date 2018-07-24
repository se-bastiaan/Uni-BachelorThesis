import hmac
import struct
from util import *

def KDFHashLength(key, label, context, length):
    blen = 32
    i    = 0
    R    = ''
    while i <= ((blen*8+255)/256):
        hmacsha1 = hmac.new(key, chr(i) + label + context + 256, sha256)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]