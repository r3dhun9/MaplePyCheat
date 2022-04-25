import struct

def p32(n):
    return struct.pack("<I", n)

def u32(s):
    return struct.unpack("<I", s)[0]

def p16(n):
    return struct.pack("<H", n)

def u16(s):
    return struct.unpack("<H", s)[0]

def p8(n):
    return struct.pack("<B", n)

def u8(s):
    return struct.unpack("<B", s)[0]

def replacePacket(dst, src, frm, to):
    dst_chr = [x for x in dst]
    i = frm
    j = 0
    while i < to:
        dst_chr[i] = src[j]
        i += 1
        j += 1
    dst = ''.join(dst_chr)
    return dst

def str2bytearray(s):
    tmp = [ord(x) for x in s]
    return bytearray(tuple(tmp))