from Crypto.Cipher import AES
from MapleAES.Morph import *
from MapleAES.Simpleaes import *

key = [
    0x13, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00,
    0xB4, 0x00, 0x00, 0x00,
    0x1B, 0x00, 0x00, 0x00,
    0x0F, 0x00, 0x00, 0x00,
    0x33, 0x00, 0x00, 0x00,
    0x52, 0x00, 0x00, 0x00
]

class MapleAES():

    def __init__(self, iv, version):
        self.iv = iv
        self.version = version
        self.aes = new(key, 1)
    
    def transformBlock(self, iv):
        return self.aes.encrypt(iv)

    def decrypt(self, c):
        rtn = self.encrypt(c)
        self.iv = shiftIv(self.iv)
        return rtn

    def encrypt(self, c):
        fresh_iv_block = self.iv * 4
        data_len = len(c)
        start_block_size = 1456
        if(data_len > 0xff00):
            start_block_size -= 4
        block_size = 0
        start = 0
        rtn = [''] * len(c)
        while start < data_len:
            if start == 0:
                block_size = start_block_size
            else:
                block_size = 1460
            block_size = min(block_size, data_len - start)
            current_iv_block = list(fresh_iv_block)
            for i in range(block_size):
                if i % 16 == 0:
                    current_iv_block = list(self.transformBlock(current_iv_block))
                rtn[start + i] = chr(c[start+i] ^ (current_iv_block[i % 16]))
            start += block_size
        return ''.join(rtn)

    def makePacket(self, data):
        v = self.version
        header = [(v ^ (self.iv[2])) & 0xff, ((v>>8) ^ (self.iv[3])) & 0xff, 0, 0]
        rest = len(data) ^ (header[1] << 8 | header[0])
        header[2] = rest & 0xff
        header[3] = (rest & 0xff00) >> 8
        cipher = self.encrypt(data)
        self.iv = shiftIv(self.iv)
        return ''.join(map(chr, header)) + cipher

    def shiftIv(self):
        self.iv = shiftIv(self.iv)
        return

    def getIv(self):
        return self.iv