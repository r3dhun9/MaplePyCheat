from MapleAES.MapleAES import MapleAES
import Packet.ClientPacket
import Packet.ServerPacket
import logging

class MaplePacket:

    def __init__(self, buf, aes):
        self.buf = buf
        self.aes = aes
        self.opcode = None
        self.data = None

    def getPacketLength(self, header):
        if len(header) == 0:
            return 0
        ivBytes = (header[0] | (header[1] << 8))
        xorredSize = (header[2] | (header[3] << 8))
        length = (xorredSize ^ ivBytes)
        logging.info("packet length: " + str(length))
        return length
    
    def decryptPacket(self):
        # decrypt data
        data = None
        header_len = 4
        packet_size = self.getPacketLength(self.buf[:header_len])
        packet = self.buf[header_len:header_len + packet_size]
        if packet_size != 0:
            data = self.aes.decrypt(packet)
        # parse opcode and data
        if data != None and len(data) > 2:
            opcode_len = 2 
            opcode = data[:opcode_len]
            self.opcode = (ord(opcode[1]) & 0xFF) | (ord(opcode[0]) & 0xFF)
            self.data = data[opcode_len:opcode_len + packet_size]
            logging.info('Opcode: {} , data: {}'.format(hex(self.opcode), ' '.join('{:>02s}'.format(hex(ord(x)).lstrip('0x')) for x in self.data)))
        elif data != None and len(data) == 2:
            self.opcode = (ord(data[1]) & 0xFF) | (ord(data[0]) & 0xFF)
            self.data = None
            logging.info('Opcode: {} , data: {}'.format(hex(self.opcode), self.data))
        return