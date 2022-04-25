from Packet.MaplePacket import MapleAES
import Packet.ServerPacket as SP
from Handler.SP.SERVER_IP import SERVER_IP
from tools.Utils import str2bytearray
import logging

class ServerPacketHandler:

    def __init__(self, packet, aes):
        self.packet = packet
        self.aes = aes

    def handlePacket(self, destination):
        logging.info('ServerPacketHandler, opcode: ' + hex(self.packet.opcode))
        if self.packet.data is None:
            self.aes.shiftIv()
            destination.sendall(self.packet.buf)
            return
        if self.packet.opcode == SP.SERVER_IP:
            s = SERVER_IP()
            s.onReceive(destination, self.packet, self.aes)
        elif self.packet.opcode == SP.MOVE_PLAYER:
            pass
        elif self.packet.opcode == SP.CLOSE_RANGE_ATTACK:
            pass
        else:
            data = str2bytearray(str(self.packet.opcode) + self.packet.data)
            packet = str2bytearray(self.aes.makePacket(data))
            destination.sendall(packet)
        return