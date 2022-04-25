from Packet.MaplePacket import MapleAES
import Packet.ClientPacket as CP
from tools.Utils import str2bytearray
import logging

class ClientPacketHandler:

    def __init__(self, packet, aes):
        self.packet = packet
        self.aes = aes

    def handlePacket(self, destination):
        logging.info('ClientPacketHandler, opcode: ' + hex(self.packet.opcode))
        if self.packet.data is None:
            self.aes.shiftIv()
            destination.sendall(self.packet.buf)
            return
        if self.packet.opcode == CP.MOVE_PLAYER:
            pass
        elif self.packet.opcode == CP.CLOSE_RANGE_ATTACK:
            pass
        else:
            data = str2bytearray(str(self.packet.opcode) + self.packet.data)
            packet = str2bytearray(self.aes.makePacket(data))
            destination.sendall(packet)
        return