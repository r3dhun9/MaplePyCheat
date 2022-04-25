from tools.Utils import replacePacket, str2bytearray

class SERVER_IP:

    def __init__(self):
        pass

    def onReceive(self, destination, packet, aes):
        ip = packet.data[2:6]
        port = packet.data[6:8]
        ip = ['\xc0', '\xa8', '\xed', '\x01']
        port = ['\x29', '\x23']
        print('SERVER_IP: Opcode: {} , data: {}'.format(hex(packet.opcode), ' '.join('{:>02s}'.format(hex(ord(x)).lstrip('0x')) for x in packet.data)))
        packet.data = replacePacket(packet.data, ip, 2, 6)
        packet.data = replacePacket(packet.data, port, 6, 8)
        print('SERVER_IP(replace): Opcode: {} , data: {}'.format(hex(packet.opcode), ' '.join('{:>02s}'.format(hex(ord(x)).lstrip('0x')) for x in packet.data)))
        data = str2bytearray(str(packet.opcode) + packet.data)
        new_packet = str2bytearray(aes.makePacket(data))
        print('SERVER_IP(encrypt): Opcode: {} , data: {}'.format(hex(packet.opcode), ' '.join('{:>02s}'.format(hex(x).lstrip('0x')) for x in new_packet)))
        destination.sendall(new_packet)
        return