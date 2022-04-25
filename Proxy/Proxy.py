import socket
import logging
import threading
import time
import random
from MapleAES.MapleAES import MapleAES
from Packet.MaplePacket import MaplePacket
from Handler.ClientPacketHandler import ClientPacketHandler
from Handler.ServerPacketHandler import ServerPacketHandler

listen_host = ''
forward_host = ''

login_listen_port = 9000
world_listen_port = 9001
login_forward_port = 10001
world_forward_port = 14000

server_inbound = None
client_inbound = None
server_outbound = None
client_outbound = None

lock = threading.Lock()

def worldServer():
    try:
        logging.info('Starting world server, wating for the connection ...')
        # Bind and listen
        mid_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mid_socket.bind((listen_host, world_listen_port))
        mid_socket.listen(5)
        logging.info('World server is listening on host: {}, port: {}'.format(listen_host, world_listen_port))
        # Accept cilent's socket
        client_socket, client_addr = mid_socket.accept()
        logging.info('Connected by {}'.format(str(client_addr)))
        logging.info('******** Fowarding packets ********')
        # Connect to server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((forward_host, world_forward_port))
        while True:
            tClient = threading.Thread(target = forward, args = (client_socket, server_socket, 0))
            tServer = threading.Thread(target = forward, args = (server_socket, client_socket, 1))
            tClient.start()
            tServer.start()
            tClient.join()
            tServer.join()
            #time.sleep(1)

    except Exception as e:
        print(e)

def loginServer():
    try:
        global server_inbound
        global client_inbound
        global server_outbound
        global client_outbound
        logging.info('Starting login server, wating for the connection ...')
        # Bind and listen
        mid_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mid_socket.bind((listen_host, login_listen_port))
        mid_socket.listen(5)
        logging.info('Login server is listening on host: {}, port: {}'.format(listen_host, login_listen_port))
        # Accept cilent's socket
        client_socket, client_addr = mid_socket.accept()
        logging.info('Connected by {}'.format(str(client_addr)))
        logging.info('******** Fowarding packets ********')
        # Connect to server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((forward_host, login_forward_port))
        # Handle first packet (version, recviv, sendiv)
        hello_login = server_socket.recv(16)
        client_socket.sendall(hello_login)
        hello_login = bytearray(hello_login)
        recvIv = [hello_login[7], hello_login[8], hello_login[9], hello_login[10]]
        sendIv = [hello_login[11], hello_login[12], hello_login[13], hello_login[14]]
        server_inbound = MapleAES(recvIv, 116)
        client_inbound = MapleAES(recvIv, 116)
        server_outbound = MapleAES(sendIv, 116)
        client_outbound = MapleAES(sendIv, 116)
        # Foward packets
        while True:
            tClient = threading.Thread(target = forward, args = (client_socket, server_socket, 0))
            tServer = threading.Thread(target = forward, args = (server_socket, client_socket, 1))
            tClient.start()
            tServer.start()
            #tClient.join()
            #tServer.join()
            time.sleep(2)

    except Exception as e:
        print(e)
        mid_socket.close()
        client_socket.close()
        server_socket.close()

# type -> 0 = client to server, 1 = server to client
def forward(source, destination, t):
    try:
        global server_inbound
        global client_inbound
        global server_outbound
        global client_outbound
        buf = source.recv(1024)
        # decrypt packet
        lock.acquire()
        if buf == b'':
            destination.sendall(buf)
            return
        if t == 0:
            logging.info('client --> server')
            packet = MaplePacket(buf, server_inbound)
            packet.decryptPacket()
            server_inbound = packet.aes
            c = ClientPacketHandler(packet, client_outbound)
            c.handlePacket(destination)
            client_outbound = c.aes
        else:
            logging.info('server --> client')
            packet = MaplePacket(buf, client_inbound)
            packet.decryptPacket()
            client_inbound = packet.aes                
            s = ServerPacketHandler(packet, server_outbound)
            s.handlePacket(destination)
            server_outbound = s.aes
        lock.release()
        return
    except socket.error:
        logging.info("SOCKET ERROR - CONNECTED FAILED")
        source.close()
        destination.close()