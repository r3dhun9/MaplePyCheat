import threading
import logging
from Proxy.Proxy import loginServer, worldServer

logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s] %(name)s [+] %(message)s', datefmt = '%b-%d %H:%M:%S')

def main():
    tLoginServer = threading.Thread(target = loginServer)
    tWorldServer = threading.Thread(target = worldServer)
    tLoginServer.start()
    tWorldServer.start()
    tLoginServer.join()
    tWorldServer.join()
    logging.info('Done')

if __name__ == '__main__':
    main()