import random
import sympy
import socket
import logging
import des

FORMAT = '[Echo Client] %(message)s'

HOST = "127.0.0.1"
PORT = 50007

MAX_NUM = 1e6
MIN_NUM = 0

logging.basicConfig(format=FORMAT)

logger = logging.getLogger("Echo Client")

logger.setLevel(logging.INFO)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

addr = (HOST, PORT)

sock.connect(addr)
logger.info("Connected to %s:%d", addr[0], addr[1])

try:
    a = random.randint(MIN_NUM, MAX_NUM)

    p = sympy.randprime(MIN_NUM, MAX_NUM)
    g = random.randint(MIN_NUM, MAX_NUM) % p

    msg = p.to_bytes(8, byteorder='big') + g.to_bytes(8, byteorder='big')

    logger.info("p = %d, g = %d", p, g)

    sock.sendall(msg)

    A = g**a % p

    msg = A.to_bytes(8, byteorder='big')

    logger.info("A = %d", A)

    sock.sendall(msg)

    msg = sock.recv(8)

    B = int.from_bytes(msg, byteorder='big')

    logger.info("B = %d", B)

    s = B**a % p

    logger.info("s = %d", s)

    key = des.DesKey(s.to_bytes(8, byteorder='big'))

    msg = b'Test Message!!!!'

    logger.info(str(msg, 'utf-8'))

    sock.sendall(key.encrypt(msg))
finally:
    logger.info("Closing connection")
    sock.close()