import random
import socket
import logging
import des

FORMAT = '[Echo Server] %(message)s'

HOST = "127.0.0.1"
PORT = 50007

MAX_NUM = 1e6
MIN_NUM = 0

logging.basicConfig(format=FORMAT)

logger = logging.getLogger("Echo Server")

logger.setLevel(logging.INFO)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.bind((HOST, PORT))
sock.listen(1)

logger.info("Listening on %s:%d", HOST, PORT)

conn, addr = sock.accept()
logger.info("Connected to %s:%d", addr[0], addr[1])

try:
    b = random.randint(MIN_NUM, MAX_NUM)

    msg = conn.recv(16)

    p = int.from_bytes(msg[:8], byteorder='big')
    g = int.from_bytes(msg[8:], byteorder='big')

    logger.info("p = %d, g = %d", p, g)

    msg = conn.recv(8)

    A = int.from_bytes(msg, byteorder='big')

    logger.info("A = %d", A)

    B = g**b % p

    msg = B.to_bytes(8, byteorder='big')

    logger.info("B = %d", B)

    conn.sendall(msg)

    s = A**b % p

    logger.info("s = %d", s)

    key = des.DesKey(s.to_bytes(8, byteorder='big'))

    msg = conn.recv(16)

    logger.info(str(key.decrypt(msg), 'utf-8'))
finally:
    logger.info("Closing connection")
    conn.close()