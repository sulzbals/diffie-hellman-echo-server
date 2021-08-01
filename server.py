import random
import socket
import logging
import des

FORMAT = '[SERVER] [%(levelname)s] %(message)s'

HOST = "127.0.0.1"
PORT = 50000

MAX_NUM = 1e6
MIN_NUM = 0

logging.basicConfig(format=FORMAT)

logger = logging.getLogger("Echo Server")

logger.setLevel(logging.INFO)

b = random.randint(MIN_NUM, MAX_NUM)
logger.info("Escolhendo b = %d (chave secreta)", b)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.bind((HOST, PORT))
sock.listen(1)
logger.info("Escutando em %s:%d", HOST, PORT)

conn, addr = sock.accept()
logger.info("Conexão aceita em %s:%d", addr[0], addr[1])

try:
    msg = conn.recv(8)
    logger.info("Mensagem recebida: 0x%s", msg.hex())

    p = int.from_bytes(msg[:4], byteorder='big')
    g = int.from_bytes(msg[4:], byteorder='big')
    logger.info("Decodificando 0x%s como p = %d, g = %d", msg.hex(), p, g)

    msg = conn.recv(4)
    logger.info("Mensagem recebida: 0x%s", msg.hex())

    A = int.from_bytes(msg, byteorder='big')
    logger.info("Decodificando 0x%s como A = %d", msg.hex(), A)

    B = g**b % p
    logger.info("Calculando B = %d**%d %% %d = %d", g, b, p, B)

    msg = B.to_bytes(4, byteorder='big')
    logger.info("Codificando B como 0x%s", msg.hex())

    conn.sendall(msg)
    logger.info("Enviando mensagem: 0x%s", msg.hex())

    s = A**b % p
    logger.info("Calculando s = %d**%d %% %d = %d (chave compartilhada)", A, b, p, s)

    key = des.DesKey(s.to_bytes(8, byteorder='big'))

    logger.info("Entrando em modo Echo Server")

    while True:
        logger.info("Aguardando mensagem")

        msg = conn.recv(16)

        if not msg:
            break

        logger.info("Mensagem recebida: 0x%s", msg.hex())

        msg = key.decrypt(msg)
        try:
            logger.info("Mensagem decriptada: %s", str(msg, 'utf-8'))
        except UnicodeDecodeError:
            logger.info("Mensagem decriptada: 0x%s", msg.hex())

        logger.info("Enviando mensagem de volta para o cliente (echo)")

        msg = key.encrypt(msg)
        logger.info("Mensagem encriptada: 0x%s", msg.hex())

        conn.sendall(msg)
        logger.info("Enviando mensagem: 0x%s", msg.hex())
finally:
    logger.info("Fechando conexão")
    conn.close()