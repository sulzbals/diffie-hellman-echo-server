import random
import sympy
import socket
import logging
import des

# Define o formato dos logs 
FORMAT = '[CLIENT] [%(levelname)s] %(message)s'

# Define o host como localhost e uma porta qualquer
HOST = "127.0.0.1"
PORT = 50000

# Intervalo dos numeros gerados para a troca de chave
MAX_NUM = 1e6
MIN_NUM = 0

logging.basicConfig(format=FORMAT)

logger = logging.getLogger("Echo Client")

logger.setLevel(logging.INFO)

a = random.randint(MIN_NUM, MAX_NUM)
logger.info("Escolhendo a = %d (chave secreta)", a)

# Cria um socket TCP/IP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

addr = (HOST, PORT)

# Conecta o socket na porta em que o server esta escutando
sock.connect(addr)
logger.info("Conexão aberta em %s:%d", addr[0], addr[1])

try:
    # Gera um primo aleatório para p e g mod p
    p = sympy.randprime(MIN_NUM, MAX_NUM)
    g = random.randint(MIN_NUM, MAX_NUM) % p
    logger.info("Escolhendo p = %d e g = %d", p, g)

    # Codifica p e g em inteiros de 4 bytes cada e concatena
    msg = p.to_bytes(4, byteorder='big') + g.to_bytes(4, byteorder='big')
    logger.info("Codificando p e g como 0x%s", msg.hex())

    sock.sendall(msg)
    logger.info("Enviando mensagem: 0x%s", msg.hex())

    A = g**a % p
    logger.info("Calculando A = %d**%d %% %d = %d", g, a, p, A)

    msg = A.to_bytes(4, byteorder='big')
    logger.info("Codificando A como 0x%s", msg.hex())

    sock.sendall(msg)
    logger.info("Enviando mensagem: 0x%s", msg.hex())

    msg = sock.recv(4)
    logger.info("Mensagem recebida: 0x%s", msg.hex())

    B = int.from_bytes(msg, byteorder='big')
    logger.info("Decodificando 0x%s como B = %d", msg.hex(), B)

    s = B**a % p
    logger.info("Calculando s = %d**%d %% %d = %d (chave compartilhada)", B, a, p, s)

    key = des.DesKey(s.to_bytes(8, byteorder='big'))

    logger.info("Testando troca de mensagens encriptadas usando a chave compartilhada s = %d", s)

    test_msg = b'Test Message!!!!'
    logger.info("Mensagem de teste: %s", str(test_msg, 'utf-8'))

    msg = key.encrypt(test_msg)
    logger.info("Mensagem encriptada: 0x%s", msg.hex())

    sock.sendall(msg)
    logger.info("Enviando mensagem: 0x%s", msg.hex())

    msg = sock.recv(16)
    logger.info("Mensagem recebida: 0x%s", msg.hex())

    msg = key.decrypt(msg)

    if msg == test_msg:
        logger.info("Mensagem decriptada: %s", str(msg, 'utf-8'))
        logger.info("Mensagem recebida equivale a mensagem enviada")
    else:
        logger.info("Mensagem decriptada: 0x%s", msg.hex())
        logger.error("Mensagem recebida difere da mensagem enviada")

    wrong_s = random.randint(MIN_NUM, MAX_NUM)
    while wrong_s == s:
        wrong_s = random.randint(MIN_NUM, MAX_NUM)

    wrong_key = des.DesKey(wrong_s.to_bytes(8, byteorder='big'))

    logger.info("Testando troca de mensagens encriptadas usando s = %d como chave para decriptação (caso de erro)", wrong_s)

    test_msg = b'Test Message!!!!'
    logger.info("Mensagem de teste: %s", str(test_msg, 'utf-8'))

    msg = key.encrypt(test_msg)
    logger.info("Mensagem encriptada: 0x%s", msg.hex())

    sock.sendall(msg)
    logger.info("Enviando mensagem: 0x%s", msg.hex())

    msg = sock.recv(16)
    logger.info("Mensagem recebida: 0x%s", msg.hex())

    msg = wrong_key.decrypt(msg)

    if msg == test_msg:
        logger.info("Mensagem decriptada: %s", str(msg, 'utf-8'))
        logger.info("Mensagem recebida equivale a mensagem enviada")
    else:
        logger.info("Mensagem decriptada: 0x%s", msg.hex())
        logger.error("Mensagem recebida difere da mensagem enviada")
finally:
    logger.info("Fechando conexão")
    sock.close()