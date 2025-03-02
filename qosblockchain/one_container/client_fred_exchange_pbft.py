# server para receber chave.pub
import socket
# import struct 
import os
import sys

SERVER_IP='0.0.0.0'
SERVER_PORT=5555
FRED_JSON = ''

# def mysend(sock, msg, MSGLEN):
#     totalsent = 0
#     while totalsent < MSGLEN:
#         sent = sock.send(msg[totalsent:])
#         if sent == 0:
#             raise RuntimeError("socket connection broken")
#         totalsent = totalsent + sent

# def myreceive(sock, MSGLEN):
#     chunks = []
#     bytes_recd = 0
#     while bytes_recd < MSGLEN:
#         chunk = sock.recv(min(MSGLEN - bytes_recd, 2048))
#         if chunk == b'':
#             raise RuntimeError("socket connection broken")
#         chunks.append(chunk)
#         bytes_recd = bytes_recd + len(chunk)
#     return b''.join(chunks)
    

def key_client():

    print("Enviando FRED para -> %s:%s\n" % (SERVER_IP,SERVER_PORT))

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect((SERVER_IP, SERVER_PORT))

    print(FRED_JSON)
    vetorbytes = FRED_JSON.encode("utf-8")
    tcp.send(len(vetorbytes).to_bytes(4, 'big'))
    print(tcp.send(vetorbytes))
    print('len: ', len(vetorbytes))    
    
    tcp.close()
        
def salvar_arquivo(caminho_arquivo, nome_arquivo, dados):

    #mkdir if doesn't exist
    try:
        os.makedirs(caminho_arquivo)
    except:
        raise SyntaxError("Folder %s já existente, seguindo..." % (caminho_arquivo))

    #write
    file = open(caminho_arquivo+nome_arquivo,'w+')
    file.write(dados)
    file.close()
    print("Aquivo %s escrito" % (caminho_arquivo+nome_arquivo))

# client para enviar chave.pub
if __name__ == '__main__':

    if len(sys.argv) != 4:
        print("[erro-modo de usar->] python client_key_exchange_pbft.py <ip_server_destino> <port> <json-fred>\n")
        exit(0)

    SERVER_IP = sys.argv[1]
    SERVER_PORT = int(sys.argv[2])
    FRED_JSON = sys.argv[3]

    key_client()
