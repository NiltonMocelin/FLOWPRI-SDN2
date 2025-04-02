import socket
import sys #para usar os parametros por linha de comando
import json
#lidar com bytes
import struct
#coletar tempo
import time

#alterado para o endereco ip ficticio do controlador
HOST="10.10.10.1"
#HOST="127.0.1.1"
PORT= 4444

if len(sys.argv) < 6:
    print("[erro-modo de usar->] python contrato_cli.py <ip_controlador> <ip_src> <ip_dst> <banda> <prioridade> <classe>\n")
    exit(0)

HOST = sys.argv[1]

print("Enviando contrato para -> HOST:%s, PORT: %d\n" % (HOST,PORT))

#with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.connect((HOST, PORT))

#n = int(sys.argv[1]) #obtem o primeiro parametro da entrada
#
#Contrato json - tem que ir melhorando esse contrato, se usar a porta origem e destino fica mais -preciso- pq nao generaliza um contrato para um ip mas para um ip+porta. - aqui eh um teste, por isso nao usa portas -
#
# {
#   "contrato":{
#   "ip_origem":"172.16.10.1",
#   "ip_destino":"172.16.10.2",
#   "banda":"10000", #em kbps
#   "prioridade":"1",
#   "classe":"0" #0=tempo-real,1=dados,2=nao classificado,3=controle
#   }
# }
#
contrato = {
        "contrato":{
            "ip_origem":sys.argv[2],
            "ip_destino":sys.argv[3],
            "banda":sys.argv[4],
            "prioridade":sys.argv[5],
            "classe":sys.argv[6]
            }
        }
contrato_json=json.dumps(contrato).encode('utf-8')
print(contrato_json)

qtdBytes = struct.pack('<i',len(contrato_json))

print("host: enviando contrato %d\n" %(round(time.monotonic() * 1000)))
tcp.send(qtdBytes)
tcp.send(contrato_json)

tcp.close()
