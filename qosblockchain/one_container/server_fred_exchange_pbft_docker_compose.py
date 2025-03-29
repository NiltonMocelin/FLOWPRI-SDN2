
# server para receber chave.pub
import socket
# import struct 
import os
import sys
import json
import psutil
import struct
import json

# poder importar from parent directory
# sys.path.append( os.path.dirname( os.path.dirname( os.path.abspath(__file__) ) )+"/client" )
sys.path.append( os.path.dirname( os.path.dirname( os.path.abspath(__file__) ) ) )

from new_blockchain_pbft_docker_compose import criar_blockchain
# from sawtooth_cli.sawadm import main as sawadm_keygen
# from sawtooth_cli.sawtooth_keygen import main as sawtooth_keygen
from qosblockchain_utils import criar_par_chaves_sawadm, criar_par_chaves_sawtooth
# from client.main_qos_cli import main as main_client

SERVER_IP   = '0.0.0.0'
SERVER_PORT = 5555
MY_IP       = SERVER_IP
TEST_MODE   = False
HOST_NUMBER = 0
SUDO_PASS   = '214336414'
KEYS_LOCATION = '/sawtooth_keys/'

### recebe FRED como txt
#- carrega FRED from txt
#- inicia o container do blockchain genesis com os ips pares e portas de rede vindos do contrato
#- (se este for o genesis) copia as chaves publicas do FRED para /pbft-shared/validators/ no container 
#- o blockchain vai iniciar
#- Se este não for o genesis, enviar para o host origem


# FRED modelo: identificacao do fluxo, identificacao de QoS previsto, chaves_nos, genesis, ip_nos,
# (identificacao de fluxo)

# exemplo FRED:
    # {
    # "ip_ver":"4",
    # "proto":"tcp",
    # "ip_src":"192.168.0.1",
    # "ip_dst":"192.168.0.2",
    # "src_port":"9999",
    # "dst_port":"9988",
    # "mac_src":"xx",
    # "mac_dst":"xx",

    # "prioridade":"1",
    # "classe":"1",
    # "bandiwdth":"1",
    # "loss":"1",
    # "delay":"1",
    # "jitter":"1",
    # "label":"youtube-video-rt",

    # "blockchain_name":"",
    # "ASN_src":"",
    # "ASN_dst":"",
    # "AS_src_ip_range":[],
    # "AS_dst_ip_range":[],
    # "ip_genesis":"",
    # "lista_peers":[{"nome_peer":"", "chave_publica":"", "ip_porta":"ip:porta"}],
    # "lista_rota":[{"ordem":"1", "nome_peer":"", "chave_publica":"", "nro_saltos(qtd_switches_rota)":""}]
    # }


#algo que ideentifique a blockchain
# network_prefix:ip:porta
blockchain_dict = {}

def get_blockchain(dst_prefix):
    return blockchain_dict[dst_prefix]

def save_blockchain(dst_prefix, endpoint_ip, porta):
    blockchain_dict[dst_prefix]= endpoint_ip+":"+porta
    return


def calculate_network_prefix_ipv4(ip_v4):
    # supomos tudo /24 -> 192.168.1.10 -> 192.168.1.0
    prefix = ip_v4.split(".")

    return prefix[0]+"."+prefix[1]+"."+prefix[2]+".0"

class Fred:
    def __init__(self, code, blockchain_name, AS_src_ip_range, AS_dst_ip_range, ip_ver, proto, ip_src, ip_dst, src_port, dst_port, mac_src, 
                 mac_dst, prioridade,classe,bandiwdth, loss, delay,jitter, label, ip_genesis, lista_peers, lista_rota):
        self.ip_ver:str = ip_ver
        self.proto:str = proto
        self.ip_src:str  = ip_src 
        self.ip_dst:str = ip_dst
        self.src_port:str = src_port
        self.dst_port:str = dst_port
        self.mac_src:str = mac_src
        self.mac_dst:str  = mac_dst 

        self.code:str = code
        
        self.prioridade:str = prioridade
        self.classe:str = classe
        self.bandiwdth:str = bandiwdth
        self.loss:str = loss
        self.delay:str = delay
        self.jitter:str  = jitter
        self.label:str = label

        self.blockchain_name:str = blockchain_name
        self.AS_src_ip_range:list = AS_src_ip_range
        self.AS_dst_ip_range:list = AS_dst_ip_range
        self.ip_genesis:str = ip_genesis
        self.lista_peers:list = lista_peers
        self.lista_rota:list = lista_rota

        # lista_peers = lista[ dict1, dict 2]
        # (dict) um peer = {"nome_peer":"", "chave_publica":"", "ip_porta":"ip:porta"}
        # uma no da rota = {"ordem":"1", "nome_peer":"", "chave_publica":"", "nro_saltos(qtd_switches_rota)":""}
        
    def toString(self):

        str_AS_src_ip_range = ''
        str_AS_dst_ip_range = ''
        str_lista_peers = ''
        str_lista_rota = ''

        for s in self.AS_src_ip_range:
            str_AS_src_ip_range+=',\"%s\"' % (s)

        for s in self.AS_dst_ip_range:
            str_AS_dst_ip_range+=',\"%s\"' % (s)
        
        for s in self.lista_peers:
            str_lista_peers+=',\"%s\"' % (json.dumps(s))
        
        for s in self.lista_rota:
            str_lista_rota+=',\"%s\"' % (json.dumps(s))
        
        str_AS_src_ip_range = str_AS_src_ip_range.replace(',','',1)
        str_AS_dst_ip_range = str_AS_dst_ip_range.replace(',','',1)
        str_lista_peers = str_lista_peers.replace(',','',1)
        str_lista_rota = str_lista_rota.replace(',','',1)

        return "{\"ip_ver\":\"%s\",\
    \"proto\":\"%s\",\
    \"ip_src\":\"%s\",\
    \"ip_dst\":\"%s\",\
    \"src_port\":\"%s\",\
    \"dst_port\":\"%s\",\
    \"mac_src\":\"%s\",\
    \"mac_dst\":\"%s\",\
    \"prioridade\":\"%s\",\
    \"classe\":\"%s\",\
    \"bandiwdth\":\"%s\",\
    \"loss\":\"%s\",\
    \"delay\":\"%s\",\
    \"jitter\":\"%s\",\
    \"label\":\"%s\",\
    \"blockchain_name\":\"%s\",\
    \"AS_src_ip_range\":[%s],\
    \"AS_dst_ip_range\":[%s],\
    \"ip_genesis\":\"%s\",\
    \"lista_peers\":[%s],\
    \"lista_rota\":[%s]\
    }" % (self.ip_ver,self.proto,self.ip_src,self.ip_dst,self.src_port,self.dst_port,self.mac_src,self.mac_dst,
                self.prioridade,self.classe,self.bandiwdth,self.loss,self.delay,self.jitter,self.label,self.blockchain_name,
                str_AS_src_ip_range,str_AS_dst_ip_range,self.ip_genesis,str_lista_peers,str_lista_rota)    

def fromJsonToFred(_json):
    """{
    "ip_ver":"",
    "proto":"",
    "ip_src":"",
    "ip_dst":"",
    "src_port":"",
    "dst_port":"",
    "mac_src":"",
    "mac_dst":"",

    "code":"",
    
    "prioridade":"",
    "classe":"",
    "bandiwdth":"",
    "loss":"",
    "delay":"",
    "jitter":"",
    "label":"",

    "blockchain_name":"",
    "ASN_src":"",
    "ASN_dst":"",
    "AS_src_ip_range":[],
    "AS_dst_ip_range":[],
    "ip_genesis":"",
    "lista_peers":[],
    "lista_rota":[]
    }"""

    try:
        ip_ver = _json["ip_ver"]
        proto = _json["proto"]
        ip_src = _json["ip_src"]
        ip_dst = _json["ip_dst"]
        src_port = _json["src_port"]
        dst_port = _json["dst_port"]
        mac_src = _json["mac_src"]
        mac_dst = _json["mac_dst"]

        code = _json["code"]

        prioridade = _json["prioridade"]
        classe = _json["classe"]
        bandiwdth = _json["bandiwdth"]
        loss = _json["loss"]
        delay = _json["delay"]
        jitter = _json["jitter"]
        label = _json["label"]

        blockchain_name = _json["blockchain_name"]
        AS_src_ip_range = _json["AS_src_ip_range"]
        AS_dst_ip_range = _json["AS_dst_ip_range"]
        ip_genesis = _json["ip_genesis"]
        lista_peers = _json["lista_peers"]
        lista_rota = _json["lista_rota"]
    except:
        raise SyntaxError("Error loading FRED from JSON !")

    return Fred(blockchain_name, AS_src_ip_range, AS_dst_ip_range, ip_ver, proto, ip_src, ip_dst, src_port, dst_port, mac_src, 
                 mac_dst, prioridade,classe,bandiwdth, loss, delay,jitter, label, ip_genesis, lista_peers, lista_rota)


def consultar_blockchains(container_name):
    return False

def ler_arquivo(file_name):

    try:
        dados = open(file_name,'r').read().strip()
    except:
        raise SyntaxError("ERROR: Check the file name > ", file_name)

    return dados

def mysend(sock, msg, MSGLEN):
    totalsent = 0
    while totalsent < MSGLEN:
        sent = sock.send(msg[totalsent:])
        if sent == 0:
            raise RuntimeError("socket connection broken")
        totalsent = totalsent + sent

def myreceive(sock, MSGLEN):
    chunks = []
    bytes_recd = 0
    while bytes_recd < MSGLEN:
        chunk = sock.recv(min(MSGLEN - bytes_recd, 2048))
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        chunks.append(chunk)
        bytes_recd = bytes_recd + len(chunk)
    return b''.join(chunks)
    
def key_server():
    print("Iniciando servidor de Freds (%s:%d)....\n" % (SERVER_IP, SERVER_PORT))

    #with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #um desses funfa
    tcp.bind((SERVER_IP, SERVER_PORT))

    tcp.listen(5)

    while True:
        print("Esperando nova conexao ...")
        conn, addr = tcp.accept()

        data_qtd_bytes:int = int.from_bytes(conn.recv(4),'big')
        data = conn.recv(data_qtd_bytes).decode()
        
        print('Recebido de ', addr)
        print('qtd bytes data:',data_qtd_bytes)
        print('json:',data)
        # continue

        fred_json = json.loads(data)

        fred_obj = fromJsonToFred(fred_json)
        fred_json = ''

        conn.close()

        # continue
        is_genesis = False
        chave_publica, chave_privada = criar_par_chaves_sawadm(KEYS_LOCATION)
        chaves_peers:list = fred_obj.lista_chaves
        ips_peers:list = fred_obj.lista_nos

        if MY_IP == fred_obj.ip_src:
            is_genesis = True        

        if fred_obj.blockchain_name == '':
            fred_obj.blockchain_name = fred_obj.ip_src +"_"+fred_obj.ip_dst

        if consultar_blockchains(fred_obj.blockchain_name):
            print("Já existe uma blockchain para esse fluxo... skipping")
            continue

        
        connections = psutil.net_connections(kind='inet')
        portas_em_uso = [conn.laddr.port for conn in connections if conn.status == psutil.CONN_LISTEN]
        portas_em_uso= list(set(portas_em_uso))
        connections = None

        REST_API_PORT= 8008
        NETWORK_PORT = 8800
        CONSENSUS_PORT = 5050
        VALIDATOR_PORT = 4004

        while(REST_API_PORT in portas_em_uso):
            REST_API_PORT+=1
        while(NETWORK_PORT in portas_em_uso):
            NETWORK_PORT+=1
        while(CONSENSUS_PORT in portas_em_uso):
            CONSENSUS_PORT+=1
        while(VALIDATOR_PORT in portas_em_uso):
            VALIDATOR_PORT+=1

        print('lista_nos: ', ips_peers)

        # criar container e blockchain
        container_id = criar_blockchain(is_genesis= is_genesis, endpoint_ip= MY_IP, chave_publica=chave_publica, chave_privada=chave_privada, chaves_peers=chaves_peers, nome_blockchain=fred_obj.blockchain_name,
                        CONSENSUS_PORT=CONSENSUS_PORT, VALIDATOR_PORT=VALIDATOR_PORT, REST_API_PORT=REST_API_PORT,NETWORK_PORT=NETWORK_PORT,PEERS_IP=ips_peers)

        if container_id == -1:
            continue

        print("Blockchain criada _ id %s, REST: %d, NETWORK: %d, chave_publica: %s" % (container_id, REST_API_PORT, NETWORK_PORT, chave_publica))

        if chave_publica not in fred_obj.lista_chaves:
            fred_obj.lista_chaves.append(chave_publica)
        
        if is_genesis:
            fred_obj.ip_genesis = MY_IP+':'+str(NETWORK_PORT)

        if MY_IP+':'+str(NETWORK_PORT) not in fred_obj.lista_nos:
            fred_obj.lista_nos.append(MY_IP+':'+str(NETWORK_PORT))

        print('new_fred: ', fred_obj.toString().strip())

        if TEST_MODE:
            continue

        # if is_genesis == False:
            
        #     fred_obj.lista_chaves.append(chave_publica)
        #     fred_obj.ip_genesis = MY_IP+':'+str(NETWORK_PORT)
        #     fred_obj.lista_nos.append(MY_IP+':'+str(NETWORK_PORT))

        #     # enviar para host_genesis
        #     enviar_fred(fred_obj.toString(), fred_obj.ip_genesis, SERVER_PORT)            
        # else:
        #     # criar primeira transacao, com o
        #     main_client('fred_server', ["reg_qos", "{}_{}:{}_{}:{}_{}".format(fred_obj.ip_ver, fred_obj.ip_src, fred_obj.src_port, fred_obj.ip_dst, fred_obj.dst_port, fred_obj.proto), "\"{}\"".format(fred_obj.toString()), "--username", "host"])


def enviar_fred(msg, server_ip, server_port):
    print("Enviando fred para -> %s:%s\n" % (server_ip,server_port))

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect((SERVER_IP, SERVER_PORT))

    try:
        # tcp.send(len(dados))
        tcp.send(msg.encode())

        tcp.close()

    except:
        raise SyntaxError("ERRO ao enviar fred !")
            

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


if __name__ == '__main__':
    """python server_fred_exchange_pbft.py"""
    """-M <my-ip-address> for identify the genesis node """
    """-S <server-ip> -> bind server-ip"""
    """-P <server-port> -> <bind server-port>"""
    """--test -> for testing mode"""

    nargs = len(sys.argv)

    if ( nargs > 8 or nargs == 0 ):
        modo_uso = """python server_fred_exchange_pbft.py -M <my-ip-address> for identify the genesis node -S <server-ip> -> bind server-ip -P <server-port> -> <bind server-port> --test -> for testing mode"""
        print('Error, modo de uso:', modo_uso)
        raise SyntaxError()

    try:
        for i in range(0, nargs):
            if sys.argv[i] == '-S':
                SERVER_IP = sys.argv[i+1]

            elif sys.argv[i] == '-P':
                SERVER_PORT = sys.argv[i+1]
                
            elif sys.argv[i] == '-M':
                MY_IP = sys.argv[i+1]
                
            elif sys.argv[i] == '--test':
                TEST_MODE = True
    except:
        print('Erro, revise os argumentos (tente)')

    # client para enviar chave.pub
    key_server()
