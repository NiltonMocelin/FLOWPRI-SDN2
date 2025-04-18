import sys
from host.host_qosblockchain.new_blockchain_pbft_docker_compose import criar_blockchain
from host.host_qosblockchain.qosblockchain_utils import criar_par_chaves_sawadm, criar_par_chaves_sawtooth
from host.host_qosblockchain.processor.qos_state import FlowTransacao, QoSRegister
# from fp_utils import calculate_network_prefix_ipv4

from qosblockchain.client.qos_client import QoSClient # do_reg_flowqos, do_list, do_show # problema auqi

from netifaces import AF_INET, ifaddresses, interfaces

# from fp_utils import get_meu_ip

import psutil

import random

FRED_SERVER_PORT = 5555
CAMINHO_CHAVE_PRIVADA='/sawtooth_keys/'
# class QoSClient:
#     def __init__(self):
#         pass

def get_meu_ip():

    interfs=interfaces()
    interfs.remove('lo')
    interface =  interfs[0]

    IPCv4 = str(ifaddresses(interface)[AF_INET][0]['addr'])
    
    IPCv6 = str(ifaddresses(interface)[10][0]['addr'].split("%")[0])
    if IPCv4 != "" and IPCv4 != None:
        return IPCv4
    return IPCv6


def calculate_network_prefix_ipv4(ip_v4:str):
    # supomos tudo /24 -> 192.168.1.10 -> 192.168.1.0
    prefix = ip_v4.split(".")

    return prefix[0]+"."+prefix[1]+"."+prefix[2]+".0"

class BlockchainArgs:
    def __init__(self, command=None, flowname=None, flowjson=None, auth_password=None, auth_user=None, username=None, url=None):
        self.auth_password
        self.auth_user
        self.username
        self.url
        self.flowjson
        self.flowname
        self.command

def criar_chave_sawtooth_keygen():
    return criar_par_chaves_sawtooth()

def criar_chave_sawadm():
    return criar_par_chaves_sawadm(CAMINHO_CHAVE_PRIVADA)

def enviar_transacao_blockchain(ip_blockchain, port_blockchain, flowname, transacao:FlowTransacao):
    print("[qosblchn] Enviando transacao para: ", ip_blockchain,':',port_blockchain)
# python main_qos_cli.py reg_qos '192.168.0.0-192.168.0.1-5000-5002-tcp' '{"name":"192.168.0.0-192.168.0.1-5000-5002-tcp","state":"Stopped","src_port":"5000","dst_port":"5000","proto":"udp","qos":[],"freds":[]}' --username hostqos
    # args = BlockchainArgs(command="reg_qos", url=ip_blockchain+":"+port_blockchain, flowname=flowname, flowjson=transacao.toString(), username='controller_key')

    print("modificando ip pq a blockchain sobe no parent do domínio")
    meuip_partes = ip_blockchain.split(".")
    ip_blockchain == "%s.%s.%s.50" % (meuip_partes[0], meuip_partes[1], meuip_partes[2])

    print("enviando transação para blockchain %s"%(ip_blockchain))
    QoSClient(ip_blockchain+":"+port_blockchain, CAMINHO_CHAVE_PRIVADA).reg_flowqos('reg_qos', flowname, transacao.toString())
    print("[qosblchn] Transacao enviada")
    return True

def show_bloco_blockchain(ip_blockchain, port_blockchain, flowname):
# python main_qos_cli.py show '192.168.0.0-192.168.0.1-5000-5002-tcp'
    # args = BlockchainArgs(command="reg_qos", url=ip_blockchain+":"+port_blockchain, flowname=flowname, username='controller_key')
    # flow = do_show(args)
    flow = QoSClient(ip_blockchain+":"+port_blockchain, CAMINHO_CHAVE_PRIVADA).show(flowname)
    return

def listar_todos_blocos_blockchain(ip_blockchain,port_blockchain):
    # python main_qos_cli.py list
    # args = BlockchainArgs(command="reg_qos", url=ip_blockchain+":"+port_blockchain, username='controller_key')
    # flows = do_list(args)
    flows = QoSClient(ip_blockchain+":"+port_blockchain, CAMINHO_CHAVE_PRIVADA).list()
    return

class BlockchainManager:
    def __init__(self):
        self.blockchain_table = {}
    def get_blockchain(self, src_prefix, dst_prefix):
        return self.blockchain_table.get(src_prefix+"-"+dst_prefix, self.blockchain_table.get(dst_prefix+"-"+src_prefix, None))
        
    def save_blockchain(self, src_prefix, dst_prefix, endpoint_ip, porta):
        self.blockchain_table[src_prefix + "-"+ dst_prefix]= "%s:%d"%(endpoint_ip,porta)
        return True


def criar_blockchain_api(meu_ip, nome_blockchain,blockchainmanager:BlockchainManager, PEERS_IP:list=None, chaves_peers:list = None, is_genesis=False):

    # adicionar blockchain na tabla de blockchains
    connections = psutil.net_connections(kind='inet')
    portas_em_uso = [conn.laddr.port for conn in connections if conn.status == psutil.CONN_LISTEN]
    portas_em_uso= list(set(portas_em_uso))
    connections = None

    REST_API_PORT  =  random.randint(5000, 30000) # 8008  existe a chance de outro container (intancia qosblockchain) subir e reservar a porta sem aparecer no sistema - entao comecar com random
    NETWORK_PORT   =  random.randint(5000, 30000) # 8800 existe a chance de outro container (intancia qosblockchain) subir e reservar a porta sem aparecer no sistema - entao comecar com random
    CONSENSUS_PORT =  random.randint(5000, 30000) # 5050 existe a chance de outro container (intancia qosblockchain) subir e reservar a porta sem aparecer no sistema - entao comecar com random
    VALIDATOR_PORT =  random.randint(5000, 30000) # 4004 existe a chance de outro container (intancia qosblockchain) subir e reservar a porta sem aparecer no sistema - entao comecar com random

    while(REST_API_PORT in portas_em_uso):
        REST_API_PORT+=1
    while(NETWORK_PORT in portas_em_uso):
        NETWORK_PORT+=1
    while(CONSENSUS_PORT in portas_em_uso):
        CONSENSUS_PORT+=1
    while(VALIDATOR_PORT in portas_em_uso):
        VALIDATOR_PORT+=1
    
    ipss= nome_blockchain.split('-')
    blockchainmanager.save_blockchain(ipss[0], ipss[1], meu_ip, NETWORK_PORT)

    print("net:", meu_ip, ':',NETWORK_PORT)
    print("rest:",  meu_ip, ':',REST_API_PORT)
    print("val:", meu_ip, ':', VALIDATOR_PORT)

    criar_chave_sawtooth_keygen()
    chave_publica, chave_privada = criar_chave_sawadm()

    criar_blockchain(nome_blockchain, meu_ip, chave_publica, chave_privada, CONSENSUS_PORT,VALIDATOR_PORT, REST_API_PORT, NETWORK_PORT, PEERS_IP, chaves_peers, is_genesis)
    return NETWORK_PORT

def tratar_blockchain_setup(serverip:str, fred, blockchain_manager:BlockchainManager):
    nome_blockchain = calculate_network_prefix_ipv4(fred.ip_src) + "-" +  calculate_network_prefix_ipv4(fred.ip_dst)
                
    chave_publica, chave_privada = criar_chave_sawadm()
    lista_chaves_publicas = fred.getPeersPKeys()
    lista_peers_ip = fred.getPeerIPs() 
 
    is_genesis = False
    genesis_node_ip = fred.ip_genesis
    meu_ip = serverip
    if meu_ip == genesis_node_ip:
        is_genesis = True

    # for chave in fred.lista_peers:
    #     lista_chaves_str += chave

    # criar_chave.. adicionar ao fred
    porta_blockchain = criar_blockchain_api(meu_ip, nome_blockchain, blockchain_manager, chaves_peers=lista_chaves_publicas, PEERS_IP=lista_peers_ip, is_genesis=is_genesis)
    
    # isso deve ser feito fora dessa funcao
    # if not is_genesis:
    #     fred.addPeer(meu_ip, chave_publica,meu_ip+':'+porta_blockchain)
    #     # se sou borda destino, enviar a borda origem 
    #     enviar_msg(fred_json=fred.toString(), server_ip=genesis_node_ip, server_port=FRED_SERVER_PORT)
    
    return porta_blockchain
    