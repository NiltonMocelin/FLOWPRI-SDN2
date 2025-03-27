import sys

from qosblockchain.one_container.new_blockchain_pbft_docker_compose import criar_blockchain
from qosblockchain.client.main_qos_cli import do_reg_flowqos, do_list, do_show
from qosblockchain.one_container.server_fred_exchange_pbft_docker_compose import criar_par_chaves_sawadm, criar_par_chaves_sawtooth
from qosblockchain.one_container.processor.qos_state import FlowTransacao
from fp_utils import enviar_msg, calculate_network_prefix_ipv4
from fp_fred import Fred

from netifaces import AF_INET, ifaddresses

# from fp_utils import get_meu_ip

import psutil

import subprocess

FRED_SERVER_PORT = 5555

def get_meu_ip():
    IPCv4 = str(ifaddresses('eth0')[AF_INET][0]['addr'])
    
    IPCv6 = str(ifaddresses('eth0')[10][0]['addr'].split("%")[0])
    if IPCv4 != "" and IPCv4 != None:
        return IPCv4
    
    return IPCv6

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
    return criar_par_chaves_sawadm()

def enviar_transacao_blockchain(ip_blockchain, port_blockchain, flowname, transacao:FlowTransacao):
# python main_qos_cli.py reg_qos '192.168.0.0-192.168.0.1-5000-5002-tcp' '{"name":"192.168.0.0-192.168.0.1-5000-5002-tcp","state":"Stopped","src_port":"5000","dst_port":"5000","proto":"udp","qos":[],"freds":[]}' --username hostqos
    args = BlockchainArgs(command="reg_qos", url=ip_blockchain+":"+port_blockchain, flowname=flowname, flowjson=transacao.toString(), username='controller_key')
    do_reg_flowqos(args)
    return True

def show_bloco_blockchain(ip_blockchain, port_blockchain, flowname):
# python main_qos_cli.py show '192.168.0.0-192.168.0.1-5000-5002-tcp'
    args = BlockchainArgs(command="reg_qos", url=ip_blockchain+":"+port_blockchain, flowname=flowname, username='controller_key')
    flow = do_show(args)
    return

def listar_todos_blocos_blockchain(ip_blockchain,port_blockchain):
    # python main_qos_cli.py list
    args = BlockchainArgs(command="reg_qos", url=ip_blockchain+":"+port_blockchain, username='controller_key')
    flows = do_list(args)
    return

class BlockchainManager:
    def __init__(self):
        self.blockchain_table = {}
    def get_blockchain(self,src_prefix, dst_prefix):
        
        if src_prefix+"-"+dst_prefix in self.blockchain_table:
            return self.blockchain_table[src_prefix+"-"+dst_prefix]
        elif dst_prefix + "-"+src_prefix in self.blockchain_table:
            return self.blockchain_table[dst_prefix +"-"+ src_prefix]
        
        return None

    def save_blockchain(self, src_prefix, dst_prefix, endpoint_ip, porta):
        self.blockchain_table[src_prefix + "-"+ dst_prefix]= endpoint_ip+":"+porta
        return True


def criar_blockchain_api(nome_blockchain, PEERS_IP:list=None, chaves_peers:list = None, is_genesis=False):

    # adicionar blockchain na tabla de blockchains
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

    criar_chave_sawtooth_keygen()
    chave_publica, chave_privada = criar_chave_sawadm()

    criar_blockchain(nome_blockchain, get_meu_ip(), chave_publica, chave_privada, CONSENSUS_PORT,VALIDATOR_PORT, REST_API_PORT, NETWORK_PORT, PEERS_IP, chaves_peers, is_genesis)
    return NETWORK_PORT

def tratar_blockchain_setup(serverip:str, fred:Fred, blockchainManager:BlockchainManager ):
    nome_blockchain = calculate_network_prefix_ipv4(fred.ip_src) + "-" +  calculate_network_prefix_ipv4(fred.ip_dst)
                
    chave_publica, chave_privada = criar_chave_sawadm()
    lista_chaves_publicas = fred.getPeersPKeys()
    lista_peers_ip = fred.getPeerIPs() 
 
    is_genesis = False
    genesis_node_ip = fred.ip_genesis
    meu_ip = get_meu_ip()
    if meu_ip == genesis_node_ip:
        is_genesis = True

    for chave in fred.lista_peers:
        lista_chaves_str += chave

    # criar_chave.. adicionar ao fred
    porta_blockchain = criar_blockchain_api(nome_blockchain, chaves_peers=lista_chaves_publicas, PEERS_IP=lista_peers_ip, is_genesis=is_genesis)
    blockchainManager.save_blockchain(fred.ip_src, fred.ip_dst, serverip,porta_blockchain)

    # isso deve ser feito fora dessa funcao
    # if not is_genesis:
    #     fred.addPeer(meu_ip, chave_publica,meu_ip+':'+porta_blockchain)
    #     # se sou borda destino, enviar a borda origem 
    #     enviar_msg(fred_json=fred.toString(), server_ip=genesis_node_ip, server_port=FRED_SERVER_PORT)
    
    return porta_blockchain
