
import os
import sys
current = os.path.dirname(os.path.realpath(__file__))

# Getting the parent directory name
# where the current directory is present.
parent = os.path.dirname(current)

# adding the parent directory to 
# the sys.path.
sys.path.append(parent)

import socket
import json
from host.host_qosblockchain.fp_api_qosblockchain import criar_blockchain_api, BlockchainManager,get_meu_ip, criar_chave_sawadm, enviar_transacao_blockchain
from host.fp_fred import Fred, fromJsonToFred, FredManager
from host.host_qosblockchain.processor.qos_state import FlowTransacao, QoSRegister
from host.host_traffic_monitoring.monitoring_utils import loadFlowMonitoringFromJson, MonitoringManager, calcular_qos
import time

FRED_SERVER_PORT = 9090

def calculate_network_prefix_ipv4(ip_v4:str):
    # supomos tudo /24 -> 192.168.1.10 -> 192.168.1.0
    prefix = ip_v4.split(".")

    return prefix[0]+"."+prefix[1]+"."+prefix[2]+".0"

def enviar_fred(fred_json, server_ip, server_port):
    print("Enviando fred para -> %s:%s\n" % (server_ip,server_port))

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect((server_ip, server_port))

    print(fred_json)
    vetorbytes = fred_json.encode("utf-8")
    tcp.send(len(vetorbytes).to_bytes(4, 'big'))
    print(tcp.send(vetorbytes))
    print('len: ', len(vetorbytes))    
    
    tcp.close()
    return 

def meu_dominio(ip_addrs:str, meu_ip:str):
    ### SOMENTE PARA IPv4 por enqunato, pq nao sei fazer isso para ipv6...
    if calculate_network_prefix_ipv4(meu_ip) == calculate_network_prefix_ipv4(ip_addrs):
        return True
    return False


def tratar_blockchain_setup(serverip:str, fred:Fred, blockchainManager:BlockchainManager ):
    nome_blockchain = calculate_network_prefix_ipv4(fred.ip_src) + "-" +  calculate_network_prefix_ipv4(fred.ip_dst)
                
    chave_publica, chave_privada = criar_chave_sawadm()
    lista_chaves_publicas = fred.getPeersPKeys()
    lista_peers_ip = fred.getPeerIPs() 
 
    is_genesis = False
    genesis_node_ip = fred.ip_genesis
    
    if serverip == genesis_node_ip:
        is_genesis = True

    # for chave in fred.lista_peers:
    #     lista_chaves_str += chave

    # criar_chave.. adicionar ao fred
    porta_blockchain = criar_blockchain_api(serverip, nome_blockchain, chaves_peers=lista_chaves_publicas, PEERS_IP=lista_peers_ip, is_genesis=is_genesis)
    blockchainManager.save_blockchain(fred.ip_src, fred.ip_dst, serverip,porta_blockchain)

    if not is_genesis:
        fred.lista_peers.append({"nome_peer":serverip, "chave_publica":chave_publica, "ip_porta":serverip+":"+str(porta_blockchain)})
        # se sou borda destino, enviar a borda origem 
        enviar_fred(fred_json=fred.toString(), server_ip=genesis_node_ip, server_port=FRED_SERVER_PORT)


def tratar_flow_monitoring(meu_ip, flow_monitoring_json, blockchainManager:BlockchainManager, fredmanager:FredManager, monitoringmanager:MonitoringManager):
# tratar o flow monitoring recebido + criar transação para a blockchain
    initime = time.time()
    print('[trat-flow-monitoring] init:', initime)
    flow_monitoring_recebido = loadFlowMonitoringFromJson(flow_monitoring_json)

    nome_fred = flow_monitoring_recebido.ip_ver +"_"+ flow_monitoring_recebido.proto+"_"+flow_monitoring_recebido.ip_src+"_"+flow_monitoring_recebido.ip_dst+"_"+flow_monitoring_recebido.src_port+"_"+flow_monitoring_recebido.dst_port
    fred_flow = fredmanager.get_fred(nome_fred)

    #calcular as medias para atraso, banda e perda
    flow_monitoring_local = monitoringmanager.getMonitoring(nome_fred)
    
    # precisa receber dois para fazer o calculo
    if flow_monitoring_local == None:
        monitoringmanager.saveMonitoring(nome_fred, flow_monitoring_recebido)
        return

    # ja havia recebido um flow monitoring antes
    qos_calculado = calcular_qos(flow_monitoring_local, flow_monitoring_recebido)

    #remover monitoramento anterior
    monitoringmanager.delMonitoring(nome_fred)

    blockchain_ip_porta = blockchainManager.get_blockchain(flow_monitoring_recebido.ip_dst)
    
    # criar_transacao_blockchain()
    if blockchain_ip_porta:
        blockchain_ip = blockchain_ip_porta.split(':')[0]
        blockchain_porta = blockchain_ip_porta.split(':')[1]

        qosregister = QoSRegister(nodename=meu_ip, route_nodes=fred_flow.lista_rota, blockchain_nodes=fred_flow.lista_peers, state=1, service_label=fred_flow.classe,application_label=fred_flow.label, req_bandwidth=fred_flow.bandiwdth, req_delay=fred_flow.delay, req_loss=fred_flow.loss, req_jitter=fred_flow.jitter, bandwidth=qos_calculado['bandwidth'], delay=qos_calculado['delay'], loss=qos_calculado['loss'], jitter=qos_calculado['jitter'])
        # faltou informacoes para montar o qosreg == req_qoss  -> ou vem do fred, ou vem do proprio flowmonitoring, melhor vir do flowmonitoring
        transacao = FlowTransacao(flow_monitoring_recebido.ip_src, flow_monitoring_recebido.ip_dst, flow_monitoring_recebido.ip_ver, flow_monitoring_recebido.src_port, flow_monitoring_recebido.dst_port, flow_monitoring_recebido.proto, qosregister)

        print("[trat-flow-monitoring] enviando transacao ", time.time())
        enviar_transacao_blockchain(flowname=nome_fred, ip_blockchain=blockchain_ip, port_blockchain=blockchain_porta, transacao=transacao)
        print("[trat-flow-monitoring] transacao enviada ", time.time())
        return True
    
    endtime = time.time()
    print('[trat-flow-monitoring] end:', initime, ' duracao:', endtime - initime)
    return False

def host_server(serverip, serverport, blockchainManager:BlockchainManager, fredmanager:FredManager, monitoringmanager:MonitoringManager):
    print("Iniciando servidor de Freds (%s:%d)....\n" % (serverip, serverport))

    #with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #um desses funfa
    tcp.bind((serverip, serverport))

    tcp.listen(5)

    while True:
        print("Esperando nova conexao ...")
        conn, addr = tcp.accept()
        initime = time.time()
        print("[management-server] init ", initime)
        data_qtd_bytes:int = int.from_bytes(conn.recv(4),'big')
        data = conn.recv(data_qtd_bytes).decode()
        
        conn.close()

        
        print('Recebido de ', addr)
        print('qtd bytes data:',data_qtd_bytes)
        print('json:',data)
        # continue

        data_json = json.loads(data)
        if "FRED" in data_json:
            print('[management-server] fred recebido')
            fred = fromJsonToFred(data_json)
          
            
            # verificar se ja existe uma blockcahin para este fluxo
            # se ja existe, fazer nada -> era para dizer que o fluxo esta ativo, mas nao precisa...
            nome_fred = str(fred.ip_ver) +"_"+ str(fred.proto)+"_"+fred.ip_src+"_"+fred.ip_dst+"_"+str(fred.src_port)+"_"+str(fred.dst_port)
            fredmanager.save_fred(nome_fred, fred)
            if blockchainManager.get_blockchain(calculate_network_prefix_ipv4(fred.ip_src), calculate_network_prefix_ipv4(fred.ip_dst)) != None:
                print("blockchain existente... ignorando")
                # nao precisa atualizar o fred, pq quando ocorrer um monitoramento, a blockchain vai ser atualizada com os requisitos e obtidos para QoS
                # logo, vamos apenas ignorar, neste caso
            else:
                tratar_blockchain_setup(serverip, fred, blockchainManager)
            
            print('[management-server] fred terminado')
            
        elif "Monitoring" in data_json:
            print("[management-server] flow monitoring recebido")
            flow_monitoring = loadFlowMonitoringFromJson(data_json)
            # receber o flow monitoring -> armazenar em flowmonitorings, mas caso ja exista um armazenado, fazer o calculo do qos e retornar um dicionario de qos -> caso contrario retornar null
            tratar_flow_monitoring(flow_monitoring, blockchainManager, fredmanager, monitoringmanager)
            print("[management-server] flow monitoring end")
        endtime= time.time()
        print("[management-server]  end:", endtime, ' duracao:',endtime - initime)

    
if __name__ == "__main__":
    blockchainManager = BlockchainManager()
    fredmanager = FredManager()
    monitoringmanager = MonitoringManager()
    SERVER_IP = get_meu_ip()
    # SERVER_IP = '172.16.3.50'
    print("Management host iniciado: host %s!" %(SERVER_IP))
    host_server(SERVER_IP, FRED_SERVER_PORT, blockchainManager, fredmanager, monitoringmanager)