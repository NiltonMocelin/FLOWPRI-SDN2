
import os
import sys
from threading import Thread

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
from host.host_traffic_monitoring.monitoring_utils import loadFlowMonitoringFromJson, MonitoringManager, calcular_qos, current_milli_time
# import time

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

    if lista_peers_ip == []:
        print("Lista Pares vazia == nao deve criar blockchain")
        return
 
    is_genesis = False
    genesis_node_ip = fred.ip_genesis
    
    if serverip == genesis_node_ip:
        is_genesis = True

    # for chave in fred.lista_peers:
    #     lista_chaves_str += chave

    print("para os experimentos com virt namespaces")
    ip_partes = serverip.split('.')
    serverip = '%s.%s.%s.50' % (ip_partes[0],ip_partes[1],ip_partes[2])

    ip_blockchain,porta_network,porta_rest = blockchainManager.get_blockchain(calculate_network_prefix_ipv4(fred.ip_src), calculate_network_prefix_ipv4(fred.ip_dst))

    if ip_blockchain == None or is_genesis:
        # criar_chave.. adicionar ao fred
        porta_network, porta_rest = criar_blockchain_api(serverip, nome_blockchain, blockchainManager, chaves_peers=lista_chaves_publicas, PEERS_IP=lista_peers_ip, is_genesis=is_genesis)

        blockchainManager.save_blockchain(calculate_network_prefix_ipv4(fred.ip_src), calculate_network_prefix_ipv4(fred.ip_dst), serverip, porta_network, porta_rest)
        if porta_network:
            print("[blkc-setup]Blockchain criada: nome: %s, porta_network:%d, porta_rest:%d" % (nome_blockchain, porta_network, porta_rest))
        else:
            print("[blkc-setup]Erro ao criar blockchain  nome: %s, porta_network:%d, porta_rest:%d" % (nome_blockchain, porta_network, porta_rest))
        if not is_genesis:
            fred.addPeer(serverip, chave_publica, serverip+':'+str(porta_network))
            # se sou borda destino, enviar a borda origem 
            enviar_fred(fred_json=fred.toString(), server_ip=genesis_node_ip, server_port=FRED_SERVER_PORT)
    else:
        print("Blockchain existente %s->%s %s:%d(network) %d(rest)" %(fred.ip_src, fred.ip_dst, ip_blockchain, porta_network,porta_rest))


def tratar_flow_monitoring(meu_ip, flow_monitoring_recebido, blockchainManager:BlockchainManager, fredmanager:FredManager, monitoringmanager:MonitoringManager):
# tratar o flow monitoring recebido + criar transação para a blockchain
    initime = current_milli_time()
    print('[trat-flow-monitoring] init:', initime)
    
    nome_fred = str(flow_monitoring_recebido.ip_ver) +"_"+ str(flow_monitoring_recebido.proto)+"_"+flow_monitoring_recebido.ip_src+"_"+flow_monitoring_recebido.ip_dst+"_"+str(flow_monitoring_recebido.src_port)+"_"+str(flow_monitoring_recebido.dst_port)
    fred_flow = fredmanager.get_fred(nome_fred)

    #calcular as medias para atraso, banda e perda
    flow_monitoring_local = monitoringmanager.getMonitoring(nome_fred)
    
    print("Aqui 1")
    # precisa receber dois para fazer o calculo
    if flow_monitoring_local == None:
        monitoringmanager.saveMonitoring(nome_fred, flow_monitoring_recebido)
        return

    print("Aqui 2")
    # ja havia recebido um flow monitoring antes
    qos_calculado = calcular_qos(flow_monitoring_local, flow_monitoring_recebido)

    print("Aqui 3")
    #remover monitoramento anterior
    monitoringmanager.delMonitoring(nome_fred)

    print("Aqui 4")
    blockchain_ip, porta_network, porta_rest = blockchainManager.get_blockchain(calculate_network_prefix_ipv4(flow_monitoring_recebido.ip_src), calculate_network_prefix_ipv4(flow_monitoring_recebido.ip_dst))
    print("Aqui 5")
    # criar_transacao_blockchain()
    if blockchain_ip:
        print('criando qosreg')
        qosregister = QoSRegister(nodename=meu_ip, route_nodes=fred_flow.lista_rota, blockchain_nodes=fred_flow.lista_peers, state=1, service_label=fred_flow.classe,application_label=fred_flow.label, req_bandwidth=fred_flow.bandwidth, req_delay=fred_flow.delay, req_loss=fred_flow.loss, req_jitter=fred_flow.jitter, bandwidth=qos_calculado['bandwidth'], delay=qos_calculado['delay'], loss=qos_calculado['loss'], jitter=qos_calculado['jitter'])
        print('criando transacao')
        # faltou informacoes para montar o qosreg == req_qoss  -> ou vem do fred, ou vem do proprio flowmonitoring, melhor vir do flowmonitoring
        transacao = FlowTransacao(flow_monitoring_recebido.ip_src, flow_monitoring_recebido.ip_dst, flow_monitoring_recebido.ip_ver, flow_monitoring_recebido.src_port, flow_monitoring_recebido.dst_port, flow_monitoring_recebido.proto, [qosregister])

        print("[trat-flow-monitoring] enviando transacao ", current_milli_time())
        Thread(target=enviar_transacao_blockchain, args=[nome_fred, blockchain_ip, porta_rest, transacao]).start()
        print("[trat-flow-monitoring] transacao enviada ", current_milli_time())
        return True
    
    endtime = current_milli_time()
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
        initime = current_milli_time()
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
          
            tratar_blockchain_setup(serverip, fred, blockchainManager)
            
            print('[management-server] fred terminado')
            
        elif "Monitoring" in data_json:
            print("[management-server] flow monitoring recebido")
            flow_monitoring = loadFlowMonitoringFromJson(data_json)
            # receber o flow monitoring -> armazenar em flowmonitorings, mas caso ja exista um armazenado, fazer o calculo do qos e retornar um dicionario de qos -> caso contrario retornar null
            tratar_flow_monitoring(get_meu_ip(), flow_monitoring, blockchainManager, fredmanager, monitoringmanager)
            print("[management-server] flow monitoring end")
        endtime= current_milli_time()
        print("[management-server]  end:", endtime, ' duracao:',endtime - initime)

    
if __name__ == "__main__":
    blockchainManager = BlockchainManager()
    fredmanager = FredManager()
    monitoringmanager = MonitoringManager()
    SERVER_IP = get_meu_ip()
    # SERVER_IP = '172.16.3.50'
    print("Management host iniciado: host %s!" %(SERVER_IP))
    host_server(SERVER_IP, FRED_SERVER_PORT, blockchainManager, fredmanager, monitoringmanager)