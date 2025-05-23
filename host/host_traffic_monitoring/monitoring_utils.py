# campos identificadores do fluxo
# peer_monitor: ip
# qtd_pacotes monitorados
# sao 20 entradas (tempo_chegada, tamanho_pacote)


import json
from pylibpcap.pcap import sniff
from scapy.all import Ether, IP
# import socket
from threading import Thread
from host.fp_fred import FredManager
from host.host_qosblockchain.fp_api_qosblockchain import criar_blockchain_api, BlockchainManager,get_meu_ip, criar_chave_sawadm, enviar_transacao_blockchain
from host.host_qosblockchain.processor.qos_state import FlowTransacao, QoSRegister
import socket
import time
import pickle
import struct


def current_milli_time():
    return round(time.time() * 1000)

def send_data(conn, data):
    serialized_data = pickle.dumps(data)
    conn.sendall(struct.pack('>I', len(serialized_data)))
    conn.sendall(serialized_data)

def enviar_msg(msg_str, server_ip, server_port):
    print("Enviando msg_str para -> %s:%s\n" % (server_ip,server_port))

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect((server_ip, server_port))

    print(msg_str)

    send_data(tcp, msg_str)
        
    tcp.close()
    return 

class FlowMonitoring:

    def __init__(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, qtd_pacotes, monitor_name, lista_pkttimestamps:list, lista_pktsizes:list):
        self.ip_ver=ip_ver
        self.ip_src=ip_src
        self.ip_dst=ip_dst
        self.src_port=src_port
        self.dst_port=dst_port
        self.proto=proto
        self.qtd_pacotes = qtd_pacotes
        self.monitor_name = monitor_name
        self.lista_pkttimestamps = lista_pkttimestamps
        self.lista_pktsizes = lista_pktsizes

    def toString(self):

        retorno = { "Monitoring": { "ip_src": self.ip_src, "ip_dst": self.ip_dst, "src_port": self.src_port, "dst_port": self.dst_port, "proto": self.proto, "qtd_pacotes": self.qtd_pacotes, "monitor_name": self.monitor_name, "timestamps": self.lista_pkttimestamps, "pktsizes": self.lista_pktsizes}}
    
        return json.dumps(retorno)
    
    def addMonitoring(self, pktsize, timestamp):
        self.lista_pktsizes.append(pktsize)
        self.lista_pkttimestamps.append(timestamp)
        self.qtd_pacotes+=1
        return

def loadFlowMonitoringFromJson(monitoring_json):

    try:
        _monitoring = monitoring_json["Monitoring"] 
        ip_ver = _monitoring["ip_ver"]
        proto = _monitoring["proto"]
        ip_src = _monitoring["ip_src"]
        ip_dst = _monitoring["ip_dst"]
        src_port = _monitoring["src_port"]
        dst_port = _monitoring["dst_port"]
        qtd_pacotes = _monitoring["qtd_pacotes"]
        monitor_name = _monitoring["monitor_name"]
        lista_tempos = _monitoring["timestamps"]
        lista_tamanhos = _monitoring["pktsizes"]

    except:
        raise SyntaxError("Error loading Monitoring from JSON !")

    return FlowMonitoring(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, qtd_pacotes, monitor_name, lista_tempos, lista_tamanhos)

class MonitoringManager:
    def __init__(self):
        self.monitorings = {}

    def saveMonitoring(self, nome:str, flowmonitoring:FlowMonitoring):
        self.monitorings[nome] = flowmonitoring

    def getMonitoring(self, nome:str):
        return self.monitorings.get(nome, None) # fazer isso em todos os get para dicionarios ...

    def delMonitoring(self, nome:str):
        return self.monitorings.pop(nome,None)
    

## tamo aqui
def calcular_qos(flow_monitoring_local:FlowMonitoring, flow_monitoring_recebido:FlowMonitoring):
    # largura de banda = soma_tam_pkts/tempo_final - tempo_inicial
    # perda = qtd_pacotes_obtida/qtd_pacotes_esperada
    # atraso = soma(temp_pkti_local - temp_pkti_recv)/qtd_pacotes

    # verificar se os dois monitoramentos sao do mesmo fluxo => isso deve ser realizado antes
    # if flow_monitoring_local.ip_dst != flow_monitoring_recebido.ip_dst or flow_monitoring_local.ip_src != flow_monitoring_recebido.ip_src or flow_monitoring_local.src_port != flow_monitoring_recebido.src_port or flow_monitoring_local.dst_port != flow_monitoring_recebido.dst_port or flow_monitoring_local.proto != flow_monitoring_recebido.proto or flow_monitoring_local.ip_ver != flow_monitoring_recebido.ip_ver:
    #     print("[calcqos] Fluxos diferentes")
    #     return None
    qtd_pacotes_esperada = 20
    atraso = 0
    qtd_pacotes_obitda = flow_monitoring_recebido.qtd_pacotes
    if flow_monitoring_local.qtd_pacotes < flow_monitoring_recebido.qtd_pacotes:
        qtd_pacotes_obitda = flow_monitoring_local.qtd_pacotes
           
    atraso_pacotes = []
    soma_pacotes_local = 0
    soma_pacotes_recebido = 0
    
    for i in range(0, qtd_pacotes_obitda):
        soma_pacotes_local += flow_monitoring_local.lista_pktsizes[i]
        soma_pacotes_recebido += flow_monitoring_recebido.lista_pktsizes[i]

        atraso_pacotes.append(flow_monitoring_local.lista_pkttimestamps[i] - flow_monitoring_recebido.lista_pkttimestamps[i])

    for tempo in atraso_pacotes:
        atraso += tempo

    soma_pacotes_local = int(soma_pacotes_local/qtd_pacotes_obitda)
    soma_pacotes_recebido = int(soma_pacotes_recebido/qtd_pacotes_obitda)
    
    lbanda = soma_pacotes_recebido if soma_pacotes_recebido < soma_pacotes_local else soma_pacotes_local
    atraso = int(atraso/qtd_pacotes_obitda)
    jitter = 0
    taxaperda = int((1- qtd_pacotes_obitda/qtd_pacotes_esperada)*10) if qtd_pacotes_obitda != 0 else 0

    # jitter soma das diferencas entre |atraso1 e atraso2| / qtd_pacotes_recebido
    jitter = 0
    for i in range(1, qtd_pacotes_obitda):
        jitter += abs(atraso_pacotes[i-1]-atraso_pacotes[i])
    jitter = int(jitter / qtd_pacotes_obitda)
    return {'bandwidth':lbanda, 'delay':atraso, 'loss':taxaperda,'jitter': jitter}


def send_flowmonitoring(flowmonitoring:FlowMonitoring, server_ip:str, server_port:int):
    print("Enviando flowmonitoring para %s:%d", server_ip, server_port)
    Thread(target=enviar_msg, args=[flowmonitoring.toString(), server_ip, server_port]).start()
    return 

def tratar_flow_monitoring(meu_ip, flow_monitoring_recebido:FlowMonitoring, blockchainManager:BlockchainManager, fredmanager:FredManager, monitoringmanager:MonitoringManager):
# tratar o flow monitoring recebido + criar transação para a blockchain
    
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

    blockchain_ip_porta = blockchainManager.get_blockchain(flow_monitoring_recebido.ip_src, flow_monitoring_recebido.ip_dst)
    
    # criar_transacao_blockchain()
    if blockchain_ip_porta:
        blockchain_ip = blockchain_ip_porta.split(':')[0]
        blockchain_porta = blockchain_ip_porta.split(':')[1]

        qosregister = QoSRegister(nodename=meu_ip, route_nodes=fred_flow.lista_rota, blockchain_nodes=fred_flow.lista_peers, state=1, service_label=fred_flow.classe,application_label=fred_flow.label, req_bandwidth=fred_flow.bandiwdth, req_delay=fred_flow.delay, req_loss=fred_flow.loss, req_jitter=fred_flow.jitter, bandwidth=qos_calculado['bandwidth'], delay=qos_calculado['delay'], loss=qos_calculado['loss'], jitter=qos_calculado['jitter'])
        # faltou informacoes para montar o qosreg == req_qoss  -> ou vem do fred, ou vem do proprio flowmonitoring, melhor vir do flowmonitoring
        transacao = FlowTransacao(flow_monitoring_recebido.ip_src, flow_monitoring_recebido.ip_dst, flow_monitoring_recebido.ip_ver, flow_monitoring_recebido.src_port, flow_monitoring_recebido.dst_port, flow_monitoring_recebido.proto, qosregister)

        enviar_transacao_blockchain(flowname=nome_fred, ip_blockchain=blockchain_ip, port_blockchain=blockchain_porta, transacao=transacao)
        return True
    else:
        print("[trat-flow-monitor] Erro, blockchain não encontrada para : src:", flow_monitoring_recebido.ip_src, " - dst:", flow_monitoring_recebido.ip_dst)
    
    return False


def start_monitoring(ip_management_host:str, port_management_host:int, meu_ip:str, interface:str):
    local_flowmonitorings_dict = {} 

    # 'tupla-id:lista[(pacote, timestamp)]'

    #for plen, t, buf in sniff("enp7s0", filters="port 53", count=-1, promisc=1, out_file="pcap.pcap"):
    # for plen, t, buf in sniff("eth0", filters="(ip and (ip[1] & 0xfc) >> 2 == 20)", count=-1, promisc=0):
    # dscp filter base: http://darenmatthews.com/blog/?p=1199 (same as in tcpdump)

    # replicating for flow label (ipv6)
    # ipv6 flow label is the bits from 12-20 ;; ipv6 flow class is from bits 4-8 (we are using the flow label bits for marking packets for classification)
    # filters = "(ip and (ip[]))" ---> as we use the number 7 as the mark in the packets, we just need to check the first 3 bits of the flow label

    # IPV6 header (small frame)
    # |   1   2  3  4  |       5  6  7 8 1 2 3 4     |5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8|
    # |--------------------------------------------------------------------------------------|
    # |  version (4)   | Traffic class (8)           |               Flow label (20)         |
    # |--------------------------------------------------------------------------------------|

    # we can just take the 3th byte of the header (16-32), then, compare to the mask of the bitlike 7 (0111)(actually, unnecessary)
    # filters = "(ip and ip[3]  == 0x7)"
    # for plen, t, buf in sniff("eth0", filters="(ip and ip[3]  == 0x7) ", count=-1, promisc=0):

    qos_marks = [50,51,52,53,54,55] # sim, agora virou uma lista de valores ..., que sao os mesmos para ipv4 e ipv6
    
    # monitoring_mark = 0x7
    QTD_PACOTES = 20
    ipv4_dscp_monitoring_filter = "(ip and ((ip[1] & 0xfc) >> 2 == %d or (ip[1] & 0xfc) >> 2 == %d or (ip[1] & 0xfc) >> 2 == %d or (ip[1] & 0xfc) >> 2 == %d or (ip[1] & 0xfc) >> 2 == %d or (ip[1] & 0xfc) >> 2 == %d))" % (qos_marks[0],qos_marks[1],qos_marks[2],qos_marks[3],qos_marks[4],qos_marks[5])
    ipv6_flow_label_monitoring_filter = "(ip6 and (ip[3]  == %d or ip[3]  == %d or ip[3]  == %d or ip[3]  == %d or ip[3]  == %d or ip[3]  == %d))" % (qos_marks[0],qos_marks[1],qos_marks[2],qos_marks[3],qos_marks[4],qos_marks[5])
    filter0 = ipv4_dscp_monitoring_filter + " or "+ ipv6_flow_label_monitoring_filter

    filter0 = "ip"
    print("Monitoramento iniciado: host %s!" %(meu_ip))
    for plen, t, buf in sniff(interface, filters=ipv4_dscp_monitoring_filter, count=-1, promisc=0):

        # se for um pacote marcado, busca no dicionario e adiciona
        # se tiver 10, cria uma thread para calcular as métricas >> receber do controlador as métricas dele (sincronizar) calcular a media, enviar a blockchain.

        # checar tos ipv4 ou flowlabel ipv6, se for QoSMONITORING, armazenar em um pcap

        # se tiver 20 pacotes nesse arquivo, extrair features para calculo

        # extrair: ip_Ver, proto, ip_src, ip_dst, src_port, dst_port
        # obter: timestamp, len(packet)
        # adicionar ao local_flowmonitorings_dict[str(ip_ver)+"_"+str(proto)+"_"+ip_src +"_"+ ip_dst +"_"+ src_port +"_"+ dst_port]

        # se tiver 20 pacotes --> enviar o local_flowmonitorings_dict[*] para o management_host usando thread
        
        ip_pkt = Ether(buf).getlayer(IP)
        if not ip_pkt:
            continue
        # print(ip_pkt.src, ip_pkt.dst, ip_pkt.version, ip_pkt.proto)
        # print("[+]: Payload len=", plen)
        # print("[+]: Time", t)
        # print("[+]: Payload", buf)
        nome_fluxo = str(ip_pkt.version) + "_"+ str(ip_pkt.proto) + "_"+ ip_pkt.src + "_"+ ip_pkt.dst + "_"+ str(ip_pkt.sport) + "_"+str(ip_pkt.dport)
        print(nome_fluxo, t, plen)

        flowmonitoring = local_flowmonitorings_dict.get(nome_fluxo, None)
        if not flowmonitoring:
            flowmonitoring = FlowMonitoring(ip_ver=ip_pkt.version, ip_src=ip_pkt.src, ip_dst=ip_pkt.dst, src_port=ip_pkt.sport, dst_port=ip_pkt.dport, proto=ip_pkt.proto, qtd_pacotes=0, monitor_name=meu_ip, lista_pktsizes=[], lista_pkttimestamps=[])
            local_flowmonitorings_dict[nome_fluxo] = flowmonitoring

        #adiciona os dados
        # verifica se ja possui 20 pkts
        # se ja existe 20 -> remove o monitoramento do dicionario e manda para o management host.
        flowmonitoring.qtd_pacotes += 1
        flowmonitoring.lista_pktsizes.append(plen)
        flowmonitoring.lista_pkttimestamps.append(t)
        
        if flowmonitoring.qtd_pacotes >= QTD_PACOTES:
            print("enviando monitoring tempo: ", current_milli_time())
            send_flowmonitoring(flowmonitoring, ip_management_host, port_management_host)
            del local_flowmonitorings_dict[nome_fluxo]