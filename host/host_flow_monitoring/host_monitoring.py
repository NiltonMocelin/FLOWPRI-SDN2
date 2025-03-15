# source: https://python-libpcap.readthedocs.io/en/latest/
# Requirements:
# sudo apt-get install libpcap-dev
# pip install python-libpcap

from pylibpcap.pcap import sniff
from scapy.all import Ether
from traffic_monitoring.monitoring_utils import loadFlowMonitoringFromJson
from host_qosblockchain.fp_api_qosblockchain import BlockchainManager, enviar_transacao_blockchain
from traffic_monitoring.monitoring_utils import FlowMonitoring

class QoSRegister:
    def __init__(self, lbanda:int, atraso:float, taxaperda:float, jitter:float):
        self.lbanda = lbanda
        self.atraso = atraso
        self.taxaperda = taxaperda
        self.jitter = jitter
    
    def toString(self):
        return '{"lbanda":%d, "atraso":%.2f, "taxaperda":%.2f, "jitter":%.2f}' % (self.lbanda, self.atraso, self.taxaperda)

def fromJsonToQoSRegister(qos_json:dict):
    lbanda = qos_json['bandwidth']
    atraso = qos_json['delay']
    taxaperda = qos_json['loss']
    jitter = qos_json['jitter']
    return QoSRegister(lbanda, atraso, taxaperda, jitter)

def calcular_qos(flow_monitoring_local:FlowMonitoring, flow_monitoring_recebido:FlowMonitoring):
    # largura de banda = soma_tam_pkts/tempo_final - tempo_inicial
    # perda = qtd_pacotes_obtida/qtd_pacotes_esperada
    # atraso = soma(temp_pkti_local - temp_pkti_recv)/qtd_pacotes

    # verificar se os dois monitoramentos sao do mesmo fluxo
    if flow_monitoring_local.ip_dst != flow_monitoring_recebido.ip_dst or flow_monitoring_local.ip_src != flow_monitoring_recebido.ip_src or flow_monitoring_local.src_port != flow_monitoring_recebido.src_port or flow_monitoring_local.dst_port != flow_monitoring_recebido.dst_port or flow_monitoring_local.proto != flow_monitoring_recebido.proto or flow_monitoring_local.ip_ver != flow_monitoring_recebido.ip_ver:
        print("[calcqos] Fluxos diferentes")
        return None

    if flow_monitoring_local.qtd_pacotes!= flow_monitoring_recebido.qtd_pacotes:
        # identificar qual pacote esta faltando
        print()
    for registrolocal, registrorecebido in zip(flow_monitoring_local.lista_registros, flow_monitoring_recebido.lista_registros):
        print()
    lbanda, atraso, taxaperda, jitter = 0
    return QoSRegister(lbanda, atraso, taxaperda, jitter)

def start_monitoring(ip_management_host:str):
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
    monitoring_mark = 0x7
    ipv4_dscp_monitoring_filter = "(ip and (ip[1] & 0xfc) >> 2 == %d)" % (monitoring_mark)
    ipv6_flow_label_monitoring_filter = "(ip6 and ip[3]  == %d)" % (monitoring_mark)
    for plen, t, buf in sniff("eth0", filters="(%s or %s)" % (ipv4_dscp_monitoring_filter, ipv6_flow_label_monitoring_filter), count=-1, promisc=0):

        # se for um pacote marcado, busca no dicionario e adiciona
        # se tiver 10, cria uma thread para calcular as métricas >> receber do controlador as métricas dele (sincronizar) calcular a media, enviar a blockchain.

        # checar tos ipv4 ou flowlabel ipv6, se for QoSMONITORING, armazenar em um pcap

        # se tiver 20 pacotes nesse arquivo, extrair features para calculo

        # extrair: ip_Ver, proto, ip_src, ip_dst, src_port, dst_port
        # obter: timestamp, len(packet)
        # adicionar ao local_flowmonitorings_dict[str(ip_ver)+"_"+str(proto)+"_"+ip_src +"_"+ ip_dst +"_"+ src_port +"_"+ dst_port]

        # se tiver 20 pacotes --> enviar o local_flowmonitorings_dict[*] para o management_host usando thread

        print("[+]: Payload len=", plen)
        print("[+]: Time", t)
        print("[+]: Payload", buf)

    # uma thread para ler qos monitoring json dos domínios.
