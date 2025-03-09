import sys
import time
from core.fp_constants import QTD_MONITORAMENTO
from fp_flow_monitoring import FlowMonitoring

# 5-tupla: [{"timestamp": "timestamp", "tamanho": "tamanho"}]
fluxos_monitorados = {}

def current_milli_time():
    return round(time.time() * 1000)


def monitorar_pacote(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, pkt):

    label = ip_ver + ip_src + ip_dst + src_port + dst_port + proto
    
    timestamp = current_milli_time()

    if label not in fluxos_monitorados.keys():
        fluxos_monitorados[label] = []

    # armazenar FlowMonitorings
    fluxos_monitorados[label].append( {"timestamp": timestamp, "tamanho": len(pkt)}  ) 

    # se eu for bordade origem
    if len(fluxos_monitorados[label]) >= QTD_MONITORAMENTO:
        #enviar_icmp para destino com o monitoramento
        fluxos_monitorados[label].clear()
        return True

    return False

def get_flow_monitorado(ip_ver, ip_src, ip_dst, src_port, dst_port, proto):

    label = ip_ver + ip_src + ip_dst + src_port + dst_port + proto

    return fluxos_monitorados[label]

def fazer_calculo_qos(flow_monitoring:FlowMonitoring):
    # se eu sou borda de destino

    # buscar o registro de qos armazenado em fluxos_monitorados
    # calcular as medias
    label = flow_monitoring.ip_ver + flow_monitoring.ip_src + flow_monitoring.ip_dst + flow_monitoring.src_port + flow_monitoring.dst_port + flow_monitoring.proto

    

    del fluxos_monitorados[label]

    return #retornar qos