import sys
import time
from core.fp_constants import QTD_MONITORAMENTO

# 5-tupla: [{"timestamp": "timestamp", "tamanho": "tamanho"}]
fluxos_monitorados = {}

def current_milli_time():
    return round(time.time() * 1000)


def monitorar_pacote(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, pkt):

    label = ip_ver + ip_src + ip_dst + src_port + dst_port + proto
    
    timestamp = current_milli_time()

    fluxos_monitorados[label].append( {"timestamp": timestamp, "tamanho": len(pkt)}  ) 

    if len(fluxos_monitorados[label]) >= QTD_MONITORAMENTO:
        #enviar_icmp para destino com o monitoramento
        fluxos_monitorados[label].clear()
        return

    return

def get_flow_monitorado(ip_ver, ip_src, ip_dst, src_port, dst_port, proto):

    label = ip_ver + ip_src + ip_dst + src_port + dst_port + proto

    return fluxos_monitorados[label]