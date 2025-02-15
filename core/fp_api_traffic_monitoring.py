import sys

sys.path.append('../traffic_classification')

from fp_utils import current_milli_time
from fp_constants import fluxos_monitorados

def monitorar_pacote(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, pkt):

    label = ip_ver + ip_src + ip_dst + src_port + dst_port + proto
    
    timestamp = current_milli_time()

    fluxos_monitorados[label].append( {"timestamp": timestamp, "tamanho": len(pkt)}  ) 

    return

def get_flow_monitorado(ip_ver, ip_src, ip_dst, src_port, dst_port, proto):

    label = ip_ver + ip_src + ip_dst + src_port + dst_port + proto

    return fluxos_monitorados[label]