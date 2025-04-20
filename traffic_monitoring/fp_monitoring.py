import sys
import time
from core.fp_constants import QTD_MONITORAMENTO
from traffic_monitoring.monitoring_utils import FlowMonitoring, MonitoringManager

# def current_milli_time():
#     return round(time.time() * 1000)


def monitorar_pacote(controller_id, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, pkt_len, monitoringmanager:MonitoringManager)->FlowMonitoring:

    label = "%d_%d_%s_%s_%d_%d" %(ip_ver,proto, ip_src, ip_dst, src_port, dst_port)
    
    timestamp = time.time()

    flow_monitoring = monitoringmanager.getMonitoring(label)

    if flow_monitoring == None:
        flow_monitoring = FlowMonitoring(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, 0, controller_id, [], [])

    # armazenar FlowMonitorings
    flow_monitoring.addMonitoring(pkt_len, timestamp)
    
    # se eu for bordade origem
    if flow_monitoring.qtd_pacotes == QTD_MONITORAMENTO:
        #enviar_icmp para destino com o monitoramento -- enviar fora disso no flowpri
        
        return flow_monitoring

    monitoringmanager.saveMonitoring(label, flow_monitoring)

    return None

def get_flow_monitorado(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, monitoringmanager:MonitoringManager):

    label = "%d_%s_%s_%d_%d_%d" %(ip_ver, ip_src, ip_dst, src_port, dst_port, proto)

    return monitoringmanager.getMonitoring(label)