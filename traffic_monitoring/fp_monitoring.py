import sys
import time
from core.fp_constants import QTD_MONITORAMENTO, IPV4_CODE, IPV6_CODE
from traffic_monitoring.monitoring_utils import FlowMonitoring, MonitoringManager
from core.fp_icmp import send_icmpv4, send_icmpv6

def current_milli_time():
    return round(time.time() * 1000)


def monitorar_pacote(controller, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, pkt, monitoringmanager:MonitoringManager)->FlowMonitoring:

    label = ip_ver +'_' + ip_src +'_' + ip_dst +'_' + src_port +'_' + dst_port +'_' + proto
    
    timestamp = current_milli_time()

    flow_monitoring = monitoringmanager.getMonitoring(label)

    if flow_monitoring == None:
        flow_monitoring = FlowMonitoring(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, 0, controller.CONTROLADOR_ID, [], [])

    # armazenar FlowMonitorings
    flow_monitoring.addMonitoring(len(pkt), timestamp)
    
    # se eu for bordade origem
    if flow_monitoring.qtd_pacotes >= QTD_MONITORAMENTO:
        #enviar_icmp para destino com o monitoramento -- enviar fora disso no flowpri
        
        return monitoringmanager.delMonitoring(label)

    monitoringmanager.saveMonitoring(label, flow_monitoring)

    return None

def get_flow_monitorado(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, monitoringmanager:MonitoringManager):

    label = ip_ver +'_' + ip_src +'_' + ip_dst +'_' + src_port +'_' + dst_port +'_' + proto

    return monitoringmanager.getMonitoring(label)