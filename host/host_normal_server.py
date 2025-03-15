import sys
import socket
import json
from host_flow_monitoring.host_monitoring import start_monitoring
from host_qosblockchain.processor.qos_state import FlowTransacao, QoSRegister
from traffic_monitoring.monitoring_utils import loadFlowMonitoringFromJson, FlowMonitoring

FRED_SERVER_PORT = 5555

if __name__ == "__main__":

    ### rotina: 
    # monitorar fluxos
    # juntou os pacotes necessarios -> montar o flowmonitoring e enviar ao host management

    if len(sys.argv) < 2:
        print("Modo de uso: host_normal_server.py <ip-management-host>")

    ip_management_host = sys.argv[1]

    
    start_monitoring(ip_management_host)