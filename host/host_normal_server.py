import sys
import socket
import json
from traffic_monitoring.monitoring_utils import start_monitoring

FRED_SERVER_PORT = 5555

if __name__ == "__main__":

    ### rotina: 
    # monitorar fluxos
    # juntou os pacotes necessarios -> montar o flowmonitoring e enviar ao host management

    if len(sys.argv) < 2:
        print("Modo de uso: host_normal_server.py <ip-management-host>")

    ip_management_host = sys.argv[1]
    
    start_monitoring(ip_management_host)