import sys
import socket
import json
from netifaces import AF_INET, ifaddresses, interfaces

import os
import sys
current = os.path.dirname(os.path.realpath(__file__))

# Getting the parent directory name
# where the current directory is present.
parent = os.path.dirname(current)

# adding the parent directory to 
# the sys.path.
sys.path.append(parent)

from host.host_traffic_monitoring.monitoring_utils import start_monitoring
def get_meu_ip():

    interfs=interfaces()
    interfs.remove('lo')
    interface =  interfs[0]

    IPCv4 = str(ifaddresses(interface)[AF_INET][0]['addr'])
    
    IPCv6 = str(ifaddresses(interface)[10][0]['addr'].split("%")[0])
    if IPCv4 != "" and IPCv4 != None:
        return IPCv4
    return IPCv6

def get_minha_interface():
    interfs=interfaces()
    interfs.remove('lo')
    return interfs[0]

PORT_MANAGEMENT_HOST = 9090

if __name__ == "__main__":

    ### rotina: 
    # monitorar fluxos
    # juntou os pacotes necessarios -> montar o flowmonitoring e enviar ao host management

    ip_management_host = get_meu_ip()
    print("Neste caso o management host eh esse aqui: se nao for, alterar o ip management host aqui!")
    
    start_monitoring(ip_management_host=ip_management_host,port_management_host=PORT_MANAGEMENT_HOST,meu_ip=ip_management_host, interface=get_minha_interface())