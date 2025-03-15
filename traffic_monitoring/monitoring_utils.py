# campos identificadores do fluxo
# peer_monitor: ip
# qtd_pacotes monitorados
# sao 20 entradas (tempo_chegada, tamanho_pacote)


import json


class FlowMonitoring:

    def __init__(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, qtd_pacotes, monitor_name, lista_pkttimestamps:list[int], lista_pktsizes:list[int]):
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
