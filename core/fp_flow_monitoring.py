# campos identificadores do fluxo
# peer_monitor: ip
# qtd_pacotes monitorados
# sao 20 entradas (tempo_chegada, tamanho_pacote)


import json


class Register:

    def __init__(self,timestamp, pktsize):
        self.timestamp = timestamp
        self.pktsize = pktsize

    def toString(self):
        return '{ "timestamp": "%s", "pktsize": %d }' % (self.timestamp, self.pktsize)

class FlowMonitoring:

    def __init__(self, ip_ver, ip_src, ip_dst, port_src, port_dst, proto, qtd_pacotes, peer_monitor, lista_pacotes:list[Register]):
        self.ip_ver=ip_ver
        self.ip_src=ip_src
        self.ip_dst=ip_dst
        self.port_src=port_src
        self.port_dst=port_dst
        self.proto=proto
        self.qtd_pacotes = qtd_pacotes
        self.peer_monitor = peer_monitor
        self.lista_pacotes = lista_pacotes

    def addRegister(self, register:Register):
        self.qtd_pacotes+=1
        self.lista_pacotes.append(register)

    def toString(self):

        retorno = '{ "Monitoring": { "ip_src": "%s", "ip_dst": "%s", "src_port": "%s", "dst_port": "%s", "proto": "%s", "qtd_pacotes": %d, "peer_monitor": "%s", "lista_pacotes": ['

        lista_pacotes = ""
        for l in self.lista_pacotes:
            lista_pacotes+= "," + l.toString()

        retorno+= lista_pacotes.removeprefix(',') + "]} }"

        return retorno

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
        peer_monitor = _monitoring["peer_monitor"]
        lista_pacotes = _monitoring["lista_pacotes"]

        lista_register = []
        for val in lista_pacotes:
            lista_register.append( Register(val["timestamp"], val["pktsize"]) )

    except:
        raise SyntaxError("Error loading Monitoring from JSON !")

    return FlowMonitoring(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, qtd_pacotes, peer_monitor, lista_register)


#{"Monitoring":{...}}