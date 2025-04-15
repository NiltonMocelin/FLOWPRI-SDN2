import json
# from fp_utils import current_milli_time
import threading
import time

class Fred:
    def __init__(self, code:int, blockchain_name:str, as_src_ip_range:list, as_dst_ip_range:list, ip_ver:int, proto:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, mac_src:str, 
                 mac_dst:str, prioridade:int,classe:int,bandwidth:int, loss:int, delay:int,jitter:int, label:str, ip_genesis:str, lista_peers:list, lista_rota:list):
        self.ip_ver:int = ip_ver
        self.proto:int = proto
        self.ip_src:str  = ip_src 
        self.ip_dst:str = ip_dst
        self.src_port:int = src_port
        self.dst_port:int = dst_port
        self.mac_src:str = mac_src
        self.mac_dst:str  = mac_dst 

        self.code:int = code
        
        self.prioridade:int = prioridade
        self.classe:int = classe
        self.bandwidth:int = bandwidth
        self.loss:int = loss
        self.delay:int = delay
        self.jitter:int  = jitter
        self.label:str = label

        self.blockchain_name:str = blockchain_name
        self.AS_src_ip_range:list = as_src_ip_range
        self.AS_dst_ip_range:list = as_dst_ip_range
        self.ip_genesis:str = ip_genesis
        self.lista_peers:list = lista_peers
        self.lista_rota:list = lista_rota

        self.timestamp = time.time()

        # lista_peers = lista[ dict1, dict 2]
        # (dict) um peer = {"nome_peer":"", "chave_publica":"", "ip_porta":"ip:porta"}
        # uma no da rota = {"ordem":"1", "nome_peer":"", "chave_publica":"", "nro_saltos(qtd_switches_rota)":""}
        
    def toString(self):
        freed = {"FRED": {"ip_ver":self.ip_ver, "proto":self.proto, "ip_src":self.ip_src, "ip_dst":self.ip_dst, "src_port":self.src_port, "dst_port":self.dst_port,
                          "mac_src":self.mac_src, "mac_dst":self.mac_dst, "priority":self.prioridade, "class":self.classe, "bandwidth":self.bandwidth,
                          "loss":self.loss, "delay":self.delay, "jitter":self.jitter, "label":self.label, "blockchain_name":self.blockchain_name,
                          "AS_src_ip_range":self.AS_src_ip_range, "AS_dst_ip_range":self.AS_dst_ip_range, "ip_genesis":self.ip_genesis,
                          "list_peers":self.lista_peers, "list_route":self.lista_rota, "code":self.code}}

        return json.dumps(freed)

    def getPeerIPs(self)->list:
        return [chave['ip_porta'] for chave in self.lista_peers]
    
    def getPeersPKeys(self) -> list:
        return [ip['chave_publica'] for ip in self.lista_peers]

    def getName(self):
        return str(self.ip_ver)+"_"+str(self.proto)+"_"+self.ip_src+"_"+self.ip_dst+"_"+str(self.src_port)+"_"+str(self.dst_port)

    def addNoh(self, nome_peer:str, chave_publica:str, nsaltos:int):
        """ordem":"1", "nome_peer":"", "chave_publica":"", "nro_saltos(qtd_switches_rota)":"""
        self.lista_rota.append({"ordem":len(self.lista_rota)+1, "nome_peer":nome_peer, "chave_publica":chave_publica, "nro_saltos":nsaltos})
        return
    
    def addPeer(self, nome_peer:str, chave_publica:str, ip_porta:str):
        """{nome_peer":"", "chave_publica":"", "ip_porta":"ip:porta}"""
        self.lista_peers.append({'nome_peer':nome_peer, 'chave_publica':chave_publica, 'ip_porta':ip_porta})
        return
def fromJsonToFred(fred_json):
    """{"FRED":{
    "ip_ver":"",
    "proto":"",
    "ip_src":"",
    "ip_dst":"",
    "src_port":"",
    "dst_port":"",
    "mac_src":"",
    "mac_dst":"",

    "code":"",
    
    "priority":"",
    "class":"",
    "bandwidth":"",
    "loss":"",
    "delay":"",
    "jitter":"",
    "label":"",

    "blockchain_name":"",
    "ASN_src":"",
    "ASN_dst":"",
    "AS_src_ip_range":[],
    "AS_dst_ip_range":[],
    "ip_genesis":"",
    "list_peers":[],
    "list_route":[]
    }}"""

    print("loading fred from json:", fred_json)
    try:
        _fred = fred_json["FRED"] 
        ip_ver = _fred["ip_ver"]
        proto = _fred["proto"]
        ip_src = _fred["ip_src"]
        ip_dst = _fred["ip_dst"]
        src_port = _fred["src_port"]
        dst_port = _fred["dst_port"]
        mac_src = _fred["mac_src"]
        mac_dst = _fred["mac_dst"]

        code = _fred["code"]

        prioridade = _fred["priority"]
        classe = _fred["class"]
        bandwidth = _fred["bandwidth"]
        loss = _fred["loss"]
        delay = _fred["delay"]
        jitter = _fred["jitter"]
        label = _fred["label"]

        blockchain_name = _fred["blockchain_name"]
        AS_src_ip_range = _fred["AS_src_ip_range"]
        AS_dst_ip_range = _fred["AS_dst_ip_range"]
        ip_genesis = _fred["ip_genesis"]
        lista_peers = _fred["list_peers"]
        lista_rota = _fred["list_route"]
    except:
        raise SyntaxError("Error loading FRED from JSON !")

    return Fred(code, blockchain_name, AS_src_ip_range, AS_dst_ip_range, ip_ver, proto, ip_src, ip_dst, src_port, dst_port, mac_src, 
                 mac_dst, prioridade,classe,bandwidth, loss, delay,jitter, label, ip_genesis, lista_peers, lista_rota)



class FredManager:
    def __init__(self):
        self.dicionario_freds = {}
        self.lock = threading.Lock()

    def get_fred(self, name:str) -> Fred:
        return self.dicionario_freds.get(name, None)

    def save_fred(self, name:str, fred:Fred) -> bool:
        with self.lock:
            self.dicionario_freds[name] = fred
        return True
    
    def del_fred(self, name:str)->bool:
        with self.lock:
            self.dicionario_freds.pop(name, None)
        return True

    def remover_freds_expirados(self):
        return True

#"{ "FRED" : {....}}"