import json

class Fred:
    def __init__(self, code, blockchain_name, AS_src_ip_range, AS_dst_ip_range, ip_ver, proto, ip_src, ip_dst, src_port, dst_port, mac_src, 
                 mac_dst, prioridade,classe,bandiwdth, loss, delay,jitter, label, ip_genesis, lista_peers, lista_rota):
        self.ip_ver:str = ip_ver
        self.proto:str = proto
        self.ip_src:str  = ip_src 
        self.ip_dst:str = ip_dst
        self.src_port:str = src_port
        self.dst_port:str = dst_port
        self.mac_src:str = mac_src
        self.mac_dst:str  = mac_dst 

        self.code:str = code
        
        self.prioridade:str = prioridade
        self.classe:str = classe
        self.bandiwdth:str = bandiwdth
        self.loss:str = loss
        self.delay:str = delay
        self.jitter:str  = jitter
        self.label:str = label

        self.blockchain_name:str = blockchain_name
        self.AS_src_ip_range:list = AS_src_ip_range
        self.AS_dst_ip_range:list = AS_dst_ip_range
        self.ip_genesis:str = ip_genesis
        self.lista_peers:list = lista_peers
        self.lista_rota:list = lista_rota

        # lista_peers = lista[ dict1, dict 2]
        # (dict) um peer = {"nome_peer":"", "chave_publica":"", "ip_porta":"ip:porta"}
        # uma no da rota = {"ordem":"1", "nome_peer":"", "chave_publica":"", "nro_saltos(qtd_switches_rota)":""}
        
    def toString(self):

        str_AS_src_ip_range = ''
        str_AS_dst_ip_range = ''
        str_lista_peers = ''
        str_lista_rota = ''

        for s in self.AS_src_ip_range:
            str_AS_src_ip_range+=',\"%s\"' % (s)

        for s in self.AS_dst_ip_range:
            str_AS_dst_ip_range+=',\"%s\"' % (s)
        
        for s in self.lista_peers:
            str_lista_peers+=',\"%s\"' % (json.dumps(s))
        
        for s in self.lista_rota:
            str_lista_rota+=',\"%s\"' % (json.dumps(s))
        
        str_AS_src_ip_range = str_AS_src_ip_range.replace(',','',1)
        str_AS_dst_ip_range = str_AS_dst_ip_range.replace(',','',1)
        str_lista_peers = str_lista_peers.replace(',','',1)
        str_lista_rota = str_lista_rota.replace(',','',1)

        return "{\"ip_ver\":\"%s\",\
    \"proto\":\"%s\",\
    \"ip_src\":\"%s\",\
    \"ip_dst\":\"%s\",\
    \"src_port\":\"%s\",\
    \"dst_port\":\"%s\",\
    \"mac_src\":\"%s\",\
    \"mac_dst\":\"%s\",\
    \"prioridade\":\"%s\",\
    \"classe\":\"%s\",\
    \"bandiwdth\":\"%s\",\
    \"loss\":\"%s\",\
    \"delay\":\"%s\",\
    \"jitter\":\"%s\",\
    \"label\":\"%s\",\
    \"blockchain_name\":\"%s\",\
    \"AS_src_ip_range\":[%s],\
    \"AS_dst_ip_range\":[%s],\
    \"ip_genesis\":\"%s\",\
    \"lista_peers\":[%s],\
    \"lista_rota\":[%s]\
    }" % (self.ip_ver,self.proto,self.ip_src,self.ip_dst,self.src_port,self.dst_port,self.mac_src,self.mac_dst,
                self.prioridade,self.classe,self.bandiwdth,self.loss,self.delay,self.jitter,self.label,self.blockchain_name,
                str_AS_src_ip_range,str_AS_dst_ip_range,self.ip_genesis,str_lista_peers,str_lista_rota)    

def fromJsonToFred(_json):
    """{
    "ip_ver":"",
    "proto":"",
    "ip_src":"",
    "ip_dst":"",
    "src_port":"",
    "dst_port":"",
    "mac_src":"",
    "mac_dst":"",

    "code":"",
    
    "prioridade":"",
    "classe":"",
    "bandiwdth":"",
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
    "lista_peers":[],
    "lista_rota":[]
    }"""

    try:
        ip_ver = _json["ip_ver"]
        proto = _json["proto"]
        ip_src = _json["ip_src"]
        ip_dst = _json["ip_dst"]
        src_port = _json["src_port"]
        dst_port = _json["dst_port"]
        mac_src = _json["mac_src"]
        mac_dst = _json["mac_dst"]

        code = _json["code"]

        prioridade = _json["prioridade"]
        classe = _json["classe"]
        bandiwdth = _json["bandiwdth"]
        loss = _json["loss"]
        delay = _json["delay"]
        jitter = _json["jitter"]
        label = _json["label"]

        blockchain_name = _json["blockchain_name"]
        AS_src_ip_range = _json["AS_src_ip_range"]
        AS_dst_ip_range = _json["AS_dst_ip_range"]
        ip_genesis = _json["ip_genesis"]
        lista_peers = _json["lista_peers"]
        lista_rota = _json["lista_rota"]
    except:
        raise SyntaxError("Error loading FRED from JSON !")

    return Fred(blockchain_name, AS_src_ip_range, AS_dst_ip_range, ip_ver, proto, ip_src, ip_dst, src_port, dst_port, mac_src, 
                 mac_dst, prioridade,classe,bandiwdth, loss, delay,jitter, label, ip_genesis, lista_peers, lista_rota)

