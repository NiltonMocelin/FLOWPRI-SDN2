# import json

class Contrato:

    def __init__(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, dscp, classe, prioridade, banda):
        """ Parametros:
        ip_ver : str
        ip_src: str
        ip_dst: str
        src_port: str
        dst_port: str
        proto: str
        dscp:str
        classe: str
        prioridade: str
        banda: str
        """     
        
        self.id = ip_ver+"_"+ip_src+"_"+ip_dst+"_"+src_port+"_"+dst_port+"_"+proto
        self.ip_ver = ip_ver
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.dscp = dscp
        self.classe = classe
        self.prioridade = prioridade
        self.banda = banda
    
        #inicialize o init com none e passe um json para carregar o contrato
    def loadFromJSON(self, json_file):

        self.ip_ver = json_file["ip_ver"]
        self.proto = json_file["ip_proto"]
        self.ip_src = json_file["ip_src"]
        self.ip_dst = json_file["ip_dst"]
        self.src_port = json_file["src_port"]
        self.dst_port = json_file["dst_port"]
        self.banda = json_file["banda"]
        self.prioridade = json_file["prioridade"]
        self.classe = json_file["classe"]

        return True

    def toString(self):
        return "Contrato: ip_src:%s; ip_dst:%s; src_port:%s; dst_port:%s; proto:%s; dscp:%s; classe:%s; prioridade:%s; banda:%s;" % (self.ip_ver,self.ip_src, self.ip_dst, self.src_port,self.dst_port, self.proto,self.dscp,self.classe,self.prioridade,self.classe)
    
    def toJSON(self):
        return """{
            ip_ver:{},
            ip_proto:{},
            ip_src:{},
            ip_dst:{},
            src_port:{},
            dst_port:{},
            banda:{},
            prioridade:{},
            classe:{}
        }""".format(self.ip_ver, self.proto, self.ip_src, self.ip_dst, self.src_port, self.dst_port, self.banda, self.prioridade, self.classe)
    


    

