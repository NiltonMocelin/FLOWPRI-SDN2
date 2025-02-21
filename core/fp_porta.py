from fp_regra import Regra
from fp_constants import CPT

class Porta:
    def __init__(self, name:int, bandaT:int, bandaC1T:int, bandaC2T:int, tamanhoFilaC1:int , tamanhoFilaC2:int, proximoSwitch:int):
        # name :str , bandaC1T : int, bandaC2T : int, tamanhoFilaC1: int , tamanhoFilaC2: int, proximoSwitch : str):
        #criar filas e setar quantidade de banda para cada classe

        #tamanhoFila = quanto alem da banda posso alocar/emprestar

        #cada fila deve ter uma variavel de controle de largura de banda utilizada e uma variavel de largura de banda total
        self.nome:int = name

        self.bandaT:int = bandaT
        #a principio o compartilhamento de largura de banda ocorre apenas entre essas duas classes
        #criar os vetores fila da classe 1
        self.c1T = bandaC1T #banda total para esta classe
        self.c1U = 0 #banda utilizada para esta classe
        #fila baixa prioridade 1, classe 1 (tempo real)
        self.p1c1rules = []
        #fila media prioridade 2, classe 1 (tempo real)
        self.p2c1rules = []
        #fila alta prioridade 3, classe 1 (tempo real)
        self.p3c1rules = []

        #criar os vetores fila da classe 2
        self.c2T:int = bandaC2T
        self.c2U = 0
        #fila baixa prioridade 1, classe 2 (dados)
        self.p1c2rules = []
        #fila media prioridade 2, classe 2 (dados)
        self.p2c2rules = []
        #fila alta prioridade 3, classe 2 (dados)
        self.p3c2rules = []

        self.berules = []

        self.controlrules = []

        #id do proximo switch (conectado ao link)
        self.next:int = proximoSwitch
        #nao eh preciso armazenar informacoes sobre as filas de best-effort e controle de rede

    def addRegra(self, regra:Regra): #porta = nome da porta
#adicionar regra na fila correta da classe switch no controlador

        if regra.classe == 1:
            self.c1U += int(regra.banda)

            if regra.prioridade == 1:             
                self.p1c1rules.append(regra)
            elif regra.prioridade ==2:
                self.p2c1rules.append(regra)
            else: #prioridade ==3
                self.p3c1rules.append(regra)
        elif regra.classe ==2:
            self.c2U += int(regra.banda)

            if regra.prioridade == 1:
                self.p1c2rules.append(regra)
            elif regra.prioridade ==2:
                self.p2c2rules.append(regra)
            else: #prioridade ==3
                self.p3c2rules.append(regra)

        elif regra.classe == 3:
            self.berules.append(regra)
        else:
            self.controlrules.append(regra)

        return True

    
    def delRegra(self, ip_ver: int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int):
        for i in self.p1c1rules:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto: 
                self.c1U -= int(i.banda)
                self.p1c1rules.remove(i)
                return 1

        for i in self.p1c2rules:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                self.c2U -= int(i.banda)
                self.p1c2rules.remove(i)
                return 2

        
        for i in self.p2c1rules:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                self.c1U -= int(i.banda)
                self.p2c1rules.remove(i)
                return 1

        for i in self.p2c2rules:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                self.c2U -= int(i.banda)
                self.p2c2rules.remove(i)
                return 2

        for i in self.p3c1rules:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                self.c1U -= int(i.banda)
                self.p3c1rules.remove(i)
                return 1

        for i in self.p3c2rules:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                self.c2U -= int(i.banda)
                self.p3c2rules.remove(i)
                return 2

        for i in self.berules:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                self.berules.remove(i)
                return 3
            
        for i in self.controlrules:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                self.controlrules.remove(i)
                return 4
            
        #print]("[delRegra]Regra Nao encontrada no switch-controlador\n")
        return -1 #regra nao encontrada

    def delAllRegras(self):
        self.c1U = 0 
        self.p1c1rules = []
        self.p2c1rules = []
        self.p3c1rules = []

        self.c2U = 0 
        self.p1c2rules = []
        self.p2c2rules = []
        self.p3c2rules = []

        self.berules = []

        self.controlrules = []

    def getRegrasC1(self):
        return self.p1c1rules + self.p2c1rules + self.p3c1rules

    def getRegrasC2(self):
        return self.p1c2rules + self.p2c2rules + self.p3c2rules
    
    def getRegrasBE(self):
        return self.berules
    
    def getRegrasCtrl(self):
        return self.controlrules

    def getBandaDisponivelQoS(self):
        #retorna a banda para classe1, classe2
        return self.c1T - self.c1U, self.c2T - self.c2U
    
