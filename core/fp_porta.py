from fp_regra import Regra, ordenaRegrasPorBandaMaiorMenor
from fp_constants import SC_REAL, SC_CONTROL, SC_BEST_EFFORT, SC_NONREAL, ALTA_PRIO, MEDIA_PRIO, BAIXA_PRIO

class Porta:
    def __init__(self, name:int, bandaT:int, bandaTotalClasseReal:int, bandaTotalClasseNaoReal:int, tamanhoFilaClasseReal:int , tamanhoFilaClasseNaoReal:int, proximoSwitch:int):
        # name :str , bandaC1T : int, bandaC2T : int, tamanhoFilaC1: int , tamanhoFilaC2: int, proximoSwitch : str):
        #criar filas e setar quantidade de banda para cada classe

        #tamanhoFila = quanto alem da banda posso alocar/emprestar

        #cada fila deve ter uma variavel de controle de largura de banda utilizada e uma variavel de largura de banda total
        self.nome:int = name

        self.bandaT:int = bandaT
        #a principio o compartilhamento de largura de banda ocorre apenas entre essas duas classes
        #criar os vetores fila da classe 1
        self.bandaTotalClasseReal = bandaTotalClasseReal #banda total para esta classe
        self.bandaUtilizadaClasseReal = 0 #banda utilizada para esta classe
        #fila alta prioridade 1, classe 1 (tempo real)
        self.regrasPrioAltaClasseReal:list[Regra] = []
        # self.p1c1rules = []
        #fila media prioridade 2, classe 1 (tempo real)
        self.regrasPrioMediaClasseReal:list[Regra] = []
        #fila baixa prioridade 3, classe 1 (tempo real)
        self.regrasPrioBaixaClasseReal:list[Regra] = []
        # self.prio3c1rules = []

        #criar os vetores fila da classe 2
        self.bandaTotalClasseNaoReal:int = bandaTotalClasseNaoReal
        self.bandaUtilizadaClasseNaoReal = 0
        #fila alta prioridade 1, classe 2 (dados)
        self.regrasPrioAltaClasseNaoReal:list[Regra] = []
        # self.p1c2rules = []
        #fila media prioridade 2, classe 2 (dados)
        # self.p2c2rules = []
        self.regrasPrioMediaClasseNaoReal:list[Regra] = []
        #fila baixa prioridade 3, classe 2 (dados)
        # self.p3c2rules = []
        self.regrasPrioBaixaClasseNaoReal:list[Regra] = []

        self.berules:list[Regra] = []

        self.controlrules:list[Regra] = []

        #id do proximo switch (conectado ao link)
        self.next:int = proximoSwitch
        #nao eh preciso armazenar informacoes sobre as filas de best-effort e controle de rede

    def addRegra(self, regra:Regra) -> bool: #porta = nome da porta
#adicionar regra na fila correta da classe switch no controlador

        if regra.classe == SC_REAL:
            self.bandaUtilizadaClasseReal += int(regra.banda)

            if regra.prioridade == ALTA_PRIO:             
                self.regrasPrioAltaClasseReal.append(regra)
            elif regra.prioridade == MEDIA_PRIO:
                self.regrasPrioMediaClasseReal.append(regra)
            else: #prioridade == BAIXA_PRIO
                self.regrasPrioBaixaClasseReal.append(regra)
        elif regra.classe ==SC_NONREAL:
            self.bandaUtilizadaClasseNaoReal += int(regra.banda)

            if regra.prioridade == ALTA_PRIO:
                self.regrasPrioAltaClasseNaoReal.append(regra)
            elif regra.prioridade ==MEDIA_PRIO:
                self.regrasPrioMediaClasseNaoReal.append(regra)
            else: #prioridade ==BAIXA_PRIO
                self.regrasPrioBaixaClasseNaoReal.append(regra)

        elif regra.classe == SC_BEST_EFFORT:
            self.berules.append(regra)
        else:
            self.controlrules.append(regra)

        return True

    
    def delRegra(self, ip_ver: int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int):
        for i in self.regrasPrioAltaClasseReal:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto: 
                self.bandaUtilizadaClasseReal -= i.banda
                self.regrasPrioAltaClasseReal.remove(i)
                return SC_REAL

        for i in self.regrasPrioAltaClasseNaoReal:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                self.bandaUtilizadaClasseNaoReal -= i.banda
                self.regrasPrioAltaClasseNaoReal.remove(i)
                return SC_NONREAL

        
        for i in self.regrasPrioMediaClasseReal:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                self.bandaUtilizadaClasseReal -= i.banda
                self.regrasPrioMediaClasseReal.remove(i)
                return SC_REAL

        for i in self.regrasPrioMediaClasseNaoReal:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                self.bandaUtilizadaClasseNaoReal -= i.banda
                self.regrasPrioMediaClasseNaoReal.remove(i)
                return SC_NONREAL

        for i in self.regrasPrioBaixaClasseReal:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                self.bandaUtilizadaClasseReal -= i.banda
                self.regrasPrioBaixaClasseReal.remove(i)
                return SC_REAL

        for i in self.regrasPrioBaixaClasseNaoReal:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                self.bandaUtilizadaClasseNaoReal -= i.banda
                self.regrasPrioBaixaClasseNaoReal.remove(i)
                return SC_NONREAL

        for i in self.berules:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                self.berules.remove(i)
                return SC_BEST_EFFORT
            
        for i in self.controlrules:
            if i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                self.controlrules.remove(i)
                return SC_CONTROL
            
        #print]("[delRegra]Regra Nao encontrada no switch-controlador\n")
        return -1 #regra nao encontrada

    def delAllRegras(self):
        self.bandaUtilizadaClasseReal = 0 
        self.regrasPrioAltaClasseReal = []
        self.regrasPrioMediaClasseReal = []
        self.regrasPrioBaixaClasseReal = []

        self.bandaUtilizadaClasseNaoReal = 0 
        self.regrasPrioAltaClasseNaoReal = []
        self.regrasPrioMediaClasseNaoReal = []
        self.regrasPrioBaixaClasseNaoReal = []

        self.berules = []

        self.controlrules = []
   

    def getRegrasC1(self) -> list[Regra]:
        return self.regrasPrioBaixaClasseReal + self.regrasPrioMediaClasseReal + self.regrasPrioAltaClasseReal


    def getRegrasC2(self) -> list[Regra]:
        return self.regrasPrioBaixaClasseNaoReal + self.regrasPrioMediaClasseNaoReal + self.regrasPrioAltaClasseNaoReal

    def getRegrasBaixaPrio(self, classe:int) -> list[Regra]:
        if classe == SC_REAL:
            return self.regrasPrioBaixaClasseReal
        elif classe == SC_NONREAL:
            return self.regrasPrioBaixaClasseNaoReal
        return []
        

    def getRegrasMediaPrio(self, classe:int) -> list[Regra]:
        if classe == SC_REAL:
            return self.regrasPrioMediaClasseReal
        elif classe == SC_NONREAL:
            return self.regrasPrioMediaClasseNaoReal
        return []
        
    def getRegrasAltaPrio(self, classe:int) -> list[Regra]:
        if classe == SC_REAL:
            return self.regrasPrioAltaClasseReal
        elif classe == SC_NONREAL:
            return self.regrasPrioAltaClasseNaoReal

        return []
        
        

    def getRegrasC1Emprestando(self) -> list[Regra]:

        regras = []
        
        aux_regras = []
        for r in self.regrasPrioBaixaClasseReal:
            if r.emprestando:
                aux_regras.append(r)
        
        ordenaRegrasPorBandaMaiorMenor(aux_regras)
        regras+= aux_regras
        aux_regras.clear()

        for r in self.regrasPrioMediaClasseReal:
            if r.emprestando:
                aux_regras.append(r)
        
        ordenaRegrasPorBandaMaiorMenor(aux_regras)
        regras+= aux_regras
        aux_regras.clear()
                
        for r in self.regrasPrioAltaClasseReal:
            if r.emprestando:
                aux_regras.append(r)
        
        ordenaRegrasPorBandaMaiorMenor(aux_regras)
        regras+= aux_regras
        aux_regras.clear()
                
        return regras

    
    def getRegrasC2Emprestando(self) -> list[Regra]:

        regras = []
        
        aux_regras = []
        for r in self.regrasPrioBaixaClasseNaoReal:
            if r.emprestando:
                aux_regras.append(r)
        
        ordenaRegrasPorBandaMaiorMenor(aux_regras)
        regras+= aux_regras
        aux_regras.clear()

        for r in self.regrasPrioMediaClasseNaoReal:
            if r.emprestando:
                aux_regras.append(r)
        
        ordenaRegrasPorBandaMaiorMenor(aux_regras)
        regras+= aux_regras
        aux_regras.clear()
                
        for r in self.regrasPrioAltaClasseNaoReal:
            if r.emprestando:
                aux_regras.append(r)
        
        ordenaRegrasPorBandaMaiorMenor(aux_regras)
        regras+= aux_regras
        aux_regras.clear()
                
        return regras

    def getRegrasBE(self) -> list[Regra]:
        return self.berules
    
    def getRegrasCtrl(self) -> list[Regra]:
        return self.controlrules

    def getBandaDisponivelQoS(self) -> tuple[int, int]:
        #retorna a banda para classe1, classe2
        return self.bandaTotalClasseReal - self.bandaUtilizadaClasseReal, self.bandaTotalClasseNaoReal - self.bandaUtilizadaClasseNaoReal
    
    def getBandaUtilizadaETotal(self, classe:int) -> tuple[int, int]:
        if classe == SC_REAL:
            return self.bandaUtilizadaClasseReal, self.bandaTotalClasseReal
        # SC_NONREAL
        return self.bandaUtilizadaClasseNaoReal, self.bandaTotalClasseNaoReal
    
    def getRegrasEmprestandoAteBandaNecessaria(self, classe:int, bandaNecessaria:int) -> list[Regra]:
        emprestando = []
        bandaE = 0

        #sim: somar os fluxos que estao emprestando e ver se a banda eh suficiente para alocar este fluxo 
        bandaDisponivelReal, bandaDisponivelNaoReal = self.getBandaDisponivelQoS()
        bandaDisponivel = 0
        if classe == SC_REAL:
            bandaDisponivel = bandaDisponivelReal
            emprestando = self.getRegrasC1Emprestando()
        else:
            bandaDisponivel = bandaDisponivelNaoReal
            emprestando = self.getRegrasC2Emprestando()

        contadorE = 0
        for i in emprestando:
            bandaE += i.banda
            contadorE+=1

            if bandaDisponivel + bandaE >= bandaNecessaria:
                break
        if bandaE + bandaDisponivel < bandaNecessaria:
            return []

        return emprestando[:contadorE]
    
    def getLowerPriorityRules(self, classe:int, prioridade:int) -> list[Regra]:
        
        if prioridade == BAIXA_PRIO:
            return []
        
        if prioridade == MEDIA_PRIO:
            return self.getRegrasBaixaPrio(classe)
        
        if prioridade == ALTA_PRIO:
            return self.getRegrasBaixaPrio(classe) + self.getRegrasMediaPrio(classe)
        
        return []

    def getLowerPriorityRulesAteBandaNecessaria(self, classe:int, prioridade:int, banda:int) -> list[Regra]:
        
        if prioridade == BAIXA_PRIO:
            return []
        
        if prioridade == MEDIA_PRIO:
            return self.getRegrasBaixaPrio(classe)
        
        if prioridade == ALTA_PRIO:
            return self.getRegrasBaixaPrio(classe) + self.getRegrasMediaPrio(classe)
        
        return []