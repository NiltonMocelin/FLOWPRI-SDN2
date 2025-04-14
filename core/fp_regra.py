from fp_utils import current_milli_time
from fp_constants import BE_HARD_TIMEOUT, QOS_HARD_TIMEOUT
import json

class Regra:
    def __init__(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int,
                dst_port:int, proto:int, porta_entrada:int, porta_saida:int, meter_id:int,
                banda: int, prioridade: int, classe: int, fila: int, application_class:str, qos_mark:int, actions:dict, emprestando: bool):
        """Parametros: 
        ip_ver: str
        ip_src: str
        ip_dst: str
        src_port: str
        dst_port: str
        proto: str
        porta_entrada: int
        porta_saida: int
        meter_id: int
        tos: int
        banda: int
        prioridade: int
        classe: int
        emprestando: bool
        fila: int
        actions: ""
        """

        self.id = str(ip_ver) + ip_src +ip_dst+str(src_port)+str(dst_port)+str(proto)

        self.classificado:bool = False
        self.ip_src:str = ip_src
        self.ip_dst:str = ip_dst
        self.ip_ver:int = ip_ver
        self.porta_saida:int = porta_saida
        self.porta_entrada: int = porta_entrada
        self.meter_id:int = meter_id
        self.emprestando:bool =emprestando
        self.banda: int = banda
        self.prioridade:int =prioridade
        self.classe:int = classe
        self.src_port:int = src_port
        self.dst_port:int = dst_port
        self.proto:int = proto
        self.fila:int = fila
        self.qos_mark:int = qos_mark 
        self.actions:dict = actions
        self.application_class:str = application_class
        self.monitorando:bool = False
        self.timestamp = current_milli_time()

        #print]("[criando-regra-controlador]src:%s; dst=%s; banda:%s, porta_dst=%d, tos=%s, emprestando=%d" % (self.ip_src, self.ip_dst, self.banda, self.porta_dst, self.tos, self.emprestando)) 

    def toString(self):

        return json.dumps(self.toDictionary())
    
    def toDictionary(self):
        dicionario = {'ip_ver':self.ip_ver, 'ip_src':self.ip_src, 'ip_dst':self.ip_dst, 'src_port':self.src_port,
                       'dst_port':self.dst_port, 'proto':self.proto, 'porta_entrada':self.porta_entrada, 'porta_saida':self.porta_saida,
                       'meter_id':self.meter_id, 'emprestando':self.emprestando, 'banda':self.banda, 'prioridade':self.prioridade, 'classe':self.classe,
                       'fila':self.fila, 'qos_mark':self.qos_mark, 'actions':self.actions, 'application_class':self.application_class, 'timestamp':self.timestamp}

        return dicionario

    def getTimestamp(self):
        return self.timestamp
    
    def getMeterId(self):
        return self.meter_id
    
    def getRegraId(self)->str:
        return self.ip_ver+"_"+self.proto +"_"+self.ip_src+ "_"+self.ip_dst + "_"+ self.src_port + "_"+self.dst_port

# parte de criação de regras 

def ordenaRegrasPorBandaMaiorMenor(lista_regras) -> list:

    _mergeSortRegras(lista_regras, 0, len(lista_regras)-1)


def _merge(lista_regras:list, esq:int, meio:int, dir:int):
    n1 = meio - esq + 1
    n2 = dir - meio

    # Copy data to temp vectors L[] and R[]
    lista_esq = lista_regras[esq : meio+1]
    lista_dir = lista_regras[meio+1 : dir+1]

    i = 0
    j = 0
    k = esq

    while i < n1 and j < n2 :
        if lista_esq[i].banda >= lista_dir[j].banda:
            lista_regras[k] = lista_esq[i]
            i+=1
        else:
            lista_regras[k] = lista_dir[j]
            j+=1
        k+=1
        

    #Copy the remaining elements of L[], 
    #if there are any
    while i < n1:
        lista_regras[k] = lista_esq[i]
        i+=1
        k+=1
    
    #Copy the remaining elements of R[], 
    #if there are any
    while j < n2:
        lista_regras[k] = lista_dir[j]
        j+=1
        k+=1

def _mergeSortRegras(lista_regras:int, esq:int, dir:int):

    if esq >= dir:
        return
    
    meio = dir + (dir - esq)/2

    _mergeSortRegras(lista_regras, esq, meio)
    _mergeSortRegras(lista_regras, meio+1, dir)
    _merge(lista_regras, esq, meio, dir)


def getRegrasExpiradas(lista_regras:list) -> list:
    tempo_atual = current_milli_time()
    lista_regras_expiradas = []

    for regra in lista_regras:
        if tempo_atual - regra.getTimestamp() > QOS_HARD_TIMEOUT * 1000: # converter para miliseconds
            lista_regras_expiradas.append(regra)
    return lista_regras_expiradas


# class Regra2:
#     def __init__(self, fred, porta_entrada:int, porta_saida:int, meter_id:int, fila:int, actions:str, emprestando:bool):

#         self.fred = fred
#         self.porta_entrada = porta_entrada
#         self.porta_saida = porta_saida
#         self.meter_id = meter_id
#         self.fila = fila
#         self.actions = actions
#         self.emprestando = emprestando

#     def getPrioridade(self):
#         return fred.