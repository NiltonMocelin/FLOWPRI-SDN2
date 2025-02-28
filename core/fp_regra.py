
class Regra:
    def __init__(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int,
                dst_port:int, proto:int, porta_entrada:int, porta_saida:int, meter_id:int,
                banda: int, prioridade: int, classe: int, fila: int, flow_label:str, actions:str, emprestando: bool):
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
        banda: str
        prioridade: str
        classe: str
        emprestando: bool
        fila: int
        actions: ""
        """

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
        self.actions:str = actions
        self.flow_label:str = flow_label

        #print]("[criando-regra-controlador]src:%s; dst=%s; banda:%s, porta_dst=%d, tos=%s, emprestando=%d" % (self.ip_src, self.ip_dst, self.banda, self.porta_dst, self.tos, self.emprestando)) 

    def toString(self):
        return "[regra]ip_ver:%s; ip_src:%s; ip_dst=%s; src_port=%d; dst_port=%d; proto=%d; banda:%d, porta_dst=%d, tos=%s, emprestando=%b" % (self.ip_ver, self.ip_src, self.ip_dst, self.src_port, self.dst_port, self.proto, self.banda, self.porta_entrada, self.porta_saida, self.emprestando) 


# parte de criação de regras 

def ordenaRegrasPorBandaMaiorMenor(lista_regras) -> list[Regra]:

    _mergeSortRegras(lista_regras, 0, len(lista_regras)-1)


def _merge(lista_regras:list[Regra], esq:int, meio:int, dir:int):
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