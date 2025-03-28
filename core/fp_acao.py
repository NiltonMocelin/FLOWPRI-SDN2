from fp_constants import CRIAR, ALL_TABLES, REMOVER
from fp_regra import Regra
# from fp_switch import Switch
from fp_utils import getQueueId

#classe para modelar uma acao - remover ou criar regra
#nome switch - (str) identificar qual switch
#porta - (int) identificar a porta do switch
#codigo - (int) identificar a acao 0-CRIAR, 1-REMOVER
#regra - (Regra) uma regra - com as informacoes suficientes para criar ou remover a regra
class Acao:

    def __init__(self, switch_obj, porta_saida_nome:int, codigo:int, regra:Regra,tipo_porta:int, tipo_switch:int):
        """
        switch_obj : SwitchOVS
        porta : int
        codigo : int
        regra: Regra
        tipo_switch: first_hop, last_hop, outro
        tipo_porta: porta_Entrada, porta_Saida
        """

        self.switch_obj=switch_obj
        self.porta_saida_nome = porta_saida_nome #int
        self.codigo = codigo
        self.regra=regra
        self.tipo_switch=tipo_switch
        self.tipo_porta = tipo_porta
    
    def getRegra(self):
        return self.regra
    #regra = [ip_src, ip_dst, porta_dst, tos, banda, prioridade, classe, emprestando]
    def executar(self):
        print(self.toString())
        if(self.codigo == CRIAR):
            # chamar a funcao de criação de regras do switch
            self.switch_obj.addRegraQoS(self.regra.ip_ver, self.regra.ip_src,self.regra.ip_dst,self.regra.src_port,self.regra.dst_port,self.regra.proto,self.regra.porta_entrada,self.regra.porta_saida,self.regra.application_class,self.regra.banda,self.regra.prioridade,self.regra.classe,self.regra.fila,self.regra.qos_mark,self.regra.porta_saida,self.tipo_porta,self.tipo_switch,self.regra.emprestando)
        else:
            #codigo == REMOVER
            self.switch_obj.delRegraQoS(ip_ver=self.regra.ip_ver, ip_src=self.regra.ip_src,ip_dst=self.regra.ip_dst,src_port=self.regra.src_port,dst_port=self.regra.dst_port,proto=self.regra.proto,qos_mark=self.regra.qos_mark,porta_entrada=self.regra.porta_entrada,porta_saida=self.regra.porta_saida,tipo_switch=self.tipo_switch)

        return True
    
    def toString(self):
        if(self.codigo == REMOVER):
            return "[Acao] switch:" + self.switch_obj.nome + " Remover: " + self.regra.toString() +"\n"
        return "[Acao] switch:" + self.switch_obj.nome + " Criar: " + self.regra.toString()+"\n"
