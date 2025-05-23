from fp_acao import Acao
from fp_porta import Porta
from fp_constants import TCP_SRC,TCP_DST, UDP_SRC, UDP_DST, ALL_TABLES, CRIAR, REMOVER, FORWARD_TABLE, ANY_PORT, NO_METER, QOS_IDLE_TIMEOUT, QOS_HARD_TIMEOUT, BE_HARD_TIMEOUT, BE_IDLE_TIMEOUT, SEMBANDA, EMPRESTANDO, NAOEMPRESTANDO
from fp_constants import FILA_C1P1, FILA_C1P2, FILA_C1P3, FILA_C2P1, FILA_C2P2, FILA_C2P3, FILA_BESTEFFORT, FILA_CONTROLE, NO_QOS_MARK, SC_REAL, SC_NONREAL, SC_BEST_EFFORT, SC_CONTROL, CONJUNCTION_ID, METER_PRIO, CONJUNCTION_PRIO, MONITORING_PRIO, MONITORING_TIMEOUT_ACTION, MONITORING_TIMEOUT_FORWARD
from fp_constants import PORTA_ENTRADA, PORTA_SAIDA, BE_PRIO, MARKING_PRIO, ligar_monitoring
from fp_regra import Regra, getRegrasExpiradas
import sys

from fp_utils import getQueueId, getEquivalentMonitoringMark, getQOSMark

from fp_openflow_rules import addRegraForwarding2, addRegraMeter, delRegraMeter, delRegraForwarding, getMeterID_from_Flow, saveMeterID_from_Flow, delMeter, addRegraMonitoring, addRegraForwarding_com_Conjunction, delRegraForwarding_com_Conjunction, desligar_regra_monitoramento
import json

class Switch:
    # TIPOS DE SWITCH
    SWITCH_FIRST_HOP=1 # primeiro switch dominio emissor
    SWITCH_LAST_HOP=2 # ultimo switch dominio destino
    SWITCH_FIRST_E_LAST_HOP=3 # errp nao deveria existir a menos que origem e destino fossem o mesmo dominio
    SWITCH_OUTRO=4 # backbone == todos os outros switches

    # switch_to_controller = {switch_name:port_to_controller}
    switch_to_controller = {}

    def __init__(self, datapath, name:int, controller, port_to_controller, ovsdb_addr=''): 
        """ Existem 3 tipos de switches: 1. borda emissora primeiro salto, 2. borda emissora ultimo salto, 3.backbones 
        1. configurar marcação de qos e meter utilizando addRegraForwarding e addRegraMeter
        2. configurar regra marcacao monitoring/matching qos(Vai alternando)
        3. configurar regra matching qos e matching monitoring
        . Os tipos variam conforme o contexto, o switch pode ser borda para um fluxo e backbone para outro
        """
                
        print("Novo switch: nome = S%s" % (str(name)))

        self.controller = controller

        self.datapath = datapath
        self.nome = name
        self.port_to_controller = port_to_controller
        self.portas = []
        self.ovsdb_addr = ovsdb_addr # formato tcp:127.0.0.1:6634

        #Como adicionar itens a um dicionario -> dicio['idade'] = 20
        self.macs = {} #chave: mac, valor: porta
        self.redes = {} #chave: ip, valor: porta
        self.hosts= {} #chave: ip, valor: mac

        #5-tuple : id
        self.meter_dict = {}
        self.tcp_src_conjunction = {}
        self.tcp_dst_conjunction = {}
        self.udp_src_conjunction = {}
        self.udp_dst_conjunction = {}
        # self.conjunctions_rules={} # [tcp_src=port]=id # isso deve ser util para associar uma conjunção a uma regra e para remover uma conjunção.

    def toString(self):
        return json.dumps({"nome":self.nome, "port_to_controller": self.port_to_controller, 
                           "ovsdb_addr":self.ovsdb_addr, "port_to_controller":self.port_to_controller, "qtd_portas": len(self.portas), "datapath": True if self.datapath else False})

    def getPortToController(self):
        return self.port_to_controller

    def setPortToController(self, port_to_controller):
        self.port_to_controller = port_to_controller

    def saveConjunction(self, port_name:int, tipo:int): # deixar isso ser chamado la nas acoes

        if tipo == TCP_SRC:
            self.tcp_src_conjunction[port_name] = self.tcp_src_conjunction.get(port_name, 0) + 1
        elif tipo == TCP_DST:
            self.tcp_dst_conjunction[port_name] = self.tcp_dst_conjunction.get(port_name, 0) + 1
        elif tipo == UDP_SRC:
            self.udp_src_conjunction[port_name] = self.udp_src_conjunction.get(port_name, 0) + 1
        else: #tipo == UDP_DST:
            self.udp_dst_conjunction[port_name] = self.udp_dst_conjunction.get(port_name, 0) + 1

        return True

    def remover_regras_expiradas(self, threshold:int):
        print("[switch] remover regras expiradas por hardtimeout + 2")

        for porta in self.portas:
            porta.removerRegrasExpiradas(threshold)
            
        return True

    def getConjuntion(self, port_name:int, tipo:int):
        if tipo == TCP_SRC:
            return self.tcp_src_conjunction.get(port_name,None)
        elif tipo == TCP_DST:
            return self.tcp_dst_conjunction.get(port_name,None)
        elif tipo == UDP_SRC:
            return self.tcp_dst_conjunction.get(port_name,None)
        #tipo == UDP_DST
        return self.udp_dst_conjunction.get(port_name,None)
    
    def isPortInConjunction(self, port_name:int, tipo:int):

        if tipo == TCP_SRC:
            if self.tcp_src_conjunction.get(port_name,None):
                return True
        elif tipo == TCP_DST:
            if self.tcp_dst_conjunction.get(port_name,None):
                return True
        elif tipo == UDP_SRC:
            if self.udp_src_conjunction.get(port_name,None):
                return True
        else: # tipo == UDP_DST
            if self.udp_dst_conjunction.get(port_name,None):
                return True
        return False
    
    def delConjunctionByCount(self, port_name:int, tipo:int)->bool:
        "returns: True if the conjunction was actually removed, False if it was decremented, because there are more flows using it right now"
        if tipo == TCP_SRC:
            val = self.tcp_src_conjunction.get(port_name,0) - 1
            if val <= 0:
                self.tcp_src_conjunction.pop(port_name, None)
                return True
            else:
                self.tcp_src_conjunction[port_name] = val
        elif tipo == TCP_DST:
            val= self.tcp_dst_conjunction.get(port_name,0)-1
            if val <= 0:
                self.tcp_dst_conjunction.pop(port_name, None)
                return True
            else:
                self.tcp_dst_conjunction[port_name] = val
        elif tipo == UDP_SRC:
            val = self.udp_src_conjunction.get(port_name,0) -1
            if val <= 0:
                self.udp_src_conjunction.pop(port_name,None)
                return True
            else:
                self.udp_src_conjunction[port_name] = val
        else: # tipo == UDP_DST
            val = self.udp_dst_conjunction.get(port_name,0) -1
            if val <= 0:
                self.udp_dst_conjunction.pop(port_name,None)
                return True
            else:
                self.udp_dst_conjunction[port_name] = val
        return False


    def delConjunction(self, port_name:int, tipo:int):
        
        if tipo == TCP_SRC:
            self.tcp_src_conjunction.pop(port_name,None)
        elif tipo == TCP_DST:
            self.tcp_dst_conjunction.pop(port_name,None)
        elif tipo == UDP_SRC:
            self.udp_src_conjunction.pop(port_name,None)
        else: # tipo == UDP_DST
            self.udp_dst_conjunction.pop(port_name,None)
        return True
    
    def setOVSDB_addr(self, ovsdb_addr):
        """ovsdb_addr format -> tcp:127.0.0.1:6633"""
        self.ovsdb_addr = ovsdb_addr
        return

    def addPorta(self, nomePorta:int, nome_interface:str, larguraBanda:int, proximoSwitch:int):
        print("[S%s] Nova porta: porta=%s, banda=%s, proximoSalto=%s\n" % (str(self.nome), str(nomePorta), str(larguraBanda), str(proximoSwitch)))
        #criar a porta no switch
        self.portas.append(Porta(nomePorta, nome_interface, int(larguraBanda), int(int(larguraBanda)*.33), int(int(larguraBanda)*.35), 0, 0, int(int(larguraBanda)*.25), int(int(larguraBanda)*.07),int(proximoSwitch)))

    def delPorta(self, nomePorta:int):
        # print("[S%s] deletando: porta=%s, banda=%s, proximoSalto=%s\n" % (str(self.nome), str(nomePorta), str(larguraBanda), str(proximoSwitch)))
        
        index = 0
        porta = None
        for i in range(0, len(self.portas)):
            if self.portas[i].nome == nomePorta:
                index = i
                porta = self.portas[i]
        
        if porta == None:
            print('porta %s não encontrada' % (str(nomePorta)))
            return

        for regra in porta.getRegrasC1() + porta.getRegrasC2():
            delRegraForwarding(self, regra.ip_ver, regra.ip_src, regra.ip_dst, regra.src_port, regra.dst_port, regra.proto)

        
        self.portas.pop(index)
        
        return 


    def getPorta(self, nomePorta:int) -> Porta:

        for i in self.portas:
            # %s x %s\n" % (i.nome, nomePorta))
            if i.nome == nomePorta:
                return i
        #print("[getPorta] porta inexistente: %s\n" % (nomePorta))
        return None
    
    def getPortas(self)->list:
        return self.portas
    
    def add_regra_monitoramento_fluxo(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida, fila, qos_mark_matching, qos_mark_action, meter_id=None):

        # a regra ainda está ativa na instancia do switch, entao nao precisa mexer la, e a regra meter ainda está ativa tbm.
        #  apenas criar a regra na tabela de fluxos novamente

        print("Criando regra monitoramento  %s:%d->%s:%d porta_saida:%d meter:%d fila:%d qos_match:%d qos_mark:%d" % (ip_src, src_port, ip_dst, dst_port, porta_saida, meter_id, fila, qos_mark_matching if qos_mark_matching else -1, qos_mark_action if qos_mark_action else -1))
        addRegraMonitoring(switch=self, ip_ver=ip_ver, ip_src=ip_src, ip_dst= ip_dst, out_port=porta_saida, src_port=src_port, dst_port=dst_port, proto=proto, fila=fila, qos_mark_matching=qos_mark_matching, qos_mark_action=qos_mark_action,flow_removed=True, meter_id=meter_id)
        return
    
    def del_regra_monitoramento_fluxo(self,ip_ver, ip_src, ip_dst, src_port, dst_port, proto):
        """Quem chama essa funcao é apenas o flow removed"""
        desligar_regra_monitoramento(switch=self, ip_ver=ip_ver,ip_src=ip_src,ip_dst=ip_dst,src_port=src_port,dst_port=dst_port,proto=proto)
        return

    def addRegraBE_soOF(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida, primeiroSaltoOrigem:bool, toController):
        """nao salva a regra, apenas cria a regra OpenFlow"""
        BE_MARK = getQOSMark(SC_BEST_EFFORT, 1)
        if primeiroSaltoOrigem:
            print("addBE_soOF primeiro salto")
            addRegraForwarding2(datapath=self.datapath, ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, out_port=porta_saida,src_port=src_port,dst_port=dst_port,proto=proto, fila=FILA_BESTEFFORT, qos_mark_action=BE_MARK, idle_timeout=BE_IDLE_TIMEOUT, hard_timeout=BE_HARD_TIMEOUT, flow_removed=False, prioridade = MARKING_PRIO, toController=toController)
            
        else:
            print("addBE_soOF backbone") # nessa topologia nao pode aparecer isso pq so tem um salto
            # addRegraForwarding2(datapath=self.datapath, ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, out_port=porta_saida,src_port=src_port,dst_port=dst_port,proto=proto, fila=FILA_BESTEFFORT, qos_mark_maching=qos_mark, idle_timeout=BE_IDLE_TIMEOUT, hard_timeout=BE_HARD_TIMEOUT, flow_removed=True)#, toController=True) 
            addRegraForwarding_com_Conjunction(self, ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst,out_port= porta_saida, src_port=src_port, dst_port=dst_port, proto=proto, fila=FILA_BESTEFFORT, qos_mark_maching=BE_MARK, idle_timeout=BE_IDLE_TIMEOUT, hard_timeout=BE_HARD_TIMEOUT, flow_removed=False, prioridade=CONJUNCTION_PRIO)
        return


    def addRegraBE(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida, marcar:bool=False, primeiroSaltoBorda:bool=False, toController=False, classificado:bool=False):
        BE_MARK = NO_QOS_MARK
        if marcar:
            BE_MARK = getQOSMark(SC_BEST_EFFORT, 1)

        self.getPorta(porta_saida).delRegra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto)
        self.getPorta(porta_saida).addRegra(Regra(ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto, porta_entrada=ANY_PORT, porta_saida= porta_saida,meter_id= NO_METER,banda= 0, prioridade=BE_PRIO,classe= SC_BEST_EFFORT,fila= FILA_BESTEFFORT, application_class="be", qos_mark=BE_MARK, actions={"qos_mark":BE_MARK, "out_port":porta_saida, "meter_id":NO_METER}, emprestando=False, classificado=classificado))
        if primeiroSaltoBorda:
            print("addBE primeiro salto")
            addRegraForwarding2(datapath=self.datapath, ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, out_port=porta_saida,src_port=src_port,dst_port=dst_port,proto=proto, fila=FILA_BESTEFFORT, qos_mark_action=BE_MARK, idle_timeout=BE_IDLE_TIMEOUT, hard_timeout=BE_HARD_TIMEOUT, flow_removed=False, prioridade = MARKING_PRIO, toController=toController)
            
        else:
            print("addBE backbone") # nessa topologia nao pode aparecer isso pq so tem um salto
            # addRegraForwarding2(datapath=self.datapath, ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, out_port=porta_saida,src_port=src_port,dst_port=dst_port,proto=proto, fila=FILA_BESTEFFORT, qos_mark_maching=qos_mark, idle_timeout=BE_IDLE_TIMEOUT, hard_timeout=BE_HARD_TIMEOUT, flow_removed=True)#, toController=True) 
            addRegraForwarding_com_Conjunction(self, ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst,out_port= porta_saida, src_port=src_port, dst_port=dst_port, proto=proto, fila=FILA_BESTEFFORT, qos_mark_maching=getQOSMark(SC_BEST_EFFORT, 1), idle_timeout=BE_IDLE_TIMEOUT, hard_timeout=BE_HARD_TIMEOUT, flow_removed=False, prioridade=CONJUNCTION_PRIO)

        return True

    def addRegraQoS(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_entrada:int, porta_saida:int, flow_label:str, banda:int, prioridade:int, classe:int, fila:int, qos_mark:int, porta_nome_armazenar_regra:int, tipo_porta:int, tipo_switch:int, emprestando:bool=False, souDestino:bool=False):
        """Como as regras sao agrupadas, nao se pode adicionar de qualquer jeito"""
        """Tipo_porta = PORTA_ENTRADA ou PORTA_SAIDA"""
        """Switch first hop = ip_src meu dominio e ser primeiro salto"""
        """Switch last hop = ip_dst meu dominio e ser ultimo salto"""
       
        print("[addRQoS] porta:%d s:%s:%d d:%s:%d" %(porta_nome_armazenar_regra, ip_src, src_port, ip_dst,dst_port))
        # !arrumar a regra, falta campos
        # !na porta de entrada, nao cria a regra, e desconta banda
        # !na porta de saida, cria a regra, e desconta banda
        meter_id = NO_METER
        if tipo_switch == Switch.SWITCH_FIRST_HOP: # obs ip_src deve ser do meu dominio e este deve ser o primeiro switch
       
            if tipo_porta == PORTA_SAIDA: # porta de saida, cria regra no switch real e na instancia
                meter_id = addRegraMeter(self, banda)

                #armazenar meter
                saveMeterID_from_Flow(self.meter_dict, ip_ver, ip_src,ip_dst,src_port,dst_port, proto, meter_id)
                # Dando erro aqui
                # print("add-switchfirsthop") # comentado aqui
                addRegraForwarding2(datapath=self.datapath,ip_ver=ip_ver,ip_src=ip_src, ip_dst=ip_dst, src_port=src_port,dst_port=dst_port, proto=proto, out_port=porta_saida, fila=fila, qos_mark_action=qos_mark, hard_timeout=MONITORING_TIMEOUT_ACTION, idle_timeout=MONITORING_TIMEOUT_ACTION, meter_id=meter_id, prioridade=MARKING_PRIO,flow_removed=True)
                
            # porta de entrada, apenas cria regra na instancia
            # SE TIVER REGRA COM METER_ID = NULL -> EH PQ A REGRA EH NO BACKBONE, O SO NA BORDA SE ASSOCIA METERS
            self.getPorta(porta_nome_armazenar_regra).addRegra(Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida,meter_id, banda, prioridade, classe, fila, flow_label, qos_mark, {"qos_mark":qos_mark, "out_port":porta_saida, "meter_id":meter_id}, emprestando, classificado=True))
            #criar meter + encaminhamento com marcacao
            
        elif tipo_switch == Switch.SWITCH_LAST_HOP: # obs ip_dst deve ser do meu dominio e este deve ser o ultimo switch
            
            if tipo_porta == PORTA_SAIDA:              # print("add-switch backbone")
                addRegraForwarding_com_Conjunction(self, ip_ver, ip_src, ip_dst, porta_saida, src_port, dst_port, proto, fila, qos_mark, QOS_IDLE_TIMEOUT, QOS_HARD_TIMEOUT, prioridade=CONJUNCTION_PRIO, flow_removed=True)

                if ligar_monitoring:
                   
                    addRegraForwarding_com_Conjunction(self, ip_ver, ip_src, ip_dst, porta_saida, src_port, dst_port, proto, fila, qos_mark_maching=getEquivalentMonitoringMark(classe, prioridade), idle_timeout=MONITORING_TIMEOUT_FORWARD, hard_timeout=MONITORING_TIMEOUT_FORWARD, prioridade=CONJUNCTION_PRIO, toController=True)
                   

            # rotina monitoring
            self.getPorta(porta_nome_armazenar_regra).addRegra(Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, meter_id, banda, prioridade, classe, fila, flow_label, qos_mark, {"qos_mark":qos_mark, "out_port":porta_saida, "meter_id":meter_id}, emprestando, classificado=True))
            # forwarding matching qos_mark - timeout de monitoring

        else: #tipo_switch == Switch.SWITCH_OUTRO:

            if tipo_porta == PORTA_SAIDA:
                # regra matching qos_mark e regra matching monitoring_markw
                addRegraForwarding_com_Conjunction(self, ip_ver, ip_src, ip_dst, porta_saida, src_port, dst_port, proto, fila, qos_mark, QOS_IDLE_TIMEOUT, QOS_HARD_TIMEOUT, prioridade=CONJUNCTION_PRIO, flow_removed=True)

                if ligar_monitoring:
                   
                    addRegraForwarding_com_Conjunction(self, ip_ver, ip_src, ip_dst, porta_saida, src_port, dst_port, proto, fila, qos_mark_maching=getEquivalentMonitoringMark(classe, prioridade), idle_timeout=MONITORING_TIMEOUT_FORWARD, hard_timeout=MONITORING_TIMEOUT_FORWARD, prioridade=CONJUNCTION_PRIO, toController=False)

            self.getPorta(porta_nome_armazenar_regra).addRegra(Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, meter_id, banda, prioridade, classe, fila, flow_label, qos_mark,{"qos_mark":qos_mark, "out_port":porta_saida, "meter_id":meter_id}, emprestando,classificado=True))

        return True
    
    def delRegraQoS(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_entrada:int, porta_saida:int,tipo_switch:int, qos_match:int):
        """Como as regras sao agrupadas, nao se pode remover de qualquer jeito"""
        """[caso 1] para Switch first-hop tem regras (tipo 1) meter e regras forwarding com marcacao de qos (tipo 2) --> essas pode remover as duas sempre que preciso"""
        """[caso 2] Para switch last-hop e outros (backbone), se  tem a regra com o par ips + matching_qos (tipo 3), se tem as regras com as portas entrada e saida (tipo 4) e se tem as regras com o par ips + matching qos_monitoring (tipo 5)"""
        """[caso 3] Em portas de entrada, as regras não são criadas, apenas devem ser removidas da instancia do switch"""

        # tipo_switch = Switch.SWITCH_FIRST_HOP (utiliza addforwarding)        
        regra = self.getPorta(porta_saida).delRegra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto)

        if not regra:
            print("Regra nao encontrada em switch:%d porta:%d" %(self.nome, porta_saida))
            return

        if regra:
            print("[del-qos] saida s%d-%d" % (self.nome, porta_saida))
        else:
            print("[del-qos] Regra nao encontrada em PORTA-SAIDA de s%d-%d" % (self.nome, porta_entrada))
        if self.getPorta(porta_entrada).delRegra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto): # ERRO AQUI
            print("[del-qos] entrada de s%d-%d" % (self.nome, porta_entrada))
        else:
            print("[del-qos] Regra nao encontrada em PORTA-ENTRADA de s%d-%d" % (self.nome, porta_entrada))
                
        # remover da porta de saida
        if tipo_switch == Switch.SWITCH_FIRST_HOP:
            delRegraForwarding(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto)
            if regra.meter_id:
                delRegraMeter(self,regra.meter_id)
                delMeter(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto)
            print("[del-qos] rm forwdng firsthp %s:%d -> %s:%d" %(ip_src, src_port, ip_dst, dst_port))
        else: # tipo_switch = Switch.SWITCH_LAST_HOP + Switch.SWITCH_OUTRO (utiliza addforwarding_conjunction) # qual dos dois da erro...
            print("[del-qos] rm conjnctn %s:%d -> %s:%d" %(ip_src, src_port, ip_dst,dst_port))
            delRegraForwarding_com_Conjunction(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida, qos_match) # checando se eu der um remover com matching que pega duas regras, ele remove as duas ou so uma
        return True

#porta_switch antes era dport -> eh a porta onde a regra vai ser salva -> porta de saida do switch
    def GBAM(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_entrada:int, porta_saida:int, banda:int, prioridade:int, classe:int, application_class:int, tipo_switch:int):
        """ Existem 3 tipos de switches: 1. borda emissora primeiro salto, 2. borda emissora ultimo salto, 3.backbones 
        1. configurar marcação de qos e meter utilizando addRegraForwarding e addRegraMeter
        2. configurar regra marcacao monitoring/matching qos(Vai alternando)
        3. configurar regra matching qos e matching monitoringk
        """

        # tem uma diferenca do GBAM de borda e do gbam backbone....

        # verificar se e
        print("[alocarGBAM-S%d] porta %d->%d, src: %s, dst: %s, banda: %d, prioridade: %d, classe: %d \n" % (self.nome, porta_entrada, porta_saida, ip_src, ip_dst,banda, prioridade, classe))

        #caso seja classe de controle ou best-effort, nao tem BAM, mas precisa criar regras da mesma forma
        #best-effort
        if classe == SC_BEST_EFFORT:
            self.addRegraBE(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida)
            return []

        #controle
        if classe == SC_CONTROL:
            addRegraForwarding2(datapath=self.datapath, qos_mark_maching=getQOSMark(classe, prioridade), prioridade=CONJUNCTION_PRIO, hard_timeout=BE_HARD_TIMEOUT, idle_timeout=BE_IDLE_TIMEOUT, flow_removed=False, ip_ver=ip_ver, ip_src=ip_src,ip_dst=ip_dst, out_port=porta_saida, src_port=src_port, dst_port=dst_port, proto=proto, fila=FILA_CONTROLE, meter_id=None)
            return []
 
        # tipo_switch==Switch.SWITCH_OUTRO
        return self._alocarGBAM_borda(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, banda, prioridade, classe, application_class, tipo_switch=tipo_switch)
        #self._backboneGBAM(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, banda, prioridade, classe)

    def _alocarGBAM_borda(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_entrada:int, porta_saida:int, banda:int, prioridade:int, classe:int, application_class:int, tipo_switch:int) -> list:
        """Criar em porta de entrada significa: essa regra deve ser salva na porta de entrada ? = Sim -> apenas armazena a regra e reduz a banda;;; Não, é na porta de saída -> entrao armazena a regra, reduz a banda e cria a regra openflow nos switches para traffic shaping"""
        # retornar uma lista de acoes

        outraClasse = SC_REAL
        if outraClasse == classe:
            outraClasse = SC_NONREAL

        lista_acoes = []
        resp_entrada, lista_remover_entrada = self._ondeAlocarFluxoQoS(porta_entrada, classe, prioridade, banda)

        resp_saida, lista_remover_saida = self._ondeAlocarFluxoQoS(porta_saida, classe, prioridade, banda)

        #nao tem como alocar em uma das portas, entao ja eras -> rejeitar fluxo
        if resp_entrada == SEMBANDA or resp_saida == SEMBANDA: 
            print("Sem banda para fluxo (rej)")
            return []

        # remover fluxos que emprestam ou com menor prioridade
        if lista_remover_saida != []:
            print("Removendo regras (port saida)")
            # print("remover regras")
            for regra in lista_remover_saida:
                lista_acoes.append(Acao(self,porta_saida, REMOVER, regra, tipo_switch), PORTA_SAIDA,tipo_switch)         
        
        # remover fluxos que emprestam ou com menor prioridade
        if lista_remover_entrada != []:
            print("Removendo regras (port entrada)")
            for regra in lista_remover_saida:
                lista_acoes.append(Acao(self,porta_entrada, REMOVER, regra, tipo_switch), PORTA_ENTRADA, tipo_switch)
            # print("remover regras")    

        # tem banda na propria classe
        if resp_saida == NAOEMPRESTANDO:
            print("criar regra na propria classe")
            lista_acoes.append(Acao(self, porta_saida, CRIAR, Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, NO_METER, banda, prioridade, classe, getQueueId(classe, prioridade), application_class,getQOSMark(classe,prioridade), {}, False, classificado=True), PORTA_SAIDA, tipo_switch))
            # return lista_acoes
        elif resp_saida == EMPRESTANDO:         # nao tem banda na propria classe, mas pode emprestar
            # print("criar regra na outra classe")
            lista_acoes.append(Acao(self, porta_saida, CRIAR, Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, NO_METER, banda, prioridade, outraClasse, getQueueId(outraClasse, prioridade), application_class, getQOSMark(outraClasse,prioridade), {}, True, classificado=True),PORTA_SAIDA, tipo_switch))
            # return lista_acoes
        
        # tem banda na propria classe
        if resp_entrada == NAOEMPRESTANDO:  # nao tem banda na propria classe, mas pode emprestar
            # print("criar regra na propria classe")
            lista_acoes.append(Acao(self, porta_entrada, CRIAR, Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, NO_METER, banda, prioridade, classe, getQueueId(classe, prioridade), application_class, getQOSMark(classe,prioridade), {}, False, classificado=True), PORTA_ENTRADA, tipo_switch))
            # return lista_acoes
        elif resp_entrada == EMPRESTANDO:
            print("criar regra na outra classe")
            lista_acoes.append(Acao(self, porta_entrada, CRIAR, Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, NO_METER, banda, prioridade, outraClasse, getQueueId(outraClasse, prioridade), application_class, getQOSMark(outraClasse,prioridade), {}, True, classificado=True),PORTA_ENTRADA,tipo_switch))
            # return lista_acoes

        #algum erro ocorreu -> rejeitar
        return lista_acoes

    def _ondeAlocarFluxoQoS(self, porta_nome:int, classe:int, prioridade:int, banda:int):
        """Retorna se o fluxo deve ser armazenado emprestando banda ou nao, e a lista de regras que se deve remover para aloca-lo
         -> tuple[int, list[Regra]]:
        """

        porta_obj = self.getPorta(porta_nome)

        # tiver banda na mesma classe -> retornar que apenas criar a regra
        bandaDisponivelPropriaClasse, bandaDisponivelOutraClasse = porta_obj.getBandaDisponivelQoS() # valor em bits
        bandaDisponivelOutraClasse = bandaDisponivelOutraClasse/100
        bandaDisponivelPropriaClasse = bandaDisponivelPropriaClasse/100
        print("porta: %d classe: %d DisponivelC1:%d DisponivelC2:%d bandaRequisitada:%d" % (porta_nome, classe, bandaDisponivelPropriaClasse,bandaDisponivelOutraClasse, banda))
        if banda <= bandaDisponivelPropriaClasse: #Total - usado > banda necessaria
            print("A")
            return NAOEMPRESTANDO, []

        # nao tiver banda mas tiver fluxos emprestando o suficiente -> retornar que deve remover esses fluxos e entao criar a regra
        emprestando = porta_obj.getRegrasEmprestandoAteBandaNecessaria(classe, banda)
        if emprestando != []:
            print("B")
            return NAOEMPRESTANDO, emprestando

        # nao tiver fluxos emprestando mas existir fluxos de menor prioridade na classe -> retornar que deve remover esses fluxos e entao criar a regra
        regrasMenorPrioridade = porta_obj.getLowerPriorityRulesAteBandaNecessaria(classe, prioridade, banda)                
        if regrasMenorPrioridade != []:
            print("C")
            return NAOEMPRESTANDO, regrasMenorPrioridade

        # nao tiver fluxos de menor prioridade mas tiver banda na outra classe para emprestar -> retornar que deve criar a regra na outra classe
        if banda <= bandaDisponivelOutraClasse:
            print("D")
            return EMPRESTANDO, []
        print("E")
        return SEMBANDA, [] # rejeitar 


    def getFreeBandwForQoS(self, in_port, classe, prioridade, banda):
        # verifica banda disponível -> retorna 0 se for na própria classe, 1 se for emprestando e -1 se for rejeitado
        
        banda_classe1,banda_classe2 = self.getPorta(in_port).getBandaDisponivelQoS()
        
        if classe == 1:
            if banda_classe1 >= banda:
                return 0
            elif banda_classe2 >= banda:
                return 1
        elif classe ==2 :
            if banda_classe1 >= banda:
                return 1
            elif banda_classe2 >= banda:
                return 0
        return -1
    
    #adicionar rotas no switch - por agora fica com o nome de rede
    def addRedeIPv4(self, ip_dst, porta): 
        print("[S%s]Rede adicionada %s: %s" % (self.nome, ip_dst, str(porta)))
        self.redes[ip_dst]=porta
        return

    def addMac(self, mac, porta):
        self.macs[mac]=porta
        return

        #retorna uma porta ou -1
    def conheceMac(self, mac):
        if mac in self.macs:
            return self.macs[mac]
        
        return -1

    def addHost(self, ip, porta):
        self.hosts[ip]=porta
        return

#aqui verificar os prefixos
    def getPortaSaida(self, ip_dst):
        #retorna int

        if ip_dst in self.redes:
            return self.redes[ip_dst]

        return None

    def delRede(self, ip_dst, porta):
        #print("[%s]Rede deletada %s: %s" % (self.nome, ip_dst, porta))
        return

    def getPortas(self) -> list:
        return self.portas
    
    def getDP(self):
        return self.datapath
    

    def listarRegras(self):
        for porta1 in self.getPortas():
            # return
            print("\n[s%s-p%s] listar regras || C1T:%d, C1U:%d || C2T:%d, C2U: %d ||:\n" % (self.nome,porta1.nome, porta1.bandaTotalClasseReal, porta1.bandaUtilizadaClasseReal, porta1.bandaTotalClasseNaoReal, porta1.bandaUtilizadaClasseNaoReal))
            for rp1c1 in porta1.getRegrasAltaPrio(SC_REAL):
                print(rp1c1.toString()+"\n")
            #print("\n -- C1P2 (qtdregras: %d):" % (este_switch.p2c1rules.length))
            for rp2c1 in porta1.getRegrasMediaPrio(SC_REAL):
                print(rp2c1.toString()+"\n")
            #print("\n -- C1P3 (qtdregras: %d):" % (este_switch.p3c1rules.length))
            for rp3c1 in porta1.getRegrasBaixaPrio(SC_REAL):
                print(rp3c1.toString()+"\n")
            #print(" -- C2P1 (qtdregras: %d):" % (este_switch.p1c2rules.length))
            for rp1c2 in porta1.getRegrasAltaPrio(SC_NONREAL):
                print(rp1c2.toString()+"\n")
            #print("\n -- C2P2 (qtdregras: %d):" % (este_switch.p2c2rules.length))
            for rp2c2 in porta1.getRegrasMediaPrio(SC_NONREAL):
                print(rp2c2.toString()+"\n")
            #print("\n -- C2P3 (qtdregras: %d):" % (este_switch.p3c2rules.length))
            for rp3c2 in porta1.getRegrasBaixaPrio(SC_NONREAL):
                print(rp3c2.toString()+"\n")
            for be in porta1.getRegrasBE():
                print(be.toString()+"\n")

def tratador_addSwitches(controller, addswitch_json):
    """[arrumar] nome dos switches e o id, se comparar como string vai dar ruim, tem que armazenar como inteiro e comparar com inteiro -> pois eles se anunciam como 0000000000000001, as vezes"""

    print("Adicionando configuracao de switch")
    for i in addswitch_json:
        print(i)

        nome_switch = i['nome_switch']

        #procurando o switch
        switch = controller.getSwitchByName(nome_switch)
        port_to_controller = i['port_to_controller']
        ovsdb_addr = i['ovsdb_addr']
        #encontrar o switch pelo nome
        #criar as portas conforme a configuracao do json
        if(switch == None):
            switch = Switch(None,nome_switch, controller, port_to_controller, ovsdb_addr)
            controller.saveSwitch(switch=switch, switch_name=nome_switch)
        else:
            switch.port_to_controller = port_to_controller
            switch.ovsdb_addr = ovsdb_addr

        for porta in i['portas']:
            
            print (porta)

            nome_porta = porta['nome_porta']
            nome_interface = porta['nome_interface']
            largura_porta = porta['banda_total']
            prox_porta = porta['proxSwitch']

            # # verificar se porta já existe -> se existir, remover a porta, as regras e as regras OVS
            # switch.delPorta(nome_porta) -> vamos suport que nunca criamos duas vezes a mesma porta...
                
            switch.addPorta(nome_porta, nome_interface, int(largura_porta), int(prox_porta))

 
def tratador_delSwitches(controller, switch_cfg):

    nome_switch = switch_cfg['nome_switch']
    #encontrar o switch
    switch_obj= controller.getSwitchByName(nome_switch)

    if switch_obj == None:
        return
    
    for porta in switch_obj.getPortas():
        switch_obj.delPorta(porta.nome)

    controller.switches.remove(switch_obj)

    print('Switch removido: %s' % (nome_switch))


# DESISTIDO/MUDADO PARA GBAM APENAS

    # def addRegraQoSBackbone(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_entrada:int, porta_saida:int, flow_label:int, banda:int, prioridade:int, classe:int, fila:int, qos_mark:int, porta_nome_armazenar_regra:int, criarMeter:bool, criarOpenFlow:bool):
    #     #Criar regras agrupadas, como em: https://manpages.ubuntu.com/manpages/focal/en/man7/ovs-fields.7.html     
    #     return
    # def _backboneGBAM(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_entrada:int, porta_saida:int, banda:int, prioridade:int, classe:int):

    #     # alocar banda para um fluxo em um switch sem reservar banda, apenas utilizando os freds, podendo até emprestar banda
    #     lista_acoes = []

    #     porta_entrada_obj = self.getPorta(porta_entrada)


    #     # buscar as regras (freds) expirados
    #     lista_regras_expiradas = getRegrasExpiradas(porta_entrada_obj.getRegrasBE() + porta_entrada_obj.getRegrasC1() + porta_entrada_obj.getRegrasC2())

    #     for regra in lista_regras_expiradas:
    #         self.delRegra(regra.ip_ver, regra.ip_src, regra.ip_dst, regra.src_port,regra.dst_port, regra.proto, regra.porta_entrada, False)
    #         self.delRegra(regra.ip_ver, regra.ip_src, regra.ip_dst, regra.src_port,regra.dst_port, regra.proto, regra.porta_saida, True)

    #     # verificar onde se pode alocar o fluxo
    #     resp_entrada, lista_remover_entrada = self._ondeAlocarFluxoQoS(porta_entrada, classe, prioridade, banda)

    #     resp_saida, lista_remover_saida = self._ondeAlocarFluxoQoS(porta_saida, classe, prioridade, banda)  
        
    #     # remover o que for necessario
    #     # remover fluxos que emprestam ou com menor prioridade
    #     if lista_remover_saida != []:
    #         # print("remover regras")
    #         for regra in lista_remover_saida:
    #             lista_acoes.append(Acao(self,porta_saida, REMOVER, regra))         
        
    #     # remover fluxos que emprestam ou com menor prioridade
    #     if lista_remover_entrada != []:
    #         for regra in lista_remover_saida:
    #             lista_acoes.append(Acao(self,porta_entrada, REMOVER, regra))
    #         # print("remover regras")  

    #     # criar a regra para backboneGBAM -> depois que todos aceitarem, cada switch precisa salvar o fred (que é a regra) e roda o agrupadorde regras de fluxo
    #     # self.agruparRegrasFluxo(ip_ver, ip_src, ip_dst)

    #     return lista_acoes

    # def agruparRegrasFluxo(self, ip_ver:int, ip_src:str, ip_dst:str, porta_nome:int, classe:int):
        # """[assumido que todas as regras armazenadas foram aceitas pelo gbam] regra de agrupamento, agrupar fluxos que possuem mesma classe, mesma porta destino na mesma regra, com uma meter agregada (nao sei qual o limite
        # de uma meter, mas neste momento nao importa) -> solução não otima, mas que pode reduzir o tamanho da tabela de fluxos no backbone"""

        # # obter todos os fluxos que possuem a mesma classe e porta destino
        # regras_classe = {}

        # lista_regras = []
        # lista_acoes = []

        # if classe == SC_BEST_EFFORT:
        #     lista_regras = self.getPorta(porta_nome).getRegrasBE()
        # elif classe == SC_REAL:
        #     lista_regras = self.getPorta(porta_nome).getRegrasC1()
        # elif classe == SC_NONREAL:
        #     lista_regras = self.getPorta(porta_nome).getRegrasC2()

        # # agrupando por porta destino e porta de saida
        # for r in lista_regras:
        #     if not regras_classe[str(r.src_port) + '_'+ str(r.dst_port) + '_'+ str(r.prioridade) + '_' +str(r.porta_saida)+ '_' +str(r.ip_ver)]:
        #         regras_classe[str(r.src_port) + '_'+ str(r.dst_port) + '_'+ str(r.prioridade) + '_' +str(r.porta_saida)+ '_' +str(r.ip_ver)] = [r]
        #     else:
        #         regras_classe[str(r.src_port) + '_'+ str(r.dst_port) + '_'+ str(r.prioridade) + '_' +str(r.porta_saida)+ '_' +str(r.ip_ver)].append(r)

        # # para cada key de regras_classe -> remover regras openflow e meter existentes para essas regras -> somar a banda -> criar nova meter, associar cada regra a essa meter -> criar a regra de fluxo agrupada
        # # sem tempo para otimizar isso
        # for regra in lista_regras:
        #     delRegraForwarding(self, regra.ip_ver, regra.ip_src, regra.ip_dst, regra.src_port, regra.dst_port, regra.proto)
        #     delRegraMeter(self, regra.meter_id)
        
        # # # somar banda de todas as regras a serem agrupadas e criar as meter rules -> nem precisa meter aqui
        # for val in regras_classe.values(): 
        # #     somabanda = 0
        #     ip_ver = -1
        #     proto = -1
        #     src_port = -1
        #     dst_port = -1
        #     ip_srcs = []
        #     ip_dsts = []
        #     porta_destino = porta_nome
        #     fila = -1
        #     for regra in val:

        #         if porta_destino == -1:
        #             src_port = regra.src_port
        #             dst_port = regra.dst_port
        #             fila = getQueueId(regra.classe, regra.prioridade)
                    
        #         ip_srcs.append(regra.ip_src)
        #         ip_dsts.append(regra.ip_dst)
        #         lista_acoes.append(Acao(self, porta_nome, REMOVER, regra))

        #     lista_acoes.append(Acao(self, porta_nome, CRIAR, Regra({})))
        #     #addRegraF()

        # #         somabanda += regra.banda

        #     # criar meter rule e associar a cada regra

        #     # criar os matchings para src_port, ip_src, ip_dst, e dst_port
        #     # criar a regra openflow no switch


        # return lista_acoes