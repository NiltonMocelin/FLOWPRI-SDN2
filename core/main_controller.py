### USAR PYTHON 3 !!

# importar o tratador da interface web
import sys, os

# sys.path.append('../../FLOWPRI-SDN2')

from netifaces import AF_INET, ifaddresses, interfaces

# import rest_topology, ofctl_rest, ws_topology

# setting path for importation
# sys.path.append('../qosblockchain')
# sys.path.append('../ryu')
# sys.path.append('../traffic_classification')
# sys.path.append('../traffic_monitoring')
# sys.path.append('../wsgiWebSocket')
# sys.path.append('../')

current = os.path.dirname(os.path.realpath(__file__))

# Getting the parent directory name
# where the current directory is present.
parent = os.path.dirname(current)

# adding the parent directory to 
# the sys.path.
sys.path.append(parent)

# # Add the parent directory to sys.path

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, inet, ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4, arp, icmp, udp, tcp, lldp, ipv6, dhcp, icmpv6

from ryu.topology import event

#socket e thread
from threading import Thread

#tratar json
import json

#tratar tempo - monotonic clock -> round(time.monotonic()*1000)
import time
import datetime
##prints logging - logging.info('tempo atual %d\n' % (round(time.monotonic()*1000)))
import logging

# importar o tratador da interface web
import sys, os

#codigos das acoes
from fp_constants import IPV4_CODE, IPV6_CODE, TCP, UDP, MARKING_PRIO, MONITORING_PRIO, METER_PRIO, CONJUNCTION_PRIO, FILA_BESTEFFORT, NO_QOS_MARK, FILA_CONTROLE, CFG_FILE, ligar_blockchain, ligar_monitoring


from fp_api_qosblockchain import tratar_blockchain_setup, criar_chave_sawadm, BlockchainManager

from fp_constants import SC_BEST_EFFORT, PORTA_MANAGEMENT_HOST_SERVER, BE_HARD_TIMEOUT

# try:
from fp_switch import Switch, tratador_addSwitches, tratador_delSwitches
# except ImportError:
#     print('Erro de importacao da classe SwitchOVS')

# from fp_server import servidor_configuracoes

from fp_acao import Acao

from fp_openflow_rules import add_default_rule, injetarPacote, addRegraMonitoring, desligar_regra_monitoramento, add_flow, getMeterID_from_Flow,delRegraMeter, addRegraForwarding2

from fp_utils import tratador_addDominioPrefix, tratador_ipsDHCP, prepare_htb_queues_switch
from fp_utils import current_milli_time, calculate_network_prefix_ipv4, getQOSMark, enviar_msg, getEquivalentMonitoringMark

# print('importando fp_topo_discovery')
#descoberta de topologia
# from fp_topology_discovery import handler_switch_enter, handler_switch_leave

# print('importando fp_dhcp')
#tratador DHCPv4
from fp_dhcp import handle_dhcp #, SimpleDHCPServer
# from dhcp_server import DHCPResponder

from fp_icmp import handle_icmps, send_icmpv4, send_icmpv6

# print('importando interface_web')
# import wsgiWebSocket.interface_web as iwb
from wsgiWebSocket.interface_web import lancar_wsgi #, _websocket_rcv, _websocket_snd, dados_json

from traffic_classification01.classificador import classificar_pacote

from traffic_monitoring.fp_monitoring import monitorar_pacote

# from fp_api_qosblockchain import BlockchainManager

from fp_fred import Fred, FredManager

from fp_rota import RotaManager, tratador_addRotas

from traffic_monitoring.monitoring_utils import MonitoringManager, calcular_qos, tratar_flow_monitoring, enviar_transacao_blockchain_api

from fp_server import servidor_configuracoes
def get_time_monotonic():
    return round(time.monotonic()*1000)

lista_monitoramento = [50,51,52,53,54,55]
class FLOWPRI2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    controller_singleton = None

    def __init__(self, *args, **kwargs):
        print("CONTROLADOR - \n Init Start\n" )# % (IPC))
        super(FLOWPRI2,self).__init__(*args,**kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}

        self.tempo_funcionamento = current_milli_time()

        self.arpList = {}
        self.ip_to_port= {}


        self._LIST_IPS_DHCP = []
        self._LIST_PREFIX_DOMINIO = []

        self.controladores_conhecidos = []

        self.switches = {}

        FLOWPRI2.controller_singleton = self

        # self.serverDHCP = SimpleDHCPServer()
        # self.serverDHCP = DHCPResponder()

        self.ip_management_host = '172.16.0.100'

        # self.CONTROLLER_INTERFACE = "eth0"
        interfs=interfaces()
        interfs.remove('lo')
        self.CONTROLLER_INTERFACE = interfs[0]

        try:
            self.IPCv4 = str(ifaddresses(self.CONTROLLER_INTERFACE)[AF_INET][0]['addr'])
            self.IPCv6 = str(ifaddresses(self.CONTROLLER_INTERFACE)[10][0]['addr'].split("%")[0])
            self.IPCc = self.IPCv4
            self.MACc = str(ifaddresses(self.CONTROLLER_INTERFACE)[17][0]['addr'])
            self.CONTROLADOR_ID = self.IPCc

            print("Controlador ID - {}"  .format(self.CONTROLADOR_ID))
            print("Controlador IPv4 - {}".format(self.IPCv4))
            print("Controlador IPv6 - {}".format(self.IPCv6))
            print("Controlador MAC - {}" .format(self.MACc))
        except:
            print("Verifique o nome da interface e modifique na main")

        # onde as principais coisas são armazenadas
        self.fredmanager = FredManager()
        self.qosblockchainmanager = BlockchainManager()
        self.rotamanager = RotaManager()
        self.flowmonitoringmanager = MonitoringManager()


        setup(self)

    @staticmethod
    def getControllerInstance():
        return FLOWPRI2.controller_singleton
    
    def getSwitchByName(self, nome) -> Switch:
        return self.switches.get(nome, None)

    def create_qos_rules(self, ip_src:str, ip_dst:str, ip_ver:int, src_port:int, dst_port:int, proto:int, fred:Fred, src_meu_dominio:bool, dst_meu_dominio:bool) -> bool:
        "cria a regra de QoS + meter + marcacao, no switch ovs e na instancia"
        "True = fluxo aceito com qos"
        "False = Fluxo rejeitado"
    
         # ARRUMAR O RETORNO -> bool
        print("[create-qos-rules]-in")

        #flow qos
        banda=fred.bandwidth
        prioridade=fred.prioridade
        classe=fred.classe
        flow_label = fred.label

        # rota com os datapaths dos switches em ordem
        switch_route = self.rotamanager.get_rota(ip_src, ip_dst)

        if switch_route == None:
            return False

        lista_acoes:list =[]

        # se o host emissor for meu dominio o primeiro switch cria as regras especiais (meter + monitoramento_encaminhamento)
        # o ultimo switch cria regras especiais tbm (meter + monitoramento_Encaminhamento + monitoramento_marcacao)

        # apenas o primeiro switch faz gbam criando a regra meter, é preciso realmente diferenciar 
        # -- no modelo atual, apenas o primeiro switch não é backbone, o resto é tudo considerado backbone
        # -- rodar o gbam igual para eles, apenas o gbam precisa diferenciar cada tipo de switch

        switch_inicial = 0
        switch_final = len(switch_route)

        if src_meu_dominio:
            switchh = self.getSwitchByName(switch_route[0].switch_name)
            porta_saida = switch_route[0].out_port
            porta_entrada = switch_route[0].in_port
            
            print("switch-first-hp")
            #first-hop
            acoes_retorno = switchh.GBAM(ip_ver=ip_ver,ip_src=ip_src,ip_dst=ip_dst,src_port=src_port,dst_port=dst_port,proto=proto, porta_entrada=porta_entrada, porta_saida=porta_saida, banda=banda,prioridade=prioridade,classe=classe, application_class=flow_label,tipo_switch=Switch.SWITCH_FIRST_HOP)
            if acoes_retorno!=[]:
                lista_acoes += acoes_retorno
            else:
                return False
            switch_inicial+=1
            
        elif dst_meu_dominio:

            #last-hop
            switchh = self.getSwitchByName(switch_route[-1].switch_name)
            porta_saida = switch_route[-1].out_port
            porta_entrada = switch_route[-1].in_port # aqui ta certo, é o ultimo mesmo
            acoes_retorno = switchh.GBAM(ip_ver=ip_ver,ip_src=ip_src,ip_dst=ip_dst,src_port=src_port,dst_port=dst_port,proto=proto, porta_entrada=porta_entrada, porta_saida=porta_saida, banda=banda,prioridade=prioridade,classe=classe, application_class=flow_label, tipo_switch=Switch.SWITCH_LAST_HOP)
            if acoes_retorno!=[]:
                lista_acoes += acoes_retorno
            else:
                return False
            switch_final-=1


        # ELSE == BORDA
        # para borda == Switch.Outro
        for i in range(switch_inicial,switch_final): # excluir o first e o last-hops
            switchh = self.getSwitchByName(switch_route[i].switch_name)
            porta_saida = switch_route[i].out_port
            porta_entrada = switch_route[i].in_port
            acoes_retorno = switchh.GBAM(ip_ver=ip_ver,ip_src=ip_src,ip_dst=ip_dst,src_port=src_port,dst_port=dst_port,proto=proto, porta_entrada=porta_entrada, porta_saida=porta_saida, banda=banda,prioridade=prioridade,classe=classe, application_class=flow_label ,tipo_switch=Switch.SWITCH_OUTRO)
            if acoes_retorno!=[]:
                lista_acoes += acoes_retorno
            else:
                return False
            
        # self.delete_rules(switch_route, ip_src, ip_dst, ip_ver, src_port, dst_port, proto, src_meu_dominio=True, qos_match=31) # o false vai forçar uma subsituição das regras... espero
        #deletar somente a regra que esta na armazenada na instancia porta
        #delete_be_rules_soOF_bordaEbackbone --> conclusao, nao precisa fazer nada
        for acao in lista_acoes:
            acao.executar()

        # agora ja pode remover as regras BE -- melhor deixar expirar por idle timeout, pq algumas regras sao substituidas
        print("[create-qos-rules]-out")
        return True # aceito

    def delete_be_rules_soOF_bordaEbackbone(ip_src:str, ip_dst:str, ip_ver:int, src_port:int, dst_port:int, proto:int, souBorda:bool):
        """ a regra do primeiro salto, no caso de ser borda -> é subsituida pela regra qos
            as regras conjunction nao vou remover (para fazer os testes nao precisa), deixar para expirar por idle_timeout ==> pronto, nao precisa fazer nada 
        """

        if souBorda:
            print("fazer nada")
        else:
            print("fazer nada")
        return

    def getRegrasAntesDeRemover(self, switch_route, ip_src:str, ip_dst:str, ip_ver:int, src_port:int, dst_port:int, proto:int):
        lista_acoes = []
        for i in switch_route: # excluir o first e o last-hops
            print("delete in backbone")
            switchh = self.getSwitchByName(i.switch_name)
            porta_saida = i.out_port
            porta_entrada = i.in_port
            switchh.getPorta(porta_saida).getRegras(ip_ver=ip_ver,proto=proto, ip_src=ip_src,ip_dst=ip_dst,src_port=src_port,dst_port=dst_port)


    def delete_rules(self, switch_route, ip_src:str, ip_dst:str, ip_ver:int, src_port:int, dst_port:int, proto:int, src_meu_dominio:bool, qos_match=None):

        switch_inicial = 0
        switch_final = len(switch_route)
        print("[delete_rules] s->%s:%d d->%s:%d proto:%d" %(ip_src,src_port,ip_dst,dst_port,proto))
        #Erro em delRegraQoS
        if src_meu_dominio:
            print("delete in first hop")
            #first-hop
            switchh = self.getSwitchByName(switch_route[0].switch_name)
            porta_saida = switch_route[0].out_port
            porta_entrada = switch_route[0].in_port
            switchh.delRegraQoS(ip_ver=ip_ver,ip_src=ip_src,ip_dst=ip_dst,src_port=src_port,dst_port=dst_port,proto=proto, porta_entrada=porta_entrada, porta_saida=porta_saida,tipo_switch=Switch.SWITCH_FIRST_HOP, qos_match=qos_match)
            switch_inicial+=1
        for i in range(switch_inicial,switch_final): # excluir o first e o last-hops
            print("delete in backbone")
            switchh = self.getSwitchByName(switch_route[i].switch_name)
            porta_saida = switch_route[i].out_port
            porta_entrada = switch_route[i].in_port
            switchh.delRegraQoS(ip_ver=ip_ver,ip_src=ip_src,ip_dst=ip_dst,src_port=src_port,dst_port=dst_port,proto=proto, porta_entrada=porta_entrada, porta_saida=porta_saida,tipo_switch=Switch.SWITCH_OUTRO, qos_match=qos_match)
        return

    def create_be_rules(self, route_nohs, ip_src:str, ip_dst:str, ip_ver:int, src_port:int, dst_port:int, proto:int, classificado:bool):
        """Cria a regra BE (com marcacao) no switch ovs e na instancia"""

        for node in route_nohs:
            switchh = self.getSwitchByName(node.switch_name)
            porta_saida = node.out_port
            print("Criando [BE] backbone")
            switchh.addRegraBE(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida, toController=False, classificado=classificado)
            
        return True

    def create_be_rules_meu_dominio(self, route_nohs, ip_src:str, ip_dst:str, ip_ver:int, src_port:int, dst_port:int, proto:int, toController:bool, limpar=False, classificado:bool=False):
        """Cria a regra BE (com marcacao) no switch ovs e na instancia"""
        # Aqui dentro, ver como remover as regra antes de criar as 
        BE_MATCH = 31
        idxnodes = 0
        for node in route_nohs:
            switchh = self.getSwitchByName(node.switch_name)
            porta_saida = node.out_port
            porta_entrada = node.out_port

            if idxnodes == 0:
                if limpar:
                    switchh.delRegraQoS(ip_ver, ip_src, ip_dst,src_port, dst_port, proto, porta_entrada=porta_entrada, porta_saida=porta_saida, qos_match=BE_MATCH, tipo_switch=Switch.SWITCH_FIRST_HOP)
                print("Criando [BE] origem")
                switchh.addRegraBE(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida, marcar=True, primeiroSaltoBorda=True, toController=toController, classificado=classificado)
            else:
                print("Criando [BE] backbone")
                if limpar:
                    switchh.delRegraQoS(ip_ver, ip_src, ip_dst,src_port, dst_port, proto, porta_entrada=porta_entrada, porta_saida=porta_saida,qos_match=BE_MATCH,tipo_switch=Switch.SWITCH_OUTRO)
                switchh.addRegraBE(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida, classificado=classificado)
            idxnodes +=1

        return True
    
    def create_be_rules_backbone_soOF(self, route_nohs, ip_src:str, ip_dst:str, ip_ver:int, src_port:int, dst_port:int, proto:int):
        for node in route_nohs:
            switchh = self.getSwitchByName(node.switch_name)
            porta_saida = node.out_port
    
            print("Criando [BE] backbone")
            switchh.addRegraBE_soOF(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida,False,False)
        return True
    
    def create_be_rules_meu_dominio_soOF(self, route_nohs, ip_src:str, ip_dst:str, ip_ver:int, src_port:int, dst_port:int, proto:int, toController:bool=False):
        indx = 0
        for node in route_nohs:
            switchh = self.getSwitchByName(node.switch_name)
            porta_saida = node.out_port
            if indx == 0:
                print("Criando [BE] backbone")
                switchh.addRegraBE_soOF(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida,True,toController)
                continue
            switchh.addRegraBE_soOF(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida,False,False)
            indx+=1
        return True
    

    def saveSwitch(self, switch_name:int, switch:Switch):
        self.switches[switch_name] = switch 
        return


    def remover_regras_freds_expirados(self):

        # #removendo freds expirados
        # self.fredmanager.remover_freds_expirados()
        # #removendo regras expiradas
        for switch in self.switches.values():
            switch.remover_regras_expiradas(BE_HARD_TIMEOUT +2)

        return
    

    def get_prefix_meu_dominio(self)->list:
        return self._LIST_PREFIX_DOMINIO

    def list_switches(self):
        return self.switches.values()
    

    def substituirRegraSeExistirBorda_posCriacaoNovas(self, switch_route, ip_src:str, ip_dst:str, ip_ver:int, src_port:int, dst_port:int, proto:int, qos_match=None):
        """Evitando remover regras, vamos aproveitar o beneficio da substituicao -> se o matching é igual == subsitui -> util para borda emissora"""
        """backbone usar outra fn"""
        indx= 0
        for noh in switch_route:

            switchh = self.getSwitchByName(noh.switch_name)
            porta_entrada = noh.in_port
            porta_saida = noh.out_port

            if indx ==0:
                switchh.delRegraQoS_semRemoverOpenFlow(ip_ver, ip_src,ip_dst,src_port,dst_port,proto,porta_entrada,porta_saida,qos_match)
                continue            
            # se nao for primeiro salto == remover a conjunction anterior qos == 31 (BE)
            switchh.delRegraConj(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, qos_match)
        return

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print("Novo switch anunciado.... tempoAtivo:",current_milli_time()-self.tempo_funcionamento,"\n")

        #aqui nao se obtem tantas informacoes sobre os switches como eu gostaria
        tempo_i = get_time_monotonic()
    
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        print("[%s] switch_features - setup de S%d \n" % (datetime.datetime.now().time(), datapath.id))

        add_default_rule(datapath)


        switch = self.getSwitchByName(datapath.id)
        if switch == None:
            switch = Switch(datapath,datapath.id, self, port_to_controller)
            self.saveSwitch(switch=switch, switch_name=datapath.id)
        else:
            switch.datapath = datapath
            self.saveSwitch(switch=switch, switch_name=datapath.id)

        port_to_controller = switch.getPortToController()
        print("Switch name: ", datapath.id)

        # deve ter rota pre configurada, se nao, precisa configurar depois
        if port_to_controller != -1:
            actionss = [parser.OFPActionSetQueue(FILA_CONTROLE), parser.OFPActionOutput(port_to_controller)]

            #adicionar regra para hosts alcançarem o controllador server
            if self.IPCv4 != '':
                matchh = parser.OFPMatch(**{'eth_type':IPV4_CODE, 'ipv4_dst':self.IPCv4})
                add_flow(datapath=datapath, priority=CONJUNCTION_PRIO, match=matchh, actions=actionss, table_id=0)
            if self.IPCv6 != '':
                matchh = parser.OFPMatch(**{'eth_type':IPV6_CODE, 'ipv6_dst':self.IPCv6})
                add_flow(datapath=datapath, priority=CONJUNCTION_PRIO, match=matchh, actions=actionss,table_id=0)
        else:
            print("[swfeatures] error conf switch->controller port (missing cfg)")

        prepare_htb_queues_switch(self, switch)

        print("Switch table:")
        for sw in self.switches.values():
            print(sw.toString())

        print('[switch_features] fim settage - tempo_decorrido: %d\n' % (get_time_monotonic() - tempo_i))

# # ### Descoberta de topologia
#     #tratador eventos onde um switch se conecta
#     @set_ev_cls(event.EventSwitchEnter)
#     def _handler_switch_enter(self, ev):
#         handler_switch_enter(self, ev)

#     #tratador de eventos onde um switch se desconecta
#     @set_ev_cls(event.EventSwitchLeave)
#     def _handler_switch_leave(self, ev):
#         handler_switch_leave(self, ev)

#tratador de eventos de modificacao de portas nos switcches
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPPR_ADD:
            reason = 'ADD'
        elif msg.reason == ofp.OFPPR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPPR_MODIFY:
            reason = 'MODIFY'
        else:
            reason = 'unknown'

        self.logger.debug('OFPPortStatus received: reason=%s desc=%s',
                          reason, msg.desc)

    #Quando um fluxo eh removido ou expirou, chama essa funcao. OBJ --> atualizar quais fluxos nao estao mais utilizando banda e remover do switch     
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """verificar se é uma regra qos monitoring == quando a regra do primeiro switch (borda emissora) da rota espirar"""
        initime = current_milli_time()
        print("###################################################################################")
        print("[flow-removed] init ", initime , " -- tempo em funcionamento:",current_milli_time()-self.tempo_funcionamento)
        tempo_i_monotonic = round(time.monotonic()*1000)
        
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
            return
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
            return
        else:
            reason = 'unknown'
            return

        ip_src = None
        ip_dst = None
        qos_match = None
        src_port = None
        dst_port = None
        proto = None
        ip_ver = None
        if 'ipv4_dst' in msg.match:
            ip_dst = msg.match['ipv4_dst']
            ip_src = msg.match['ipv4_src']
            ip_ver = IPV4_CODE
        elif 'ipv6_dst' in msg.match:
            ip_dst = msg.match['ipv6_dst']
            ip_src = msg.match['ipv6_src']
            ip_ver = IPV4_CODE
        if 'ip_dscp' in msg.match:
            qos_match= msg.match['ip_dscp']
        if 'ipv6_flabel' in msg.match:
            qos_match= msg.match['ipv6_flabel']
        if 'tcp_src' in msg.match:
            src_port = msg.match['tcp_src']
            dst_port = msg.match['tcp_dst']
            proto=TCP
        if 'udp_src' in msg.match:
            src_port = msg.match['udp_src']
            dst_port = msg.match['udp_dst']
            proto=UDP
        
        if not qos_match:
            qos_match = 0
        #por agora, tanto as regras de ida quanto as de volta sao marcadas para notificar com o evento
        #atualizar no switch que gerou o evento
        route_nodes = self.rotamanager.get_rota(ip_src, ip_dst)

        if route_nodes == None:
            print("[flow-removed]Problema com as rotas !!")
            return

        if src_port == None and dst_port == None: 
            print("[flow-removed]Regra conj expirou")
            #nao fazer nada, pois nao precisa, as portas podem ser reaproveitadas, deixa la na tabela
            return

        #Se nao tiver dscp ou ipv6_flable entao remover best-effort (mas nao vai ser o caso) -- no entanto as regras best-effort nao serao notificadas entao nao precisa
        # arrumar aqui

        switchh = self.getSwitchByName(dp.id)

        regra_salva = switchh.getPorta(route_nodes[0].out_port).getRegra(ip_ver,proto,ip_src,ip_dst,src_port, dst_port)
        print("[flw-rmvd] razao:%s s->%s:%d d->%s:%d qos_match:%d" %( reason, ip_src,src_port, ip_dst,dst_port, qos_match))
        if not regra_salva:
            print("[flw-rmvd] Era BE (sem regra armazenada)== fazer nada")
            return

        #     # se quem expirou foi o primeiro switch da borda emissora -> a regra de monitoramento, entao, verificar se deve ligar ou desligar
            # if dp.id == route_nodes[0].switch_name:
        if self.souDominioBorda(ip_src):    
            if dp.id == route_nodes[0].switch_name:
                switchh = self.getSwitchByName(dp.id)
                # sss mudando apra que a regra de monitormaneto ative no primeiro switch e nao no ultimo mais -- pq nao fazia sentido ser no ultimo, se é o primeiro que ocorre marcacao e criação da regra de monitormaento
                if regra_salva.classe!=SC_BEST_EFFORT:
                    if not regra_salva.monitorando:
                        regra_salva.monitorando = True
                        #iniciar monitoramento: regra de monitoramento
                        if ligar_monitoring:
                            print("Ligando regra monitoramento %s:%d->%s:%d porta_saida:%d meter:%d fila:%d qos_match:%d (-> 0) qos_mark:%d" %(ip_src, src_port, ip_dst,dst_port, route_nodes[0].out_port, regra_salva.meter_id, regra_salva.fila, regra_salva.qos_mark, getEquivalentMonitoringMark(regra_salva.classe, regra_salva.prioridade)))
                            switchh.add_regra_monitoramento_fluxo(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, route_nodes[0].out_port, regra_salva.fila, qos_mark_action=getEquivalentMonitoringMark(regra_salva.classe, regra_salva.prioridade),qos_mark_matching=None,meter_id=regra_salva.meter_id)
                            return
                    else:
                        print("Ja estava monitorando -> agora removere")
                else:
                    print("Regra BE ? (nao deveriam gerar flowremoved)")
            
            print("switch diferente de primeiro mas eh borda origem")
            self.delete_rules(route_nodes, ip_src, ip_dst, ip_ver, src_port, dst_port, proto, src_meu_dominio=True, qos_match=qos_match)
        else:
            print("Nao sou borda emissora")    
            self.delete_rules(route_nodes, ip_src, ip_dst, ip_ver, src_port, dst_port, proto, src_meu_dominio=False, qos_match=qos_match)

        print("Depois da remocao !")
        switchh.listarRegras()

        endtime = current_milli_time()
        print('[pktin] icmpv4 finish (monotonic)', round(time.monotonic()*1000)- tempo_i_monotonic)
        print("[flow-removed] end:", endtime, ' duracao:', endtime-initime)
        return 0

    def tratamento_pktin_sem_marcacao_meu_dominio(self, rota_fluxo, este_switch_obj:Switch, nome_switch_primeiro_salto:int, ip_ver, ip_src,ip_dst,src_port,dst_port, proto, out_port, msg):
        if nome_switch_primeiro_salto == este_switch_obj.nome: # quem disparou foi o primeiro switch da rota == iniciar classificacao fluxo + criar regra de classificacao
            print("[pkt-in]: iniciando classificacao de fluxo %d" % (este_switch_obj.nome))
            classificar_pacote(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, msg.data, reiniciar=True) # classificar do zero
            print("criar regras BE sem conjunction + marcacao BE + copia para controlador")
            # self.create_be_rules_meu_dominio(route_nohs=rota_fluxo, ip_src=ip_src, ip_dst=ip_dst, ip_ver=ip_ver, src_port=src_port,dst_port=dst_port,proto=proto, toController=True)
            self.create_be_rules_meu_dominio_soOF(route_nohs=rota_fluxo, ip_src=ip_src, ip_dst=ip_dst, ip_ver=ip_ver, src_port=src_port,dst_port=dst_port,proto=proto, toController=True)
            injetarPacote(este_switch_obj.datapath, FILA_BESTEFFORT, out_port, msg, qos_mark=getQOSMark(SC_BEST_EFFORT,1))  
        else: # nao foi primeiro switch da rota,== ERRO, mas ... vamos entao == repetir o reinicio da classificacao 
            print("[pkt-in]: comportamento inesperado - este pacote deveria ter regra BE no switch %d" % (este_switch_obj.nome))
            classificar_pacote(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, msg.data, reiniciar=True) # classificar do zero
            print("criar regras BE conjunction (sem marcacao e sem controlador)")
            # self.create_be_rules_meu_dominio(route_nohs=rota_fluxo, ip_src=ip_src, ip_dst=ip_dst, ip_ver=ip_ver, src_port=src_port,dst_port=dst_port,proto=proto, toController=True)
            self.create_be_rules_meu_dominio_soOF(route_nohs=rota_fluxo, ip_src=ip_src, ip_dst=ip_dst, ip_ver=ip_ver, src_port=src_port,dst_port=dst_port,proto=proto, toController=True)
            injetarPacote(este_switch_obj.datapath, FILA_BESTEFFORT, out_port, msg, qos_mark=getQOSMark(SC_BEST_EFFORT,1))  
        return
    
    def tratamento_pktin_com_marcacao_meu_dominio(self, rota_fluxo, este_switch_obj:Switch, out_port, ip_ver, ip_src , ip_dst, src_port, dst_port, proto, eth_src, eth_dst, qos_mark, msg):
        primeiro_switch_obj= self.getSwitchByName(rota_fluxo[0].switch_name)
        nome_switch_primeiro_salto = rota_fluxo[0].switch_name

        be_mark = getQOSMark(SC_BEST_EFFORT, 1) #31 << 2 = tos, 31 ==dscp

        if qos_mark == be_mark: #BE == fazer classificacao se for o primeiro switch da rota que gerou, se nao, apenas recriar a regra BE
            flow_classificacao = classificar_pacote(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, msg.data)

            if flow_classificacao == None:
                print("[trat_meu-domin]Classificacao em andamento -- nao fazer nada")
                return 
            
            # if src_port != 6000:
            #    flow_classificacao.classe_label = "be" 

            # flow_classificacao.classe_label = 'be' # testar be
            if flow_classificacao.classe_label == "be":
                print("Fluxo BE ip_src:%s src_port:%d ip_dst:%s dst_port:%d" %(ip_src, src_port, ip_dst,dst_port))
                # atualizar a regra para parar de enviar ao controlador
                # self.delete_rules(rota_fluxo, ip_src, ip_dst, ip_ver, src_port, dst_port, proto, src_meu_dominio=True, qos_match=31)
                self.create_be_rules_meu_dominio_soOF(route_nohs=rota_fluxo, ip_src=ip_src, ip_dst=ip_dst, ip_ver=ip_ver, src_port=src_port,dst_port=dst_port, proto=proto, toController=False)
                return
            
            #### aqui testando
            else: 
                print("criar regras qos, criar fred, preencher e enviar icmp fred announcement.")
                print("Fluxo QoS ip_src:%s src_port:%d ip_dst:%s dst_port:%d" %(ip_src, src_port, ip_dst,dst_port))
                self.tratamento_meu_dominio_pos_classificacao(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, eth_src, eth_dst, flow_classificacao, rota_fluxo) # nao eh BE
                # movido para addregraqos # este_switch_obj.getPorta(out_port).getRegra(ip_ver, proto, ip_src, ip_dst, src_port, dst_port).classificado = True 
                # return # nao reinjetar, pois eh uma copia
            ######
            
        return
    
    def tratamento_pktin_backbone(self, rota_fluxo, este_switch_obj, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, eth_src, eth_dst, qos_mark, out_port, msg):
        print("[packet-in] nao sou borda")
        BE_MARK = 31

        tempo_i_mili = current_milli_time()

        if qos_mark == 0: # == um fluxo nao marcado chegou nesse dominio backbone ? a borda nao marcou nem como bE nem QOS == algo errado aconteceu na borda == tratar como BE
            print('[pkt-in] comportamento não esperado no backbone: pacote nao marcado nem BE nem QOS (erro na borda) == tratado como BE')
        elif qos_mark != BE_MARK: 
            print('[pkt-in] comportamento não esperado no backbone: pacote marcado com QoS + pktin + nao borda == fazer nada')
            
            return

        # nao precisa mas enfim
        # self.delete_rules(rota_fluxo, ip_src, ip_dst, ip_ver, src_port, dst_port, proto, src_meu_dominio=False, qos_match=qos_mark)
        self.create_be_rules_backbone_soOF(rota_fluxo, ip_src, ip_dst, ip_ver, src_port, dst_port, proto)

        injetarPacote(este_switch_obj.datapath, FILA_BESTEFFORT, out_port, msg, qos_mark=qos_mark) # podia injetar no ultimo da rota tbm, mas como todos ja tem a regra nesse ponto, pode ser em qualquer um
        print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- tempo_i_mili)
        return
    
    def tratamento_monitoramento_fluxo(self, ip_ver, ip_src, eth_src, ip_dst, eth_dst, src_port, dst_port, proto, pkt_len, switch, out_port, souOrigem:bool, souDestino:bool):
        label = "%d_%d_%s_%s_%d_%d" %(ip_ver, proto, ip_src, ip_dst, src_port, dst_port)
        monitoramento_recebido = self.flowmonitoringmanager.getMonitoring(label)
        monitoramento_fluxo = monitorar_pacote(self.IPCc, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, pkt_len, monitoringmanager= self.flowmonitoringmanager)

        if monitoramento_fluxo != None:
            print("Monitoramento realizado")

        # monitoramento_fluxo = None
        # desligar_regra_monitoramento(switch=switch_ultimo, ip_ver=ip_ver,ip_src=ip_src,ip_dst=ip_dst,out_port=out_port,src_port=src_port,dst_port=dst_port,proto=proto)
        if monitoramento_fluxo != None: #quando o monitoramento estiver completo
            # mudar a regra de monitoramento do primerio switch da rota para nao enviar pacotes ao controlador  -> essa regra tem um tempo hardtimeout menor 2s e uma flag, da proxima vez que expirar deve voltar a monitorar
            
            if souOrigem:
                desligar_regra_monitoramento(switch=switch, ip_ver=ip_ver,ip_src=ip_src,ip_dst=ip_dst,out_port=out_port,src_port=src_port,dst_port=dst_port,proto=proto)

                #enviar icmp
                if ip_ver == IPV4_CODE:
                    INFORMATION_REQUEST=15
                    send_icmpv4(datapath=switch.datapath, srcMac=eth_src,dstMac=eth_dst, srcIp=ip_src, dstIp=ip_dst, outPort=out_port,seq=0, data=monitoramento_fluxo.toString().encode(), type=INFORMATION_REQUEST)
                else:
                    send_icmpv6(datapath=switch.datapath, srcMac=eth_src, srcIp=ip_src,dstMac=eth_dst,dstIp=ip_dst,outPort=out_port,data=monitoramento_fluxo.toString().encode(), type=icmpv6.ICMPV6_NI_QUERY)
                
                self.flowmonitoringmanager.delMonitoring(label)
            elif souDestino:

                # verificar se ja recebi um flowmonitoring

                if monitoramento_recebido:
                    
                    fred = self.fredmanager.get_fred(label) 

                    qos_calculado = calcular_qos(monitoramento_recebido, monitoramento_fluxo)

                    self.flowmonitoringmanager.delMonitoring(label)

                    ip_blockchain,porta_network,porta_rest = self.qosblockchainmanager.get_blockchain(calculate_network_prefix_ipv4(fred.ip_src), calculate_network_prefix_ipv4(fred.ip_dst))


                    print("Enviando Transação para blockchain %s:%d", )
                    enviar_transacao_blockchain_api(self.IPCc, ip_blockchain,porta_rest,fred.getName(),qos_calculado,fred  )
                #monitorar o pacote -> se completou o monitoramento:
                    # nao desligar a regra de monitoramento
                    # se ja tiver um flowmonitoring armazenado para o fluxo (recebido de icmp) - fazer o calculo de qos -> criar uma transacao
                    # Se nao tiver um flowmonitoing armazenado para  o fluxo, armazenar e esperar o icmp, para fazer o calculo e a transação la

                print("enviar ao host via socket !!!")
                Thread(target=enviar_msg, args=[monitoramento_fluxo.toString(), self.ip_management_host, PORTA_MANAGEMENT_HOST_SERVER]).start()
        # nao injetar esse pacote, pois ele ja esta sendo encaminhado, apenas copiado ao controlador tbm
        # return
        return 

    def tratamento_meu_dominio_pos_classificacao(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, eth_src:str, eth_dst:str, flow_classificacao, nohs_rota):
        
        initime = current_milli_time()
        print("[trat_qos_pos_class] init ", initime)
       
        # construir o FRED aqui 
        fred = Fred(ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto, mac_src=eth_src,
                     mac_dst=eth_dst, code=0, blockchain_name='blockchain_name', as_dst_ip_range=self._LIST_PREFIX_DOMINIO, 
                     as_src_ip_range=[],label=flow_classificacao.application_label,
                     ip_genesis=self.ip_management_host, lista_peers=[], lista_rota=[], classe=flow_classificacao.classe, delay=flow_classificacao.delay, 
                     prioridade=flow_classificacao.priority, loss=flow_classificacao.loss, bandwidth=flow_classificacao.bandwidth, jitter=flow_classificacao.jitter)
        minha_chave_publica,minha_chave_privada = criar_chave_sawadm()
        # me adicionar como par no fred
        fred.addNoh(self.IPCv4, minha_chave_publica, len(nohs_rota))
        self.fredmanager.save_fred(fred.getName(), fred)
        
        # souDestino = self.souDominioBorda(ip_dst)
        if self.create_qos_rules(ip_src, ip_dst, ip_ver, src_port, dst_port, proto, fred, src_meu_dominio=True, dst_meu_dominio=False): 

            # aqui eh onde cria a blockchain, mas tbm onde se envia o fred para anunciar qos            
            Thread(target=self.blockchain_setup, args=[nohs_rota, fred, minha_chave_publica]).start()
            
        else:# so para deixar organizado
            print("[trat_qos_pos_class] qos rejeitado -> continuar com BE")
            # self.delete_rules(nohs_rota, ip_src, ip_dst, ip_ver, src_port, dst_port, proto, src_meu_dominio=True, qos_match=31)
            self.create_be_rules_meu_dominio_soOF(route_nohs=nohs_rota, ip_src=ip_src, ip_dst=ip_dst, ip_ver=ip_ver, src_port=src_port,dst_port=dst_port,proto=proto, toController=False)
            endtime = current_milli_time()
            print("[trat_qos_pos_class] end ", endtime, '  duracao: ', endtime - initime)            
            return False

        endtime = current_milli_time()
        print("[trat_qos_pos_class] end ", endtime, '  duracao: ', endtime - initime)
        return True


    def blockchain_setup(self,nohs_rota, fred, minha_chave_publica, souDestino=False):

        print("[blkc-setup]Regras QoS criadas")
        print("print: Todas as blockchains criadas (nomes) :", self.qosblockchainmanager.blockchain_table.keys())

        blockchain_ip, porta_network, porta_rest  = self.qosblockchainmanager.get_blockchain(calculate_network_prefix_ipv4(fred.ip_src), calculate_network_prefix_ipv4(fred.ip_dst))
        # criar blockchain ? -- so se ja nao existir uma blockchain para esse destino
        temp = current_milli_time()
        print("[blkc-setup] blockchain setup init - ", temp)

        meu_ip = self.IPCv4
        if fred.ip_ver == IPV6_CODE:  
            meu_ip = self.IPCv6

        print("para os experimentos com virt namespaces")
        ip_partes = meu_ip.split('.')
        meu_ip = '%s.%s.%s.50' % (ip_partes[0],ip_partes[1],ip_partes[2])


        condicao_evitar_multiplas_blockchains = fred.ip_src.split('.')[2] < fred.ip_dst.split('.')[2]

        print("criando blockchain")            
        if ligar_blockchain and condicao_evitar_multiplas_blockchains:
            if blockchain_ip == None and condicao_evitar_multiplas_blockchains:
                porta_network, porta_rest=tratar_blockchain_setup(meu_ip, fred, self.qosblockchainmanager)
                fred.addPeer(meu_ip, minha_chave_publica, meu_ip+':'+str(porta_network))
                self.qosblockchainmanager.save_blockchain(calculate_network_prefix_ipv4(fred.ip_src), calculate_network_prefix_ipv4(fred.ip_dst), meu_ip, porta_network, porta_rest)

                if porta_network:
                    print("[blkc-setup]Blockchain criada: porta_network:%d, porta_rest:%d" % (porta_network, porta_rest))
                else:
                    print("[blkc-setup]Erro ao criar blockchain nome")            
            else:
                print("Blockchain existente %s->%s %s:%d(network) %d(rest)" %(fred.ip_src, fred.ip_dst, blockchain_ip, porta_network,porta_rest))
            
        # fred announcement
        if not souDestino: # enviar anuncio de fred
  
            INFORMATION_REQUEST = 15 
            if fred.ip_ver == IPV4_CODE:
                send_icmpv4(datapath=self.getSwitchByName(nohs_rota[-1].switch_name).datapath, srcMac=fred.mac_src,dstMac=fred.mac_dst, srcIp=fred.ip_src, dstIp=fred.ip_dst, outPort=nohs_rota[-1].out_port,seq=0, data=fred.toString().encode(), type=INFORMATION_REQUEST)
            else:
                send_icmpv6(datapath=self.getSwitchByName(nohs_rota[-1].switch_name).datapath, srcMac=fred.mac_src, srcIp=fred.ip_src,dstMac=fred.mac_dst,dstIp=fred.ip_dst,outPort=nohs_rota[-1].out_port,data=fred.toString().encode(), type=icmpv6.ICMPV6_NI_QUERY)
        else:
            #enviar_msg ao management host
            enviar_msg(fred.toString(), self.ip_management_host, PORTA_MANAGEMENT_HOST_SERVER)
        print("[blkc-setup] blockchain setup end - ", current_milli_time(), ' duracao - ', current_milli_time() - temp)

        return

    def souDominioBorda(self, ip_test):
        for prefix in self.get_prefix_meu_dominio():
            if calculate_network_prefix_ipv4(ip_test) == prefix:
                return True
        return False

#arrumando ate aqui
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

####################### LEARNING PHASE ###############################################################################
        timpo_i_mili = current_milli_time()

        tempo_i_monotonic = round(time.monotonic()*1000)
        print("\n\n###################################################################################")
        print("[packet_in] init ", timpo_i_mili, " ---- tempo em funcionamento: ",current_milli_time()-self.tempo_funcionamento)

        tempo_i = get_time_monotonic()

        # cuidado com essa funcao, deveria ser uma thread
        # self.remover_regras_freds_expirados()

        #####           obter todas as informacoes uteis do pacote          #######
        msg = ev.msg #representa a mensagem packet_in
        dp = msg.datapath #representa o switch
        ofp = dp.ofproto #protocolo openflow na versao implementada pelo switch
        parser = dp.ofproto_parser

        print("Tamanho do pacote: ", msg.total_len, "   ou seria:   ", len(msg.data))

        #obter porta de entrada qual o switch recebeu o pacote
        in_port = msg.match['in_port']

        #identificar o switch
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        self.ip_to_port.setdefault(dpid, {})

        #analisar o pacote recebido usando a biblioteca packet
        pkt = packet.Packet(msg.data)
        pkt_eth= pkt.get_protocol (ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ipv6 = pkt.get_protocol(ipv6.ipv6)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_icmpv4 = pkt.get_protocol(icmp.icmp)
        pkt_icmpv6 = pkt.get_protocol(icmpv6.icmpv6)
        pkt_arp = pkt.get_protocol(arp.arp)

          # campos ethernet
        eth_dst=pkt_eth.dst
        eth_src=pkt_eth.src
        ethertype = pkt_eth.ethertype

        # campos observados
        ip_ver = ethertype
        ip_dst = ''
        ip_src = ''
        qos_mark = NO_QOS_MARK
        src_port = -1
        dst_port = -1
        proto = -1

      
        if pkt_ipv4:
            print("tem header ipv4")
            # ip_ver = pkt_ipv4.version
            ip_dst = pkt_ipv4.dst 
            ip_src = pkt_ipv4.src
            qos_mark = pkt_ipv4.tos >> 2 # (esse eh o ipv4.tos) dscp sao apenas os 8 primeiros bits, nao contando os 2 ultimos, porem tos conta todos
        elif pkt_ipv6:
            print("tem header ipv6 - rejeitado")
            # ip_ver = pkt_ipv6.version
            ip_dst = pkt_ipv6.dst 
            ip_src = pkt_ipv6.src
            qos_mark = pkt_ipv6.flow_label
            return

        if pkt_udp:
            print("tem header udp")
            src_port = pkt_udp.src_port
            dst_port = pkt_udp.dst_port
            proto = UDP
        elif pkt_tcp:
            print("tem header tcp")
            src_port = pkt_tcp.src_port
            dst_port = pkt_tcp.dst_port
            proto = TCP
        
        # if pkt_icmpv4:
        #     print("tem header icmpv4")
        #     print(pkt.__dict__)
        # el
        if pkt_icmpv6:
            print("tem header icmpv6 -rejeitado")
            return 
           
        
        #tratar pacotes arp
        if pkt_arp:
            ip_src= pkt_arp.src_ip
            ip_dst= pkt_arp.dst_ip
            eth_src = pkt_arp.src_mac
            eth_dst = pkt_arp.dst_mac
            proto = pkt_arp.proto
            
            # if self.souDominioBorda(ip_dst): #arp
            print("[packet-in]Tratando ARP %s->%s" %(ip_src, ip_dst))
            self.mac_to_port[dpid][eth_src] = in_port
            self.ip_to_port[dpid][ip_src] = in_port
            arppList = self.ip_to_port[dpid]
            route_nohs = self.rotamanager.get_rota(ip_src, ip_dst)
            if route_nohs == None or route_nohs == []:
                # nao tem rota, verificar se conhece o endereco mac, criar regra pelo endereço mac -- ou encontrar a rota pelo endereco mac ?
                # porta_saida_in_switch = controller.mac_to_port[in_switch_id]
                # 
                # getSwitchByName(in_switch_id).criarRegraBE_ip(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida)
                print("[creat_be]Error: no route found for this flow: s:%s d:%s qos_mark:%d" %(ip_src, ip_dst, qos_mark))
                return False

            # rotina controle
            print("getting switch %d"%(route_nohs[-1].switch_name))
            switch = self.getSwitchByName(route_nohs[-1].switch_name)

            injetarPacote(switch.datapath, FILA_CONTROLE, route_nohs[-1].out_port, msg)

            return

        if not pkt_eth:
            print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
            return

        if not pkt_ipv4 and not pkt_ipv6:
            print("sem header ip")
            print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
            return
        
        rota_fluxo = self.rotamanager.get_rota(ip_src, ip_dst)
        este_switch = self.getSwitchByName(dpid)

        if not este_switch:
            print("[pktin] Switch nao encontrado! Abort")
            return
        
        #essa informacao nao importa ao switch, poderia ser uma variavel do controlador, essas duas info poderiam ser um dict {switch: {mac_src: ip_src}}
        este_switch.addMac(eth_src, in_port)
        
        este_switch.addHost(ip_src, in_port)

        #aprender endereco MAC, evitar flood proxima vez
        self.mac_to_port[dpid][eth_src] = in_port

        #adaptar essa parte depois, aqui so se quer saber se eh conhecida a porta destino para
        out_port= None
        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        
        # fluxo novo -> classificar
        # fazer classificaçao trafego    

        if rota_fluxo == None:
            print("[pkt-in]Não ha rota para este fluxo ! abort")
            return

        # encontrar a porta de saida para poder injetar o pacote 
        for noh in rota_fluxo:
            if noh.switch_name == dpid:
                out_port = noh.out_port
        
        # filtro
        # descobrir uma condição para : 
        #     1 - Monitorar pacotes com dscp monitoramento 
        #     2 - reinjetar pacotes que ja deveriam estar sendo eviados pela regra criada anteriormente (provavelmente buffer de pacotes)
        #     3 - tratar pacotes com qos_mark = 0 ou 31 -- como best-effort(backbone) ou classificacao(borda origem)
        
        regra_existente = este_switch.getPorta(out_port).getRegra(ip_ver, proto, ip_src, ip_dst, src_port, dst_port)
        classificado = False
        if regra_existente:
            classificado = regra_existente.classificado
        if classificado and qos_mark not in lista_monitoramento:
            # print("Pacote ja tratado - so fazer monitoramento - fazer nada") --> na verdade reijetar pq, se veio aqui sem ser classificado - se perdeu ou ficou no buffer
            print("[pkt-in] %s:%d->%s:%d qos_mark:%d - ja tratado - reinjetar" % (ip_src, src_port, ip_dst, dst_port, qos_mark))
            este_switch.listarRegras() # debug
            injetarPacote(self.getSwitchByName(rota_fluxo[-1].switch_name).datapath, FILA_BESTEFFORT, rota_fluxo[-1].out_port, pkt)
            return
        
        # print('pacote',msg.__dict__)
        print("[pkt-in] Parte 1")

        print("[packet-in] switch_name: %d, eth_type: %d, pkt_in ip_src: %s; ip_dst: %s; src_port: %d; dst_port: %d; proto: %d; qos_mark: %d\n" % (dpid, ethertype, ip_src, ip_dst, src_port, dst_port, proto, qos_mark))
        este_switch.listarRegras()

####################### LEARNING PHASE ###############################################################################
######################## IMCP ########################################################################################
        # ICMP nao tem "PORTAS"
        #tratador dhcp ipv4
        dhcpPkt = pkt.get_protocol(dhcp.dhcp)
        if dhcpPkt:
            print("[packet-in]tratando dhcp")
            handle_dhcp(self, dhcpPkt, dp, in_port)
            # self.serverDHCP._handle_dhcp(dp, in_port, pkt)
            # print('Ignorando dhcp - configure manualmente !')
            print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
            return

        # tratar freds anunciados # aqui apenas icmpv6 agora
        if pkt_icmpv4: # envio icmp precisa ser origem frep.src, destino, fred.dst
            print("[packet-in]tratando imcpv4")
            handle_icmps(self, msg, pkt_icmpv4, pkt_icmpv4.type, ip_ver, eth_src, ip_src, eth_dst, ip_dst)
            print('[pktin] icmpv4 finish (monotonic)', round(time.monotonic()*1000)- tempo_i_monotonic)
            print("[packet_in] icmpv4 finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
            return
        if pkt_icmpv6:   
            print("[packet-in]tratando imcpv6")
            handle_icmps(self, msg, pkt_icmpv6, pkt_icmpv6.type_, ip_ver, eth_src, ip_src, eth_dst, ip_dst)      
            print('[pktin] icmpv4 finish (monotonic)', round(time.monotonic()*1000)- tempo_i_monotonic)
            print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
            return
        
######################## IMCP ########################################################################################
######################## Unmactched ########################################################################################     

 

        print("[pkt-in] Parte 2")
                
        if self.souDominioBorda(ip_src): # se chegou aqui, nao é icmp
            print("[packet-in] sou dominio de borda para esse fluxo")
            if qos_mark == 0: # sem marcacao -> marcar como BE e para enviar copia ao controlador para a classificação
                if pkt_ipv4:
                    pkt_ipv4.ip_dscp = 31
                else:
                    pkt_ipv6.ipv6_flabel = 31
                # aqui perfeito
                print("[trat_meu-domin]Pacote sem marcacao: %d" % (qos_mark))
                self.tratamento_pktin_sem_marcacao_meu_dominio(rota_fluxo, este_switch, rota_fluxo[0].switch_name,ip_ver, ip_src, ip_dst, src_port, dst_port, proto, out_port, msg) # essa funciona ctz
            
            elif qos_mark in lista_monitoramento: # qos == fazer monitoramento, monitorar fluxo
                print("[trat_meu-domin]Tem Marcacao QoS -> Fazer monitoramento de QoS, sem injetar o pacote")
                # switch_ultimo = self.getSwitchByName(rota_fluxo[-1].switch_name)
                self.tratamento_monitoramento_fluxo(ip_ver=ip_ver, ip_src=ip_src, eth_src=eth_src, ip_dst=ip_dst,eth_dst=eth_dst,src_port=src_port,dst_port=dst_port,proto=proto,pkt_len=msg.total_len, switch=self.getSwitchByName(rota_fluxo[0].switch_name), out_port=rota_fluxo[0].out_port, souOrigem=True, souDestino=False)
                return
            else: # pacote marcado (com BE), fazer a classificação
 
                print("[trat_meu-domin]Pacote com marcacao: %d" % (qos_mark))
                self.tratamento_pktin_com_marcacao_meu_dominio(rota_fluxo, este_switch, out_port, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, eth_src, eth_dst,qos_mark, msg)
            este_switch.listarRegras()
            print("pkt-in finish (monotonic) : ", round(time.monotonic()*1000)- tempo_i_monotonic)
            print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
            return
        
        else: # nao sou borda de origem
            
            if self.souDominioBorda(ip_dst) and qos_mark in lista_monitoramento: # sou borda de destino e estou monitorando pacotes
                print("[trat_domin_destino]Tem Marcacao QoS -> Fazer monitoramento de QoS, sem injetar o pacote")
                # switch_ultimo = self.getSwitchByName(rota_fluxo[-1].switch_name)
                self.tratamento_monitoramento_fluxo(ip_ver=ip_ver, ip_src=ip_src, eth_src=eth_src, ip_dst=ip_dst,eth_dst=eth_dst,src_port=src_port,dst_port=dst_port,proto=proto,pkt_len=msg.total_len, switch=self.getSwitchByName(rota_fluxo[0].switch_name), out_port=rota_fluxo[0].out_port, souOrigem=False, souDestino=True)
                este_switch.listarRegras()  
                print("pkt-in finish (monotonic) : ", round(time.monotonic()*1000)- tempo_i_monotonic)
                print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
                return	 

            else: # nao sou borda de origem, e vou tratar os pacotes como BE, até que receba um icmp da origem
                self.tratamento_pktin_backbone(rota_fluxo, este_switch, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, eth_src, eth_dst, qos_mark, out_port, msg) # aqui esta o erro

                este_switch.listarRegras()

                print("pkt-in finish (monotonic) : ", round(time.monotonic()*1000)- tempo_i_monotonic)
                print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
                return	 
    

def setup(controller):

    #################
    #   INICIANDO SOCKET - R0ECEBER CONTRATOS (hosts e controladores)
    ################

    load_cfg(controller)

    t3 = Thread(target=servidor_configuracoes, args=[controller, controller.IPCc])
    t3.start()

    # # iniciar o servidor web aqui
    # t4 = Thread(target=lancar_wsgi)
    # t4.start()

    #t1.join()

    # pre-carregar topo-configuration
def load_cfg(controller):
    #setar as configurações:
    #   switch: ports, banda, salto para controlador (se não, não tem como configurar usando o servidor)
    #   rotas: rotas para os hosts
    #   managementhost: ip
    #   usar os tratadores já implementados

    print("Lading cfg...")
    cfg_file = open('cfg.json', 'r+')

    json_file = json.loads(cfg_file.read())

    print(json_file)

    if "ManagementHost" in json_file:
        controller.ip_management_host = json_file["ManagementHost"]
    
    if "addSwitches" in json_file:
        tratador_addSwitches(controller, json_file["addSwitches"]) # ok
        
    if "addRotas" in json_file:
        tratador_addRotas(controller.rotamanager, json_file['addRotas']) # ok

    if "addDominioPrefix" in json_file:
        tratador_addDominioPrefix(controller, json_file["addDominioPrefix"])

    if "ipsDHCP" in json_file:
        tratador_ipsDHCP(controller, json_file["ipsDHCP"])

   
    # OK
    # print('managementhost:',controller.ip_management_host)
    
    # for switch in controller.switches:
    #     print("addSwitch: ", switch.toString())

    # for rota in controller.rotamanager.rotas:
    #     print("addRota: ",rota)
    
    # print("DHCP: ",controller._LIST_IPS_DHCP)

    # print("PREFIXS: ",controller._LIST_PREFIX_DOMINIO)

    print("config loaded....")
