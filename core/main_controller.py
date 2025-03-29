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
from fp_constants import IPV4_CODE, IPV6_CODE, TCP, UDP, IP_MANAGEMENT_HOST, class_prio_to_monitoring_mark

from fp_api_qosblockchain import tratar_blockchain_setup, criar_chave_sawadm, BlockchainManager

from fp_constants import SC_BEST_EFFORT

# try:
from fp_switch import Switch
# except ImportError:
#     print('Erro de importacao da classe SwitchOVS')

# from fp_server import servidor_configuracoes

from fp_acao import Acao

from fp_openflow_rules import add_default_rule, injetarPacote, addRegraMonitoring, desligar_regra_monitoramento

from fp_utils import check_domain_hosts
from fp_utils import current_milli_time, get_ips_meu_dominio

# print('importando fp_topo_discovery')
#descoberta de topologia
from fp_topology_discovery import handler_switch_enter, handler_switch_leave
# print('importando fp_dhcp')
#tratador DHCPv4
from fp_dhcp import handle_dhcp

from fp_icmp import handle_icmps, send_icmpv4, send_icmpv6

# print('importando interface_web')
# import wsgiWebSocket.interface_web as iwb
from wsgiWebSocket.interface_web import lancar_wsgi #, _websocket_rcv, _websocket_snd, dados_json

from traffic_classification.classificator import classificar_pacote

from traffic_monitoring.fp_monitoring import monitorar_pacote

# from fp_api_qosblockchain import BlockchainManager

from fp_fred import Fred, FredManager

from fp_rota import RotaManager

from traffic_monitoring.monitoring_utils import MonitoringManager

def get_time_monotonic():
    return round(time.monotonic()*1000)

class FLOWPRI2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    controller_singleton = None

    def __init__(self, *args, **kwargs):
        print("CONTROLADOR - \n Init Start\n" )# % (IPC))
        super(FLOWPRI2,self).__init__(*args,**kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}

        # onde as principais coisas são armazenadas
        self.fredmanager = FredManager()
        self.qosblockchainmanager = BlockchainManager()
        self.rotamanager = RotaManager()
        self.flowmonitoringmanager = MonitoringManager()

        self.arpList = {}

        self.controladores_conhecidos = []

        self.switches = {}

        FLOWPRI2.controller_singleton = self

        self.CONTROLLER_INTERFACE = "eth2"
        #  self.CONTROLLER_INTERFACE = "enp7s0"
        try:
            self.IPCv4 = str(ifaddresses(self.CONTROLLER_INTERFACE)[AF_INET][0]['addr'])
            self.IPCv6 = str(ifaddresses(self.CONTROLLER_INTERFACE)[10][0]['addr'].split("%")[0])
            self.IPCc = self.IPCv4
            self.MACC = str(ifaddresses(self.CONTROLLER_INTERFACE)[17][0]['addr'])
            self.CONTROLADOR_ID = self.IPCc
        except:
            print("Verifique o nome da interface e modifique na main")

        print("Controlador ID - {}"  .format(self.CONTROLADOR_ID))
        print("Controlador IPv4 - {}".format(self.IPCv4))
        print("Controlador IPv6 - {}".format(self.IPCv6))
        print("Controlador MAC - {}" .format(self.MACC))

        # setup()

    @staticmethod
    def getControllerInstance():
        return FLOWPRI2.controller_singleton
    
    def getSwitchByName(self, nome) -> Switch:
        return self.switches.get(nome, None)

    def create_qos_rules(self, ip_src:str, ip_dst:str, ip_ver:int, src_port:int, dst_port:int, proto:int, fred:Fred, src_meu_dominio:bool) -> bool:
        "cria a regra de QoS + meter + marcacao, no switch ovs e na instancia"
        "True = fluxo aceito com qos"
        "False = Fluxo rejeitado"
        # ARRUMAR O RETORNO -> bool

        #flow qos
        banda=fred.bandiwdth
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
            
            #first-hop
            acoes_retorno = switchh.GBAM(ip_ver=ip_ver,ip_src=ip_src,ip_dst=ip_dst,src_port=src_port,dst_port=dst_port,proto=proto, porta_entrada=porta_entrada, porta_saida=porta_saida, banda=banda,prioridade=prioridade,classe=classe, application_class=flow_label,tipo_switch=Switch.SWITCH_FIRST_HOP)
            if acoes_retorno!=[]:
                lista_acoes += acoes_retorno
            else:
                return False
            #last-hop
            switchh = self.getSwitchByName(switch_route[-1].switch_name)
            porta_saida = switch_route[-1].out_port
            porta_entrada = switch_route[-1].in_port
            acoes_retorno = switchh.GBAM(ip_ver=ip_ver,ip_src=ip_src,ip_dst=ip_dst,src_port=src_port,dst_port=dst_port,proto=proto, porta_entrada=porta_entrada, porta_saida=porta_saida, banda=banda,prioridade=prioridade,classe=classe, application_class=flow_label, tipo_switch=Switch.SWITCH_LAST_HOP)
            if acoes_retorno!=[]:
                lista_acoes += acoes_retorno
            else:
                return False

            switch_inicial+=1 # excluir o first-hop
            switch_final-=1 # excluir o last-hop
        # ELSE == BORDA
        # para borda
        for i in range(switch_inicial,switch_final): # excluir o first e o last-hops
            switchh = self.getSwitchByName(switch_route[i].switch_name)
            porta_saida = switch_route[i].out_port
            porta_entrada = switch_route[i].in_port
            acoes_retorno = switchh.GBAM(ip_ver=ip_ver,ip_src=ip_src,ip_dst=ip_dst,src_port=src_port,dst_port=dst_port,proto=proto, porta_entrada=porta_entrada, porta_saida=porta_saida, banda=banda,prioridade=prioridade,classe=classe, application_class=flow_label ,tipo_switch=Switch.SWITCH_OUTRO)
            if acoes_retorno!=[]:
                lista_acoes += acoes_retorno
            else:
                return False
            
        # se chegou ate aqui, o fluxo foi aceito, entao, mandar as acoes executarem
        for acao in lista_acoes:
            acao.executar()
        
        return True # aceito

    def create_be_rules(self, ip_src:str, ip_dst:str, ip_ver:int, src_port:int, dst_port:int, proto:int):
        """Cria a regra BE (com marcacao) no switch ovs e na instancia"""
        # criar regras agrupadas ...
        # rota com os datapaths dos switches em ordem
        route_nohs = self.rotamanager.get_rota(ip_src, ip_dst)

        if route_nohs == None:
            # nao tem rota, verificar se conhece o endereco mac, criar regra pelo endereço mac -- ou encontrar a rota pelo endereco mac ?
            # porta_saida_in_switch = controller.mac_to_port[in_switch_id]
            # 
            # getSwitchByName(in_switch_id).criarRegraBE_ip(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida)
            print("[creat_be]Error: no route found for this flow: s:%s d:%s" %(ip_src, ip_dst))
            return False

        nodes = 0
        for node in route_nohs:
            switchh = self.getSwitchByName(node.switch_name)
            porta_saida = node.out_port
            # teria que agrupar as regras em conjunctions -- marcar no primeiro switch da rota
            if node == 0:
                switchh.addRegraBE(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida, marcar=True)
            else:
                switchh.addRegraBE(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida)
            nodes +=1

        return True

    def saveSwitch(self, switch_name:int, switch:Switch):
        self.switches[switch_name] = switch 
        return


    def remover_regras_freds_expirados(self):

        #removendo freds expirados
        self.fredmanager.remover_freds_expirados()
        #removendo regras expiradas
        for switch in self.switches.values():
            switch.remover_regras_expiradas()

        return

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print("Novo switch anunciado....\n")

        #aqui nao se obtem tantas informacoes sobre os switches como eu gostaria
        tempo_i = get_time_monotonic()
    
        datapath = ev.msg.datapath

        print("[%s] switch_features - setup de S%d \n" % (datetime.datetime.now().time(), datapath.id))

        switch = Switch(datapath,str(datapath.id), self)

        self.saveSwitch(switch=switch, switch_name=datapath.id)
       
        add_default_rule(datapath)

        """adicionar regra para monitorar pacotes marcados com destino o meu domínio"""

        logging.info('[switch_features] fim settage - tempo_decorrido: %d\n' % (get_time_monotonic() - tempo_i))

# ### Descoberta de topologia
    #tratador eventos onde um switch se conecta
    @set_ev_cls(event.EventSwitchEnter)
    def _handler_switch_enter(self, ev):
        handler_switch_enter(self, ev)

    #tratador de eventos onde um switch se desconecta
    @set_ev_cls(event.EventSwitchLeave)
    def _handler_switch_leave(self, ev):
        handler_switch_leave(self, ev)

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

        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        ip_src = None
        ip_dst = None
        qos_mark = None
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
            qos_mark= msg.match['ip_dscp']
        if 'ipv6_flabel' in msg.match:
            qos_mark= msg.match['ipv6_flabel']
        if 'tcp_src' in msg.match:
            src_port = msg.match['tcp_src']
            dst_port = msg.match['tcp_dst']
            proto=TCP
        if 'udp_src' in msg.match:
            src_port = msg.match['udp_src']
            dst_port = msg.match['udp_dst']
            proto=UDP

        #por agora, tanto as regras de ida quanto as de volta sao marcadas para notificar com o evento
        #atualizar no switch que gerou o evento
        route_nodes = self.rotamanager.get_rota(ip_src, ip_dst)

        if route_nodes == None:
            print("[flow-removed]Problema com as rotas !!")
            return

        #Se nao tiver dscp ou ipv6_flable entao remover best-effort (mas nao vai ser o caso) -- no entanto as regras best-effort nao serao notificadas entao nao precisa

        dominio_borda = False
        # Se eu sou borda origem E se for o ultimo switch da rota, atualizar regra de monitoramento
        if check_domain_hosts(ip_src):
            dominio_borda = True
            # se quem expirou foi a regra de monitoramento, entao, verificar se deve ligar ou desligar
            if dp.id == route_nodes[-1].switch_name:
                switchh = self.getSwitchByName(dp.id)
                if switchh.getPorta(route_nodes[-1].out_port).getRegra(ip_ver,proto,ip_src,ip_dst,src_port,dst_port).monitorando:
                    addRegraMonitoring(switchh, ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, out_port=route_nodes[-1].out_port, src_port=src_port, dst_port=dst_port, proto=proto)
                return 
        
        # OBS backbone tem outro comportamento !!!!!!
        primeiro_switch = 0
        ultimo_switch = len(route_nodes)

        # remover a regra que encaminha fluxo monitorado -- somente se nao tiver outro fluxo utilizando... == remover a regra da instancia, verificar se existe algum fluxo com mesmo ips e mesmo qos_mark, se nao tiver, remover a regra monitoramento e regra qos_mark agrupadas
        if dominio_borda:
            primeiro_switch+=1
            ultimo_switch-=1
            switchh_first_hop = self.getSwitchByName(route_nodes[primeiro_switch].switch_name)
            switchh_first_hop.delRegraQoS(switchh, ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto, porta_entrada=route_nodes[i].in_port, porta_saida=route_nodes[primeiro_switch].out_port, qos_mark=qos_mark, tipo_switch=Switch.SWITCH_FIRST_HOP)
            switchh_last_hop = self.getSwitchByName(route_nodes[ultimo_switch].switch_name)
            switchh_last_hop.delRegraQoS(switchh, ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto, porta_entrada=route_nodes[-1].in_port, porta_saida=route_nodes[-1].out_port, qos_mark=qos_mark, tipo_switch=Switch.SWITCH_LAST_HOP)

        for i in range(primeiro_switch, ultimo_switch):
            switchh = self.getSwitchByName(route_nodes[i].switch_name)
            switchh.delRegraQoS(switchh, ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto, porta_entrada=route_nodes[i].in_port, porta_saida=route_nodes[i].out_port, qos_mark=qos_mark, tipo_switch=Switch.SWITCH_OUTRO)
            # remove_qos_rules(ip_ver=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto)

        return 0

    def tratamento_pacote_meu_dominio(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, eth_src:str, eth_dst:str, pkt, qos_mark:int, switchh:Switch):
        # Arrumar isso, EEE, tem dois comportamentos dominio de borda e dominio de destino !!! == essa mesma funcao vai tratar os dois casos ? 
        # ops, para o dominio de borda de destino, vai ocorrer o comportamento no icmp - aqui trata pacotes ip

                # se o pacote for marcado para monitoramento, apenas armazenaR timestamp, len(pkt)
        # injetar o pacote ou contar 20 e mudar a regra -- OFPP_CONTROLLER
        marcacao_pkt = 0
        nohs_rota = self.rotamanager.get_rota(ip_src, ip_dst)

        if nohs_rota == None:
            print('[trat_meu-domin] erro: sem rotas para %s -> %s'%(ip_src,ip_dst))
            return
        if ip_ver == IPV4_CODE:
            marcacao_pkt = qos_mark >> 2 # (esse eh o ipv4.tos) dscp sao apenas os 8 primeiros bits, nao contando os 2 ultimos, porem tos conta todos
        elif ip_ver == IPV6_CODE:
            marcacao_pkt = qos_mark
        else:
            print("[tratamento_meu_dominoi] erro: tipo de pacote nao identificado")
            return

        # verificar se eh uma marcacao de monitoramento
        if marcacao_pkt in class_prio_to_monitoring_mark.values(): # MARCACAO_MONITORAMENTO:
            monitoramento_fluxo = monitorar_pacote(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, pkt, self.flowmonitoringmanager)
            if monitoramento_fluxo != None: #quando o monitoramento estiver completo
                # mudar a regra de monitoramento do primerio switch da rota para nao enviar pacotes ao controlador  -> essa regra tem um tempo hardtimeout menor 2s e uma flag, da proxima vez que expirar deve voltar a monitorar
                desligar_regra_monitoramento(switch=switchh, ip_ver=ip_ver,ip_src=ip_src,ip_dst=ip_dst,out_port=nohs_rota[-1].out_port,src_port=src_port,dst_port=dst_port,proto=proto)
                
                #enviar icmp
                if ip_ver == IPV4_CODE:
                    send_icmpv4(datapath=self.getSwitchByName(nohs_rota[-1].switch_name).datapath, srcMac=eth_src,dstMac=eth_dst, srcIp=ip_src, dstIp=ip_dst, outPort=nohs_rota[-1].out_port,seq=0, data=monitoramento_fluxo.toString())
                else:
                    send_icmpv6(datapath=self.getSwitchByName(nohs_rota[-1].switch_name).datapath, srcMac=eth_src, srcIp=ip_src,dstMac=eth_dst,dstIp=ip_dst,outPort=nohs_rota[-1].out_port,data=monitoramento_fluxo.toString())
            # nao injetar esse pacote, pois ele ja esta sendo encaminhado, apenas copiado ao controlador tbm
            # return

        flow_classificacao = classificar_pacote(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, pkt)

        # criar regras qos, criar fred, preencher e enviar icmpv6.
        print("criar regras qos, criar fred, preencher e enviar icmpv6.")

        if flow_classificacao.classe_label != "be":
            print('Fluxo classificado: '+ current_milli_time())

            # construir o FRED aqui 
            fred = Fred(ip_ver=ip_ver, ip_src=ip_src, src_port=src_port, dst_port=dst_port, proto=proto, mac_src=eth_src,
                         mac_dst=eth_dst, code=0, blockchain_name='blockchain_name', as_dst_ip_range=get_ips_meu_dominio(), 
                         as_src_ip_range=[],label=flow_classificacao.application_label,
                         ip_genesis=IP_MANAGEMENT_HOST, lista_peers=[], lista_rota=[], classe=flow_classificacao.classe_label, delay=flow_classificacao.delay, 
                         prioridade=flow_classificacao.priority, loss=flow_classificacao.loss, bandiwdth=flow_classificacao.bandwidth)

            minha_chave_publica,minha_chave_privada = criar_chave_sawadm()
            # me adicionar como par no fred
            fred.addNoh(FLOWPRI2.IPCv4, minha_chave_publica, len(nohs_rota))

            self.fredmanager.save_fred(fred.getName(), fred)
            if self.create_qos_rules(ip_src, ip_dst, ip_ver, src_port, dst_port, proto, fred,True):
                print("Regras criadas")
                
                porta_blockchain = self.qosblockchainmanager.get_blockchain(ip_src, ip_dst)
                # criar blockchain ? -- so se ja nao existir uma blockchain para esse destino
                if porta_blockchain == None:
                    if ip_ver == IPV4_CODE:
                        porta_blockchain=tratar_blockchain_setup(FLOWPRI2.IPCv4, fred, self.qosblockchainmanager)
                        fred.addPeer(FLOWPRI2.IPCv4, minha_chave_publica, FLOWPRI2.IPCv4+':'+str(porta_blockchain))
                    else: #ip_ver == IPV6_CODE
                        porta_blockchain=tratar_blockchain_setup(FLOWPRI2.IPCv6, fred, self.qosblockchainmanager)
                        fred.addPeer(FLOWPRI2.IPCv6, minha_chave_publica, FLOWPRI2.IPCv6+':'+str(porta_blockchain))
                else:
                    if ip_ver == IPV4_CODE:
                        fred.addPeer(FLOWPRI2.IPCv4, minha_chave_publica, FLOWPRI2.IPCv4+':'+str(porta_blockchain))
                        send_icmpv4(datapath=self.getSwitchByName(nohs_rota[-1].switch_name).datapath, srcMac=eth_src,dstMac=eth_dst, srcIp=ip_src, dstIp=ip_dst, outPort=nohs_rota[-1].out_port,seq=0, data=fred.toString())
                    else:
                        fred.addPeer(FLOWPRI2.IPCv6, minha_chave_publica, FLOWPRI2.IPCv6+':'+str(porta_blockchain))
                        send_icmpv6(datapath=self.getSwitchByName(nohs_rota[-1].switch_name).datapath, srcMac=eth_src, srcIp=ip_src,dstMac=eth_dst,dstIp=ip_dst,outPort=nohs_rota[-1].out_port,data=fred.toString())
            else:# so para deixar organizado
                self.create_be_rules(ip_src, ip_dst, ip_ver, src_port, dst_port, proto)    
        else:
            self.create_be_rules(ip_src, ip_dst, ip_ver, src_port, dst_port, proto)
        return True


#arrumando ate aqui
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

####################### LEARNING PHASE ###############################################################################
        timpo_i_mili = current_milli_time()
        print("[packet_in] init ", timpo_i_mili)

        tempo_i = get_time_monotonic()

        # cuidado com essa funcao, deveria ser uma thread
        self.remover_regras_freds_expirados()

        #####           obter todas as informacoes uteis do pacote          #######
        msg = ev.msg #representa a mensagem packet_in
        dp = msg.datapath #representa o switch
        ofp = dp.ofproto #protocolo openflow na versao implementada pelo switch
        parser = dp.ofproto_parser

        #obter porta de entrada qual o switch recebeu o pacote
        in_port = msg.match['in_port']

        #identificar o switch
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})

        #analisar o pacote recebido usando a biblioteca packet
        pkt = packet.Packet(msg.data)
        pkt_eth= pkt.get_protocol (ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ipv6 = pkt.get_protocol(ipv6.ipv6)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_icmpv4 = pkt.get_protocol(icmp.icmp)
        pkt_icmpv6 = pkt.get_protocol(icmpv6.icmpv6)

        if not pkt_eth:
            print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
            return

        # campos ethernet
        eth_dst=pkt_eth.dst
        eth_src=pkt_eth.src
        ethertype = pkt_eth.ethertype

        # campos observados
        ip_ver = ethertype
        ip_dst = None
        ip_src = None
        qos_mark = None
        src_port = None
        dst_port = None
        proto = None

        if pkt_ipv4:
            # ip_ver = pkt_ipv4.version
            ip_dst = pkt_ipv4.dst 
            ip_src = pkt_ipv4.src
            qos_mark = pkt_ipv4.tos
        elif pkt_ipv6:
            # ip_ver = pkt_ipv6.version
            ip_dst = pkt_ipv6.dst 
            ip_src = pkt_ipv6.src
            qos_mark = pkt_ipv6.flow_label

        if pkt_udp:
            src_port = pkt_udp.src_port
            dst_port = pkt_udp.dst_port
            proto = UDP
        elif pkt_tcp:
            src_port = pkt_tcp.src_port
            dst_port = pkt_tcp.dst_port
            proto = TCP
        else:
            return

        print("[%s] pkt_in ip_src: %s; ip_dst: %s; src_port: %d; dst_port: %d; proto: %d\n" % (datetime.datetime.now().time(), ip_src, ip_dst, src_port, dst_port, proto))

        # aprendizagem
        este_switch = self.getSwitchByName(str(dpid))
        este_switch.listarRegras()

        #essa informacao nao importa ao switch, poderia ser uma variavel do controlador, essas duas info poderiam ser um dict {switch: {mac_src: ip_src}}
        este_switch.addMac(eth_src, in_port)
        
        este_switch.addHost(ip_src, in_port)

        #aprender endereco MAC, evitar flood proxima vez
        self.mac_to_port[dpid][eth_src] = in_port

        #adaptar essa parte depois, aqui so se quer saber se eh conhecida a porta destino para
        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            out_port = None

####################### LEARNING PHASE ###############################################################################
######################## IMCP ########################################################################################
        #tratador dhcp ipv4
        dhcpPkt = pkt.get_protocol(dhcp.dhcp)
        if dhcpPkt:
            handle_dhcp(dhcpPkt, dp, in_port)
            print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
            return

        # tratar freds anunciados # aqui apenas icmpv6 agora
        if pkt_icmpv6:  
            handle_icmps(pkt_icmpv6, pkt_icmpv6.type_, ip_ver, ip_src, ip_dst)      
            print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
            return
        
        if pkt_icmpv4:   
            handle_icmps(pkt_icmpv4, pkt_icmpv4.type, ip_ver, ip_src, ip_dst)      
            print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
            return
        
######################## IMCP ########################################################################################
######################## Unmactched ########################################################################################
        # fluxo novo -> classificar
        # fazer classificaçao trafego

        if check_domain_hosts(ip_src): # se chegou aqui, nao é icmp
            self.tratamento_pacote_meu_dominio(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, eth_src, eth_dst, pkt, qos_mark, este_switch)
            injetarPacote(este_switch.datapath, fila, out_port, msg)   ### onde injetar isso ....
            print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
            return

        # se não for meu dominio ou sou backbone e não recebi fred, então fluxo BE
        # nao teve classificação ou foi best-effort
        print("criar regras best-effort")

        fredd=Fred(ip_ver=ip_ver, ip_src=ip_src, src_port=src_port, dst_port=dst_port, proto=proto, mac_src=eth_src,
                         mac_dst=eth_dst, code=0, blockchain_name='', as_dst_ip_range=[], 
                         as_src_ip_range=[],label='be',
                         ip_genesis='', lista_peers=[], lista_rota=[], classe=SC_BEST_EFFORT, delay=0, 
                         prioridade=0, loss=0, bandiwdth=0)

        self.fredmanager.save_fred(fredd.getName(), fredd)
        self.create_be_rules(self, ip_src, ip_dst, ip_ver, src_port, dst_port, proto)

        #injetar pacote na rede --> antes injetava direto no ultimo switch, mas não é muito realista, então vou injetar no próprio (qq coisa volta ao que era)
        # switch_ultimo = None
        # out_port = switch_ultimo.getPortaSaida(ip_dst) # !!!!
        fila = None
        injetarPacote(este_switch.datapath, fila, out_port, msg)

        # logging.info('[Packet_In] pacote sem match - fim - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))
        print("[%s] pkt_in fim \n" % (datetime.datetime.now().time()))

        print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
        return	 

def setup(controller):

    #################
    #   INICIANDO SOCKET - R0ECEBER CONTRATOS (hosts e controladores)
    ################

    t3 = Thread(target=servidor_configuracoes, args=[controller, controller.IPCc])
    t3.start()

    # # iniciar o servidor web aqui
    # t4 = Thread(target=lancar_wsgi)
    # t4.start()

    #t1.join()




### NAo utilizado 
    # def remove_qos_rules(self,ip_ver, proto, ip_src, ip_dst, src_port, dst_port):
        
    #     # comportamento borda = remover as regras de fluxos
    #     rota_nodes = self.rotamanager.get_rota(ip_src, ip_dst)
    #     # para casos contrarios, remover a regra de toda a rota e realizar a classificacao novamente...
    #     for rota_noh in rota_nodes:
    #         switch = self.getSwitchByName(rota_noh.switch_name)
    #         # switch.updateRegras(ip_src, ip_dst, tos) # essa funcao nao faz nada, eh de uma versao antiga --- se tiver tempo, remove-la
    #         porta_nome = switch.getPortaSaida(ip_dst)

    #         switch.delRegra(ip_ver)

    #         # comportamento backbone -> remover os freds que estão a mais tempo que o hardtimeout ! e reagrupar as regras que restaram
    #     IDLE_TIMEOUT = 1
    #     # se o fluxo foi removido por idle_timeout
    #     if IDLE_TIMEOUT:
    #         self.fredmanager.del_fred({})
    #     # remover_freds_expirados() -> que ja sria necessário mesmo
    #     self.fredmanager.remover_freds_expirados()
    #     # verificar quais regras precisam ser recriadas (em caso de backbone) -> 

    #     # reagrupar_regras_backbone() (em caso de backbone)

    #     return