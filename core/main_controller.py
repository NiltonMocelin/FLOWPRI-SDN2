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
from fp_constants import REMOVER, MARCACAO_MONITORAMENTO, IPV4_CODE, IPV6_CODE, TCP, UDP, IP_MANAGEMENT_HOST


from fp_constants import IPCc,IPCv4, IPCv6, CONTROLLER_INTERFACE, MACC, SC_BEST_EFFORT, SC_CONTROL,SC_NONREAL,SC_REAL

# try:
from fp_switch import Switch
# except ImportError:
#     print('Erro de importacao da classe SwitchOVS')

from fp_server import servidor_configuracoes

from fp_acao import Acao

from fp_regra import Regra

from fp_openflow_rules import add_default_rule, injetarPacote, addRegraMonitoring, desligar_regra_monitoramento

from fp_utils import get_ipv4_header, get_eth_header, get_ipv6_header, get_tcp_header, get_udp_header, getSwitchByName, get_rota, ip_meu_dominio, create_be_rules, create_qos_rules
from fp_utils import current_milli_time, get_ips_meu_dominio, remove_qos_rules


# print('importando fp_topo_discovery')
#descoberta de topologia
from fp_topology_discovery import handler_switch_enter, handler_switch_leave
# print('importando fp_dhcp')
#tratador DHCPv4
from fp_dhcp import handle_dhcp

from fp_icmp import handle_icmpv6, handle_icmpv4, rejeitar_fred, send_icmpv4, send_icmpv6

# print('importando interface_web')
# import wsgiWebSocket.interface_web as iwb
from wsgiWebSocket.interface_web import lancar_wsgi #, _websocket_rcv, _websocket_snd, dados_json

from traffic_classification.classificator import classificar_pacote

from traffic_monitoring.fp_monitoring import monitorar_pacote

from fp_api_qosblockchain import BlockchainManager

from fp_fred import Fred, FredManager

from fp_rota import RotaManager

def get_time_monotonic():
    return round(time.monotonic()*1000)

class FLOWPRI2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    controller_singleton = None

    #self.mac_to_port = {} arrumar esses dois, tirar do controlador e trzer para ca
    #self.ip_to_mac = {}

    #vetor com os enderecos ip dos controladores conhecidos (enviaram icmps)

     #switches administrados pelo controlador
    # rotas_ipv4 = {} # ip_dst/prefix:mask :list[switch_name]
    # rotas_ipv6 = {} # ip_dst/prefix:mask :list[switch_name]

    @staticmethod
    def getControllerInstance():
        return FLOWPRI2.controller_singleton

    def __init__(self, *args, **kwargs):
        print("CONTROLADOR - \n Init Start\n" )# % (IPC))
        setup()
        print("done")

        super(FLOWPRI2,self).__init__(*args,**kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}

        # onde as principais coisas são armazenadas
        self.fredmanager = FredManager()
        self.qosblockchainmanager = BlockchainManager()
        self.rotamanager = RotaManager()

        self.arpList = {}

        self.controladores_conhecidos = []

        self.switches = {}

    def getSwitchByName(self, nome) -> Switch:
        return self.switches.get(nome, None)

    def remove_qos_rules(self,ip_ver, proto, ip_src, ip_dst, src_port, dst_port):
        
        # comportamento borda = remover as regras de fluxos
        rota_nodes = get_rota(ip_src, ip_dst)
        # para casos contrarios, remover a regra de toda a rota e realizar a classificacao novamente...
        for rota_noh in rota_nodes:
            switch = self.getSwitchByName(rota_noh.switch_name)
            # switch.updateRegras(ip_src, ip_dst, tos) # essa funcao nao faz nada, eh de uma versao antiga --- se tiver tempo, remove-la
            porta_nome = switch.getPortaSaida(ip_dst)

            switch.delRegra(ip_ver)

            # comportamento backbone -> remover os freds que estão a mais tempo que o hardtimeout ! e reagrupar as regras que restaram
        IDLE_TIMEOUT = 1
        # se o fluxo foi removido por idle_timeout
        if IDLE_TIMEOUT:
            self.fredmanager.del_fred({})
        # remover_freds_expirados() -> que ja sria necessário mesmo
        self.fredmanager.remover_freds_expirados()
        # verificar quais regras precisam ser recriadas (em caso de backbone) -> 

        # reagrupar_regras_backbone() (em caso de backbone)

        return

    def create_qos_rules(self, ip_src:str, ip_dst:str, ip_ver:int, src_port:int, dst_port:int, proto:int, fred:dict, in_switch_id:int):

        #flow qos
        banda=fred["banda"]
        prioridade=fred["prioridade"]
        classe=fred["classe"]
        flow_label = fred["label"]

        # rota com os datapaths dos switches em ordem
        switch_route = self.rotamanager.get_rota(ip_src, ip_dst)

        if switch_route == None:
            return False

        lista_acoes:list[Acao] =[]

        # for switch in switch_route:
            #GBAM

        return True

    def create_be_rules(self, ip_src:str, ip_dst:str, ip_ver:int, src_port:int, dst_port:int, proto:int, in_switch_id:int):

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

        for node in route_nohs:
            switchh = self.getSwitchByName(node.switch_name)
            porta_saida = node.out_port
            # teria que agrupar as regras em conjunctions
            switchh.addRegraBE(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida)

        return True

    def saveSwitch(self, switch_name:int, switch:Switch):
        self.switches[switch_name] = switch 
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

        # Se eu sou borda origem E se for o ultimo switch da rota, atualizar regra de monitoramento
        if ip_meu_dominio(ip_src):
            if dp.id == route_nodes[-1].switch_name:
                addRegraMonitoring(self.getSwitchByName(dp.id), ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, out_port=route_nodes[-1].out_port, src_port=src_port, dst_port=dst_port, proto=proto)
    
        # OBS backbone tem outro comportamento !!!!!!
        # nao é o ultimo switch da rota, entao remover mesmo
        self.remove_qos_rules(ip_ver=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto)

        return 0

    def tratamento_pacote_meu_dominio(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, eth_src, eth_dst, pkt, qos_mark, dpid):
                # se o pacote for marcado para monitoramento, apenas armazenaR timestamp, len(pkt)
        # injetar o pacote ou contar 20 e mudar a regra -- OFPP_CONTROLLER
        marcacao_pkt = 0

        if ip_ver == 4:
            marcacao_pkt = qos_mark >> 2 # (esse eh o ipv4.tos) dscp sao apenas os 8 primeiros bits, nao contando os 2 ultimos, porem tos conta todos
        elif ip_ver == 6:
            marcacao_pkt = qos_mark
        else:
            print("[tratamento_meu_dominoi] erro: tipo de pacote nao identificado")
            return

        if marcacao_pkt == MARCACAO_MONITORAMENTO:
            if monitorar_pacote(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, pkt): #quando o monitoramento estiver completo
                # mudar a regra de monitoramento do primerio switch da rota para nao enviar pacotes ao controlador  -> essa regra tem um tempo hardtimeout menor 2s e uma flag, da proxima vez que expirar deve voltar a monitorar
                desligar_regra_monitoramento(ip_ver,ip_src,ip_dst,src_port,dst_port,proto)
                pass
            # nao injetar esse pacote, pois ele ja esta sendo encaminhado, apenas copiado ao controlador tbm
            return

        flow_classificacao = classificar_pacote(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, pkt)

        # criar regras qos, criar fred, preencher e enviar icmpv6.
        print("criar regras qos, criar fred, preencher e enviar icmpv6.")

        if flow_classificacao.classe_label != "be":

            # construir o FRED aqui 
            fred = Fred(ip_ver=ip_ver, ip_src=ip_src, src_port=src_port, dst_port=dst_port, proto=proto, mac_src=eth_src,
                         mac_dst=eth_dst, code=0, blockchain_name='blockchain_name', as_dst_ip_range=get_ips_meu_dominio(), 
                         as_src_ip_range=[],label=flow_classificacao.application_label,
                         ip_genesis=IP_MANAGEMENT_HOST, lista_peers=[], lista_rota=[], classe=flow_classificacao.classe_label, delay=flow_classificacao.delay, 
                         prioridade=flow_classificacao.priority, loss=flow_classificacao.loss, bandiwdth=flow_classificacao.bandwidth)

            self.fredmanager.save_fred(fred.getName(), fred) #### AAQUII
            if self.create_qos_rules(ip_src, ip_dst, ip_ver, src_port, dst_port, proto, fred, dpid):
                print("Regras criadas")

                nohs_rota = self.rotamanager.get_rota(ip_src, ip_dst)

                if nohs_rota == None:
                    print("Erro: sem rota configurada para o pacote s:%s d:%s" % (ip_src, ip_dst))
                if ip_ver == 4:
                    send_icmpv4(datapath=self.getSwitchByName(nohs_rota[-1].switch_name).datapath, srcMac=eth_src,dstMac=eth_dst, srcIp=ip_src, dstIp=ip_dst, outPort=nohs_rota[-1].out_port,seq=0, data=fred.toString())
                else:
                    send_icmpv6(datapath=self.getSwitchByName(nohs_rota[-1].switch_name).datapath, srcMac=eth_src, srcIp=ip_src,dstMac=eth_dst,dstIp=ip_dst,outPort=nohs_rota[-1].out_port,data=fred.toString())
        else:
            self.create_be_rules(self, ip_src, ip_dst, ip_ver, src_port, dst_port, proto, flow_label='be', flow_qos="be", in_switch_id=dpid)
        return True

#arrumando ate aqui
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

####################### LEARNING PHASE ###############################################################################
        timpo_i_mili = current_milli_time()
        print("[packet_in] init ", timpo_i_mili)

        tempo_i = get_time_monotonic()
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
        eth_dst,eth_src,ethertype = get_eth_header(pkt_eth)

        # campos ipv4 - se tiver, se não None
        ip_ver = None
        ipv4_version,ipv4_header_length,ipv4_tos,ipv4_total_length,ipv4_identification,ipv4_flags,ipv4_offset,ipv4_ttl,ipv4_proto,ipv4_csum,ipv4_src,ipv4_dst,ipv4_option = get_ipv4_header(pkt_ipv4)
        
        # campos ipv6 - se tiver
        ipv6_version,ipv6_traffic_class,ipv6_flow_label,ipv6_payload_length,ipv6_nxt,ipv6_hop_limit,ipv6_src,ipv6_dst,ipv6_ext_hdrs = get_ipv6_header(pkt_ipv6)

        # campos tcp = se tiver
        tcp_src_port,tcp_dst_port,tcp_seq,tcp_ack,tcp_offset,tcp_bits,tcp_window_size,tcp_csum,tcp_urgent,tcp_option = get_tcp_header(pkt_tcp)

        # campos udp = se tiver
        udp_src_port,udp_dst_port,udp_total_length,udp_csum = get_udp_header(pkt_udp)
        qos_mark = None

        if ipv4_version:
            ip_ver = 4
            ip_dst = ipv4_dst 
            ip_src = ipv4_src
            qos_mark = pkt_ipv4.tos
        elif ipv6_version:
            ip_ver = 6
            ip_dst = ipv6_dst 
            ip_src = ipv6_src
            qos_mark = pkt_ipv6.flow_label

        if udp_src_port:
            src_port = udp_src_port
            dst_port = udp_dst_port
            proto = UDP
        else:
            src_port = tcp_src_port
            dst_port = tcp_dst_port
            proto = TCP

        print("[%s] pkt_in ip_src: %s; ip_dst: %s; src_port: %d; dst_port: %d; proto: %d\n" % (datetime.datetime.now().time(), ipv4_src, ip_dst, src_port, dst_port, proto))

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
            handle_icmpv6(pkt_icmpv6, eth_src, eth_dst, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, str(dpid))
            print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
            return
        
        if pkt_icmpv4:     
            handle_icmpv4(pkt_icmpv4, eth_src, eth_dst, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, str(dpid))
            print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
            return
        
######################## IMCP ########################################################################################
######################## Unmactched ########################################################################################
        # fluxo novo -> classificar
        # fazer classificaçao trafego
        flow_label = "be"

        if ip_meu_dominio(ip_src):
            self.tratamento_pacote_meu_dominio(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, eth_src, eth_dst, pkt, qos_mark, dpid)
            injetarPacote(este_switch.datapath, fila, out_port, msg)   ### onde injetar isso ....
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
        self.create_be_rules(self, ip_src, ip_dst, ip_ver, src_port, dst_port, proto, in_switch_id=dpid)

        #injetar pacote na rede --> antes injetava direto no ultimo switch, mas não é muito realista, então vou injetar no próprio (qq coisa volta ao que era)
        # switch_ultimo = None
        # out_port = switch_ultimo.getPortaSaida(ip_dst) # !!!!
        fila = None
        injetarPacote(este_switch.datapath, fila, out_port, msg)

        # logging.info('[Packet_In] pacote sem match - fim - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))
        print("[%s] pkt_in fim \n" % (datetime.datetime.now().time()))

        print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
        return	 

def setup():

    global CONTROLADOR_ID, IPCc, IPCv4, IPCv6, MACC

    CONTROLADOR_ID = str(CONTROLLER_INTERFACE)
    IPCv4 = str(ifaddresses(CONTROLLER_INTERFACE)[AF_INET][0]['addr'])
    
    IPCv6 = str(ifaddresses(CONTROLLER_INTERFACE)[10][0]['addr'].split("%")[0])
    IPCc = IPCv4
    
    MACC = str(ifaddresses(CONTROLLER_INTERFACE)[17][0]['addr'])

    print("Controlador ID - {}".format(CONTROLADOR_ID))
    print("Controlador IPv4 - {}".format(IPCv4))
    print("Controlador IPv6 - {}".format(IPCv6))
    print("Controlador MAC - {}".format(MACC))

    #################
    #   INICIANDO SOCKET - R0ECEBER CONTRATOS (hosts e controladores)
    ################

    # t3 = Thread(target=servidor_configuracoes)
    # t3.start()

    # # iniciar o servidor web aqui
    # t4 = Thread(target=lancar_wsgi)
    # t4.start()

    #t1.join()
