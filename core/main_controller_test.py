### USAR PYTHON 3 !!

# importar o tratador da interface web
import sys, os

from netifaces import AF_INET, ifaddresses, interfaces

# setting path for importation
# sys.path.append('../qosblockchain')
# sys.path.append('../ryu')
# sys.path.append('../traffic_classification')
# sys.path.append('../traffic_monitoring')
# sys.path.append('../wsgiWebSocket')
# sys.path.append('../')

# # Add the parent directory to sys.path
sys.path.append( os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/")

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, inet, ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4, arp, icmp, udp, tcp, lldp, ipv6, dhcp, icmpv6



from ryu.topology import event

#tratar tempo - monotonic clock -> round(time.monotonic()*1000)
import time
import datetime
##prints logging - logging.info('tempo atual %d\n' % (round(time.monotonic()*1000)))
import logging

# importar o tratador da interface web
import sys, os

from fp_constants import switches, IPC,IPV4, IPCv6, CONTROLLER_INTERFACE, MACC

# try:
from fp_switch import SwitchOVS
# except ImportError:
#     print('Erro de importacao da classe SwitchOVS')


from fp_openflow_rules import add_classification_table, add_default_rule

from fp_utils import current_milli_time

# print('importando fp_topo_discovery')
#descoberta de topologia
from fp_topology_discovery import handler_switch_enter, handler_switch_leave

class Dinamico(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        print("CONTROLADOR - \n Init Start\n" )# % (IPC))
        super(Dinamico,self).__init__(*args,**kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}

        # #contratos.append(contrato)
        # _websocket_snd(pc_status())

        global controller_singleton
        controller_singleton = self
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print("Novo switch anunciado....\n")

        #aqui nao se obtem tantas informacoes sobre os switches como eu gostaria
        tempo_i = round(time.monotonic()*1000)
    
        datapath = ev.msg.datapath

        print("[%s] switch_features - setup de S%d \n" % (datetime.datetime.now().time(), datapath.id))

        switch = SwitchOVS(datapath,str(datapath.id), self)

        switches.append(switch) 
       
        #[CLASSIFICACAO] regra default -> enviar para tabela 2
        add_classification_table(datapath)
       
        add_default_rule(datapath)

        """adicionar regra para monitorar pacotes marcados com destino o meu domínio"""

        logging.info('[switch_features] fim settage - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))

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
        """verificar se é uma regra qos monitoring"""

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
        tos = None
        src_port = None
        dst_port = None
        proto = None
        ip_ver = None
        if 'ipv4_dst' in msg.match:
            ip_dst = msg.match['ipv4_dst']
            ip_src = msg.match['ipv4_src']
            ip_ver = 'ipv4'
        elif 'ipv6_dst' in msg.match:
            ip_dst = msg.match['ipv6_dst']
            ip_src = msg.match['ipv6_src']
            ip_ver = 'ipv6'

        if 'ip_dscp' in msg.match:
            tos= msg.match['ip_dscp']
        if 'tcp_src' in msg.match:
            src_port = msg.match['tcp_src']
            dst_port = msg.match['tcp_dst']
            proto='tcp'
        if 'udp_src' in msg.match:
            src_port = msg.match['udp_src']
            dst_port = msg.match['udp_dst']
            proto='udp'
       
   
        return 0

#arrumando ate aqui
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        timpo_i_mili = current_milli_time()
        print("[packet_in] init ", timpo_i_mili)

        tempo_i = round(time.monotonic()*1000)
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


if __name__ == "__main__":
    CONTROLADOR_ID = str(CONTROLLER_INTERFACE)
    IPCv4 = str(ifaddresses(CONTROLLER_INTERFACE)[AF_INET][0]['addr'])
    IPCv6 = str(ifaddresses(CONTROLLER_INTERFACE)[10][0]['addr'].split("%")[0])
    IPC = IPCv4

    MACC = str(ifaddresses(CONTROLLER_INTERFACE)[17][0]['addr'])

    print("Controlador ID - {}".format(CONTROLADOR_ID))
    print("Controlador IP - {}".format(IPCv6))
    print("Controlador MAC - {}".format(MACC))
