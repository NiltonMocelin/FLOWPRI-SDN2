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

from traffic_classification.classificator import flows_dict

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
from fp_constants import REMOVER, MARCACAO_MONITORAMENTO

from fp_constants import switches

from fp_constants import switches, IPC,IPV4, IPCv6, CONTROLLER_INTERFACE, MACC

# try:
from fp_switch import SwitchOVS
# except ImportError:
#     print('Erro de importacao da classe SwitchOVS')

from fp_server import servidor_configuracoes

from fp_acao import Acao

from fp_regra import Regra

from fp_openflow_rules import add_classification_table, add_default_rule

from fp_utils import get_ipv4_header, get_eth_header, get_ipv6_header, get_tcp_header, get_udp_header, getSwitchByName, get_rota, ip_meu_dominio, create_be_rules, create_qos_rules, monitorar_pacote
from fp_utils import current_milli_time

from fp_api_traffic_classification import tratador_classificacao_trafego

from fp_api_traffic_monitoring import get_flow_monitorado


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


#################
#   INICIANDO SOCKET - RECEBER CONTRATOS (hosts e controladores)
################

t3 = Thread(target=servidor_configuracoes)
t3.start()

## iniciar o servidor web aqui
t4 = Thread(target=lancar_wsgi)
t4.start()

#t1.join()


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
       
       
        meter_id = int(ip_src.split(".")[3] + ip_dst.split(".")[3])
        #print("[event-flowRemove] ipv4_dst:%s, ipv4_src:%s, ip_dscp:%s\n" % (ip_dst,ip_src,tos))
        print("[%s] flow_removed - removendo regra ip_src: %s, ip_dst: %s, dscp: %d, meter: %d \n" % (datetime.datetime.now().time(), ip_src, ip_dst, int(tos), meter_id))

        #por agora, tanto as regras de ida quanto as de volta sao marcadas para notificar com o evento
        #atualizar no switch que gerou o evento

        switch = self.getSwitchByName(str(dp.id))
        if switch != None:
            # switch.updateRegras(ip_src, ip_dst, tos) # essa funcao nao faz nada, eh de uma versao antiga --- se tiver tempo, remove-la
            porta_nome = switch.getPortaSaida(ip_dst)

            #versao mais elegante
            Acao(switch_obj = switch,porta = int(porta_nome),codigo = REMOVER, regra= Regra(ip_ver=ip_ver, ip_src=ip_src,ip_dst=ip_dst,src_port=src_port, dst_port=dst_port, proto=proto, porta_saida = int(porta_nome), tos=tos, banda=None, prioridade=None, classe=None, emprestando=None)).executar()

            # switch.getPorta(porta_nome).delRegra(ip_src, ip_dst, tos)
            # switch.delRegraM(meter_id)

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

        if ipv4_version:
            ip_ver = 'ipv4'
            ip_dst = ipv4_dst 
            ip_src = ipv4_src
        elif ipv6_version:
            ip_ver = 'ipv6'
            ip_dst = ipv6_dst 
            ip_src = ipv6_src

        if udp_src_port:
            src_port = udp_src_port
            dst_port = udp_dst_port
            proto = 'udp'
        else:
            src_port = tcp_src_port
            dst_port = tcp_dst_port
            proto = 'tcp'

        print("[%s] pkt_in ip_src: %s; ip_dst: %s; src_port: %s; dst_port: %s; proto: %s\n" % (datetime.datetime.now().time(), ipv4_src, ip_dst, src_port, dst_port, proto))

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

        # fluxo novo -> classificar
        # fazer classificaçao trafego
        flow_label = "best-effort"
        fred = {}

        if ip_meu_dominio(ip_src):

            # se o pacote for marcado para monitoramento, apenas armazenaR timestamp, len(pkt)
            # injetar o pacote ou contar 20 e mudar a regra -- OFPP_CONTROLLER
            marcacao_pkt = 0
            qtd_pkts = 0

            if pkt_ipv4:
                marcacao_pkt = pkt_ipv4.tos
            elif pkt_ipv6:
                marcacao_pkt = pkt_ipv6.flow_label

            if marcacao_pkt == MARCACAO_MONITORAMENTO:
                qtd_pkts = monitorar_pacote(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, pkt)

            if qtd_pkts >= 10:
                
                flow_monitorado_dict = get_flow_monitorado(ip_ver, ip_src, ip_dst, src_port, dst_port, proto)
                
                b = json.dumps(flow_monitorado_dict)
                
                # pegar rota, escolher ultimo switch e inserir o icmp
                switch_rota = get_rota(ip_src, ip_dst, ip_ver, src_port, dst_port, proto, dpid)

                switch_ultimo = getSwitchByName(switch_rota[-1].switch_name)

                if pkt_ipv4:
                    send_icmpv4(switch_ultimo.datapath, eth_src, ip_src, eth_dst, ip_dst, switch_rota[-1].out_port, 0, b, id=1, type=15, ttl=64)
                    
                elif pkt_ipv6:
                    send_icmpv6(switch_ultimo.datapath, eth_src, ip_src, eth_dst, ip_dst, switch_rota[-1].out_port, b, type=139, ttl=64)

            fred = tratador_classificacao_trafego(pkt)
            flow_label = fred["label"]


        if flow_label != "best-effort":
            # criar regras qos, criar fred, preencher e enviar icmpv6.
            print("criar regras qos, criar fred, preencher e enviar icmpv6.")

            if create_qos_rules(ip_src, ip_dst, ip_ver, src_port, dst_port, proto, fred, dpid):
                print("Regras criadas")
            
            else: 
                print("Fluxo teve QoS rejeitado (falta de recursos)")
                # informar os outros domínios para enviar o fluxo por best-effort por enquanto. -> via icmpv6
                rejeitar_fred(fred, in_switch_id=dpid)

                create_be_rules(self, ip_src, ip_dst, ip_ver, src_port, dst_port, proto, flow_label, flow_qos="qqcoisa", in_switch_id=dpid)
            print("[packet_in] finish ", current_milli_time(), " - decorrido:",  current_milli_time()- timpo_i_mili)
            return

        # nao teve classificação ou foi best-effort
        print("criar regras best-effort")
        create_be_rules(self, ip_src, ip_dst, ip_ver, src_port, dst_port, proto, flow_label, flow_qos="qqcoisa", in_switch_id=dpid)

        # ## comportamento diferente se for backbone...
        # if check_domain_hosts(ip_src) == False and check_domain_hosts(ip_dst) == False:
        #     print("backbone")

        #injetar pacote na rede
        switch_ultimo = None
        out_port = switch_ultimo.getPortaSaida(ip_dst) # !!!!
        fila = None
        switch_ultimo.injetarPacote(switch_ultimo.datapath, fila, out_port, msg)

        # logging.info('[Packet_In] pacote sem match - fim - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))
        print("[%s] pkt_in fim \n" % (datetime.datetime.now().time()))

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
