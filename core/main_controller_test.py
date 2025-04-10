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
from ryu.lib.packet import packet, in_proto
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

from fp_constants import IPV4_CODE, IPV6_CODE,NO_QOS_MARK, NO_METER

# try:
from fp_switch import Switch
# except ImportError:
#     print('Erro de importacao da classe SwitchOVS')


# from fp_openflow_rules import add_classification_table, add_default_rule

from fp_utils import current_milli_time, getQOSMark, getEquivalentMonitoringMark

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
    
    def _add_flow(self, dp, match, actions): ### cuidado com buffer id, já tivemos problema com isso uma vez (essa aqui é tirada do ryu)
        inst = [dp.ofproto_parser.OFPInstructionActions(
            dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = dp.ofproto_parser.OFPFlowMod(
            dp, cookie=0, cookie_mask=0, table_id=0,
            command=dp.ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0xff, buffer_id=0xffffffff,
            out_port=dp.ofproto.OFPP_ANY, out_group=dp.ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        dp.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, table_id, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod=None
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,priority=priority, match=match, instructions=inst, table_id=table_id)#, table_id = FORWARD_TABLE)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,match=match, instructions=inst, table_id=table_id)#, table_id = FORWARD_TABLE)
        datapath.send_msg(mod)
    #add regra tabela FORWARD
    def addRegraForwarding(self, datapath, ip_ver:int, ip_src:str, ip_dst:str, out_port:int, src_port:int, dst_port:int, proto:int, fila:int, meter_id:int, qos_mark_maching:int, idle_timeout:int, hard_timeout:int, qos_mark_action:int=NO_QOS_MARK, prioridade:int=10,  flow_removed:bool=True, toController:bool=False):
        # apenas primeiro switch da roda do dominio de origem devem usar essa regra, para marcar com qos e usar a meter
        print("addForw-init")
        # como setar corretamente os campos de match (linha 1352): https://github.com/faucetsdn/ryu/blob/master/ryu/ofproto/ofproto_v1_3_parser.py
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dicionario_parametros = {}

        dicionario_parametros['eth_type'] = ip_ver
        dicionario_parametros['ip_proto'] = proto

        if ip_ver == IPV4_CODE:
            dicionario_parametros['ipv4_src'] = ip_src
            dicionario_parametros['ipv4_dst'] = ip_dst
        elif ip_ver == IPV6_CODE:
            dicionario_parametros['ipv6_src'] = ip_src
            dicionario_parametros['ipv6_dst'] = ip_dst

        if proto == in_proto.IPPROTO_TCP:
            if src_port != -1:
                dicionario_parametros['tcp_src'] = src_port
            if dst_port != -1:
                dicionario_parametros['tcp_dst'] = dst_port
        elif proto == in_proto.IPPROTO_UDP:
            if src_port != -1:
                dicionario_parametros['udp_src'] = src_port
            if dst_port != -1:
                dicionario_parametros['udp_dst'] = dst_port

        if qos_mark_maching != NO_QOS_MARK:
            if ip_ver == IPV4_CODE:
                dicionario_parametros['ip_dscp'] = qos_mark_maching
            elif ip_ver == IPV6_CODE:
                dicionario_parametros['ipv6_flabel'] = qos_mark_maching

        #https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#flow-instruction-structures
        # hardtimeout = 5 segundos # isso eh para evitar problemas com pacotes que sao marcados como best-effort por um contrato nao ter chego a tempo. Assim vou garantir que daqui 5s o controlador possa identifica-lo. PROBLEMA: fluxos geralmente nao duram 5s, mas eh uma abordagem.

        #Para que a regra emita um evento de flow removed, ela precisa carregar uma flag, adicionada no OFPFlowMod
        #flags=ofproto.OFPFF_SEND_FLOW_REM

        #tratamento especial para este tipo de trafego
        match = parser.OFPMatch(**dicionario_parametros)

        actions = []
        if qos_mark_action != NO_QOS_MARK:
            if ip_ver == IPV4_CODE:
                actions.append(parser.OFPActionSetField(ip_dscp=qos_mark_action))
            elif ip_ver == IPV6_CODE:
                actions.append(parser.OFPActionSetField(ipv6_flabel=qos_mark_action))

        actions.append(parser.OFPActionSetQueue(fila))
        actions.append(parser.OFPActionOutput(out_port))

        if toController:
            actions.append(parser.OFPActionOutput(ofproto.OFPP_CONTROLLER))

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] # essa instrucao eh necessaria?

        if meter_id != NO_METER:
            # inst.append(parser.OFPInstructionMeter(meter_id=meter_id)) # ou é um ou é o outro...
            inst.append(parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER))

        mod = None
        #marcar para gerar o evento FlowRemoved
        if flow_removed:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idle_timeout, hard_timeout= hard_timeout, priority=prioridade, match=match, instructions=inst, table_id=0, flags=ofproto.OFPFF_SEND_FLOW_REM)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idle_timeout, hard_timeout= hard_timeout, priority=prioridade, match=match, instructions=inst, table_id=0)
        print("addForw:", match, inst)
        print(datapath.send_msg(mod))
        print("addFow-end")

    def addRegraMeter(self, datapath, banda, meter_id = None):

        if meter_id == None:
            print("[addRegraM] meter id missing")
            return
        # if meter_id == None:
        #     meter_id = generateMeterId(switch)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #criando meter bands
        bands = [parser.OFPMeterBandDrop(type_=ofproto.OFPMBT_DROP, len_=0, rate=banda, burst_size=100)]#e esse burst_size ajustar?
        req = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS, meter_id=meter_id, bands=bands)
        print(datapath.send_msg(req))
        return

    def addRegraForwarding2(self, datapath, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, out_port, fila, qos_mark_action=None, qos_mark_matching=None, meter_id=None, flow_removed=False, toController=False):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        mathing_dict = {'eth_type':ip_ver, 'ip_proto':proto}
        actionss=[]
        
        if ip_ver == 2048: 
            mathing_dict['ipv4_src'] = ip_src
            mathing_dict['ipv4_dst'] = ip_dst
            if qos_mark_action:
                actionss.append(parser.OFPActionSetField(ip_dscp=qos_mark_action))
            if qos_mark_matching != NO_QOS_MARK:
                mathing_dict['ip_dscp'] = qos_mark_matching
        else:
            mathing_dict['ipv6_src'] = ip_src
            mathing_dict['ipv6_dst'] = ip_dst
            if qos_mark_action:
                actionss.append(parser.OFPActionSetField(ipv6_flabel=qos_mark_action))
            if qos_mark_matching != NO_QOS_MARK:
                mathing_dict['ipv6_flabel'] = qos_mark_matching

        if proto == 6:
            mathing_dict['tcp_src'] = src_port
            mathing_dict['tcp_dst'] = dst_port
        else:
            mathing_dict['udp_src'] = src_port
            mathing_dict['udp_dst'] = dst_port


        matchh =parser.OFPMatch(**mathing_dict)
        actionss.append(parser.OFPActionSetQueue(fila))
        actionss.append(parser.OFPActionOutput(out_port))

        if toController:
            actionss.append(parser.OFPActionOutput(ofproto.OFPP_CONTROLLER))

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actionss)] # essa instrucao eh necessaria?
        if meter_id:
            # inst.append(parser.OFPInstructionMeter(meter_id=meter_id)) # ou é um ou é o outro...
            inst.append(parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER))

        mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = 10, hard_timeout= 15, priority=10, match=matchh, instructions=inst, table_id=0)
        if flow_removed:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = 10, hard_timeout= 15, priority=10, match=matchh, instructions=inst, table_id=0, flags=ofproto.OFPFF_SEND_FLOW_REM)

        # self.add_flow(datapath=datapath, priority=10, match=matchh, actions=actionss,table_id=0)
        datapath.send_msg(mod)
        return 
    def add_flow2(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        print(datapath.send_msg(mod))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print("Novo switch anunciado....\n")

        #aqui nao se obtem tantas informacoes sobre os switches como eu gostaria
        tempo_i = round(time.monotonic()*1000)
    
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        switch = Switch(controller=self, datapath=datapath, name=datapath.id, port_to_controller=0, ovsdb_addr="")
        
        # testando regra BE e QOS + marcacao + forwarding para controlador
        # self.addRegraMeter(datapath, 5000, 3)
        # self.addRegraForwarding2(datapath, 2048, '172.16.1.30', '172.16.2.30', 2000,3000, 6, 3, 7, 55) # ok
        # self.addRegraForwarding2(datapath, 2048, '172.16.1.30', '172.16.2.30', 2000,3000, 6, 3, 7, 55, meter_id=3) # ok
        # self.addRegraForwarding2(datapath, 2048, '172.16.1.30', '172.16.2.30', 2000,3000, 6, 3, 7, 55, meter_id=3, toController=True) # ok
        # self.addRegraForwarding2(datapath, 2048, '172.16.1.30', '172.16.2.30', 2000,3000, 6, 3, 7, qos_mark_matching=22, qos_mark_action=33, meter_id=3, toController=True) # ok

        # testando regra monitoramento 
        # switch.add_regra_monitoramento_fluxo(ip_ver=2048, ip_src='172.16.1.30', ip_dst='172.16.2.30', src_port=2000,dst_port=3000, proto=6, porta_saida=3, fila=5, qos_mark_action=22, qos_mark_matching=33)

        # print("TESTANDOO")
        # match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,tcp_src=3000)
        # actions = [parser.NXActionConjunction(clause=1,n_clauses=2,id_=11)]
        # self.add_flow2(datapath, 0, match, actions)
        # # self.del_flow(datapath, match)     

        # match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,tcp_dst=2000)
        # actions = [parser.NXActionConjunction(clause=1,n_clauses=2,id_=12)]
        # # self.del_flow(datapath, match)        
        # self.add_flow2(datapath, 0, match, actions)


        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow2(datapath, 0, match, actions)


        print("TESTANDOO")
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src='172.16.1.1')
        actions = [parser.NXActionConjunction(clause=0,n_clauses=2, id_=222)]
        self.add_flow2(datapath, 0, match, actions)
        # self.del_flow(datapath, match)     

        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,tcp_dst=2300)
        actions = [parser.NXActionConjunction(clause=1,n_clauses=2,id_=1111)]
        # self.del_flow(datapath, match)        
        self.add_flow2(datapath, 0, match, actions)

        # # match = parser.OFPMatch(conj_id=10,eth_type=0x0800, ipv4_src="192.168.0.1")
        # dicta = {"eth_type":0x0800, "ipv4_src":"192.100.1.1", "ipv4_dst":"192.100.1.2", "ip_dscp":10, "conj_id":10}        
        # match = parser.OFPMatch(**dicta)
        # actions = [parser.OFPActionOutput(2)]
        # # self.del_flow(datapath, match)
        # self.add_flow2(datapath, 0, match, actions)
        
        # dicta = {"eth_type":0x0800, "ipv4_src":"192.100.1.1", "ipv4_dst":"192.100.1.2", "ip_dscp":20, "conj_id":10}        
        # match = parser.OFPMatch(**dicta)
        # actions = [parser.OFPActionOutput(2)]
        # # self.del_flow(datapath, match)
        # self.add_flow2(datapath, 0, match, actions)

        # dicta = {"eth_type":0x0800, "ipv4_src":"192.100.1.1", "ipv4_dst":"192.100.1.2", "ip_dscp":20}#, "ip_dscp":10, "conj_id":10}        
        # match = parser.OFPMatch(**dicta)
        # actions = [parser.OFPActionOutput(2)]
        # self.del_flow(datapath, match)
        # logging.info('[switch_features] fim settage - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))

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
    CONTROLADOR_ID=CONTROLLER_INTERFACE = str('veth1')
    IPCv4 = str(ifaddresses(CONTROLLER_INTERFACE)[AF_INET][0]['addr'])
    IPCv6 = str(ifaddresses(CONTROLLER_INTERFACE)[10][0]['addr'].split("%")[0])
    IPC = IPCv4

    MACC = str(ifaddresses(CONTROLLER_INTERFACE)[17][0]['addr'])

    print("Controlador ID - {}".format(CONTROLADOR_ID))
    print("Controlador IP - {}".format(IPCv6))
    print("Controlador MAC - {}".format(MACC))
