# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, ipv6, icmp,icmpv6,arp, udp, tcp
from ryu.lib.packet import ether_types
from ryu.lib.ip import ipv4_to_int


from classificador import classificar_pacote

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


        print("TESTANDOO")
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,tcp_src=1000)
        actions = [parser.NXActionConjunction(clause=1,n_clauses=2,id_=10)]
        self.add_flow(datapath, 0, match, actions)
        # self.del_flow(datapath, match)     

        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,tcp_dst=2000)
        actions = [parser.NXActionConjunction(clause=2,n_clauses=2,id_=10)]
        # self.del_flow(datapath, match)        
        self.add_flow(datapath, 0, match, actions)

        # match = parser.OFPMatch(conj_id=10,eth_type=0x0800, ipv4_src="192.168.0.1")
        dicta = {"eth_type":0x0800, "ipv4_src":"192.100.1.1", "ipv4_dst":"192.100.1.2", "ip_dscp":10, "conj_id":10}        
        match = parser.OFPMatch(**dicta)
        actions = [parser.OFPActionOutput(2)]
        # self.del_flow(datapath, match)
        self.add_flow(datapath, 0, match, actions)
        
        dicta = {"eth_type":0x0800, "ipv4_src":"192.100.1.1", "ipv4_dst":"192.100.1.2", "ip_dscp":20, "conj_id":10}        
        match = parser.OFPMatch(**dicta)
        actions = [parser.OFPActionOutput(2)]
        # self.del_flow(datapath, match)
        self.add_flow(datapath, 0, match, actions)

        dicta = {"eth_type":0x0800, "ipv4_src":"192.100.1.1", "ipv4_dst":"192.100.1.2", "ip_dscp":20}#, "ip_dscp":10, "conj_id":10}        
        match = parser.OFPMatch(**dicta)
        actions = [parser.OFPActionOutput(2)]
        self.del_flow(datapath, match)

    def del_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, match=match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPP_ANY)
        datapath.send_msg(mod)

        return
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
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
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
                #analisar o pacote recebido usando a biblioteca packet
        pkt = packet.Packet(msg.data)
        eth= pkt.get_protocol (ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ipv6 = pkt.get_protocol(ipv6.ipv6)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_icmpv4 = pkt.get_protocol(icmp.icmp)
        pkt_icmpv6 = pkt.get_protocol(icmpv6.icmpv6)
        pkt_arp = pkt.get_protocol(arp.arp)

          # campos ethernet
        eth_dst=eth.dst
        eth_src=eth.src
        ethertype = eth.ethertype

        # campos observados
        ip_ver = ethertype
        ip_dst = ''
        ip_src = ''
        qos_mark = -1
        src_port = -1
        dst_port = -1
        proto = -1

        # print('pacote',pkt.__dict__)
        if pkt_ipv4:
            print("tem header ipv4")
            # ip_ver = pkt_ipv4.version
            ip_dst = pkt_ipv4.dst 
            ip_src = pkt_ipv4.src
            qos_mark = pkt_ipv4.tos
        elif pkt_ipv6:
            print("tem header ipv4")
            # ip_ver = pkt_ipv6.version
            ip_dst = pkt_ipv6.dst 
            ip_src = pkt_ipv6.src
            qos_mark = pkt_ipv6.flow_label

        if pkt_udp:
            print("tem header udp")
            src_port = pkt_udp.src_port
            dst_port = pkt_udp.dst_port
            proto = 17
        elif pkt_tcp:
            print("tem header tcp")
            src_port = pkt_tcp.src_port
            dst_port = pkt_tcp.dst_port
            proto = 6
        
        if pkt_icmpv4:
            print("tem header icmpv4")
            print(pkt.__dict__)
        elif pkt_icmpv6:
            print("tem header icmpv6")
            print(pkt.__dict__)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src


        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # fluxo chega aqui sem marcacao
        if pkt_tcp or pkt_udp:
            print("Entrou classificacao")
            if classificar_pacote(ip_ver=ip_ver, ip_src=ip_src, src_port=src_port, ip_dst=ip_dst, dst_port=dst_port,proto=proto, pkt_bytes=msg.data) != None:
                print("Fim da classificacao")

                #update regra para parar de enviar pacotes ao controlador
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                actions = [parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return 
                # exit(0)

        actions = [parser.OFPActionOutput(out_port), parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
