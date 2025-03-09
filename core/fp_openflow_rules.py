from fp_constants import FORWARD_TABLE,CLASSIFICATION_TABLE,FILA_CONTROLE, ALL_TABLES, IPV4_CODE, IPV6_CODE, TCP, UDP, BE_IDLE_TIMEOUT, QOS_IDLE_TIMEOUT, QOS_HARD_TIMEOUT, BE_HARD_TIMEOUT, MONITORING_TIMEOUT, NO_METER,NO_QOS_MARK, OFP_NO_BUFFER
from fp_switch import Switch

from ryu.lib.packet import ether_types, in_proto
from ryu.ofproto.ofproto_v1_3_parser import OFPFlowMod, OFPMatch
from ryu.ofproto import ofproto_parser

# mudar os matches para:
# match.set_in_port(in_port)
# match.set_dl_type(eth_IP)


# os melhores exemplos estao em: ryu/ryu/tests


def _add_flow(dp, match, actions): ### cuidado com buffer id, já tivemos problema com isso uma vez (essa aqui é tirada do ryu)
    inst = [dp.ofproto_parser.OFPInstructionActions(
        dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
    mod = dp.ofproto_parser.OFPFlowMod(
        dp, cookie=0, cookie_mask=0, table_id=0,
        command=dp.ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
        priority=0xff, buffer_id=0xffffffff,
        out_port=dp.ofproto.OFPP_ANY, out_group=dp.ofproto.OFPG_ANY,
        flags=0, match=match, instructions=inst)
    dp.send_msg(mod)


def add_flow(datapath, priority, match, actions, table_id, buffer_id=None):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    mod=None
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    if buffer_id:
        mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,priority=priority, match=match, instructions=inst, table_id=table_id)#, table_id = FORWARD_TABLE)
    else:
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,match=match, instructions=inst, table_id=table_id)#, table_id = FORWARD_TABLE)
    datapath.send_msg(mod)

########### Testando ############

def add_classification_table(datapath):
    parser = datapath.ofproto_parser
    inst = [parser.OFPInstructionGotoTable(FORWARD_TABLE)]
    mod = parser.OFPFlowMod(datapath=datapath, table_id=CLASSIFICATION_TABLE, instructions=inst, priority=0) #criando a regra default
    datapath.send_msg(mod)

def add_default_rule(datapath):
    #[FORWARD] regra default -> enviar para o controlador
    parser = datapath.ofproto_parser
    ofproto = datapath.ofproto
    match = parser.OFPMatch()
    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                      ofproto.OFPCML_NO_BUFFER)]
    add_flow(datapath, 0, match, actions, FORWARD_TABLE)

def add_forward_table(datapath, actions, prioridade):
    parser = datapath.ofproto_parser
    inst = [parser.OFPInstructionGotoTable(FORWARD_TABLE)]
    mod = None
    if actions == None:
        mod = parser.OFPFlowMod(datapath=datapath, table_id=FORWARD_TABLE,priority=prioridade, instructions=inst)
    else:
        mod = parser.OFPFlowMod(datapath=datapath, table_id=FORWARD_TABLE,priority=prioridade, instructions=inst, actions=actions)
    datapath.send_msg(mod)

def _send_packet(datapath, port, pkt):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    pkt.serialize()
    print("To dpid {0} packet-out {1}".format(datapath.id, pkt))
    data = pkt.data
    actions = [parser.OFPActionOutput(port=port)]
    out = parser.OFPPacketOut(datapath=datapath,
                              buffer_id=ofproto.OFP_NO_BUFFER,
                              in_port=ofproto.OFPP_CONTROLLER,
                              actions=actions,
                              data=data)
    datapath.send_msg(out)


#   #criar uma mensagem para remover uma regra de fluxo no ovsswitch
# def delRegraT(switch:Switch, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, ip_dscp, tabela=ALL_TABLES):
#     """ Parametros:
#     ip_ver:str
#     ip_src:str
#     ip_dst:str
#     src_port:str
#     dst_port:str
#     proto:str
#     ip_dscp:int
#     tabela=ALL_TABLES
#     """
#     #tabela = 255 = ofproto.OFPTT_ALL = todas as tabelas
#     #print("Deletando regra - ipsrc: %s, ipdst: %s, tos: %d, tabela: %d\n" % (ip_src, ip_dst, tos, tabela))
#     #tendo o datapath eh possivel criar pacotes de comando para o switch/datapath
#     #caso precise simplificar, pode chamar o cmd e fazer tudo via ovs-ofctl
#     #modelo com ovs-ofctl:
#     #we can remove all or individual flows from the switch
#     # sudo ovs-ofctl del-flows <expression>
#     # ex. sudo ovs-ofctl del-flows dp0 dl_type=0x800
#     # ex. sudo ovs-ofctl del-flows dp0 in_port=1
    
#     datapath = switch.datapath
#     ofproto = datapath.ofproto
#     parser:ofproto_parser = datapath.ofproto_parser
#     #remover a regra meter associada
#     meter_id = int(ip_src.split(".")[3] + ip_dst.split(".")[3])                
#     delRegraM(datapath, meter_id)
                    
#     if(ip_dscp != None):
#         ip_dscp = '000000'
    
#     #generico ipv4
#     match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst, ip_dscp=ip_dscp)
#     if ip_ver == 'ipv6':
#         match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6, ipv6_src=ip_src, ipv6_dst=ip_dst, ip_dscp=ip_dscp)
#     #tratamento especial para este tipo de trafego
#     if proto ==in_proto.IPPROTO_TCP:
#         match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto = proto, ipv4_src=ip_src, ipv4_dst=ip_dst, tcp_src = src_port, tcp_dst=dst_port,ip_dscp=ip_dscp)
#         if ip_ver == 'ipv6':
#             match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6, ip_proto = proto, ipv6_src=ip_src, ipv6_dst=ip_dst, tcp_src = src_port, tcp_dst=dst_port,ip_dscp=ip_dscp)
#     elif proto == in_proto.IPPROTO_UDP:
#         match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto = proto, ipv4_src=ip_src, ipv4_dst=ip_dst, udp_src = src_port, udp_dst=dst_port,ip_dscp=ip_dscp)
#         if ip_ver == 'ipv6':
#             match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6, ip_proto = proto, ipv6_src=ip_src, ipv6_dst=ip_dst, udp_src = src_port, udp_dst=dst_port,ip_dscp=ip_dscp)
#     mod = datapath.ofproto_parser.OFPFlowMod(datapath, command=ofproto.OFPFC_DELETE, match=match, table_id=tabela, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
#     ##esse funciona - remove tudo
#     #mod = datapath.ofproto_parser.OFPFlowMod(datapath, command=ofproto.OFPFC_DELETE, table_id=ofproto.OFPTT_ALL, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
#     datapath.send_msg(mod)
#     return 0
    
    

#Injetar pacote no controlador com instrucoes - serve para injetar pacotes que foram encaminhado por packet_in (se nao eles sao perdidos)
def injetarPacote(datapath, fila:int, out_port:int, packet, buffer_id=OFP_NO_BUFFER):
    datapath = datapath
    actions = [datapath.ofproto_parser.OFPActionSetQueue(fila), datapath.ofproto_parser.OFPActionOutput(out_port)] 
    out = datapath.ofproto_parser.OFPPacketOut(
        datapath=datapath,
        buffer_id=buffer_id,
        in_port=100,
        actions=actions,
        data=packet.data)

    datapath.send_msg(out)

#add regra tabela FORWARD
def addRegraF(switch:Switch, ip_ver:int, ip_src:str, ip_dst:int, out_port:int, src_port:int, dst_port:int, proto:int, fila:int, meter_id:int, qos_mark:int, idle_timeout:int, hard_timeout:int, prioridade:int=10,  flow_removed:bool=True):
    """ Parametros:
    ip_ver:str
    ip_src: str
    ip_dst: str
    ip_dscp: int
    out_port: int
    src_port: int
    dst_port: int 
    proto: str
    fila: int
    meter_id: int 
    flag: int
    hardtime=None
    """

    # se precisar recuperar o buffer_id = msg.buffer_id

    # como setar corretamente os campos de match (linha 1352): https://github.com/faucetsdn/ryu/blob/master/ryu/ofproto/ofproto_v1_3_parser.py
    datapath = switch.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    
    match:OFPMatch = parser.OFPMatch()
    match.set_ip_proto(proto)
    match.set_dl_type(ip_ver)
    if ip_ver == IPV4_CODE:
        match.set_ipv4_src(ip_src)
        match.set_ipv4_dst(ip_dst)
    elif ip_ver == IPV6_CODE:
        match.set_ipv6_src(ip_src)
        match.set_ipv6_dst(ip_dst)

    if proto == in_proto.IPPROTO_TCP:
        match.set_ip_proto(TCP)
        if src_port != -1:
            match.set_tcp_src(src_port)
        if dst_port != -1:
            match.set_tcp_dst(dst_port)
    elif proto == in_proto.IPPROTO_UDP:
        match.set_ip_proto(UDP)
        if src_port != -1:
            match.set_udp_src(src_port)
        if dst_port != -1:
            match.set_udp_dst(dst_port)
    
    if qos_mark != NO_QOS_MARK:
        if ip_ver == IPV4_CODE:
            match.set_ip_dscp=qos_mark
        elif ip_ver == IPV6_CODE:
            match.set_ipv6_flabel=qos_mark

    #https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#flow-instruction-structures
    # hardtimeout = 5 segundos # isso eh para evitar problemas com pacotes que sao marcados como best-effort por um contrato nao ter chego a tempo. Assim vou garantir que daqui 5s o controlador possa identifica-lo. PROBLEMA: fluxos geralmente nao duram 5s, mas eh uma abordagem.
    
    #Para que a regra emita um evento de flow removed, ela precisa carregar uma flag, adicionada no OFPFlowMod
    #flags=ofproto.OFPFF_SEND_FLOW_REM
      
    #tratamento especial para este tipo de trafego
    actions = [parser.OFPActionSetQueue(fila), parser.OFPActionOutput(out_port)]
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] # essa instrucao eh necessaria?

    if meter_id != NO_METER:
        # inst.append(parser.OFPInstructionMeter(meter_id=meter_id)) # ou é um ou é o outro...
        inst.append(parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER))
        
    #marcar para gerar o evento FlowRemoved
    if flow_removed:
        mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idle_timeout, hard_timeout= hard_timeout, priority=prioridade, match=match, instructions=inst, table_id=FORWARD_TABLE, flags=ofproto.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(mod)
        return
    mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idle_timeout, hard_timeout= hard_timeout, priority=prioridade, match=match, instructions=inst, table_id=FORWARD_TABLE)
    datapath.send_msg(mod)
    
#add regra tabela CLASSIFICATION
#se o destino for um ip de controlador, 
def addRegraC(switch:Switch, ip_ver:int ,ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, qos_mark:int, idle_timeout:int, hard_timeout:int, prioridade:int=10):
    """  ADD regra monitoring
    parametros:
    ip_ver: str
    ip_src: str
    ip_dst: str
    src_port: str
    dst_port: str
    proto: str
    ip_dscp: str
    """
    #https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#flow-instruction-structures
     #criar regra na tabela de marcacao - obs - utilizar idletime para que a regra suma - serve para que em switches que nao sao de borda essa regra nao exista
                     #obs: cada switch passa por um processo de enviar um packet_in para o controlador quando um fluxo novo chega,assim, com o mecanismo de GBAM, pode ser que pacotes de determinados fluxos sejam marcados com TOS diferentes da classe original, devido ao emprestimo, assim, em cada switch o pacote pode ter uma marcacao - mas com essa regra abaixo, os switches que possuem marcacao diferentes vao manter a regra de remarcacao. Caso ela expire e cheguem novos pacotes, ocorrera novo packet in e o controlador ira executar um novo GBAM - que vai criar uma nova regra de marcacao
    #print("[criando-regra-tabela-marcacao] ipsrc: %s, ipdst: %s, tos: %d\n" % (ip_src, ip_dst, ip_dscp))
    datapath = switch.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    actions = []
    match:OFPMatch = parser.OFPMatch()
    match.set_ip_proto(proto)
    match.set_dl_type(ip_ver)
    if ip_ver == IPV4_CODE:
        match.set_ipv4_src(ip_src)
        match.set_ipv4_dst(ip_dst)
        if qos_mark != NO_QOS_MARK:
            actions.append(parser.OFPActionSetField(ip_dscp=qos_mark))
    elif ip_ver == IPV6_CODE:
        match.set_ipv6_src(ip_src)
        match.set_ipv6_dst(ip_dst)

        if qos_mark != NO_QOS_MARK:
            actions.append(parser.OFPActionSetField(ipv6_flabel=qos_mark))

    if proto == in_proto.IPPROTO_TCP:
        match.set_ip_proto(TCP)
        if src_port != -1:
            match.set_tcp_src(src_port)
        if dst_port != -1:
            match.set_tcp_dst(dst_port)
    elif proto == in_proto.IPPROTO_UDP:
        match.set_ip_proto(UDP)
        if src_port != -1:
            match.set_udp_src(src_port)
        if dst_port != -1:
            match.set_udp_dst(dst_port)

    inst = [parser.OFPInstructionGotoTable(FORWARD_TABLE), parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

    mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idle_timeout, hard_timeout = hard_timeout, priority=prioridade, match=match, instructions=inst, table_id=CLASSIFICATION_TABLE)
    datapath.send_msg(mod)

def delRegraF(switch:Switch, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int):
    # como setar corretamente os campos de match (linha 1352): https://github.com/faucetsdn/ryu/blob/master/ryu/ofproto/ofproto_v1_3_parser.py
    datapath = switch.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    
    match:OFPMatch = parser.OFPMatch()
    match.set_ip_proto(proto)
    match.set_dl_type(ip_ver)
    if ip_ver == IPV4_CODE:
        match.set_ipv4_src(ip_src)
        match.set_ipv4_dst(ip_dst)
    elif ip_ver == IPV6_CODE:
        match.set_ipv6_src(ip_src)
        match.set_ipv6_dst(ip_dst)

    if proto == TCP:
        match.set_ip_proto(TCP)
        if src_port != -1:
            match.set_tcp_src(src_port)
        if dst_port != -1:
            match.set_tcp_dst(dst_port)
    elif proto == UDP:
        match.set_ip_proto(UDP)
        if src_port != -1:
            match.set_udp_src(src_port)
        if dst_port != -1:
            match.set_udp_dst(dst_port)
    
    mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPMC_DELETE, match=match, table_id=ALL_TABLES) #, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
    datapath.send_msg(mod)
    return




def generateMeterId(switch:Switch):

    id_valido = 0

    ids_utilizados = switch.meter_dict.values()
    
    while True:
        if id_valido not in ids_utilizados:
            break

        id_valido += 1
        
    return id_valido

def getMeterID_from_Flow(switch:Switch, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int):
    meter_id = NO_METER
    try:
        meter_id = switch.meter_dict[str(ip_ver)+ip_src+ip_dst+str(src_port)+str(dst_port)+str(proto)]
    except:
        return NO_METER

    return meter_id

def delMeter(switch:Switch, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int):
    # essas funcoes deveriam estar em switch. ....
    try:
        del switch.meter_dict[str(ip_ver)+ip_src+ip_dst+str(src_port)+str(dst_port)+str(proto)]
    except:
        print("[delMeter]Meter rule nao encontrada..")
    return

 #criando regra meter
def addRegraM(switch:Switch, banda, meter_id = None):

    if meter_id == None:
        print("[addRegraM] meter id missing")
        return
    # if meter_id == None:
    #     meter_id = generateMeterId(switch)

    datapath = switch.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    #criando meter bands
    bands = [parser.OFPMeterBandDrop(type_=ofproto.OFPMBT_DROP, len_=0, rate=banda, burst_size=100)]#e esse burst_size ajustar?
    req = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS, meter_id=meter_id, bands=bands)
    datapath.send_msg(req)
    return

def delRegraM(switch:Switch, meter_id):
    datapath = switch.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    
    req = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_DELETE, meter_id=meter_id)
    datapath.send_msg(req)
    return

