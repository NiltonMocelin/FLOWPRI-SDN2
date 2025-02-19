from fp_constants import FORWARD_TABLE,CLASSIFICATION_TABLE,FILA_CONTROLE


# mudar os matches para:
# match.set_in_port(in_port)
# match.set_dl_type(eth_IP)


# os melhores exemplos estao em: ryu/ryu/tests


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
