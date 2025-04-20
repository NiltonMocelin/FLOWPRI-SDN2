from fp_constants import FORWARD_TABLE,FILA_CONTROLE, ALL_TABLES, IPV4_CODE, IPV6_CODE, TCP, UDP, BE_IDLE_TIMEOUT, QOS_IDLE_TIMEOUT, QOS_HARD_TIMEOUT, BE_HARD_TIMEOUT, MONITORING_TIMEOUT_ACTION, MONITORING_TIMEOUT_FORWARD, NO_METER,NO_QOS_MARK, OFP_NO_BUFFER, MARCACAO_MONITORAMENTO, CONJUNCTION_ID, TCP_SRC, TCP_DST, UDP_SRC, UDP_DST, MONITORING_PRIO, CONJUNCTION_PRIO, METER_PRIO
from fp_constants import NO_METER, PORTA_ENTRADA, PORTA_SAIDA
# from fp_switch import Switch

from ryu.lib.packet import in_proto #, ether_types
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch #, OFPFlowMod
# from ryu.ofproto import ofproto_parser
from fp_utils import getEquivalentMonitoringMark, getQOSMark, getQueueId

from fp_regra import Regra
from fp_acao import Acao

# os melhores exemplos estao em: ryu/ryu/tests

############################@ IMPORTANTE @#################################
# A ORDEM DA TABLE_ID IMPORTA !!! SE NAO TIVER UMA TABELA 0, APENAS 1...2, 
# A REGRA EH DESCARTADA, NAO CHEGA NO PACKET-IN EVENT !!
############################@ IMPORTANTE @#################################

lista_meter_ids=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540, 541, 542, 543, 544, 545, 546, 547, 548, 549, 550, 551, 552, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564, 565, 566, 567, 568, 569, 570, 571, 572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 586, 587, 588, 589, 590, 591, 592, 593, 594, 595, 596, 597, 598, 599, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 614, 615, 616, 617, 618, 619, 620, 621, 622, 623, 624, 625, 626, 627, 628, 629, 630, 631, 632, 633, 634, 635, 636, 637, 638, 639, 640, 641, 642, 643, 644, 645, 646, 647, 648, 649, 650, 651, 652, 653, 654, 655, 656, 657, 658, 659, 660, 661, 662, 663, 664, 665, 666, 667, 668, 669, 670, 671, 672, 673, 674, 675, 676, 677, 678, 679, 680, 681, 682, 683, 684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 694, 695, 696, 697, 698, 699, 700, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712, 713, 714, 715, 716, 717, 718, 719, 720, 721, 722, 723, 724, 725, 726, 727, 728, 729, 730, 731, 732, 733, 734, 735, 736, 737, 738, 739, 740, 741, 742, 743, 744, 745, 746, 747, 748, 749, 750, 751, 752, 753, 754, 755, 756, 757, 758, 759, 760, 761, 762, 763, 764, 765, 766, 767, 768, 769, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 786, 787, 788, 789, 790, 791, 792, 793, 794, 795, 796, 797, 798, 799, 800, 801, 802, 803, 804, 805, 806, 807, 808, 809, 810, 811, 812, 813, 814, 815, 816, 817, 818, 819, 820, 821, 822, 823, 824, 825, 826, 827, 828, 829, 830, 831, 832, 833, 834, 835, 836, 837, 838, 839, 840, 841, 842, 843, 844, 845, 846, 847, 848, 849, 850, 851, 852, 853, 854, 855, 856, 857, 858, 859, 860, 861, 862, 863, 864, 865, 866, 867, 868, 869, 870, 871, 872, 873, 874, 875, 876, 877, 878, 879, 880, 881, 882, 883, 884, 885, 886, 887, 888, 889, 890, 891, 892, 893, 894, 895, 896, 897, 898, 899, 900, 901, 902, 903, 904, 905, 906, 907, 908, 909, 910, 911, 912, 913, 914, 915, 916, 917, 918, 919, 920, 921, 922, 923, 924, 925, 926, 927, 928, 929, 930, 931, 932, 933, 934, 935, 936, 937, 938, 939, 940, 941, 942, 943, 944, 945, 946, 947, 948, 949, 950, 951, 952, 953, 954, 955, 956, 957, 958, 959, 960, 961, 962, 963, 964, 965, 966, 967, 968, 969, 970, 971, 972, 973, 974, 975, 976, 977, 978, 979, 980, 981, 982, 983, 984, 985, 986, 987, 988, 989, 990, 991, 992, 993, 994, 995, 996, 997, 998, 999]

# lista_meter_ids=[1]

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

def add_flow(datapath, priority, match, actions, table_id, buffer_id=None, idle_timeout=0):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    mod=None
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    if buffer_id:
        mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,priority=priority, match=match, instructions=inst, table_id=table_id)#, table_id = FORWARD_TABLE)
    else:
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,match=match, instructions=inst, table_id=table_id, idle_timeout = idle_timeout)#, table_id = FORWARD_TABLE)
    datapath.send_msg(mod)

def del_flow(datapath, dicionario_parametros):
    # ex: dicionario_parametros={"eth_type"=0x0800 (ipv4), "ip_proto"=6 (tcp), "tcp_src"=1000 (tcp src port) }
    
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    
    match:OFPMatch = parser.OFPMatch(**dicionario_parametros)

    mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, match=match, table_id=0, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
    print(datapath.send_msg(mod))

########### Testando ############

# def add_classification_table(datapath):
#     parser = datapath.ofproto_parser
#     inst = [parser.OFPInstructionGotoTable(FORWARD_TABLE)]
#     mod = parser.OFPFlowMod(datapath=datapath, table_id=CLASSIFICATION_TABLE, instructions=inst, priority=0) #criando a regra default
#     datapath.send_msg(mod)

def add_default_rule(datapath):
    #[FORWARD] regra default -> enviar para o controlador
    parser = datapath.ofproto_parser
    ofproto = datapath.ofproto
    match = parser.OFPMatch()
    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                      ofproto.OFPCML_NO_BUFFER)]
    add_flow(datapath, 0, match, actions, 0)

def add_forward_table(datapath, actions, prioridade):
    parser = datapath.ofproto_parser
    inst = [parser.OFPInstructionGotoTable(0)]
    mod = None
    if actions == None:
        mod = parser.OFPFlowMod(datapath=datapath, table_id=0,priority=prioridade, instructions=inst)
    else:
        mod = parser.OFPFlowMod(datapath=datapath, table_id=0,priority=prioridade, instructions=inst, actions=actions)
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

#Injetar pacote no controlador com instrucoes - serve para injetar pacotes que foram encaminhado por packet_in (se nao eles sao perdidos)
def injetarPacote(datapath, fila:int, out_port:int, packet, buffer_id=OFP_NO_BUFFER, qos_mark=None, ip_ver=2048):
    """Obs essa funcao nao marca o pacote, a marcacao precisa acontecer no pacote antes de enviar"""
    datapath = datapath
    parser = datapath.ofproto_parser
    actions = [parser.OFPActionSetQueue(fila), parser.OFPActionOutput(out_port)] 
    if qos_mark:
        if ip_ver == IPV4_CODE:
            actions.append(parser.OFPActionSetField(ip_dscp=qos_mark))
        else:
            actions.append(parser.OFPActionSetField(ipv6_flabel=qos_mark))
    out = datapath.ofproto_parser.OFPPacketOut(
        datapath=datapath,
        buffer_id=buffer_id,
        in_port=100,
        actions=actions,
        data=packet.data)
    print("[inj-pkt] fila:%d porta:%d marcar:%d" %(fila, out_port, qos_mark if qos_mark else 0))
    datapath.send_msg(out)

def add_conjunction(switch, ip_ver:int, port_name:int, tipo:int, clause_number:int, n_clauses:int, idd:int): # conjunction 
    """ As conjuncoes (regra que tem conjunction nas acoes) e o cabeçalho da conjuncao (a que tem conjunction no match),
    precisam ter a mesma prioridade, ou não funcionam e sao tratadas como conjunções diferentes"""
    # Como usar conjunctions:
    # a regra conjunction possui a descricao da conjunção na acao e os valores do conjunto são colocados no match, como outra regra qualquer.
    # cada regra conjunction possui um valor do conjunto, e então a descrição da conjunção diz quantas clausulas devem ser avaliadas,a ordem de analise e o id da conjunction.
    # não se pode ter ações de encaminhamento, mas pode ter de remarcação

    # ENTão, numa regra de encaminhamento, se pode ter match com apenas uma conjunction (pelo que entendi e pelo que se pode fazer)
    # porem, como as conjunctions podem ter varias ações (varios campos de match com varios valores, que se combinam como OU), pode se montar 
    # diversas listas de valores para os campos de match, apenas utilizando os ids e numero de clausula.

    # Obs: no match, o primeiro campo deve ser conj_id (de outra forma não funcionou, talvez eu tenha errado, mas para garantir, sempre siga assim)

    match_dict = {}
    if tipo == TCP_SRC:
        match_dict = {"eth_type":ip_ver, "ip_proto":TCP, "tcp_src":port_name}
    elif tipo == TCP_DST:
        match_dict = {"eth_type":ip_ver, "ip_proto":TCP, "tcp_dst":port_name}
    elif tipo == UDP_SRC:
        match_dict = {"eth_type":ip_ver, "ip_proto":UDP, "udp_src":port_name}
    else: # tipo == UDP_DST
        match_dict = {"eth_type":ip_ver, "ip_proto":UDP, "udp_dst":port_name}

    print("criando conjunction: ", match_dict)
    switch.saveConjunction(port_name=port_name, tipo=tipo)

    clause_number-=1 # O RYU INCREMENTA 1 NESSE VALOR SOZINHO, ENTAO PARA CORRIGIR, VAMOS DECREMENTAR 1

    datapath=switch.datapath
    parser=datapath.ofproto_parser
    actions = [parser.NXActionConjunction(clause=clause_number, n_clauses=n_clauses,id_=idd)]
    matchh = parser.OFPMatch(**match_dict)
    # matchh.set_tcp_src()
    add_flow(datapath=datapath,priority=CONJUNCTION_PRIO,match=matchh,actions=actions, table_id=FORWARD_TABLE, idle_timeout=BE_HARD_TIMEOUT)
    return

def del_conjunction(switch, ip_ver:int, port_name:int, tipo:int)->bool:

    removido = switch.delConjunctionByCount(port_name, tipo)

    if not removido: # tem mais fluxos usando, mas o conjunction count foi decrementado e numa proxima pode ser removido
        return False
    matchh = {}

    if tipo == TCP_SRC:
        matchh = {"eth_type":ip_ver, "ip_proto":TCP, "tcp_src":port_name}
    elif tipo == TCP_DST:
        matchh = {"eth_type":ip_ver, "ip_proto":TCP, "tcp_dst":port_name}
    elif tipo == UDP_SRC:
        matchh = {"eth_type":ip_ver, "ip_proto":TCP, "udp_src":port_name}
    else: # tipo == UDP_DST
        matchh = {"eth_type":ip_ver, "ip_proto":TCP, "udp_dst":port_name}

    del_flow(switch.datapath, matchh)
    return True

def desligar_regra_monitoramento(switch, ip_ver:int, ip_src:str, ip_dst:str, out_port:int, src_port:int, dst_port:int, proto:int):
    # atualizar regra no switch, para que ela pare de enviar copias de pacotes ao controlador e sem marcacao de pacotes
    regra_salva = switch.getPorta(out_port).getRegra(ip_ver=ip_ver, proto=proto, ip_src=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port)
    if regra_salva == None:
        print("ERRO em addRegraMonitoring: "+ ip_src+"_"+ip_dst)
        return False
    meter_id = regra_salva.meter_id

    regra_salva.monitorando = True # tem que ser true, para bater no flowremoved e excluir as regras,na proxima vez
    if meter_id == -1 or meter_id == None:
        print("erro ao recuperar regra meter para o fluxo")
        meter_id=None

    print("Desligando Monitoring para %s:%d -> %s:%d fila:%d qos_mark:%d meter: %s"  %(ip_src, src_port, ip_dst, dst_port, regra_salva.fila, regra_salva.qos_mark, str(meter_id) if meter_id else 'NDA'))

    addRegraForwarding2(datapath=switch.datapath,ip_ver=ip_ver, proto=proto, ip_src=ip_src, prioridade=MONITORING_PRIO, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, out_port=out_port,fila=regra_salva.fila, qos_mark_matching=None, qos_mark_action=regra_salva.qos_mark, meter_id=meter_id,idle_timeout=MONITORING_TIMEOUT_ACTION,hard_timeout=MONITORING_TIMEOUT_ACTION,flow_removed=True, toController=False) 
    return True

def addRegraMonitoring(switch, ip_ver:int, ip_src:str, ip_dst:str, out_port:int, src_port:int, dst_port:int, proto:int, fila, qos_mark_matching=None, qos_mark_action=None, meter_id=None, flow_removed=False): # meter_id no caso de o switch ser o primeiro e ultimo salto
    #igual a addRegraForwarding -> diferenca timeouts 2s (realizar o monitoramento a cada 2s) e action para o controlador ou não
    # Essa nao precisa retornar quando expirar

    addRegraForwarding2(datapath=switch.datapath,ip_ver=ip_ver, proto=proto, ip_src=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, out_port=out_port,fila=fila, qos_mark_matching=qos_mark_matching, qos_mark_action=qos_mark_action,idle_timeout=MONITORING_TIMEOUT_ACTION, prioridade=MONITORING_PRIO, meter_id=meter_id, hard_timeout=MONITORING_TIMEOUT_ACTION, flow_removed=False, toController=True)

    return True

def delRegraForwarding_com_Conjunction(switch, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_saida:int, qos_match:int):
    """remover a regra do switch antes"""
    """Aqui se remove a conjunction, do switch, e da instancia, mas nao a regra de encaminhamento da instancia"""
    """Retorna True se removeu a conjunction e a regra de encaminhamento """
    # tentar remover o conjunction (par src port e dst_port)
    # [TESTE] del_conjunction(switch=switch, ip_ver=ip_ver, port_name=src_port, tipo=TCP_SRC if proto == TCP else UDP_SRC) # pode ser aqui o problema
    # [TESTE] del_conjunction(switch=switch, ip_ver=ip_ver, port_name=dst_port, tipo=TCP_DST if proto == UDP else UDP_DST)
    
    # se removeu o par:
    ## verificar se mais alguma regra ativa com ip_src e ip_dst
    ## se nao tiver, remover a regra ip_src ip_dst qos_mark
    # ip_ver:int, proto:int, ip_src:str, ip_dst:str, src_port:int,dst_port:int
    if switch.getPorta(porta_saida).getRegra_com_QoSMark(ip_ver,proto,ip_src,ip_dst,src_port,dst_port,qos_match) == None:
        dict_matching = {"eth_type":IPV6_CODE, "ipv6_src":ip_src, 'ipv6_dst':ip_dst} # nao fiz para ipv6
        if ip_ver == IPV4_CODE:
            dict_matching = {"eth_type":ip_ver, "ipv4_src":ip_src, 'ipv4_dst':ip_dst, 'ip_dscp':qos_match}
        
        del_flow(switch.datapath,dict_matching)
        return True

    return False

# regras agrupadas, não usar meter !!
def addRegraForwarding_com_Conjunction(switch, ip_ver:int, ip_src:str, ip_dst:str, out_port:int, src_port:int, dst_port:int, proto:int, fila:int, qos_mark_maching:int, idle_timeout:int, hard_timeout:int, flow_removed=False, prioridade:int=10, toController:bool=False):
    """ As conjuncoes (regra que tem conjunction nas acoes) e o cabeçalho da conjuncao (a que tem conjunction no match),
    precisam ter a mesma prioridade, ou não funcionam e sao tratadas como conjunções diferentes"""
    # switches backbone ou que nao sao o primeiro da rota de borda devem usar essa regra, para agrupar os fluxos e encaminhar os fluxos marcados com qos ou com monitoramento (sim sao 2 regras por fluxo de qos)
    # ou o ultimo switch da rota de borda precisa ter a regra para remarcar os fluxos com qos para monitoring... ( continua sendo duas regras)

    # se precisar recuperar o buffer_id = msg.buffer_id

    # como setar corretamente os campos de match (linha 1352): https://github.com/faucetsdn/ryu/blob/master/ryu/ofproto/ofproto_v1_3_parser.py
    datapath = switch.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    
    dicionario_parametros = {}

    add_conjunction(switch=switch, ip_ver=ip_ver, port_name=src_port, tipo=TCP_SRC if proto == TCP else UDP_SRC, clause_number=1,n_clauses=2,idd=CONJUNCTION_ID)
    add_conjunction(switch=switch, ip_ver=ip_ver, port_name=dst_port, tipo=TCP_DST if proto == TCP else UDP_DST, clause_number=2,n_clauses=2,idd=CONJUNCTION_ID)
 # dicionario_parametros = {'conj_id':10, 'eth_type':2048}
    dicionario_parametros = {}
    dicionario_parametros['conj_id'] = CONJUNCTION_ID
    dicionario_parametros['eth_type'] = ip_ver
    # dicionario_parametros['ip_proto'] = proto # se der erro na criacao das  conjunction eh aqui -> descomentar
    if ip_ver == IPV4_CODE:
        dicionario_parametros['ipv4_src'] = ip_src
        dicionario_parametros['ipv4_dst'] = ip_dst
    elif ip_ver == IPV6_CODE:
        dicionario_parametros['ipv6_src'] = ip_src
        dicionario_parametros['ipv6_dst'] = ip_dst
    if qos_mark_maching != NO_QOS_MARK and qos_mark_maching !=None: # testando funcionamento das conjunctions
        if ip_ver == IPV4_CODE:
            dicionario_parametros['ip_dscp'] = qos_mark_maching
        elif ip_ver == IPV6_CODE:
            dicionario_parametros['ipv6_flabel'] = qos_mark_maching
    # match = parser.OFPMatch(conj_id=10, eth_type=2048) # esse funciona
    match = parser.OFPMatch(**dicionario_parametros)

    print('params:', match)
    actions = []
    # if qos_mark_action != NO_QOS_MARK:
    #     if ip_ver == IPV4_CODE:
    #         actions.append(parser.OFPActionSetField(ip_dscp=qos_mark_action))
    #     elif ip_ver == IPV6_CODE:
    #         actions.append(parser.OFPActionSetField(ipv6_flabel=qos_mark_action))
    actions.append(parser.OFPActionSetQueue(fila))
    actions.append(parser.OFPActionOutput(out_port))

    if toController:
       actions.append(parser.OFPActionOutput(ofproto.OFPP_CONTROLLER))

    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    
    print("[addRegraConj] match:", dicionario_parametros, ' ; actions{qos_match:', qos_mark_maching, ', fila:', fila,', outport:',out_port)
    
    # #marcar para gerar o evento FlowRemoved
    if flow_removed:
        mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idle_timeout, hard_timeout= hard_timeout, priority=CONJUNCTION_PRIO, match=match, instructions=inst, table_id=0, flags=ofproto.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(mod)
        return
    
    mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idle_timeout, hard_timeout= hard_timeout, priority=CONJUNCTION_PRIO, match=match, instructions=inst, table_id=0)
    datapath.send_msg(mod)

# 

def addRegraForwarding2(datapath, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, out_port:int, fila:int, idle_timeout:int, hard_timeout:int, prioridade:int, qos_mark_action=None, qos_mark_matching=None, meter_id=None, flow_removed=False, toController=False):
    parser = datapath.ofproto_parser
    ofproto = datapath.ofproto
    mathing_dict = {'eth_type':ip_ver, 'ip_proto':proto}
    actionss=[]
    
    if ip_ver == 2048: 
        mathing_dict['ipv4_src'] = ip_src
        mathing_dict['ipv4_dst'] = ip_dst
        if qos_mark_action:
            actionss.append(parser.OFPActionSetField(ip_dscp=qos_mark_action))
        if qos_mark_matching != -1 and qos_mark_matching != None:
            mathing_dict['ip_dscp'] = qos_mark_matching
    else:
        mathing_dict['ipv6_src'] = ip_src
        mathing_dict['ipv6_dst'] = ip_dst
        if qos_mark_action:
            actionss.append(parser.OFPActionSetField(ipv6_flabel=qos_mark_action))
        if qos_mark_matching !=-1 and qos_mark_matching !=None:
            mathing_dict['ipv6_flabel'] = qos_mark_matching
    if proto == TCP:
        mathing_dict['ip_proto'] = TCP
        mathing_dict['tcp_src'] = src_port
        mathing_dict['tcp_dst'] = dst_port
    else:
        mathing_dict['ip_proto'] = UDP
        mathing_dict['udp_src'] = src_port
        mathing_dict['udp_dst'] = dst_port
    matchh =parser.OFPMatch(**mathing_dict)
    actionss.append(parser.OFPActionSetQueue(fila))
    actionss.append(parser.OFPActionOutput(out_port))
    if toController:
        actionss.append(parser.OFPActionOutput(ofproto.OFPP_CONTROLLER))
    inst = []
    if meter_id:
        # inst.append(parser.OFPInstructionMeter(meter_id=meter_id)) # ou é um ou é o outro...
        inst.append(parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER))
     
    inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actionss))

    mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idle_timeout, hard_timeout=hard_timeout, priority=prioridade, match=matchh, instructions=inst, table_id=0)
    if flow_removed:
        mod = parser.OFPFlowMod(datapath=datapath, idle_timeout =idle_timeout, hard_timeout=hard_timeout, priority=prioridade, match=matchh, instructions=inst, table_id=0, flags=ofproto.OFPFF_SEND_FLOW_REM)
    # self.add_flow(datapath=datapath, priority=10, match=matchh, actions=actionss,table_id=0)
    print("[addForw2] match:", mathing_dict, ' ; actions{qos_mark', qos_mark_action, ', qos_match:', qos_mark_matching, ', fila:', fila,', outport:',out_port, '; meter_id', meter_id)
    if datapath.send_msg(mod):
        print("[addF2] OK")
    else:
        print("[addF2] Fail")
    return 

def delRegraForwarding(switch, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, qos_match=None):
    # como setar corretamente os campos de match (linha 1352): https://github.com/faucetsdn/ryu/blob/master/ryu/ofproto/ofproto_v1_3_parser.py
    datapath = switch.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    
    dicionario_parametros = {}

    dicionario_parametros['eth_type'] = ip_ver
    dicionario_parametros['ip_proto'] = proto

    if ip_ver == IPV4_CODE:
        dicionario_parametros['ipv4_src'] = ip_src
        dicionario_parametros['ipv4_dst'] = ip_dst
        if qos_match:
            dicionario_parametros['ip_dscp'] = qos_match
    else:
        dicionario_parametros['ipv6_src'] = ip_src
        dicionario_parametros['ipv6_dst'] = ip_dst
        if qos_match:
            dicionario_parametros['ipv6_flabel'] = qos_match

    if proto == TCP:
        if src_port != -1:
            dicionario_parametros['tcp_src'] = src_port
        if dst_port != -1:
            dicionario_parametros['tcp_dst'] = dst_port
    elif proto == UDP:
        if src_port != -1:
            dicionario_parametros['udp_src'] = src_port
        if dst_port != -1:
            dicionario_parametros['udp_dst'] = dst_port

     
    match:OFPMatch = parser.OFPMatch(**dicionario_parametros)

    mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, match=match, out_port=ofproto.OFPP_ANY,table_id=0, out_group=ofproto.OFPG_ANY)
    datapath.send_msg(mod)
    return

def generateMeterId(switch):
    """Obs id das meter precisam ser > 0"""    
    return lista_meter_ids.pop(0)

def getMeterID_from_Flow(meter_dict, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, qos_match:int):
    meter_id = NO_METER
    try:
        meter_id = meter_dict[str(ip_ver)+ip_src+ip_dst+str(src_port)+str(dst_port)+str(proto)+str(qos_match)]
    except:
        return NO_METER

    return meter_id

def saveMeterID_from_Flow(meter_dict, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, meter_id:int):
    meter_dict[str(ip_ver)+ip_src+ip_dst+str(src_port)+str(dst_port)+str(proto)] = meter_id
    return

def delMeter(switch, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int):
    # essas funcoes deveriam estar em switch. ....
    try:
        del switch.meter_dict[str(ip_ver)+ip_src+ip_dst+str(src_port)+str(dst_port)+str(proto)]
    except:
        print("[delMeter]Meter rule nao encontrada..")
    return

 #criando regra meter
def addRegraMeter(switch, banda):
    """Obs ids das meter precisa ser > 1"""
    meter_id = generateMeterId(switch)

    if meter_id == None:
        print("[addRegraM] meter id missing")
        return
    
    print("[addRegraM] Nova meter ", meter_id)
    # if meter_id == None:
    #     meter_id = generateMeterId(switch)

    datapath = switch.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    #criando meter bands
    bands = [parser.OFPMeterBandDrop(type_=ofproto.OFPMBT_DROP, len_=0, rate=banda, burst_size=100)]#e esse burst_size ajustar?
    req = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS, meter_id=meter_id, bands=bands)
    if not datapath.send_msg(req):
        print("Erro ao criar regra meter id: %d" % (meter_id))
    return meter_id


def delRegraMeter(switch, meter_id):
    if meter_id == None or meter_id == -1:
        print("sem meter")
        return
    print("del meter id: %d"%(meter_id))
    datapath = switch.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    
    req = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_DELETE, meter_id=meter_id)
    datapath.send_msg(req)
    return


def tratador_delRegras(controller, regras_json):

    for regra in regras_json:

        nome_switch = regras_json['nome_switch']
        switch_obj = None
    
        #encontrar o switch
        switch_obj= controller.getSwitchByName(nome_switch)
        
        if switch_obj == None:
            print("[serv_del_regra] Verifique o nome do switch (nao encontrado)!!")
            #tentar a proxima regra
            continue

        ip_ver = regra['ip_ver']
        ip_src = regra['ip_src']
        ip_dst = regra['ip_dst']
        src_port = regra['src_port']
        dst_port = regra['dst_port']
        proto = regra['proto']
        porta_saida = regra['porta_saida']
        porta_entrada = regra['porta_entrada']
        # qos_mark = regra['qos_mark']
        meter_id = regra['meter_id']
        switch_borda = regra['switch_borda'] #bool

        if meter_id != NO_METER: # qos 
            delRegraMeter(meter_id)
            delMeter(controller, ip_ver, ip_src, ip_dst, src_port, dst_port, proto)
        switch_obj.getPorta(porta_saida).delRegra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto)
        switch_obj.getPorta(porta_entrada).delRegra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto)
        if switch_borda:
            delRegraForwarding(controller, ip_ver, ip_src, ip_dst, src_port, dst_port, proto)
        else:
            delRegraForwarding_com_Conjunction(switch_obj, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida)
    return



def tratador_addRegras(controller, novasregras_json):
    """[{'nome_switch':1, },{}]"""
    for regra in novasregras_json:

        print(regra)

        nome_switch = regra['nome_switch']
        switch_obj = None
        
        #encontrar o switch
        switch_obj = controller.getSwitchByName(nome_switch)

        if switch_obj == None:
            print("Regra falhou!!")
            #tentar a proxima regra
            continue

        ip_ver = regra['ip_ver']
        ip_src = regra['ip_src']
        ip_dst = regra['ip_dst']
        porta_saida = regra['porta_saida']
        porta_entrada = regra['porta_entrada']
        src_port = regra['src_port']
        dst_port = regra['dst_port']
        proto = regra['proto']
        #isso vai ser modificado outro momento
        classe = regra['classe']
        prioridade = regra['prioridade']
        banda = regra['banda']
        application_class = regra['application_class']
        emprestando = regra['emprestando'] # true or false
        criar_meter = regra['criar_meter'] # true or false
        tipo_switch = regra['tipo_switch'] # ver fp_switch
        meter_id = NO_METER
        if criar_meter:
            meter_id = criar_meter

        # passando por cima do GBAM, nao vai rodar o GBAM
        Acao(switch_obj, porta_saida, Regra.CRIAR, Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, meter_id, banda, prioridade, classe, getQueueId(classe, prioridade), application_class, getQOSMark(classe, prioridade), {}, emprestando), PORTA_ENTRADA, tipo_switch).executar()
        Acao(switch_obj, porta_saida, Regra.CRIAR, Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, meter_id, banda, prioridade, classe, getQueueId(classe, prioridade), application_class, getQOSMark(classe, prioridade), {}, emprestando), PORTA_SAIDA, tipo_switch).executar()

    return None


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




####################### EXPLICAÇÂO CONJUNCTIONS #########################
    # #ref para implementar com o ryu corretamente https://github.com/faucetsdn/ryu/blob/master/ryu/ofproto/nicira_ext.py
    # formato esperado
    # pelo visto precisa configurar como um campo experimental, o matching com conjunctions
    # "OFPMatch": {
    #     "length": 12, 
    #     "oxm_fields": [
    #        {
    #           "OXMTlv": {
    #              "field": "conj_id", 
    #              "mask": null, 
    #              "value": 11259375
    #           }
    #        }
    #     ], 
    # aparentemente todos os match fields são tradados como oxm fields, e os nicira_ext(conjunctions), sao concatenados com os oxm_fields (ver ryu/ryu/ofproto/ofproto_v1_3.py)
    # só adicionar o conj_id em OFMAtch(conj_id=id)

    
#add regra tabela CLASSIFICATION
#se o destino for um ip de controlador, 
# def addRegraClassification(switch, ip_ver:int ,ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, qos_mark:int, idle_timeout:int, hard_timeout:int, prioridade:int=10):
#     """  ADD regra monitoring
#     parametros:
#     ip_ver: int
#     ip_src: str
#     ip_dst: str
#     src_port: int
#     dst_port: int
#     proto: int
#     ip_dscp: int
#     """
#     #https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#flow-instruction-structures
#      #criar regra na tabela de marcacao - obs - utilizar idletime para que a regra suma - serve para que em switches que nao sao de borda essa regra nao exista
#                      #obs: cada switch passa por um processo de enviar um packet_in para o controlador quando um fluxo novo chega,assim, com o mecanismo de GBAM, pode ser que pacotes de determinados fluxos sejam marcados com TOS diferentes da classe original, devido ao emprestimo, assim, em cada switch o pacote pode ter uma marcacao - mas com essa regra abaixo, os switches que possuem marcacao diferentes vao manter a regra de remarcacao. Caso ela expire e cheguem novos pacotes, ocorrera novo packet in e o controlador ira executar um novo GBAM - que vai criar uma nova regra de marcacao
#     #print("[criando-regra-tabela-marcacao] ipsrc: %s, ipdst: %s, tos: %d\n" % (ip_src, ip_dst, ip_dscp))
#     datapath = switch.datapath
#     ofproto = datapath.ofproto
#     parser = datapath.ofproto_parser

#     actions = []

#     dicionario_parametros = {}

#     dicionario_parametros['eth_type'] = ip_ver
#     dicionario_parametros['ip_proto'] = proto

#     if ip_ver == IPV4_CODE:
#         dicionario_parametros['ipv4_src'] = ip_src
#         dicionario_parametros['ipv4_dst'] = ip_dst
#         if qos_mark != NO_QOS_MARK:
#             actions.append(parser.OFPActionSetField(ip_dscp=qos_mark))
#     elif ip_ver == IPV6_CODE:
#         dicionario_parametros['ipv6_src'] = ip_src
#         dicionario_parametros['ipv6_dst'] = ip_dst

#         if qos_mark != NO_QOS_MARK:
#             actions.append(parser.OFPActionSetField(ipv6_flabel=qos_mark))

#     if proto == in_proto.IPPROTO_TCP:
#         if src_port != -1:
#             dicionario_parametros['tcp_src'] = src_port
#         if dst_port != -1:
#             dicionario_parametros['tcp_dst'] = dst_port
#     elif proto == in_proto.IPPROTO_UDP:
#         if src_port != -1:
#             dicionario_parametros['udp_src'] = src_port
#         if dst_port != -1:
#             dicionario_parametros['udp_dst'] = dst_port

#     match:OFPMatch = parser.OFPMatch(**dicionario_parametros)

#     inst = [parser.OFPInstructionGotoTable(FORWARD_TABLE), parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
#     mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idle_timeout, hard_timeout = hard_timeout, priority=prioridade, match=match, instructions=inst, table_id=CLASSIFICATION_TABLE)
#     datapath.send_msg(mod)

#add regra tabela FORWARD
# def addRegraForwarding(switch, ip_ver:int, ip_src:str, ip_dst:str, out_port:int, src_port:int, dst_port:int, proto:int, fila:int, meter_id:int, qos_mark_maching:int, idle_timeout:int, hard_timeout:int, qos_mark_action:int=NO_QOS_MARK, prioridade:int=10,  flow_removed:bool=True, toController:bool=False):
#     # apenas primeiro switch da roda do dominio de origem devem usar essa regra, para marcar com qos e usar a meter
#     print("addForw-init")
#     # como setar corretamente os campos de match (linha 1352): https://github.com/faucetsdn/ryu/blob/master/ryu/ofproto/ofproto_v1_3_parser.py
#     datapath = switch.datapath
#     ofproto = datapath.ofproto
#     parser = datapath.ofproto_parser
    
#     dicionario_parametros = {}

#     dicionario_parametros['eth_type'] = ip_ver
#     dicionario_parametros['ip_proto'] = proto
    
#     if ip_ver == IPV4_CODE:
#         dicionario_parametros['ipv4_src'] = ip_src
#         dicionario_parametros['ipv4_dst'] = ip_dst
#     elif ip_ver == IPV6_CODE:
#         dicionario_parametros['ipv6_src'] = ip_src
#         dicionario_parametros['ipv6_dst'] = ip_dst

#     if proto == in_proto.IPPROTO_TCP:
#         if src_port != -1:
#             dicionario_parametros['tcp_src'] = src_port
#         if dst_port != -1:
#             dicionario_parametros['tcp_dst'] = dst_port
#     elif proto == in_proto.IPPROTO_UDP:
#         if src_port != -1:
#             dicionario_parametros['udp_src'] = src_port
#         if dst_port != -1:
#             dicionario_parametros['udp_dst'] = dst_port
    
#     if qos_mark_maching != NO_QOS_MARK:
#         if ip_ver == IPV4_CODE:
#             dicionario_parametros['ip_dscp'] = qos_mark_maching
#         elif ip_ver == IPV6_CODE:
#             dicionario_parametros['ipv6_flabel'] = qos_mark_maching

#     #https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#flow-instruction-structures
#     # hardtimeout = 5 segundos # isso eh para evitar problemas com pacotes que sao marcados como best-effort por um contrato nao ter chego a tempo. Assim vou garantir que daqui 5s o controlador possa identifica-lo. PROBLEMA: fluxos geralmente nao duram 5s, mas eh uma abordagem.
    
#     #Para que a regra emita um evento de flow removed, ela precisa carregar uma flag, adicionada no OFPFlowMod
#     #flags=ofproto.OFPFF_SEND_FLOW_REM
      
#     #tratamento especial para este tipo de trafego
#     match:OFPMatch = parser.OFPMatch(**dicionario_parametros)
    
#     actions = []
#     if qos_mark_action != NO_QOS_MARK:
#         if ip_ver == IPV4_CODE:
#             actions.append(parser.OFPActionSetField(ip_dscp=qos_mark_action))
#         elif ip_ver == IPV6_CODE:
#             actions.append(parser.OFPActionSetField(ipv6_flabel=qos_mark_action))

#     actions.append(parser.OFPActionSetQueue(fila))
#     actions.append(parser.OFPActionOutput(out_port))

#     if toController:
#         actions.append(parser.OFPActionOutput(ofproto.OFPP_CONTROLLER))

#     inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] # essa instrucao eh necessaria?

#     if meter_id != NO_METER:
#         # inst.append(parser.OFPInstructionMeter(meter_id=meter_id)) # ou é um ou é o outro...
#         inst.append(parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER))
    
#     mod = None
#     #marcar para gerar o evento FlowRemoved
#     if flow_removed:
#         mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idle_timeout, hard_timeout= hard_timeout, priority=prioridade, match=match, instructions=inst, table_id=FORWARD_TABLE, flags=ofproto.OFPFF_SEND_FLOW_REM)
#     else:
#         mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idle_timeout, hard_timeout= hard_timeout, priority=prioridade, match=match, instructions=inst, table_id=FORWARD_TABLE)
#     print("addForw:", match, inst)
#     print(datapath.send_msg(mod))
#     print("addFow-end")
