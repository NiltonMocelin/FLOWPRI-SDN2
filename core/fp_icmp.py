from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ofproto_v1_3, inet, ether
from ryu.lib.packet import ipv4, arp, icmp, udp, tcp, lldp, ipv6, dhcp, icmpv6

from fp_constants import FILA_CONTROLE, PORTA_MANAGEMENT_HOST_SERVER, IPV4_CODE, IPV6_CODE, IP_MANAGEMENT_HOST

from fp_fred import Fred, fromJsonToFred

import json

from fp_utils import current_milli_time, getQoSMark, enviar_msg

# from fp_api_qosblockchain import get_blockchain, criar_blockchain

from fp_utils import souDominioBorda, check_domain_hosts

from traffic_monitoring.monitoring_utils import MonitoringManager, FlowMonitoring, loadFlowMonitoringFromJson

from traffic_monitoring.monitoring_utils import tratar_flow_monitoring

from fp_api_qosblockchain import tratar_blockchain_setup, criar_chave_sawadm
# from main_controller import FLOWPRI2

from fp_switch import Switch

############# send_icmp TORNADO GLOBAL EM 06/10 - para ser aproveitado em server socket ###################
#https://ryu-devel.narkive.com/1CxrzoTs/create-icmp-pkt-in-the-controller
def send_icmpv4(datapath, srcMac, srcIp, dstMac, dstIp, outPort, seq, data, id=1, type=8, ttl=64):

    e = ethernet.ethernet(dst=dstMac, src=srcMac, ethertype=ether.ETH_TYPE_IP)

    iph = ipv4.ipv4(4, 5, 0, 0, 0, 2, 0, ttl, 1, 0, srcIp, dstIp)

    actions = [datapath.ofproto_parser.OFPActionSetQueue(FILA_CONTROLE), datapath.ofproto_parser.OFPActionOutput(outPort)] #no fim tem que ir na fila de controle

    icmph = icmp.icmp(type, 0, 0, data=data)#pode enviar os dados que quiser, mas tem que ser um vetor binario
        
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(iph)
    p.add_protocol(icmph)
    p.serialize()

    out = datapath.ofproto_parser.OFPPacketOut(
    datapath=datapath,
    buffer_id=datapath.ofproto.OFP_NO_BUFFER,
    in_port=100,
    actions=actions,
    data=p.data)

    datapath.send_msg(out)
    return 0

def send_icmpv6(datapath, srcMac, srcIp, dstMac, dstIp, outPort, data, type=8, ttl=64):

    e = ethernet.ethernet(dst=dstMac, src=srcMac, ethertype=ether.ETH_TYPE_IPV6)

    iph = ipv6.ipv6(version=6, traffic_class=0, flow_label=0, payload_length=0, nxt=inet.IPPROTO_TCP, hop_limit=255, src=srcIp, dst=dstIp)

    actions = [datapath.ofproto_parser.OFPActionSetQueue(FILA_CONTROLE), datapath.ofproto_parser.OFPActionOutput(outPort)] #no fim tem que ir na fila de controle

    icmph = icmpv6.icmpv6(type, 0, 0, data=data)#pode enviar os dados que quiser, mas tem que ser um vetor binario

    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(iph)
    p.add_protocol(icmph)
    p.serialize()

    out = datapath.ofproto_parser.OFPPacketOut(
    datapath=datapath,
    buffer_id=datapath.ofproto.OFP_NO_BUFFER,
    in_port=100,
    actions=actions,
    data=p.data)

    datapath.send_msg(out)
    return 0

def tratar_icmp_rejeicao(controller, fred_icmp:Fred, ip_ver, eth_src, ip_src, eth_dst, ip_dst):
    nohs_rota = controller.rotamanager.get_rota(fred_icmp.ip_src, fred_icmp.ip_dst)

    dominio_borda = False
    # Se eu sou borda origem E se for o ultimo switch da rota, atualizar regra de monitoramento
    if check_domain_hosts(ip_src):
        dominio_borda = True

    primeiro_switch = 0
    ultimo_switch = len(nohs_rota)
    
    # remover a regra que encaminha fluxo monitorado -- somente se nao tiver outro fluxo utilizando... == remover a regra da instancia, verificar se existe algum fluxo com mesmo ips e mesmo qos_mark, se nao tiver, remover a regra monitoramento e regra qos_mark agrupadas
    if dominio_borda:
        primeiro_switch+=1
        ultimo_switch-=1
        switchh_first_hop = controller.getSwitchByName(nohs_rota[primeiro_switch].switch_name)
        switchh_first_hop.delRegraQoS(switchh, ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=fred_icmp.src_port, dst_port=fred_icmp.dst_port, proto=fred_icmp.proto, porta_entrada=nohs_rota[i].in_port, porta_saida=nohs_rota[primeiro_switch].out_port, qos_mark=getQoSMark(fred_icmp.classe,fred_icmp.prioridade), tipo_switch=Switch.SWITCH_FIRST_HOP)
        switchh_last_hop = controller.getSwitchByName(nohs_rota[ultimo_switch].switch_name)
        switchh_last_hop.delRegraQoS(switchh, ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=fred_icmp.src_port, dst_port=fred_icmp.dst_port, proto=fred_icmp.proto, porta_entrada=nohs_rota[-1].in_port, porta_saida=nohs_rota[-1].out_port, qos_mark=getQoSMark(fred_icmp.classe,fred_icmp.prioridade), tipo_switch=Switch.SWITCH_LAST_HOP)
    for i in range(primeiro_switch, ultimo_switch):
        switchh = controller.getSwitchByName(nohs_rota[i].switch_name)
        switchh.delRegraQoS(switchh, ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=fred_icmp.src_port, dst_port=fred_icmp.dst_port, proto=fred_icmp.proto, porta_entrada=nohs_rota[i].in_port, porta_saida=nohs_rota[i].out_port, qos_mark=getQoSMark(fred_icmp.classe,fred_icmp.prioridade), tipo_switch=Switch.SWITCH_OUTRO)
        # remove_qos_rules(ip_ver=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto)

    # criar a regra best-effort
    controller.create_be_rules(fred_icmp.ip_src, fred_icmp.ip_dst, fred_icmp.ip_ver, fred_icmp.src_port, fred_icmp.dst_port, fred_icmp.proto)    
    # dar sequencia no icmp
    
    INFORMATION_REPLY = 16
    # enviar fred rejeitando fluxo, apenas para trás <-, nao precisa enviar para frente tbm
    # Fazer a rejeicao de fred
    if fred_icmp.ip_ver == IPV4_CODE:# ips trocados para devolver o icmp
        send_icmpv4(controller.getSwitchByName(nohs_rota[0].switch_name).datapath, eth_dst, ip_dst, eth_src, ip_src,  nohs_rota[0].in_port, 0, fred_icmp.toString(),type=INFORMATION_REPLY)
    else: 
        send_icmpv6(controller.getSwitchByName(nohs_rota[0].switch_name).datapath, eth_dst, ip_dst, eth_src, ip_src,  nohs_rota[0].in_port, fred_icmp.toString(), icmpv6.ICMPV6_NI_REPLY)

    return

def tratador_icmp_flow_monitoring(controller, flow_monitoring:FlowMonitoring):
    tratar_flow_monitoring(flow_monitoring, controller.qosblockchainmanager, controller.fredmanager, controller.flowmonitoringmanager)

    # dar sequencia no icmp - na verdade aqui envia o flowmonitoring via socket para o host management
    enviar_msg(flow_monitoring.toString(), IP_MANAGEMENT_HOST, PORTA_MANAGEMENT_HOST_SERVER)
    return

def tratador_icmp_fred(controller, fred:Fred, eth_src, ip_src, eth_dst, ip_dst):
    """ eu sou dominio de borda de destino -> devo tratar o fred e enviar via socket para o meu host_management"""
    INFORMATION_REPLY = 16
    # todos os switches aqui sao tratados como switches backbone
    # verificar se sou borda ou backbone
    nohs_rota = controller.rotamanager.get_rota(fred.ip_src, fred.ip_dst)
    minha_chave_publica,minha_chave_privada = criar_chave_sawadm()
    fred.addNoh(controller.IPCv4, minha_chave_publica, len(nohs_rota))

    if nohs_rota == None:
        print('[trat_meu-domin] erro: sem rotas para %s -> %s'%(fred.ip_src,fred.ip_dst))
        return
        
    controller.fredmanager.save_fred(fred.getName(), fred)
    if controller.create_qos_rules(fred.ip_src, fred.ip_dst, fred.ip_ver, fred.src_port, fred.dst_port, fred.proto, fred, False):
        print("Regras criadas")
        if souDominioBorda(fred.ip_ver, fred.ip_src, fred.ip_dst):        
            # salvar ou atualizar fred no dicionario
            controller.fredmanager.save_fred(fred.getName(),fred) # apenas os dominios participantes da blockchain salvam o fred ? (acho que sim)
            porta_blockchain = controller.qosblockchainmanager.get_blockchain(fred.ip_src, fred.ip_dst)
            # criar blockchain ? -- so se ja nao existir uma blockchain para esse destino
            if porta_blockchain == None:
                if fred.ip_ver == IPV4_CODE:
                    porta_blockchain=tratar_blockchain_setup(controller.IPCv4, fred, controller.qosblockchainmanager)
                    fred.addPeer(controller.IPCv4, minha_chave_publica, controller.IPCv4+':'+str(porta_blockchain))
                else: #ip_ver == IPV6_CODE
                    porta_blockchain=tratar_blockchain_setup(controller.IPCv6, fred, controller.qosblockchainmanager)
                    fred.addPeer(controller.IPCv6, minha_chave_publica, controller.IPCv6+':'+str(porta_blockchain))
            else:
                if fred.ip_ver == IPV4_CODE:
                    fred.addPeer(controller.IPCv4, minha_chave_publica, controller.IPCv4+':'+str(porta_blockchain))
                    # send_icmpv4(datapath=controller.getSwitchByName(nohs_rota[-1].switch_name).datapath, srcMac=eth_src,dstMac=eth_dst, srcIp=ip_src, dstIp=ip_dst, outPort=nohs_rota[-1].out_port,seq=0, data=fred.toString())
                    enviar_msg(fred.toString(), IP_MANAGEMENT_HOST, PORTA_MANAGEMENT_HOST_SERVER)
                else:
                    fred.addPeer(controller.IPCv6, minha_chave_publica, controller.IPCv6+':'+str(porta_blockchain))
                    # send_icmpv6(datapath=self.getSwitchByName(nohs_rota[-1].switch_name).datapath, srcMac=eth_src, srcIp=ip_src,dstMac=eth_dst,dstIp=ip_dst,outPort=nohs_rota[-1].out_port,data=fred.toString())
                    enviar_msg(fred.toString(), IP_MANAGEMENT_HOST, PORTA_MANAGEMENT_HOST_SERVER)
    else:# so para deixar organizado
        controller.create_be_rules(fred.ip_src, fred.ip_dst, fred.ip_ver, fred.src_port, fred.dst_port, fred.proto)    
        # enviar fred rejeitando fluxo, apenas para trás <-, nao precisa enviar para frente tbm
        # Fazer a rejeicao de fred
        if fred.ip_ver == IPV4_CODE:# ips trocados para devolver o icmp
            send_icmpv4(controller.getSwitchByName(nohs_rota[0].switch_name).datapath, eth_dst, ip_dst, eth_src, ip_src,  nohs_rota[0].in_port, 0, fred.toString(),type=INFORMATION_REPLY)
        else: 
            send_icmpv6(controller.getSwitchByName(nohs_rota[0].switch_name).datapath, eth_dst, ip_dst, eth_src, ip_src,  nohs_rota[0].in_port, fred.toString(), icmpv6.ICMPV6_NI_REPLY)

    print("[tratador_icmp_fred] fim "+ current_milli_time())
    return 

def handle_icmps(pkt_icmp, tipo_icmp, ip_ver, eth_src, ip_src, eth_dst, ip_dst):
    
    # verificar o conteudo do icmp
    fred_icmp = None
    monitoramento_icmp = None
    INFORMATION_REQUEST = 15
    INFORMATION_REPLY = 16

    if "FRED" in pkt_icmp.data:
        fred_icmp = fromJsonToFred(json.loads(pkt_icmp.data))
        
    if "Monitoring" in pkt_icmp.data:
        flow_monitoring = loadFlowMonitoringFromJson(json.loads(pkt_icmp.data))   
    # verificar o tipo do icmp
    if tipo_icmp == icmpv6.ICMPV6_NI_QUERY or tipo_icmp == INFORMATION_REQUEST:
        if fred_icmp:
            tratador_icmp_fred(fred_icmp, eth_src, ip_src, eth_dst, ip_dst)
        if flow_monitoring:
            tratador_icmp_flow_monitoring(flow_monitoring)

    elif tipo_icmp == icmpv6.ICMPV6_NI_REPLY or tipo_icmp == INFORMATION_REPLY:
        if fred_icmp:
            tratar_icmp_rejeicao(fred_icmp, ip_ver, eth_src, ip_src, eth_dst, ip_dst)

    return 