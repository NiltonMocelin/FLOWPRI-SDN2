from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ofproto_v1_3, inet, ether
from ryu.lib.packet import ipv4, arp, icmp, udp, tcp, lldp, ipv6, dhcp, icmpv6

from fp_constants import FILA_CONTROLE, PORTA_MANAGEMENT_HOST_SERVER, IPCc

import fp_fred

import json

from fp_utils import get_rota,send_fred_socket, remove_qos_rules, create_qos_rules, remover_fred, salvar_fred
from fp_utils import getSwitchByName

# from fp_api_qosblockchain import get_blockchain, criar_blockchain

from fp_utils import souDominioBorda, check_domain_hosts

from traffic_monitoring.fp_flow_monitoring import Register, FlowMonitoring, loadFlowMonitoringFromJson

from traffic_monitoring.fp_monitoring import fazer_calculo_qos

from fp_api_qosblockchain import criar_chave_sawadm
from main_controller import create_qos_rules

from fp_api_qosblockchain import enviar_transacao_blockchain


def rejeitar_fred(fred, in_switch_id):
    switches_rota = get_rota(fred.ip_dst, fred.ip_src, fred.ip_ver, fred.dst_port, fred.src_port, fred.proto, in_switch_id)
    if switches_rota == None:
        print("Nao há rotas configuradas para o destino %s " % (fred.ip_dst))
        return False

    for s in switches_rota:
        getSwitchByName(switches_rota[-1].switch_name)
        remove_qos_rules(fred)

    send_icmpv6()

    return


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


def tratador_icmp_flow_monitoring(flow_monitoring:FlowMonitoring):
    
    # verificar se sou borda ou backbone
    if souDominioBorda(flow_monitoring.ip_ver, flow_monitoring.ip_src, flow_monitoring.ip_dst):

        # tem monitoramento -> comparar com meu monitoramento -> criar 
        qos = fazer_calculo_qos(flow_monitoring)
        
        # criar transacao na blockchain
        enviar_transacao_blockchain({}) # se existir a blockchain -> se nao existir emitir erro
    
    # dar sequencia no icmp
    return

def tratador_icmp_fred(fred:fp_fred.Fred):

    # verificar se sou borda ou backbone
    if souDominioBorda(fred.ip_ver, fred.ip_src, fred.ip_dst):

        # tem fred -> criar regras qos para borda -> criar blockchain se nao existir (rotina blockchain)
        if create_qos_rules({}): # modo borda
            rotina_blockchain() # cria se nao existe, preenche os campos do fred

    else:
        create_qos_rules({}) # modo borda

    # salvar ou atualizar fred no dicionario
    salvar_fred(fred)
    return 


def handle_icmps(pkt_icmpv6, mac_src, mac_dst, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, in_switch_id):
    
    # verificar o conteudo do icmp
    fred_icmp = None
    monitoramento_icmp = None

    if "FRED" in pkt_icmpv6.data:
        fred_icmp = fp_fred.fromJsonToFred(json.loads(pkt_icmpv6.data))
        
    if "Monitoring" in pkt_icmpv6.data:
        flow_monitoring = loadFlowMonitoringFromJson(json.loads(pkt_icmpv6.data))   

    # verificar o tipo do icmp
    if pkt_icmpv6.type_ == icmpv6.ICMPV6_NI_QUERY:
        tratador_icmp_fred(fred_icmp, monitoramento_icmp, ip_ver, ip_src, ip_dst)
        tratador_icmp_flow_monitoring(fred_icmp, monitoramento_icmp, ip_ver, ip_src, ip_dst)

    elif pkt_icmpv6.type_ == icmpv6.ICMPV6_NI_REPLY:
        tratar_icmp_rejeicao(fred_icmp, monitoramento_icmp, ip_ver, ip_src, ip_dst)

    return 

def handle_icmpv6(pkt_icmpv6, mac_src, mac_dst, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, in_switch_id):
    #print("\n Recebeu Pacote ICMP: \n")

    # icmpv6.ICMPV6_NI_QUERY == anuncio de FRED
    if pkt_icmpv6.type_ == icmpv6.ICMPV6_NI_QUERY:

        # aqui pode ser duas coisas: anuncio fred ou flow monitoring
        fred = tratador_icmp_fred(pkt_icmpv6, in_switch_id)
        flow_monitoring = tratador_icmp_flow_monitoring(pkt_icmpv6, in_switch_id)

        # modificar fred                
        minha_chave_publica, minha_chave_privada = criar_chave_sawadm()
    
         # verificar se sou um controlador de borda -> sou um par da blockchain
        if souDominioBorda(ip_ver, ip_src, ip_dst):
            
            if fred == None:
                print("ICMPv6 %d incorreto" % (icmpv6.ICMPV6_NI_QUERY))
                return False

            ip_blockchain, port_blockchain = "",""# get_blockchain(ip_dst)

            fred.lista_peers.append({"nome_peer":IPCc, "chave_publica":minha_chave_publica, "ip_porta":"%s:%s" % (ip_blockchain,str(port_blockchain))})

            # apenas o nó genesis (host origem do primeiro fluxo entre os dois dominios de borda)
            # é quem cria a transação -> pois só após ele subir a blockchain com o bloco genesis é que os pares podem enviar transações.
        
            if ip_blockchain == None:
               ip_blockchain, port_blockchain= "",""#criar_blockchain()

            create_qos_rules({}) # modo borda

        else: # nao sou dominio de borda
            
            # criar regras G-BAM backbone             
            fred.lista_rota.append({"ordem": str(ordem), "nome_peer": IPCc, "chave_publica": minha_chave_publica, "saltos": len(switches_rota)})
            
            create_qos_rules({}) # modo backbone
            return

        if fred == None:
            print("ICMPv6 %d incorreto" % (icmpv6.ICMPV6_NI_QUERY))
            return False

        ordem = len(fred.lista_peers) 
        fred.lista_rota.append({"ordem": str(ordem), "nome_peer": IPCc, "chave_publica": minha_chave_publica, "saltos": len(switches_rota)})


        # salvar fred
        fp_fred.salvar_novo_fred(fred)

        switch_final_rota_dp = getSwitchByName(switches_rota[-1].switch_name).datapath
        switch_final_rota_out_port = switches_rota[-1].out_port

        # enviar fred para frente
        # send_icmpv6(fred)

        # se eu sou um controlador da borda destino, o host aceita fred via socket apenas
        if check_domain_hosts(ip_dst):
            send_fred_socket(fred, ip_dst, PORTA_MANAGEMENT_HOST_SERVER)
        else:
            send_icmpv6(switch_final_rota_dp, mac_src, ip_src, mac_dst, ip_dst, switch_final_rota_out_port, fred)

        # criar as regras de qos conforme o fred
        if not create_qos_rules(ip_src, ip_dst, ip_ver, src_port, dst_port, proto, fred, in_switch_id):
            
            """fred rejeitado"""
            rejeitar_fred()
            return

    # FRED rejeitado
    if pkt_icmpv6.type_ == icmpv6.ICMPV6_NI_REPLY:
        print("fred rejeitado...")

        # remover regras do fred
        remove_qos_rules(fred)

        # remover fred da lista de freds
        remover_fred(fred)

        switches_rota = get_rota(fred.ip_dst, fred.ip_src, fred.ip_ver, fred.dst_port, fred.src_port, fred.proto, in_switch_id)
        if switches_rota == None:
            print("Nao há rotas configuradas para o destino %s " % (ip_dst))
            return False
        
        switch_final_rota_dp = getSwitchByName(switches_rota[-1].switch_name).datapath
        switch_final_rota_out_port = switches_rota[-1].out_port

        # enviar icmpv6 para a origem, informando que foi rejeitado
        send_icmpv6(switch_final_rota_dp, mac_dst, ip_dst, mac_src, ip_src, switch_final_rota_out_port, fred)


def tratador_icmpv4_monitoring(pkt_icmpv4, in_switch_id):
    return

def handle_icmpv4(pkt_icmpv4, mac_src, mac_dst, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, in_switch_id):
    #print("\n Recebeu Pacote ICMP: \n")

    INFORMATION_REQUEST = 15
    INFORMATION_REPLY = 16

    # icmpv6.ICMPV6_NI_QUERY == anuncio de FRED
    if pkt_icmpv4.type == INFORMATION_REQUEST:
        fred = tratador_icmp_fred(pkt_icmpv4, in_switch_id)

        if fred == None:
            
            

            return False

        # modificar fred                
        minha_chave_publica = ''
        switches_rota = get_rota(fred.ip_src, fred.ip_dst, fred.ip_ver, fred.src_port, fred.dst_port, fred.proto, in_switch_id)
        if switches_rota == None:
            print("Nao há rotas configuradas para o destino %s " % (ip_dst))
            return False
        
        ordem = len(fred.lista_peers) 
        fred.lista_rota.append({"ordem": str(ordem), "nome_peer": "controllerXX", "chave_publica": minha_chave_publica, "saltos": len(switches_rota)})

         # verificar se sou um controlador de borda -> sou um par da blockchain
        if check_domain_hosts(ip_src) == True or check_domain_hosts(ip_dst) == True:
            ip_blockchain, port_blockchain = "","" #get_blockchain(ip_dst)

            fred.lista_peers.append({"nome_peer":"controllerX", "chave_publica":minha_chave_publica, "ip_porta":"%s:%s" % (ip_blockchain,str(port_blockchain))})

            # apenas o nó genesis (host origem do primeiro fluxo entre os dois dominios de borda)
            # é quem cria a transação -> pois só após ele subir a blockchain com o bloco genesis é que os pares podem enviar transações.

            if ip_blockchain == None:
               ip_blockchain, port_blockchain= "",""#criar_blockchain()


        # salvar fred
        fp_fred.salvar_novo_fred(fred)

        switch_final_rota_dp = getSwitchByName(switches_rota[-1].switch_name).datapath
        switch_final_rota_out_port = switches_rota[-1].out_port

        # enviar fred para frente
        # send_icmpv6(fred)

        # se eu sou um controlador da borda destino, o host aceita fred via socket apenas
        if check_domain_hosts(ip_dst):
            send_fred_socket(fred, ip_dst, PORTA_MANAGEMENT_HOST_SERVER)
        else:
            send_icmpv6(switch_final_rota_dp, mac_src, ip_src, mac_dst, ip_dst, switch_final_rota_out_port, fred)

        # criar as regras de qos conforme o fred
        if not create_qos_rules(ip_src, ip_dst, ip_ver, src_port, dst_port, proto, fred, in_switch_id):
            
            """fred rejeitado"""
            rejeitar_fred()
            return

    # FRED rejeitado
    if pkt_icmpv4.type_ == INFORMATION_REPLY:
        fred = tratador_icmpv4_fred(pkt_icmpv4, in_switch_id)

        print("fred rejeitado...")

        # remover regras do fred
        remove_qos_rules(fred)

        # remover fred da lista de freds
        remover_fred(fred)

        switches_rota = get_rota(fred.ip_dst, fred.ip_src, fred.ip_ver, fred.dst_port, fred.src_port, fred.proto, in_switch_id)
        if switches_rota == None:
            print("Nao há rotas configuradas para o destino %s " % (ip_dst))
            return False
        
        switch_final_rota_dp = getSwitchByName(switches_rota[-1].switch_name).datapath
        switch_final_rota_out_port = switches_rota[-1].out_port

        # enviar icmpv6 para a origem, informando que foi rejeitado
        send_icmpv4(switch_final_rota_dp, mac_dst, ip_dst, mac_src, ip_src, switch_final_rota_out_port, fred)
