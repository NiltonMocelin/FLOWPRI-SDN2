### USAR PYTHON 3 !!

# importar o tratador da interface web
import sys, os

# # Add the parent directory to sys.path
sys.path.append( os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/wsgiWebSocket")

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
 
# importacoes de dependecias de refatoracao de codigo
from fp_constants import CPT
from fp_constants import PORTAC_ICMP15, PORTAC_ICMP16, SC_REAL
from fp_constants import SC_CONTROL
from fp_constants import IPC, MACC, PORTAC_C, CRIAR, CPF
from fp_constants import FORWARD_TABLE, ALL_TABLES

#codigos das acoes
from fp_constants import REMOVER, CRIAR

from fp_constants import switches, freds, controladores_conhecidos, controller_singleton, rotas_ipv4, rotas_ipv6

from fp_constants import dhcp_msg_type_code

from fp_rota import Rota

# try:
from fp_switch import SwitchOVS
# except ImportError:
#     print('Erro de importacao da classe SwitchOVS')

from fp_server import servidor_socket_controladores,servidor_socket_hosts,servidor_configuracoes, enviar_contratos

from fp_acao import Acao
from fp_regra import Regra

from fp_contrato import Contrato

from fp_openflow_rules import add_classification_table, add_default_rule, send_icmpv4, send_icmpv6

from fp_utils import get_ipv4_header, get_eth_header, get_ipv6_header, get_tcp_header, get_udp_header

print('importando fp_topo_discovery')
#descoberta de topologia
from fp_topology_discovery import handler_switch_enter, handler_switch_leave
print('importando fp_dhcp')
#tratador DHCPv4
from fp_dhcp import handle_dhcp_discovery, handle_dhcp_request, handle_dhcp, mac_to_client_ip

print('importando interface_web')
# import wsgiWebSocket.interface_web as iwb
from interface_web import lancar_wsgi #, _websocket_rcv, _websocket_snd, dados_json


#################
#   INICIANDO SOCKET - RECEBER CONTRATOS (hosts e controladores)
################

t1 = Thread(target=servidor_socket_hosts)
t1.start()

t2 = Thread(target=servidor_socket_controladores)
t2.start()

t3 = Thread(target=servidor_configuracoes)
t3.start()

## iniciar o servidor web aqui
t4 = Thread(target=lancar_wsgi)
t4.start()

#t1.join()


def addControladorConhecido(ipnovo):
    #print]("Verificando se ja conhece o controlador: %s \n" %(ipnovo))
    if checkControladorConhecido(ipnovo) == 1:
        #print]("controlador ja conhecido\n")
        return

    controladores_conhecidos.append(ipnovo)
    #print]("novo controlador conhecido\n")

def checkControladorConhecido(ip):
    for i in controladores_conhecidos:
        if i == ip:
            #conhecido
            return 1
    #desconhecido
    return 0

class Dinamico(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        print("CONTROLADOR %s - \n Init Start\n" % (IPC))
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
       
        if ip_src == None or ip_dst == None or tos == None:
            #print("Algo deu errado - ip ou tos nao reconhecido\n")
            return 1

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
        pkt_icmp = pkt.get_protocol(icmp.icmp)

        if not pkt_eth:
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

        este_switch.addMac(eth_src, in_port)
        
        este_switch.addHost(ipv4_src, in_port)

        #aprender endereco MAC, evitar flood proxima vez
        self.mac_to_port[dpid][eth_src] = in_port
        #adaptar essa parte depois, aqui so se quer saber se eh conhecida a porta destino para
        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            out_port = None

        #tratador dhcp
        dhcpPkt = pkt.get_protocol(dhcp.dhcp)
        if dhcpPkt:
            handle_dhcp(dhcpPkt, dp, in_port)

        if pkt_icmp:
            #print("\n Recebeu Pacote ICMP: \n")

            if pkt_icmp.type == 15: #request information -> enviar um information reply
                
                print("[%s] tratamento ICMP 15 \n" % (datetime.datetime.now().time()))

                addControladorConhecido(ipv4_src)

                #verificar se ja tenho o contrato e enviar o tos que tenho, caso for o mesmo tos que ja recebi, nao vou receber resposta
                data_json = json.loads(pkt_icmp.data)

                cip_ver = data_json['ip_ver']
                cip_src = data_json['ip_src']
                cip_dst = data_json['ip_dst']
                csrc_port = data_json['src_port']
                cdst_port = data_json['dst_port']
                cproto = data_json(pkt_icmp.data)['proto']
                # cip_dst = ip_dst
                cdscp = -1

                ##***************************************#
                #procurando  nos contratos o dscp
                contrato = buscarFred(ip_ver=cip_ver, ip_src=cip_src, ip_dst=cip_dst, src_port=csrc_port, dst_port=cdst_port, proto=cproto)

                if contrato == None:
                    print("[icmp-15] Falhou - contrato nao identificado para a quintupla ip_ver: %s; ip_src: %s; ip_dst: %s; src_port: %s; dst_port: %s; proto: %s" % (cip_ver, cip_src, cip_dst, csrc_port, csrc_port, cproto))
                    #ignorar ou responder vazio?
                    return
                cdscp = CPT[(contrato.classe , contrato.prioridade, contrato.banda)]
                
                data = {"ip_ver": cip_ver, "ip_dst":cip_dst, "ip_src":cip_src, "src_port": csrc_port, "dst_port": cdst_port, "proto": cproto,"dscp":cdscp, "banda":contrato.banda, "prioridade": contrato.prioridade, "classe": contrato.classe}
                data = json.dumps(data)#.encode()
                #print("[ICMP-15] contrato desejado:%s\n" % (data))  

                switches_rota = self.getRota(str(dpid), IPC)
                switches_rota[-1].addRegraC(ip_ver=ip_ver, ip_src=IPC, ip_dst=ip_src, src_port=PORTAC_ICMP15, dst_port=PORTAC_ICMP15, proto='icmp-15', ip_dscp= 61)
                for s in switches_rota:
                    #porta de saida
                    out_port = s.getPortaSaida(ip_src)
                                                                                                                                                            
                    s.alocarGBAM(ip_ver=ip_ver, ip_src=IPC, ip_dst = ip_src, src_port = PORTAC_ICMP15, dst_port = PORTAC_ICMP15, proto = 'icmp-15', porta_saida = out_port, banda = '1000', prioridade = str(2), classe = str(SC_CONTROL))


                switches_rota = self.getRota(str(dpid), ip_dst)
                
                #obter o switch mais da borda de destino e gerar o inf req para dar sequencia e descobrir novos controladores ate o host destino
                switch_ultimo = switches_rota[-1]
                out_port = switch_ultimo.getPortaSaida(ip_dst)

                switch_ultimo_dp = switch_ultimo.getDP()
                #print("[ICMP-15] Dando sequencia no icmp 15 criando no ultimo switch da rota \n src:%s, dst:%s, saida:%d\n", ip_src, ip_dst, out_port)
                send_icmpv4(switch_ultimo_dp, eth_src, ip_src, eth_dst, ip_dst,out_port,0,pkt_icmp.data,1,15,64)

                # logging.info('[Packet_In] fim icmp 15  - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))
                print("[%s] tratamento ICMP 15 - fim \n" % (datetime.datetime.now().time()))

                return 
                
    ############################
    #### OUTRO CASO: RECEBI UM INF. REPLY: solicitando que envie os contratos referentes a um determinado host destino
    #### DOIS COMPORTAMENTOS: (i) sou o controlador destino ;; (ii) nao sou o controlador destino
    #### (i): criar as regras na rota entre controlador e destino (switches do dominio)- de marcacao no switch mais proximo do controlador e de encaminhamento nos demais
    #### (ii): criar as regras nos switches entre ip_src e ip_dst para receber os contratos que virao em da direcao ip_dst->ip_src :: - de marcacao no switch mais proxima do controlador destino (ip_dst) - de encaminhamento nos demais
    ############################
            #pkt: responder o arp caso seja para o endereco do controlador-> information reply (enviar os contratos para este controlador)
            if pkt_icmp.type==16:

                #print("[ICMP-16] Recebido\n")
                addControladorConhecido(ip_src)

                ##print("ICMP Information Reply -> Received\n")
                ## somente enviar os contratos caso o controlador seja o destino do icmp, caso contrario, apenas criar as regras de marcacao e encaminhamento + injetar o icmp no switch mais da borda proxima do destino
                switches_rota = self.getRota(str(dpid), ip_src)
                switch_ultimo = switches_rota[-1] ## pegando o ultimo switch da rota
                switch_primeiro = switches_rota[0]

        ###### (i) sou o controlador de destino
                if ip_dst == IPC:
                    
                    print("[%s] tratamento ICMP 16 - controlador destino \n" % (datetime.datetime.now().time()))
                    #enviar os contratos correspondentes para o controlador que respondeu utilizando socket
                    #print("[ICMP-16] Enviar os contratos para: ip_dst %s; mac_dst %s; ip_src e mac_src -> host root\n" % (ip_src,src))

                    dados = json.loads(pkt_icmp.data)
                    cip_ver = dados['ip_ver']
                    cip_src = dados['ip_src']
                    cip_dst = dados['ip_dst']
                    csrc_port = dados['src_port']
                    cdst_port = dados['dst_port']
                    cproto = dados['proto']
                    cdscp = dados['dscp']

                    
                    #procurando  nos contratos o dscp
                    buscar_contratos = buscarContrato(ip_ver=cip_ver, ip_src=cip_src, ip_dst=cip_dst, src_port=csrc_port, dst_port=cdst_port, proto=cproto)

                    if buscar_contratos == None:
                        return

                    #verificar se o tos recebido no icmp 16 eh o mesmo que o tos do contrato que seria enviado, se for, ignorar esse icmp, o controlador que respondeu ja possui o contrato atualizado
                    cb_dscp = CPT[(buscar_contratos.classe, buscar_contratos.prioridade, buscar_contratos.banda)]
                    if cdscp == cb_dscp:
                        return
                          
                      #se o contrato foi encontrato e eh diferente, nao precisa testar com os outros contratos

                    ### criar regras para encaminhar as respostas do ICMP 15 atraves dos switches da rota para o dominio do controlador emissor original e para o controlador enviar os contratos
    #criar regras de marcacao e encaminhamento: switch de borda (switch_ultimo)
    #criar regras de encaminhamento: switches da rota
               
                    #ip_dst = controlador emissor do icmp 15
                    #ip_src = controlador enviando icmp 16
                    #tos = 29 - fila de controle

                    #o ip do host destino final, deve estar nos dados do pacote ICMP = nao implementado ainda
                    #ip_host_destino = msg.data

                    #criar a regra de encaminhamento + marcacao --- para enviar os contratos
                    #regra de marcacao - apenas no switch que esta conectado ao controlador
                    #primeiro switch == switch conectado ao controlador - alterado para TC[ip_src]
                    switch_primeiro.addRegraC(ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto, ip_dscp = 61)

                    #out_port = switch_primeiro.getPortaSaida(ip_src)

                    #criar regras de encaminhamento de contratos nos switches da rota 
                    for s in switches_rota:
                        out_port = s.getPortaSaida(ip_src)
                        s.alocarGBAM(ip_ver=ip_ver, ip_src =ip_src, ip_dst= ip_dst, src_port=src_port, dst_port=dst_port, proto=proto, porta_saida=out_port, banda='1000', prioridade='2', classe='4') #criando as regras - alterado para tc[ip_src]

                    #criando a volta tbm pq precisa estabelecer a conexao
                    

                    #enviar_contratos(host_ip, host_port, ip_dst_contrato)
                    # - host_ip e host_port (controlador que envia)
                    # - ip_dst_contrato #ip do host destino (deve estar nos dados do pacote icmp 16 recebido
                        # def enviar_contratos(ip_ver, ip_dst, dst_port, contrato_obj):
                    Thread(target=enviar_contratos, args=(ip_ver, ip_src, PORTAC_C, buscar_contratos)).start()

                    # logging.info('[Packet_In] icmp 16 - controlador destino - fim - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))
                    print("[%s] tratamento ICMP 16 - controlador destino - fim \n" % (datetime.datetime.now().time()))

                    return 0

          ###### (ii) esse controlador nao eh o controlador destino - logo criar as regras de marcacao e encaminhamento para passar os contratos
                #os contratos virao do controlador destino -> controlador origem de icmp 16
                #switches_rota == switches da rota(destino, origem), logo precisa marcar no primeiro switch apenas

                print("[%s] tratamento ICMP 16 - controlador da rota:\n" % (datetime.datetime.now().time()))
                
                switch_primeiro.addRegraC(ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto, ip_dscp=61)
                
                #print("[ICMP-16] criando regras de encaminhamento de contratos entre src:%s, dst:%s\n" % (ip_dst, ip_src))

                #demais switches: regras de encaminhamento - ida
                for i in switches_rota:
                    out_port = i.getPortaSaida(ip_src) # obtendo a porta que leva a enviar os contratos ao controlador requisitante
                    i.alocarGBAM(ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto, porta_saida=out_port, banda='1000', prioridade='2', classe='4') #alocando-criando as regras de encaminhamento

                #criar a volta tbm, pq eh tcp [ultimo switch] e como nao sao pacotes para o controlador desse dominio, nao ha reggras pre-definidas para o encaminhamento
                switches_rota[-1].addRegraC(ip_src, ip_dst, 61)
                for i in switches_rota:
                    out_port = i.getPortaSaida(ip_dst) # obtendo a porta que leva a enviar os contratos ao controlador requisitante
                    i.alocarGBAM(ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, porta_saida=out_port, banda='1000', prioridade='2', classe='4') #alocando-criando as regras de encaminhamento

                #reinjetar o icmp no switch mais da borda proxima do destino
                #print("[ICMP-16] recriando icmp 16 no switch mais proximo src:%s dst:%s out:%s:%d\n" % (ip_src, ip_dst, switch_primeiro.nome, out_port))
                out_port = switch_primeiro.getPortaSaida(ip_dst)
                send_icmpv4(switch_primeiro.datapath, eth_src, ip_src, eth_dst, ip_dst, out_port, 0,pkt_icmp.data,1,16,64)

                # logging.info('[Packet_In] icmp 16 - nao destino - fim - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))
                print("[%s]  tratamento ICMP 16 - controlador da rota - fim \n" % (datetime.datetime.now().time()))

                return
        
        #######         Buscar correspondencia Pkt-in com contratos         ############
        #print("---------------------------------\n")
        #print("procurando match com contratos\n")
        # (1) identificar se o pacote tem match com algum contrato
        contrato_fluxo = buscarContrato(ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto)
        if contrato_fluxo != None:
            print("[%s] com match nos contratos :\n" % (datetime.datetime.now().time()))
                    
            #alocar o fluxo switch conforme seus requisitos - verificar em qual fila o fluxo deve ser posicionado
            #encontrar todos os switches da rota definida para este ip destino/rede + escolher um switch para enviar o ICMP inf. req. (que deve ser o que disparou o packet_in)
    
            switches_rota = self.getRota(str(dpid), ip_dst) #no momento os switches nao estao sendo adicionados em ordem, mas poderiam ser
            #verificar em qual fila da porta posicionar o fluxo
            banda = contrato_fluxo.banda
            prioridade =  contrato_fluxo.prioridade
            classe =  contrato_fluxo.classe
                    
            #1- Enviar ICMP inf req. (poderia usar o ultimo switch da rota, mas por agora estamos usando o primeiro, que dispara o packet_in)
            
            switches_rota = self.getRota(str(dpid), ip_dst)
            switch_ultimo = switches_rota[-1]

            #saber para qual porta deve ser encaminhado --- implementar isso
            out_port = switch_ultimo.getPortaSaida(ip_dst)
            switch_ultimo_dp = switch_ultimo.getDP()

            #teste echo request - se funcionar adaptar para o request information [ok]
            #deve ser enviado pelo switch mais proximo do destino (da borda) - se nao cada switch vai precisar tratar esse pacote
            #enviar os identificadores do contrato (v2: ip origem/destino sao os identificadores - origem vai em dados, destino vai no destino do icmp ) 
            data = {"ip_ver":ip_ver, "ip_src":ip_src, "ip_dst": ip_dst, "src_port": src_port, "dst_port": dst_port, "proto": proto, "banda":banda, "prioridade":prioridade, "classe":classe}
            data = json.dumps(data)
            
            send_icmpv4(switch_ultimo_dp, MACC, IPC, eth_dst, ip_dst, out_port, 0, data, 1, 15,64)
                          
            #print("[%s] icmp enviado enviado - ipdst=%s  portasaida=%d\n" % (switch_ultimo.nome,ip_dst,out_port))
            #print("---------------------------------\n")
                             
            #print("[%s] Criando regra tabela de marcacao no switch de borda (0) - toda regra vinda de outro dominio (borda) deve ser remarcada para valer nesse dominio\n" % (switches_rota[0].nome))
                             
            #adicionar a regra na classe switch
            #adicionar a regra na tabela do ovsswitch
            acoes = []

            #ANTES VERIFICAR SE A PORTA POSSUI FILA, se nao, nao adianta utilizar GBAM ## no caso todas as portas possuem filas, eu pensava que somente a porta 4 possuia, mas nao eh verdade
            #### criar as regras em cada switch da rota entre ip_src -> ip_dest
            #IDA -- em todos os switches da rota
            for i in range(len(switches_rota)):
                out_port = switches_rota[i].getPortaSaida(ip_dst)
                #obtendo o vetor de acoes
                
                acoes_aux = switches_rota[i].alocarGBAM(ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port= dst_port, proto=proto, porta_saida=out_port, banda=banda, prioridade= prioridade, classe=classe)

                #se algum dos switches nao puder alocar, rejeitar o fluxo
                #retorno vazio = nao tem espaco para alocar o fluxo
                if len(acoes_aux)==0:
                    #rejeitar o fluxo
                    #print("Fluxo rejeitado!\n")
                    return

                #adicionando as acoes
                for a in acoes_aux:
                    acoes.append(a)
                    
                #chegou ate aqui, entao todos os switches possuem espaco para alocar o fluxo
                #executar cada acao de criar/remover regras
                for a in acoes:
                    a.executar()

                #pegar o switch mais proximo do destino e injetar o pacote que gerou o packet_in
                out_port = switch_ultimo.getPortaSaida(ip_dst)
                #a ultima acao deve ser de criar a regra no ultimo switch da rota
                ultima_acao = acoes[len(acoes)-1]
                    
                fila = CPF[(ultima_acao.regra.classe, ultima_acao.regra.prioridade)]
                switch_ultimo.injetarPacote(switch_ultimo.datapath,fila, out_port, msg)

                #1 criar regra de marcacao/classificacao - switch mais da borda = que disparou o packet_in
                #encontrar qual tos foi definido para a criacao da regra no switch de borda mais proximo do emissor
                for a in acoes:
                    if(a.nome_switch == str(dpid) and a.codigo == CRIAR):
                        switches_rota[0].addRegraC(ip_ver = ip_ver, ip_src= ip_src,ip_dst= ip_dst, src_port=src_port, dst_port=dst_port, proto=proto, ip_dscp=a.regra.tos)
                        break
                    
                # logging.info('[Packet_In] pacote com match - fim - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))
                print("[%s] pkt_in fim \n" % (datetime.datetime.now().time()))
                return
				
	    #todos os contratos foram checados e nao foi achado correspondencia
        #fluxo nao identificado -> fila de best-effort
        #print("Fluxo nao identificado\n")
            
        print("[%s] sem match nos contratos \n" % (datetime.datetime.now().time()))

        #criar a regra de marcacao para este fluxo com o tos de best effort
        #criar regra para a fila de best-effort (match= {tos, ip_dst} = (meter band + fila=tos) + (porta_saida=ip_dst)
        #1- Encontrar os switches da rota
        switches_rota = self.getRota(str(dpid), ip_dst)
        dscp = 60 #best-effort
        classe = 3 #best-effort
        prioridade= 3#menor?

        #se o fluxo for desconhecido (por ter expirado alguma regra) e for de controladores - a classe deve ser classe de controle
        if checkControladorConhecido(ip_src) == 1 or checkControladorConhecido(ip_dst) == 1:
            dscp = 61 #controle
            classe = 4 #controle 

        #criar regra na tabela de classificacao do switch de borda - marcar como best-effort
        #a variavel este switch, pode ser um switch do meio do caminho que perdeu as regras de encaminhamento e gerou o packet_in
        #por isso, deve se usar o primeiro switch da rota para criar as regras, evitando que um switch do meio do caminho tenha regras de marcacao
        #assim, o switch do meio so tem as regras de encaminnhamento atualizadas
        switches_rota[0].addRegraC(ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto, ip_dscp = dscp)    

        for i in range(len(switches_rota)):        
            #criar em cada outro switch as regras de encaminhamento    
            #porta de saida
            out_port = switches_rota[i].getPortaSaida(ip_dst)
            #ida
            switches_rota[i].alocarGBAM(ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port = src_port, dst_port=dst_port, proto=proto, porta_saida=out_port, banda= '1000', prioridade=prioridade, classe= classe)

        #pegar o switch mais proximo do destino e injetar o pacote que gerou o packet_in
        switch_ultimo = switches_rota[-1]
        out_port = switch_ultimo.getPortaSaida(ip_dst)
        fila = CPF[(classe,1)]
        switch_ultimo.injetarPacote(switch_ultimo.datapath,fila, out_port, msg)

        # logging.info('[Packet_In] pacote sem match - fim - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))
        print("[%s] pkt_in fim \n" % (datetime.datetime.now().time()))

        return	 
                    