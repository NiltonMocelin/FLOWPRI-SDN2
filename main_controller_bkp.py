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

#para invocar scripts e comandos tc qdisc
import subprocess

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
from fp_constants import CPT, ALL_TABLES, FILA_CONTROLE
from fp_constants import PORTAC_ICMP15, PORTAC_ICMP16, SC_REAL
from fp_constants import SC_NONREAL, SC_BEST_EFFORT, SC_CONTROL
from fp_constants import IPC, MACC, PORTAC_C, CRIAR, CPF
from fp_constants import CLASSIFICATION_TABLE, FORWARD_TABLE, ALL_TABLES

#codigos das acoes
from fp_constants import REMOVER, CRIAR, EMPRESTANDO, NAOEMPRESTANDO

from fp_constants import switches, contratos, controladores_conhecidos, controller_singleton

from fp_constants import dhcp_msg_type_code

# try:
from fp_switch import SwitchOVS
# except ImportError:
#     print('Erro de importacao da classe SwitchOVS')

from fp_server import servidor_socket_controladores,servidor_socket_hosts,tratador_configuracoes, enviar_contratos

from fp_acao import Acao
from fp_regra import Regra

from fp_contrato import Contrato
print('importando fp_topo_discovery')
#descoberta de topologia
from fp_topology_discovery import handler_switch_enter, handler_switch_leave
print('importando fp_dhcp')
#tratador DHCPv4
from fp_dhcp import handle_dhcp_discovery, handle_dhcp_request, mac_to_client_ip
print('importando interface_web')
# import wsgiWebSocket.interface_web as iwb
from interface_web import lancar_wsgi #, _websocket_rcv, _websocket_snd, dados_json


def getController():
    return controller_singleton

def buscarContratoId(id):
    for i in contratos:
        if i.id == id:
            return i
        
    return None

def buscarContrato(ip_ver, ip_src, ip_dst, src_port, dst_port, proto):
    """ Parametros
    ip_ver: str
    ip_src: str
    ip_dst: str
    src_port: str
    dst_port: str
    proto: str
    """
    for i in contratos:
        if i.ip_ver == ip_ver and i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
            return i
        
    return None

def buscarConflitoContrato(contrato):
    """ Parametros
    contrato: Contrato
    """
    
    contratos_conflitantes = []
    contratos_conflitantes.append(contrato)

    for i in contratos:
        if i.ip_src == contrato.ip_src and i.ip_dst == contrato.ip_dst and i.src_port == contrato.src_port and i.dst_port == contrato.dst_port and i.proto == contrato.proto:
            if i.ip_ver != contrato.ip_ver or i.proto != contrato.proto or i.banda != contrato.banda or i.prioridade != contrato.prioridade or i.classe != contrato.classe:
                contratos_conflitantes.append(i) 
        
    return contratos_conflitantes

#remove um contrato e as regras associadas a ele nos switches da rota entre ip_src, ip_dst
def delContratoERegras(switches_rota, contrato):
    """ Parametros
    switches_rota: List
    contrato: Contrato
    """

    ##checar se ja existe um contrato e remover --- isso ocorre antes de adicionar o novo contrato, por isso consigo pegar o contrato antigo
    
    contratos_conflitantes = buscarConflitoContrato(contrato)

    if len(contratos_conflitantes) < 2:
        print("[delContratosRegras] Nada a fazer!")
        return

    #quero manter apenas o novo - entao o removo da lista
    contratos_conflitantes.pop(0)

    for i in contratos_conflitantes:

        #contrato exatamente igual ao que estamos incluindo ?
        # if i.ip_src==contrato.ip_src and i.ip_dst==contrato.ip_dst and i.src_port==contrato.src_port and i.dst_port==contrato.dst_port and i.proto==contrato.proto and contrato.banda == i.banda and contrato.classe == i.classe and contrato.prioridade == i.prioridade:
        # contratos.remove(i)

        for s in switches_rota:
            out_port = s.getPortaSaida(i.ip_dst) #inteiro
            porta = s.getPorta(out_port)
            
            #deletando a regra referente ao contrato antigo - pq nao vale mais, ele foi removido
            #se a regra estava ativa, ela sera removida dos switches tbm
            Acao(s,porta,REMOVER, Regra(i.ip_ver, i.ip_src,i.ip_dst,i.src_port, i.dst_port, 
                                                                i.proto, out_port,i.dscp, i.banda, i.prioridade,
                                                                i.classe, 0)).executar()

            contratos.remove(i)
 
            return


def tratador_addSwitch(addswitch_json):

    print("Adicionando configuracao de switch")
    for i in addswitch_json:
        print(i)

        nome_switch = i['nome']
        datapath = i['datapath']
        qtdPortas = i['qtdPortas']

        switch = None
        
        #procurando o switch
        for i in switches:
            if str(i.nome) == str(nome_switch):
                switch = i

        #encontrar o switch pelo nome
        #criar as portas conforme a configuracao do json
        if(switch == None):
            print("Switch S%s, nao encontrado no dominio - configuracao rejeitada\n" % str(nome_switch))
            continue
        
        print("mostrando portas \n")
        # print(i['portas'])

        for porta in i['portas']:
            print (porta)

            nome_porta = porta['nome']
            largura_porta = porta['larguraBanda']
            prox_porta = porta['proxSwitch']

            switch.addPorta(nome_porta, int(largura_porta), int(prox_porta))

            interface = "s" + str(nome_switch) + "-eth"+ str(nome_porta)
###
            #criar as novas filas
            lbandatotal = int(largura_porta)
            #classe tempo-real ids=[0,1,2]
            lbandaclasse1 = int(lbandatotal * 0.33)
            #classe nao-tempo-real/dados ids=[3,4,5]
            lbandaclasse2 = int(lbandatotal * 0.35)
            #classe best-effort id = 6
            lbandaclasse3 = int(lbandatotal * 0.25)
            #classe controle id = 7
            lbandaclasse4 = int(lbandatotal * 0.07)

            #critico - tem que saber o endereco para o ovsdb]
            # #limpar entradas de qos anterior do ovsdb para  porta

            #aparenta funcionar com python3, mas com python 2 como eh agora -- nao
            # OVSDB_ADDR = 'tcp:127.0.0.1:6640'

            # # #Returns True if the given addr is valid OVSDB server address, otherwise False.
            # print(vsctl.valid_ovsdb_addr(OVSDB_ADDR))

            # ovs_vsctl = vsctl.VSCtl(OVSDB_ADDR)

            # # #limpar antes as configuracoes existentes de qos de fila tc
            # # # comando -> echo mininet | sudo -S tc qdisc del dev s1-eth1 root

            # table = "Port"
            # column = "qos"
            # command = vsctl.VSCtlCommand('clear', (table, interface, column))

            # ovs_vsctl.run_command([command])
            # print(command)

            #obs desse jeito so funciona em rede local!!! --- se o switch estiver em outro pc nao rola -- tem que utilizar a conexao com ovsdb sei la
            p = subprocess.Popen("echo mininet | sudo ovs-vsctl clear port s1-eth4 qos", stdout=subprocess.PIPE, shell=True)

            print("[new_switch_handler]Entradas de qos anteriores foram removidas do ovsdb para a porta {}".format(nome_porta))

            p = subprocess.Popen("echo mininet | sudo -S tc qdisc del dev {} root".format(interface), stdout=subprocess.PIPE, shell=True)

            # print(p.__dict__)
            if(p.stderr == None):
                print("[new_switch_handler] SUCESSO - filas anteriores removidas {}".format(interface))
            else:
                print("[new_switch_handler] FALHA - Erro em remover filas anteriores {}".format(interface))

            #tentar com apenas a configuracao ovs-vsctl - sem limpar o tcqdisc ---> nao funciona
            #ovs-vsctl clear port s1-eth4 qos

            # # queues = [{'min-rate': '10000', 'max-rate': '100000', 'priority': '5'},{'min-rate':'500000'}]
            # # ovs_bridge.set_qos(interface, type='linux-htb', max_rate="15000000", queues=queues)
            # # #deu certo?

            script_qos = "echo mininet | sudo ovs-vsctl -- set port {} qos=@newqos -- \
                                    --id=@newqos create qos type=linux-htb other-config:max-rate={} \
                                    queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6,7=@q7 -- \
                                    --id=@q0 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=10 -- \
                                    --id=@q1 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=5 -- \
                                    --id=@q2 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=2 -- \
                                    --id=@q3 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=10 -- \
                                    --id=@q4 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=5 -- \
                                    --id=@q5 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=2 -- \
                                    --id=@q6 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=10 -- \
                                    --id=@q7 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=2 \
                                    ".format(interface, 
                                    str(lbandatotal),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse3), str(lbandatotal),
                                    str(lbandaclasse4), str(lbandaclasse4+100))

            print(script_qos)                                    
            #aplicando o script aqui
            p = subprocess.Popen(script_qos, stdout=subprocess.PIPE, shell=True)

            if(p.stderr == None):
                print("[new_switch_handler] SUCESSO - Novas configuracoes de filas foram estabelecidas porta {}\n{}".format(interface,script_qos))
            else:
                print("[new_switch_handler] FALHA - Erro em novas configuracoes de filas porta {}\n{}".format(interface,script_qos))
 
def tratador_delSwitch(switch_cfg):

    nome_switch = switch_cfg['nome']

    for switch in switches:
        if switch.nome == nome_switch:
            switches.remove(switch)
            break

    print('Switch removido: %s' % (nome_switch))


def tratador_rotas(novasrotas_json):

    print("Adicionando novas rotas:")
    for rota in novasrotas_json:
        print(rota)

        #poderia obter uma lista de switches e ir em cada um adicinoando a rota

        nome_switch = rota['switch_id']
        prefixo = rota['prefixo_rede']
        mascara = rota['mascara_rede']
        tipo = rota['tipo'] # adicionar rota/remover rota

        porta_saida = rota['porta_saida']

        switch = None

        #procurando switch        
        for i in switches:
            if str(i.nome) == str(nome_switch):
                switch = i
                break
    
        if(switch == None):
            print("Switch S%s, nao encontrado no dominio - configuracao rejeitada\n" % str(nome_switch))
            continue

        if tipo == 'adicionar':
            switch.addRedeIPv4(prefixo, int (porta_saida))
        else:
            switch.delRede(prefixo, int (porta_saida))

def tratador_regras(novasregras_json):
    #   *Nao implementado*
    # -> encontrar o switch onde as regras devem ser instaladas
    # tipos de regras possiveis
    # - delete e add
    # - regras marcacao
    # - regras meter (classes com qos -> gbam)
    # - regra de encaminhamento (best-effort)

    for regra in novasregras_json:

        print(regra)

        nome_switch = regra['switch_id']
        switch_obj = None
        
        #encontrar o switch
        for switch in switches:
            if switch.nome == nome_switch:
                switch_obj = switch
                break
        
        if switch_obj == None:
            print("Regra falhou!!")
            #tentar a proxima regra
            continue

        tipo_regra = regra['tipo_regra'] #(add/delete)
        ip_ver = regra['ip_ver']
        ip_src = regra['ip_src']
        ip_dst = regra['ip_dst']
        porta_saida = regra['porta_saida']
        src_port = regra['src_port']
        dst_port = regra['dst_port']
        proto = regra['proto']
        #isso vai ser modificado outro momento
        classe = regra['classe']
        prioridade = regra['prioridade']
        banda = regra['banda']

        if tipo_regra == 'delete':
            #se for uma regra GBAM deletar aqui
            #ip_ver:str, ip_src:str, ip_dst:str, src_port:str, dst_port:str, proto:str, porta_saida_obj: Porta, classe: str, prioridade: str, banda: str)
            if not switch_obj.delRegraGBAM(ip_ver=ip_ver, ip_src = ip_src, ip_dst = ip_dst, src_port=src_port, dst_port=dst_port, proto=proto, porta_saida = porta_saida, banda=banda, prioridade=prioridade, classe=classe):
                #se for uma regra best-effort remover aqui
                switch_obj.delRegraT(ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst,src_port=src_port, dst_port=dst_port, proto=proto,ip_dscp=None)

        elif tipo_regra == 'add':
            switch_obj.alocarGBAM(ip_ver=ip_ver, ip_src = ip_src, ip_dst = ip_dst, proto=proto, dst_port = dst_port, src_port= src_port, porta_saida = porta_saida, banda=banda, prioridade=prioridade, classe=classe)

    return None


#################
#   INICIANDO SOCKET - RECEBER CONTRATOS (hosts e controladores)
################

t1 = Thread(target=servidor_socket_hosts)
t1.start()

t2 = Thread(target=servidor_socket_controladores)
t2.start()

t3 = Thread(target=tratador_configuracoes)
t3.start()

## iniciar o servidor web aqui
t4 = Thread(target=lancar_wsgi)
t4.start()

#t1.join()

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

def send_icmpv6(datapath, srcMac, srcIp, dstMac, dstIp, outPort, seq, data, id=1, type=8, ttl=64):

    e = ethernet.ethernet(dst=dstMac, src=srcMac, ethertype=ether.ETH_TYPE_IP)

    iph = ipv6.ipv6(4, 5, 0, 0, 0, 2, 0, ttl, 1, 0, srcIp, dstIp)

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

#         #procurar em todos os switches do controlador, qual gerou um packet in de um host - ou seja - o host esta mais proximo de qual switch
    def getSwitchFromMac(self, mac):
        for s in switches:
            if s.conheceMac(mac) != -1:
                return s.nome

    #dado um conjunto de switches (var global) pertencentes a um dominio/controlador, recuperar o conjunto de switches que fazem parte da rota para o end destino/rede
    def getRota(self,switch_primeiro_dpid, ip_dst):
		#por enquanto nao importam as rotas - rotas fixas e um switch
        #switches eh uma variavel global que compreende os switches do controlador
        #rota = vetor de switches
        rota = []
        ##print("[getRota] src:%s, dst:%s\n" % (ip_src, ip_dst))

        if switch_primeiro_dpid == None:
            for s in switches:
                if ip_dst in s.hosts:
                    switch_primeiro_dpid = s.nome

        if switch_primeiro_dpid == None:
            return None

        #pegar o primeiro switch da rota, baseado no ip_Src --- ou, por meio do packet in, mas entao nao poderia criar as regras na criacao dos contratos
        switch_primeiro = self.getSwitchByName(str(switch_primeiro_dpid))
        rota.append(switch_primeiro)

        #pegar o salto do ultimo switch inserido na rota
        nextDpid = switch_primeiro.getPorta(switch_primeiro.getPortaSaida(ip_dst)).next #retorna inteiro

        #print("switch_primeiro: %s, nextDpid: %d\n" % (switch_primeiro.nome, nextDpid))

        while nextDpid > 0:
            s = self.getSwitchByName(nextDpid)
            rota.append(s)
            #se o .next da porta for -1, esse eh o switch de borda
            nextDpid = s.getPorta(s.getPortaSaida(ip_dst)).next
        
        #for r in rota:
            #print("[rota]: %s" % (r.nome))
            
        return rota
    
    def getSwitchByName(self, nome):
        print("procurando switch: %s\n" % nome)
        for i in switches:
            if str(i.nome) == str(nome):
                return i

        return None
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print("Novo switch anunciado....\n")

        #aqui nao se obtem tantas informacoes sobre os switches como eu gostaria
        tempo_i = round(time.monotonic()*1000)
    
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        print("[%s] switch_features - setup de S%d \n" % (datetime.datetime.now().time(), datapath.id))

        switch = SwitchOVS(datapath,str(datapath.id), self)

        switches.append(switch)
        #print("\nSwitch criado\n")

        # global FORWARD_TABLE
        # global CLASSIFICATION_TABLE

###########################################################################################
##########        Criar regras TABELAs - marcacao e identificacao              ###########
###########################################################################################
       
		#tabela 0 - classifica os pacotes e envia para a tabela 2
        #criar tabelas https://github.com/knetsolutions/ryu-exercises/blob/master/ex6_multiple_tables.py
        #pacotes sem TOS - sem regras de marcacao e nao sendo icmp information request/reply -> para a tabela 2 (FORWARD)
        
        #[CLASSIFICACAO] regra default -> enviar para tabela 2
        self.add_classification_table(datapath)
       
        #[FORWARD] regra default -> enviar para o controlador
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, FORWARD_TABLE)

        logging.info('[switch_features] fim settage - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))

    	#Regras ICMP inf. Req. e inf. reply --
        
        #as demais regras de marcacao sao feitas com base no packet_in e contratos

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

########### Testando ############

    def add_classification_table(self, datapath):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(FORWARD_TABLE)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=CLASSIFICATION_TABLE, instructions=inst, priority=0) #criando a regra default
        datapath.send_msg(mod)

    def add_forward_table(self, datapath, actions, prioridade):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(FORWARD_TABLE)]
        mod = None
        if actions == None:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=FORWARD_TABLE,priority=prioridade, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=FORWARD_TABLE,priority=prioridade, instructions=inst, actions=actions)

        datapath.send_msg(mod)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("To dpid {0} packet-out {1}".format(datapath.id, pkt))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

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

    def encontrarMatchContratos(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto):
        
        #encontrou
        for i in contratos:
            if i.ip_ver == ip_ver and i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                return i

        #nao encontrou
        return None, None, None

#arrumando ate aqui

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        tempo_i = round(time.monotonic()*1000)
        #####           obter todas as informacoes uteis do pacote          #######
        msg = ev.msg #representa a mensagem packet_in
        dp = msg.datapath #representa o switch
        ofp = dp.ofproto #protocolo openflow na versao implementada pelo switch
        parser = dp.ofproto_parser

        #identificar o switch
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})

        #analisar o pacote recebido usando a biblioteca packet
        pkt = packet.Packet(msg.data)

        #print("[event] Packet_in -- switch: %s\n [Inspecionando pkt]\n" % (str(dpid)))
        #print("Cabecalhos:\n")
        #for p in pkt.protocols:
        #    print (p)

        #obter os cabecalhos https://osrg.github.io/ryu-book/en/html/packet_lib.html
        #obter o frame ethernet
        pkt_eth= pkt.get_protocol (ethernet.ethernet)
        if not pkt_eth:
            return

        ##end macs
        dst = pkt_eth.dst
        src = pkt_eth.src

        #end ips
        ip_src = None
        ip_dst = None

        #portas udp ou tcp
        src_port = None
        dst_port = None

        #protocolo ip de transporte utilizado
        proto = None

        #tipo pacote
        pkt_type = pkt_eth.ethertype

        ip_ver = None

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ipv6 = pkt.get_protocol(ipv6.ipv6)
        if pkt_ipv4:
            #print("\nPacote IPv4: ")
            ip_src = pkt_ipv4.src
            ip_dst = pkt_ipv4.dst
            ip_ver = 'ipv4'
        elif pkt_ipv6:
            ip_src = pkt_ipv4.src
            ip_dst = pkt_ipv4.dst
            ip_ver = 'ipv6'

        # if 'ip_dscp' in msg.match:
        #     tos= msg.match['ip_dscp']
        if 'tcp_src' in msg.match:
            src_port = msg.match['tcp_src']
            dst_port = msg.match['tcp_dst']
            proto='tcp'
        if 'udp_src' in msg.match:
            src_port = msg.match['udp_src']
            dst_port = msg.match['udp_dst']
            proto='udp'

        #se o de cima nao funcionar tentar..
        # pkt_udp = pkt.get_protocol(udp.udp)
        # if pkt_udp:
        #     src_port = pkt_udp.src_port
        #     dst_port = pkt.udp.dst_port

        # pkt_tcp = pkt.get_protocol(tcp.tcp)
        # if pkt_udp:
        #     src_port = pkt_tcp.src_port
        #     dst_port = pkt.tcp.dst_port

        print("[%s] pkt_in ip_src: %s; ip_dst: %s; src_port: %s; dst_port: %s; proto: %s\n" % (datetime.datetime.now().time(), ip_src, ip_dst, src_port, dst_port, proto))

        #obter porta de entrada qual o switch recebeu o pacote
        in_port = msg.match['in_port']

        #print("\nlistar todas as regras do switch-%s:\n" %(str(dpid)))
        este_switch = self.getSwitchByName(str(dpid))
        este_switch.listarRegras()

        este_switch.addMac(src, in_port)
        
        este_switch.addHost(ip_src, in_port)


        #tratador dhcp
        dhcpPkt = pkt.get_protocol(dhcp.dhcp)
        if dhcpPkt:
            #verificar o tipo da mensagem
            msgType = ord(dhcpPkt.options.option_list[0].value)
            
            print(msgType)

            print(dhcpPkt.__dict__)
            try:
                self.logger.info("Receive DHCP message type %s" %
                                 (dhcp_msg_type_code[msgType]))
            except KeyError:
                self.logger.info("Receive UNKNOWN DHCP message type %d" %
                                 (msgType))
                
            if msgType == dhcp.DHCP_DISCOVER:
                print( 'TIPO111111111111111')
                handle_dhcp_discovery(dp, in_port, dhcpPkt)
            elif msgType == dp.DHCP_REQUEST:
                print( '22222222222222222222')
                handle_dhcp_request(dhcpPkt, dp, in_port)
                self.logger.info(mac_to_client_ip)
            else:
                pass




        #aprender endereco MAC, evitar flood proxima vez
        self.mac_to_port[dpid][src] = in_port
        #adaptar essa parte depois, aqui so se quer saber se eh conhecida a porta destino para
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = None

        #########             ACOES DO CONTROLADOR              ####################
        #recebi um pacote desconhecido -> Packet_In
        #Sao 2 forks: i)eh Pacote ICMP? ou ii)NAo

        #i) eh Pacote ICMP - verificar se eh ICMP i.1)Information Request ou i.2)information Reply

        #pkt: responder o arp-> request information + continuar com o arp anterior (replicar)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
		
        if pkt_icmp:
            #print("\n Recebeu Pacote ICMP: \n")
            
        ############################3
        ####  RECEBI UM INF. REQUEST:solicitando informacoes - se tem interesse em
        ####  receber o contrato referente ao ip destino (em breve sera adicionado o ip origem tbm):
        #### (i) encapsular o endereco destino do host o qual se quer os contratos em um icmp 16
        #### (2) obter o switch mais proximo do ip_src (controlador que gerou o icmp 15)
        #### (3) enviar o icmp 16 para o ip_src
        #### [suprimido](4) [nao precisa - todos os switches conectados ao controlador possuem 
        # regra de encaminhamento para o controlador estabelecida quando se conectam ao
        #  controlador]criar as regras de marcacao e encaminhamento
        #  de pacotes entre o controlador emissor (ip_src) e o controlador do dominio (IPC)
        # - marcacao no switch mais proximo de ip_src e encaminhamento nos demais switches da rota
        #### (5) encontrar o switch mais proximo do ip_dst (host destino do icmp 15 recebido) e reinjetar o icmp 15 recebido, para descobrir novos controladores
        ############################

            if pkt_icmp.type == 15: #request information -> enviar um information reply
                
                print("[%s] tratamento ICMP 15 \n" % (datetime.datetime.now().time()))

                #aqui se for possivel colocar o endereco destino ao qual o fluxo quer alcancar, nos dados do icmp, sera excelente para identificar os contratos que devem ser enviados. para este controlador
                #enviar um information reply:
                #ip-destino: ip_src -> origem pkt-in
                #mac-destino: src -> origem pkt-in (host root do outro controlador)
                #ip-origem: "10.123.123.1" ip do host root (controlador)
                #mac-origem: "00:00:00:00:00:05" mac do host root
                #output_port: in_port -> do pkt-in

                #preparando o ip destino que desejo os contratos, para solicitar via icmp 16 ao controlador emissor do icmp 15
                #enviando o ip_dst como json
                #print("[ICMP-15] Recebido\n")
                
                addControladorConhecido(ip_src)

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
                contrato = buscarContrato(ip_ver=cip_ver, ip_src=cip_src, ip_dst=cip_dst, src_port=csrc_port, dst_port=cdst_port, proto=cproto)

                if contrato == None:
                    print("[icmp-15] Falhou - contrato nao identificado para a quintupla ip_ver: %s; ip_src: %s; ip_dst: %s; src_port: %s; dst_port: %s; proto: %s" % (cip_ver, cip_src, cip_dst, csrc_port, csrc_port, cproto))
                    #ignorar ou responder vazio?
                    return
                cdscp = CPT[(contrato.classe , contrato.prioridade, contrato.banda)]
                
                data = {"ip_ver": cip_ver, "ip_dst":cip_dst, "ip_src":cip_src, "src_port": csrc_port, "dst_port": cdst_port, "proto": cproto,"dscp":cdscp, "banda":contrato.banda, "prioridade": contrato.prioridade, "classe": contrato.classe}
                data = json.dumps(data)#.encode()
                #print("[ICMP-15] contrato desejado:%s\n" % (data))  

######### etapa 3 - responder com icmp 16                  
### RESPONDENDO ICMP 15 inf. req com um ICMP 16 inf. reply + ip_dst que quero dos contratos - injetar pelo primeiro switch da rota entre este controlador e o emissor == switch que gerou o packet_in
                ### o primeiro switch da rota eh o proprio que enviou o packet_in
                send_icmpv4(dp,MACC, IPC, src, ip_src, in_port,0,data,1,16,64) # se mostrou desnecessario, mas deixei a implementacao de qualquer forma, dst_controlador=True)
                #print("[ICMP-15] ICMP Information Request -> Replied\n")


###############3
                ########### AAAAQUUUUI AQUI AQUI ####

                #as regras de vinda dos pacotes de contrato ja existem, pq sao para este controlador
                #no entanto as regras de volta (tcp-handshake) nao existem e sao do tipo controle tbm, entao criar 
                switches_rota = self.getRota(str(dpid), IPC)
                switches_rota[-1].addRegraC(ip_ver=ip_ver, ip_src=IPC, ip_dst=ip_src, src_port=PORTAC_ICMP15, dst_port=PORTAC_ICMP15, proto='icmp-15', ip_dscp= 61)
                for s in switches_rota:
                    #porta de saida
                    out_port = s.getPortaSaida(ip_src)
                                                                                                                                                            
                    s.alocarGBAM(ip_ver=ip_ver, ip_src=IPC, ip_dst = ip_src, src_port = PORTAC_ICMP15, dst_port = PORTAC_ICMP15, proto = 'icmp-15', porta_saida = out_port, banda = '1000', prioridade = str(2), classe = str(SC_CONTROL))

######### etapa 4 - suprimida - movida para o switch_feature_handler
            #     #preparar para receber os contratos                
            #     #criar as regras nos switches da rota que leva ao controlador,
            #     # para receber os contratos que serao enviados pelo controlador emissor do inf. req.
            #    #obtendo todos os switches da rota
            #     switches_rota = SwitchOVS.getRota(IPC, ip_src)

            #     #criar a regra de marcacao no switch mais proximo da borda de origem == gerou packet_in
            #     #este_switch = SwitchOVS.getSwitch(str(dpid)) #isso ja foi feito mais acima no codigo
            #     #marcar com tos de controle
            #     este_switch.addRegraC(ip_src, IPC, 29)
                
            #     #em cada switch, o este_switch inclusive, criar as regras de encaminhamento
            #     for s in switches_rota:
            #         out_port = s.getPortaSaida(IPC)
            #         #criando as regras de encaminhamento nos demais switches
            #         s.alocarGBAM(out_port, ip_src, IPC, '1000', '2', '4')

####### etapa 5 - reijetar icmp 15
    ### SEGUINDO O ICMP 15 inf. req. - injetar pelo ultimo switch da  rota
        #obtendo a rota entre src e destino, assim como era antes
                switches_rota = self.getRota(str(dpid), ip_dst)
                
                #obter o switch mais da borda de destino e gerar o inf req para dar sequencia e descobrir novos controladores ate o host destino
                switch_ultimo = switches_rota[-1]
                out_port = switch_ultimo.getPortaSaida(ip_dst)

                switch_ultimo_dp = switch_ultimo.getDP()
                #print("[ICMP-15] Dando sequencia no icmp 15 criando no ultimo switch da rota \n src:%s, dst:%s, saida:%d\n", ip_src, ip_dst, out_port)
                send_icmpv4(switch_ultimo_dp, src, ip_src, dst, ip_dst,out_port,0,pkt_icmp.data,1,15,64)

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
                send_icmpv4(switch_primeiro.datapath, src, ip_src, dst, ip_dst, out_port, 0,pkt_icmp.data,1,16,64)

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
            
            send_icmpv4(switch_ultimo_dp, MACC, IPC, dst, ip_dst, out_port, 0, data, 1, 15,64)
                          
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

#para invocar scripts e comandos tc qdisc
import subprocess

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
from fp_constants import CPT, ALL_TABLES, FILA_CONTROLE
from fp_constants import PORTAC_ICMP15, PORTAC_ICMP16, SC_REAL
from fp_constants import SC_NONREAL, SC_BEST_EFFORT, SC_CONTROL
from fp_constants import IPC, MACC, PORTAC_C, CRIAR, CPF
from fp_constants import CLASSIFICATION_TABLE, FORWARD_TABLE, ALL_TABLES

#codigos das acoes
from fp_constants import REMOVER, CRIAR, EMPRESTANDO, NAOEMPRESTANDO

from fp_constants import switches, contratos, controladores_conhecidos, controller_singleton

from fp_constants import dhcp_msg_type_code

# try:
from fp_switch import SwitchOVS
# except ImportError:
#     print('Erro de importacao da classe SwitchOVS')

from fp_server import servidor_socket_controladores,servidor_socket_hosts,tratador_configuracoes, enviar_contratos

from fp_acao import Acao
from fp_regra import Regra

from fp_contrato import Contrato
print('importando fp_topo_discovery')
#descoberta de topologia
from fp_topology_discovery import handler_switch_enter, handler_switch_leave
print('importando fp_dhcp')
#tratador DHCPv4
from fp_dhcp import handle_dhcp_discovery, handle_dhcp_request, mac_to_client_ip
print('importando interface_web')
# import wsgiWebSocket.interface_web as iwb
from interface_web import lancar_wsgi #, _websocket_rcv, _websocket_snd, dados_json


def getController():
    return controller_singleton

def buscarContratoId(id):
    for i in contratos:
        if i.id == id:
            return i
        
    return None

def buscarContrato(ip_ver, ip_src, ip_dst, src_port, dst_port, proto):
    """ Parametros
    ip_ver: str
    ip_src: str
    ip_dst: str
    src_port: str
    dst_port: str
    proto: str
    """
    for i in contratos:
        if i.ip_ver == ip_ver and i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
            return i
        
    return None

def buscarConflitoContrato(contrato):
    """ Parametros
    contrato: Contrato
    """
    
    contratos_conflitantes = []
    contratos_conflitantes.append(contrato)

    for i in contratos:
        if i.ip_src == contrato.ip_src and i.ip_dst == contrato.ip_dst and i.src_port == contrato.src_port and i.dst_port == contrato.dst_port and i.proto == contrato.proto:
            if i.ip_ver != contrato.ip_ver or i.proto != contrato.proto or i.banda != contrato.banda or i.prioridade != contrato.prioridade or i.classe != contrato.classe:
                contratos_conflitantes.append(i) 
        
    return contratos_conflitantes

#remove um contrato e as regras associadas a ele nos switches da rota entre ip_src, ip_dst
def delContratoERegras(switches_rota, contrato):
    """ Parametros
    switches_rota: List
    contrato: Contrato
    """

    ##checar se ja existe um contrato e remover --- isso ocorre antes de adicionar o novo contrato, por isso consigo pegar o contrato antigo
    
    contratos_conflitantes = buscarConflitoContrato(contrato)

    if len(contratos_conflitantes) < 2:
        print("[delContratosRegras] Nada a fazer!")
        return

    #quero manter apenas o novo - entao o removo da lista
    contratos_conflitantes.pop(0)

    for i in contratos_conflitantes:

        #contrato exatamente igual ao que estamos incluindo ?
        # if i.ip_src==contrato.ip_src and i.ip_dst==contrato.ip_dst and i.src_port==contrato.src_port and i.dst_port==contrato.dst_port and i.proto==contrato.proto and contrato.banda == i.banda and contrato.classe == i.classe and contrato.prioridade == i.prioridade:
        # contratos.remove(i)

        for s in switches_rota:
            out_port = s.getPortaSaida(i.ip_dst) #inteiro
            porta = s.getPorta(out_port)
            
            #deletando a regra referente ao contrato antigo - pq nao vale mais, ele foi removido
            #se a regra estava ativa, ela sera removida dos switches tbm
            Acao(s,porta,REMOVER, Regra(i.ip_ver, i.ip_src,i.ip_dst,i.src_port, i.dst_port, 
                                                                i.proto, out_port,i.dscp, i.banda, i.prioridade,
                                                                i.classe, 0)).executar()

            contratos.remove(i)
 
            return


def tratador_addSwitch(addswitch_json):

    print("Adicionando configuracao de switch")
    for i in addswitch_json:
        print(i)

        nome_switch = i['nome']
        datapath = i['datapath']
        qtdPortas = i['qtdPortas']

        switch = None
        
        #procurando o switch
        for i in switches:
            if str(i.nome) == str(nome_switch):
                switch = i

        #encontrar o switch pelo nome
        #criar as portas conforme a configuracao do json
        if(switch == None):
            print("Switch S%s, nao encontrado no dominio - configuracao rejeitada\n" % str(nome_switch))
            continue
        
        print("mostrando portas \n")
        # print(i['portas'])

        for porta in i['portas']:
            print (porta)

            nome_porta = porta['nome']
            largura_porta = porta['larguraBanda']
            prox_porta = porta['proxSwitch']

            switch.addPorta(nome_porta, int(largura_porta), int(prox_porta))

            interface = "s" + str(nome_switch) + "-eth"+ str(nome_porta)
###
            #criar as novas filas
            lbandatotal = int(largura_porta)
            #classe tempo-real ids=[0,1,2]
            lbandaclasse1 = int(lbandatotal * 0.33)
            #classe nao-tempo-real/dados ids=[3,4,5]
            lbandaclasse2 = int(lbandatotal * 0.35)
            #classe best-effort id = 6
            lbandaclasse3 = int(lbandatotal * 0.25)
            #classe controle id = 7
            lbandaclasse4 = int(lbandatotal * 0.07)

            #critico - tem que saber o endereco para o ovsdb]
            # #limpar entradas de qos anterior do ovsdb para  porta

            #aparenta funcionar com python3, mas com python 2 como eh agora -- nao
            # OVSDB_ADDR = 'tcp:127.0.0.1:6640'

            # # #Returns True if the given addr is valid OVSDB server address, otherwise False.
            # print(vsctl.valid_ovsdb_addr(OVSDB_ADDR))

            # ovs_vsctl = vsctl.VSCtl(OVSDB_ADDR)

            # # #limpar antes as configuracoes existentes de qos de fila tc
            # # # comando -> echo mininet | sudo -S tc qdisc del dev s1-eth1 root

            # table = "Port"
            # column = "qos"
            # command = vsctl.VSCtlCommand('clear', (table, interface, column))

            # ovs_vsctl.run_command([command])
            # print(command)

            #obs desse jeito so funciona em rede local!!! --- se o switch estiver em outro pc nao rola -- tem que utilizar a conexao com ovsdb sei la
            p = subprocess.Popen("echo mininet | sudo ovs-vsctl clear port s1-eth4 qos", stdout=subprocess.PIPE, shell=True)

            print("[new_switch_handler]Entradas de qos anteriores foram removidas do ovsdb para a porta {}".format(nome_porta))

            p = subprocess.Popen("echo mininet | sudo -S tc qdisc del dev {} root".format(interface), stdout=subprocess.PIPE, shell=True)

            # print(p.__dict__)
            if(p.stderr == None):
                print("[new_switch_handler] SUCESSO - filas anteriores removidas {}".format(interface))
            else:
                print("[new_switch_handler] FALHA - Erro em remover filas anteriores {}".format(interface))

            #tentar com apenas a configuracao ovs-vsctl - sem limpar o tcqdisc ---> nao funciona
            #ovs-vsctl clear port s1-eth4 qos

            # # queues = [{'min-rate': '10000', 'max-rate': '100000', 'priority': '5'},{'min-rate':'500000'}]
            # # ovs_bridge.set_qos(interface, type='linux-htb', max_rate="15000000", queues=queues)
            # # #deu certo?

            script_qos = "echo mininet | sudo ovs-vsctl -- set port {} qos=@newqos -- \
                                    --id=@newqos create qos type=linux-htb other-config:max-rate={} \
                                    queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6,7=@q7 -- \
                                    --id=@q0 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=10 -- \
                                    --id=@q1 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=5 -- \
                                    --id=@q2 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=2 -- \
                                    --id=@q3 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=10 -- \
                                    --id=@q4 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=5 -- \
                                    --id=@q5 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=2 -- \
                                    --id=@q6 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=10 -- \
                                    --id=@q7 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=2 \
                                    ".format(interface, 
                                    str(lbandatotal),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse3), str(lbandatotal),
                                    str(lbandaclasse4), str(lbandaclasse4+100))

            print(script_qos)                                    
            #aplicando o script aqui
            p = subprocess.Popen(script_qos, stdout=subprocess.PIPE, shell=True)

            if(p.stderr == None):
                print("[new_switch_handler] SUCESSO - Novas configuracoes de filas foram estabelecidas porta {}\n{}".format(interface,script_qos))
            else:
                print("[new_switch_handler] FALHA - Erro em novas configuracoes de filas porta {}\n{}".format(interface,script_qos))
 
def tratador_delSwitch(switch_cfg):

    nome_switch = switch_cfg['nome']

    for switch in switches:
        if switch.nome == nome_switch:
            switches.remove(switch)
            break

    print('Switch removido: %s' % (nome_switch))


def tratador_rotas(novasrotas_json):

    print("Adicionando novas rotas:")
    for rota in novasrotas_json:
        print(rota)

        #poderia obter uma lista de switches e ir em cada um adicinoando a rota

        nome_switch = rota['switch_id']
        prefixo = rota['prefixo_rede']
        mascara = rota['mascara_rede']
        tipo = rota['tipo'] # adicionar rota/remover rota

        porta_saida = rota['porta_saida']

        switch = None

        #procurando switch        
        for i in switches:
            if str(i.nome) == str(nome_switch):
                switch = i
                break
    
        if(switch == None):
            print("Switch S%s, nao encontrado no dominio - configuracao rejeitada\n" % str(nome_switch))
            continue

        if tipo == 'adicionar':
            switch.addRedeIPv4(prefixo, int (porta_saida))
        else:
            switch.delRede(prefixo, int (porta_saida))

def tratador_regras(novasregras_json):
    #   *Nao implementado*
    # -> encontrar o switch onde as regras devem ser instaladas
    # tipos de regras possiveis
    # - delete e add
    # - regras marcacao
    # - regras meter (classes com qos -> gbam)
    # - regra de encaminhamento (best-effort)

    for regra in novasregras_json:

        print(regra)

        nome_switch = regra['switch_id']
        switch_obj = None
        
        #encontrar o switch
        for switch in switches:
            if switch.nome == nome_switch:
                switch_obj = switch
                break
        
        if switch_obj == None:
            print("Regra falhou!!")
            #tentar a proxima regra
            continue

        tipo_regra = regra['tipo_regra'] #(add/delete)
        ip_ver = regra['ip_ver']
        ip_src = regra['ip_src']
        ip_dst = regra['ip_dst']
        porta_saida = regra['porta_saida']
        src_port = regra['src_port']
        dst_port = regra['dst_port']
        proto = regra['proto']
        #isso vai ser modificado outro momento
        classe = regra['classe']
        prioridade = regra['prioridade']
        banda = regra['banda']

        if tipo_regra == 'delete':
            #se for uma regra GBAM deletar aqui
            #ip_ver:str, ip_src:str, ip_dst:str, src_port:str, dst_port:str, proto:str, porta_saida_obj: Porta, classe: str, prioridade: str, banda: str)
            if not switch_obj.delRegraGBAM(ip_ver=ip_ver, ip_src = ip_src, ip_dst = ip_dst, src_port=src_port, dst_port=dst_port, proto=proto, porta_saida = porta_saida, banda=banda, prioridade=prioridade, classe=classe):
                #se for uma regra best-effort remover aqui
                switch_obj.delRegraT(ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst,src_port=src_port, dst_port=dst_port, proto=proto,ip_dscp=None)

        elif tipo_regra == 'add':
            switch_obj.alocarGBAM(ip_ver=ip_ver, ip_src = ip_src, ip_dst = ip_dst, proto=proto, dst_port = dst_port, src_port= src_port, porta_saida = porta_saida, banda=banda, prioridade=prioridade, classe=classe)

    return None


#################
#   INICIANDO SOCKET - RECEBER CONTRATOS (hosts e controladores)
################

t1 = Thread(target=servidor_socket_hosts)
t1.start()

t2 = Thread(target=servidor_socket_controladores)
t2.start()

t3 = Thread(target=tratador_configuracoes)
t3.start()

## iniciar o servidor web aqui
t4 = Thread(target=lancar_wsgi)
t4.start()

#t1.join()

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

def send_icmpv6(datapath, srcMac, srcIp, dstMac, dstIp, outPort, seq, data, id=1, type=8, ttl=64):

    e = ethernet.ethernet(dst=dstMac, src=srcMac, ethertype=ether.ETH_TYPE_IP)

    iph = ipv6.ipv6(4, 5, 0, 0, 0, 2, 0, ttl, 1, 0, srcIp, dstIp)

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

#         #procurar em todos os switches do controlador, qual gerou um packet in de um host - ou seja - o host esta mais proximo de qual switch
    def getSwitchFromMac(self, mac):
        for s in switches:
            if s.conheceMac(mac) != -1:
                return s.nome

    #dado um conjunto de switches (var global) pertencentes a um dominio/controlador, recuperar o conjunto de switches que fazem parte da rota para o end destino/rede
    def getRota(self,switch_primeiro_dpid, ip_dst):
		#por enquanto nao importam as rotas - rotas fixas e um switch
        #switches eh uma variavel global que compreende os switches do controlador
        #rota = vetor de switches
        rota = []
        ##print("[getRota] src:%s, dst:%s\n" % (ip_src, ip_dst))

        if switch_primeiro_dpid == None:
            for s in switches:
                if ip_dst in s.hosts:
                    switch_primeiro_dpid = s.nome

        if switch_primeiro_dpid == None:
            return None

        #pegar o primeiro switch da rota, baseado no ip_Src --- ou, por meio do packet in, mas entao nao poderia criar as regras na criacao dos contratos
        switch_primeiro = self.getSwitchByName(str(switch_primeiro_dpid))
        rota.append(switch_primeiro)

        #pegar o salto do ultimo switch inserido na rota
        nextDpid = switch_primeiro.getPorta(switch_primeiro.getPortaSaida(ip_dst)).next #retorna inteiro

        #print("switch_primeiro: %s, nextDpid: %d\n" % (switch_primeiro.nome, nextDpid))

        while nextDpid > 0:
            s = self.getSwitchByName(nextDpid)
            rota.append(s)
            #se o .next da porta for -1, esse eh o switch de borda
            nextDpid = s.getPorta(s.getPortaSaida(ip_dst)).next
        
        #for r in rota:
            #print("[rota]: %s" % (r.nome))
            
        return rota
    
    def getSwitchByName(self, nome):
        print("procurando switch: %s\n" % nome)
        for i in switches:
            if str(i.nome) == str(nome):
                return i

        return None
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print("Novo switch anunciado....\n")

        #aqui nao se obtem tantas informacoes sobre os switches como eu gostaria
        tempo_i = round(time.monotonic()*1000)
    
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        print("[%s] switch_features - setup de S%d \n" % (datetime.datetime.now().time(), datapath.id))

        switch = SwitchOVS(datapath,str(datapath.id), self)

        switches.append(switch)
        #print("\nSwitch criado\n")

        # global FORWARD_TABLE
        # global CLASSIFICATION_TABLE

###########################################################################################
##########        Criar regras TABELAs - marcacao e identificacao              ###########
###########################################################################################
       
		#tabela 0 - classifica os pacotes e envia para a tabela 2
        #criar tabelas https://github.com/knetsolutions/ryu-exercises/blob/master/ex6_multiple_tables.py
        #pacotes sem TOS - sem regras de marcacao e nao sendo icmp information request/reply -> para a tabela 2 (FORWARD)
        
        #[CLASSIFICACAO] regra default -> enviar para tabela 2
        self.add_classification_table(datapath)
       
        #[FORWARD] regra default -> enviar para o controlador
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, FORWARD_TABLE)

        logging.info('[switch_features] fim settage - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))

    	#Regras ICMP inf. Req. e inf. reply --
        
        #as demais regras de marcacao sao feitas com base no packet_in e contratos

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

########### Testando ############

    def add_classification_table(self, datapath):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(FORWARD_TABLE)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=CLASSIFICATION_TABLE, instructions=inst, priority=0) #criando a regra default
        datapath.send_msg(mod)

    def add_forward_table(self, datapath, actions, prioridade):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(FORWARD_TABLE)]
        mod = None
        if actions == None:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=FORWARD_TABLE,priority=prioridade, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=FORWARD_TABLE,priority=prioridade, instructions=inst, actions=actions)

        datapath.send_msg(mod)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("To dpid {0} packet-out {1}".format(datapath.id, pkt))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

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

    def encontrarMatchContratos(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto):
        
        #encontrou
        for i in contratos:
            if i.ip_ver == ip_ver and i.ip_src == ip_src and i.ip_dst == ip_dst and i.src_port == src_port and i.dst_port == dst_port and i.proto == proto:
                return i

        #nao encontrou
        return None, None, None

#arrumando ate aqui

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        tempo_i = round(time.monotonic()*1000)
        #####           obter todas as informacoes uteis do pacote          #######
        msg = ev.msg #representa a mensagem packet_in
        dp = msg.datapath #representa o switch
        ofp = dp.ofproto #protocolo openflow na versao implementada pelo switch
        parser = dp.ofproto_parser

        #identificar o switch
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})

        #analisar o pacote recebido usando a biblioteca packet
        pkt = packet.Packet(msg.data)

        #print("[event] Packet_in -- switch: %s\n [Inspecionando pkt]\n" % (str(dpid)))
        #print("Cabecalhos:\n")
        #for p in pkt.protocols:
        #    print (p)

        #obter os cabecalhos https://osrg.github.io/ryu-book/en/html/packet_lib.html
        #obter o frame ethernet
        pkt_eth= pkt.get_protocol (ethernet.ethernet)
        if not pkt_eth:
            return

        ##end macs
        dst = pkt_eth.dst
        src = pkt_eth.src

        #end ips
        ip_src = None
        ip_dst = None

        #portas udp ou tcp
        src_port = None
        dst_port = None

        #protocolo ip de transporte utilizado
        proto = None

        #tipo pacote
        pkt_type = pkt_eth.ethertype

        ip_ver = None

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ipv6 = pkt.get_protocol(ipv6.ipv6)
        if pkt_ipv4:
            #print("\nPacote IPv4: ")
            ip_src = pkt_ipv4.src
            ip_dst = pkt_ipv4.dst
            ip_ver = 'ipv4'
        elif pkt_ipv6:
            ip_src = pkt_ipv4.src
            ip_dst = pkt_ipv4.dst
            ip_ver = 'ipv6'

        # if 'ip_dscp' in msg.match:
        #     tos= msg.match['ip_dscp']
        if 'tcp_src' in msg.match:
            src_port = msg.match['tcp_src']
            dst_port = msg.match['tcp_dst']
            proto='tcp'
        if 'udp_src' in msg.match:
            src_port = msg.match['udp_src']
            dst_port = msg.match['udp_dst']
            proto='udp'

        #se o de cima nao funcionar tentar..
        # pkt_udp = pkt.get_protocol(udp.udp)
        # if pkt_udp:
        #     src_port = pkt_udp.src_port
        #     dst_port = pkt.udp.dst_port

        # pkt_tcp = pkt.get_protocol(tcp.tcp)
        # if pkt_udp:
        #     src_port = pkt_tcp.src_port
        #     dst_port = pkt.tcp.dst_port

        print("[%s] pkt_in ip_src: %s; ip_dst: %s; src_port: %s; dst_port: %s; proto: %s\n" % (datetime.datetime.now().time(), ip_src, ip_dst, src_port, dst_port, proto))

        #obter porta de entrada qual o switch recebeu o pacote
        in_port = msg.match['in_port']

        #print("\nlistar todas as regras do switch-%s:\n" %(str(dpid)))
        este_switch = self.getSwitchByName(str(dpid))
        este_switch.listarRegras()

        este_switch.addMac(src, in_port)
        
        este_switch.addHost(ip_src, in_port)


        #tratador dhcp
        dhcpPkt = pkt.get_protocol(dhcp.dhcp)
        if dhcpPkt:
            #verificar o tipo da mensagem
            msgType = ord(dhcpPkt.options.option_list[0].value)
            
            print(msgType)

            print(dhcpPkt.__dict__)
            try:
                self.logger.info("Receive DHCP message type %s" %
                                 (dhcp_msg_type_code[msgType]))
            except KeyError:
                self.logger.info("Receive UNKNOWN DHCP message type %d" %
                                 (msgType))
                
            if msgType == dhcp.DHCP_DISCOVER:
                print( 'TIPO111111111111111')
                handle_dhcp_discovery(dp, in_port, dhcpPkt)
            elif msgType == dp.DHCP_REQUEST:
                print( '22222222222222222222')
                handle_dhcp_request(dhcpPkt, dp, in_port)
                self.logger.info(mac_to_client_ip)
            else:
                pass




        #aprender endereco MAC, evitar flood proxima vez
        self.mac_to_port[dpid][src] = in_port
        #adaptar essa parte depois, aqui so se quer saber se eh conhecida a porta destino para
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = None

        #########             ACOES DO CONTROLADOR              ####################
        #recebi um pacote desconhecido -> Packet_In
        #Sao 2 forks: i)eh Pacote ICMP? ou ii)NAo

        #i) eh Pacote ICMP - verificar se eh ICMP i.1)Information Request ou i.2)information Reply

        #pkt: responder o arp-> request information + continuar com o arp anterior (replicar)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
		
        if pkt_icmp:
            #print("\n Recebeu Pacote ICMP: \n")
            
        ############################3
        ####  RECEBI UM INF. REQUEST:solicitando informacoes - se tem interesse em
        ####  receber o contrato referente ao ip destino (em breve sera adicionado o ip origem tbm):
        #### (i) encapsular o endereco destino do host o qual se quer os contratos em um icmp 16
        #### (2) obter o switch mais proximo do ip_src (controlador que gerou o icmp 15)
        #### (3) enviar o icmp 16 para o ip_src
        #### [suprimido](4) [nao precisa - todos os switches conectados ao controlador possuem 
        # regra de encaminhamento para o controlador estabelecida quando se conectam ao
        #  controlador]criar as regras de marcacao e encaminhamento
        #  de pacotes entre o controlador emissor (ip_src) e o controlador do dominio (IPC)
        # - marcacao no switch mais proximo de ip_src e encaminhamento nos demais switches da rota
        #### (5) encontrar o switch mais proximo do ip_dst (host destino do icmp 15 recebido) e reinjetar o icmp 15 recebido, para descobrir novos controladores
        ############################

            if pkt_icmp.type == 15: #request information -> enviar um information reply
                
                print("[%s] tratamento ICMP 15 \n" % (datetime.datetime.now().time()))

                #aqui se for possivel colocar o endereco destino ao qual o fluxo quer alcancar, nos dados do icmp, sera excelente para identificar os contratos que devem ser enviados. para este controlador
                #enviar um information reply:
                #ip-destino: ip_src -> origem pkt-in
                #mac-destino: src -> origem pkt-in (host root do outro controlador)
                #ip-origem: "10.123.123.1" ip do host root (controlador)
                #mac-origem: "00:00:00:00:00:05" mac do host root
                #output_port: in_port -> do pkt-in

                #preparando o ip destino que desejo os contratos, para solicitar via icmp 16 ao controlador emissor do icmp 15
                #enviando o ip_dst como json
                #print("[ICMP-15] Recebido\n")
                
                addControladorConhecido(ip_src)

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
                contrato = buscarContrato(ip_ver=cip_ver, ip_src=cip_src, ip_dst=cip_dst, src_port=csrc_port, dst_port=cdst_port, proto=cproto)

                if contrato == None:
                    print("[icmp-15] Falhou - contrato nao identificado para a quintupla ip_ver: %s; ip_src: %s; ip_dst: %s; src_port: %s; dst_port: %s; proto: %s" % (cip_ver, cip_src, cip_dst, csrc_port, csrc_port, cproto))
                    #ignorar ou responder vazio?
                    return
                cdscp = CPT[(contrato.classe , contrato.prioridade, contrato.banda)]
                
                data = {"ip_ver": cip_ver, "ip_dst":cip_dst, "ip_src":cip_src, "src_port": csrc_port, "dst_port": cdst_port, "proto": cproto,"dscp":cdscp, "banda":contrato.banda, "prioridade": contrato.prioridade, "classe": contrato.classe}
                data = json.dumps(data)#.encode()
                #print("[ICMP-15] contrato desejado:%s\n" % (data))  

######### etapa 3 - responder com icmp 16                  
### RESPONDENDO ICMP 15 inf. req com um ICMP 16 inf. reply + ip_dst que quero dos contratos - injetar pelo primeiro switch da rota entre este controlador e o emissor == switch que gerou o packet_in
                ### o primeiro switch da rota eh o proprio que enviou o packet_in
                send_icmpv4(dp,MACC, IPC, src, ip_src, in_port,0,data,1,16,64) # se mostrou desnecessario, mas deixei a implementacao de qualquer forma, dst_controlador=True)
                #print("[ICMP-15] ICMP Information Request -> Replied\n")


###############3
                ########### AAAAQUUUUI AQUI AQUI ####

                #as regras de vinda dos pacotes de contrato ja existem, pq sao para este controlador
                #no entanto as regras de volta (tcp-handshake) nao existem e sao do tipo controle tbm, entao criar 
                switches_rota = self.getRota(str(dpid), IPC)
                switches_rota[-1].addRegraC(ip_ver=ip_ver, ip_src=IPC, ip_dst=ip_src, src_port=PORTAC_ICMP15, dst_port=PORTAC_ICMP15, proto='icmp-15', ip_dscp= 61)
                for s in switches_rota:
                    #porta de saida
                    out_port = s.getPortaSaida(ip_src)
                                                                                                                                                            
                    s.alocarGBAM(ip_ver=ip_ver, ip_src=IPC, ip_dst = ip_src, src_port = PORTAC_ICMP15, dst_port = PORTAC_ICMP15, proto = 'icmp-15', porta_saida = out_port, banda = '1000', prioridade = str(2), classe = str(SC_CONTROL))

######### etapa 4 - suprimida - movida para o switch_feature_handler
            #     #preparar para receber os contratos                
            #     #criar as regras nos switches da rota que leva ao controlador,
            #     # para receber os contratos que serao enviados pelo controlador emissor do inf. req.
            #    #obtendo todos os switches da rota
            #     switches_rota = SwitchOVS.getRota(IPC, ip_src)

            #     #criar a regra de marcacao no switch mais proximo da borda de origem == gerou packet_in
            #     #este_switch = SwitchOVS.getSwitch(str(dpid)) #isso ja foi feito mais acima no codigo
            #     #marcar com tos de controle
            #     este_switch.addRegraC(ip_src, IPC, 29)
                
            #     #em cada switch, o este_switch inclusive, criar as regras de encaminhamento
            #     for s in switches_rota:
            #         out_port = s.getPortaSaida(IPC)
            #         #criando as regras de encaminhamento nos demais switches
            #         s.alocarGBAM(out_port, ip_src, IPC, '1000', '2', '4')

####### etapa 5 - reijetar icmp 15
    ### SEGUINDO O ICMP 15 inf. req. - injetar pelo ultimo switch da  rota
        #obtendo a rota entre src e destino, assim como era antes
                switches_rota = self.getRota(str(dpid), ip_dst)
                
                #obter o switch mais da borda de destino e gerar o inf req para dar sequencia e descobrir novos controladores ate o host destino
                switch_ultimo = switches_rota[-1]
                out_port = switch_ultimo.getPortaSaida(ip_dst)

                switch_ultimo_dp = switch_ultimo.getDP()
                #print("[ICMP-15] Dando sequencia no icmp 15 criando no ultimo switch da rota \n src:%s, dst:%s, saida:%d\n", ip_src, ip_dst, out_port)
                send_icmpv4(switch_ultimo_dp, src, ip_src, dst, ip_dst,out_port,0,pkt_icmp.data,1,15,64)

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
                send_icmpv4(switch_primeiro.datapath, src, ip_src, dst, ip_dst, out_port, 0,pkt_icmp.data,1,16,64)

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
            
            send_icmpv4(switch_ultimo_dp, MACC, IPC, dst, ip_dst, out_port, 0, data, 1, 15,64)
                          
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
                    